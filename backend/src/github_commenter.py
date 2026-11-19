import hashlib
import os
import re
from typing import List, Optional
import requests

SEVERITY_EMOJI = {
    'Critical': '🔴',
    'High':     '🟠',
    'Medium':   '🟡',
    'Low':      '🟢',
}


def _build_review_body(
    vulnerabilities: list,
    provider: Optional[str] = None,
    model: Optional[str] = None,
) -> str:
    """
    Renders the full GitHub PR review body in rich Markdown, showing actual provider/model.
    """
    raw_prov = (provider or os.getenv('LLM_PROVIDER') or os.getenv('MODEL_PROVIDER') or 'mock').strip().lower()
    prov_names = {
        'nvidia': 'NVIDIA NIM',
        'bedrock': 'Amazon Bedrock',
        'gemini': 'Google Gemini',
        'mock': 'SageArmor AI Engine',
        'recorded': 'Recorded LLM Dataset',
    }
    provider_str = prov_names.get(raw_prov, provider or 'SageArmor AI Engine')
    model_str = model or os.getenv('LLM_MODEL') or os.getenv('BEDROCK_MODEL_ID') or ('meta/llama3-8b-instruct' if raw_prov == 'nvidia' else 'anthropic.claude-3-haiku' if raw_prov == 'bedrock' else 'v1.0')
    footer = f"> _Scanned by **SageArmor AI** — powered by {provider_str} ({model_str})._\n> _Review is advisory only. Fixes require human approval before merge._"

    if not vulnerabilities:
        return (
            "## ✅ SageArmor AI — Security Review Passed\n\n"
            "No vulnerabilities were detected in this Pull Request.\n\n"
            f"> _Scanned by [SageArmor AI](https://github.com) — powered by {provider_str} ({model_str})._"
        )

    lines = [
        "## 🛡️ SageArmor AI — Security Review Report",
        "",
        f"Found **{len(vulnerabilities)}** security finding(s) that require your attention.",
        "",
        "---",
        "",
    ]

    for i, v in enumerate(vulnerabilities, 1):
        severity = v.get('severity', 'Low')
        emoji = SEVERITY_EMOJI.get(severity, '🟢')
        issue = v.get('issue', 'Unknown Issue')
        is_verified = v.get('verified') is True or str(v.get('verification_status', '')).lower() == 'confirmed'
        v_status = " `[Verified Exploit]`" if is_verified else ""
        explanation = v.get('explanation', '')
        poc = v.get('poc_exploit_scenario', '')
        file_ref = v.get('file', '')
        line_ref = v.get('line', '')

        # Support both old (suggested_fix) and new (remediation.patch) schemas
        remediation = v.get('remediation', {})
        patch = remediation.get('patch') if isinstance(remediation, dict) else None
        patch = patch or v.get('suggested_fix', '')
        fix_explanation = remediation.get('explanation', '') if isinstance(remediation, dict) else ''

        lines += [
            f"### {emoji} Finding #{i}: {issue}{v_status}",
            "",
            f"**Severity:** `{severity}`" + (f" | **File:** `{file_ref}:{line_ref}`" if file_ref else ""),
            "",
            f"**Risk Explanation:**",
            f"> {explanation}",
            "",
        ]

        if poc:
            lines += [
                "**Simulated Attack Scenario:**",
                "```diff",
                f"- {poc}",
                "```",
                "",
            ]

        if patch:
            lines += [
                "**Suggested Remediation:**",
                "```",
                patch,
                "```",
            ]
            if fix_explanation:
                lines += [f"_{fix_explanation}_", ""]

        lines += ["---", ""]

    lines += ["", footer]

    return "\n".join(lines)


def _compute_findings_fingerprint(vulnerabilities: list) -> str:
    """Computes a stable fingerprint for a set of findings to detect duplicates."""
    items = []
    for v in vulnerabilities:
        items.append(f"{v.get('file', '')}:{v.get('line', '')}:{v.get('issue', '')}:{v.get('severity', '')}")
    return hashlib.sha256(";".join(sorted(items)).encode("utf-8")).hexdigest()[:16]


def post_pr_review(
    repo_full_name: str,
    pr_number: int,
    vulnerabilities: list,
    provider: Optional[str] = None,
    model: Optional[str] = None,
    changed_files: Optional[List[str]] = None,
) -> bool:
    """
    Posts a structured AI security review as a GitHub PR review comment.
    Filters to changed files only and avoids duplicate comments on the same PR.
    """
    github_token = os.getenv('GITHUB_TOKEN')
    if not github_token:
        print("[github_commenter] GITHUB_TOKEN not set — skipping PR comment.")
        return False

    if not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', str(repo_full_name or '')):
        print("[github_commenter] Invalid repository identifier — skipping PR comment.")
        return False

    # Feed only active non-refuted findings into PR comments
    vulnerabilities = [
        v for v in (vulnerabilities or [])
        if str(v.get("verification_status", "")).lower() not in ("refuted", "false_positive")
        and not v.get("refuted")
    ]

    # Scan changed files only if changed_files list is provided
    if changed_files is not None:
        changed_set = set(changed_files)
        vulnerabilities = [v for v in vulnerabilities if not v.get('file') or v.get('file') in changed_set]

    headers = {
        "Authorization": f"token {github_token}",
        "Accept": "application/vnd.github.v3+json",
        "Content-Type": "application/json",
    }

    # Avoid duplicate comments: check existing reviews on this PR
    reviews_url = f"https://api.github.com/repos/{repo_full_name}/pulls/{pr_number}/reviews"
    try:
        existing_res = requests.get(reviews_url, headers=headers, timeout=10, allow_redirects=False)
        if existing_res.status_code == 200:
            existing_reviews = existing_res.json()
            fingerprint = _compute_findings_fingerprint(vulnerabilities)
            for rev in existing_reviews:
                body = rev.get("body", "")
                if "SageArmor AI — Security Review" in body and fingerprint in body:
                    print(f"[github_commenter] Duplicate review detected on PR #{pr_number} — skipping comment.")
                    return True
    except Exception as e:
        print(f"[github_commenter] Notice: could not check existing reviews: {str(e)}")

    review_body = _build_review_body(vulnerabilities, provider=provider, model=model)
    # Embed invisible fingerprint tag in review body to track uniqueness
    fingerprint = _compute_findings_fingerprint(vulnerabilities)
    review_body += f"\n<!-- sagearmor-fingerprint:{fingerprint} -->"

    payload = {
        "body": review_body,
        "event": "COMMENT",   # Advisory: does not approve or request changes
    }

    try:
        response = requests.post(reviews_url, headers=headers, json=payload, timeout=15, allow_redirects=False)
        if response.status_code in (200, 201):
            print(f"[github_commenter] Successfully posted review to PR #{pr_number} on {repo_full_name}")
            return True
        else:
            print(f"[github_commenter] GitHub API error {response.status_code}: {response.text[:300]}")
            return False
    except Exception as e:
        print(f"[github_commenter] Exception posting PR review: {str(e)}")
        return False
