import json
import os
import hmac
import hashlib
import re
import time
import uuid
import requests
from typing import Any, Dict, List, Optional, Tuple
from datetime import datetime, timezone
from urllib.parse import quote, urlparse
from dotenv import load_dotenv
import boto3
from .prompt_builder import build_security_prompt
from .github_commenter import post_pr_review
from .function_cache import SelectiveFunctionScanner
from .cascade_engine import CascadeEngine
from .sandbox_verifier import apply_verification_gate, SandboxVerifier

load_dotenv()

# try:
#     import google.generativeai as genai
# except Exception:
#     genai = None

from .prompt_builder import build_security_prompt
from .github_commenter import post_pr_review
from .attack_intelligence import build_attack_intelligence, build_copilot_prompt
from .code_graph import build_code_graph, merge_with_heuristic_graph
from .repo_selective_scan import selective_repo_scan
from .repo_selective_scan import _is_allowed_repo_url
from .sast_scanner import SASTScanner
from .autofix_engine import start_autofix_job
from .autofix_prompt import build_autofix_prompt
from .finding_schema import anchor_findings, normalize_findings, rank_findings
from .finding_schema import SCHEMA_VERSION
from .llm_provider import create_provider, redact_secrets
from .job_manager import (
    create_job,
    get_job,
    update_job,
    update_job_progress,
    mark_completed,
    mark_failed,
    submit_job,
    record_stage_timing,
    record_observability,
    add_job_event,
)


def _get_feature_flags(body=None):
    flags = {
        "cache": os.getenv("FEATURE_CACHE", "true").lower() in ("true", "1", "yes"),
        "cascade": os.getenv("FEATURE_CASCADE", "true").lower() in ("true", "1", "yes"),
        "model": os.getenv("FEATURE_MODEL", "true").lower() in ("true", "1", "yes"),
        "verification": os.getenv("FEATURE_VERIFICATION", "true").lower() in ("true", "1", "yes"),
        "taint": os.getenv("FEATURE_TAINT", "true").lower() in ("true", "1", "yes"),
        "autofix": os.getenv("FEATURE_AUTOFIX", "true").lower() in ("true", "1", "yes"),
    }
    if isinstance(body, dict) and isinstance(body.get("features"), dict):
        for k, v in body["features"].items():
            if k in flags:
                flags[k] = bool(v)
    return flags

load_dotenv()

SUPPORTED_LANGUAGES = {
    'python', 'javascript', 'typescript', 'java', 'ruby', 'rust', 'sql',
    'cpp', 'c', 'csharp', 'go', 'kotlin', 'php', 'swift', 'terraform',
    'yaml', 'json', 'mixed', 'repository',
}

# Pick up Gemini Key from `.env`
# gemini_api_key = os.getenv('GEMINI_API_KEY')
nvidia_api_key = os.getenv('NVIDIA_API_KEY')
nvidia_model = os.getenv('NVIDIA_MODEL', 'meta/llama3-8b-instruct')


def _current_model_id():
    """Model id for the active provider, read at call time so values from .env apply."""
    provider = _get_model_provider()
    if provider == 'nvidia':
        return os.getenv('NVIDIA_MODEL', 'meta/llama3-8b-instruct')
    if provider == 'gemini':
        return os.getenv('GEMINI_MODEL', 'gemini-3.5-flash-lite')
    return os.getenv('MODEL_ID', '')
# Initialize Bedrock client
# In Lambda, boto3 natively picks up credentials and region from the IAM role.
# For local testing, it will pick up from the environment variables (.env).
# bedrock = boto3.client(
#     service_name='bedrock-runtime',
#     region_name=os.getenv('AWS_REGION', 'us-east-1')
# )

def _is_truthy(value):
    return str(value or '').strip().lower() in {'1', 'true', 'yes', 'on'}

_DAILY_BUDGET_TRACKER = {
    "date": None,
    "tokens": 0,
    "requests": 0,
}
MAX_DAILY_TOKENS = int(os.getenv("SAGEARMOR_MAX_DAILY_TOKENS", "200000"))

def _get_system_health() -> dict:
    import shutil
    return {
        "model_available": bool(os.getenv("NVIDIA_API_KEY") or os.getenv("AWS_ACCESS_KEY_ID") or os.getenv("MODEL_PROVIDER") == "mock"),
        "docker_available": bool(shutil.which("docker")),
        "github_available": bool(os.getenv("GITHUB_TOKEN")),
        "disk_available": True,
    }


def _get_model_provider():
    explicit = (os.getenv('LLM_PROVIDER') or os.getenv('MODEL_PROVIDER') or '').strip().lower()
    if explicit in {'nvidia', 'gemini', 'bedrock', 'mock', 'recorded'}:
        return explicit
    if explicit:
        raise ValueError('MODEL_PROVIDER must be one of nvidia, bedrock, gemini, mock, or recorded')
    return 'bedrock'


# def _gemini_model_candidates():
#     configured = (os.getenv('GEMINI_MODEL') or '').strip()
#     preferred = [
#         'gemini-1.5-flash',
#         'gemini-2.5-flash',
#         'gemini-2.0-flash',
#         'gemini-2.0-flash-lite',
#     ]
# 
#     candidates = []
#     if configured:
#         candidates.append(configured)
# 
#     for name in preferred:
#         if name not in candidates:
#             candidates.append(name)
# 
#     return candidates


# def _extract_gemini_text(response):
#     try:
#         text = (getattr(response, 'text', '') or '').strip()
#         if text:
#             return text
#     except Exception:
#         pass
# 
#     chunks = []
#     candidates = getattr(response, 'candidates', None) or []
#     for candidate in candidates:
#         content = getattr(candidate, 'content', None)
#         parts = getattr(content, 'parts', None) if content else None
#         if not parts:
#             continue
#         for part in parts:
#             t = getattr(part, 'text', None)
#             if t:
#                 chunks.append(t)
# 
#     return '\n'.join(chunks).strip()


def _parse_json_from_text(text):
    if not text:
        raise json.JSONDecodeError('Empty text', '', 0)

    # Step 0: Strip markdown fences
    clean = text.replace('```json', '').replace('```', '').strip()

    # Step 1: Try direct parse (fastest path)
    for attempt in [clean, text]:
        try:
            return json.loads(attempt)
        except json.JSONDecodeError:
            pass

    # Step 2: Use raw_decode to handle "Extra data" — extracts first valid JSON
    decoder = json.JSONDecoder()
    for attempt in [clean, text]:
        for start_char in ['{', '[']:
            idx = attempt.find(start_char)
            if idx != -1:
                try:
                    result, _ = decoder.raw_decode(attempt, idx)
                    return result
                except json.JSONDecodeError:
                    pass

    # Step 3: Aggressive bracket matching (handles truncated JSON from token limits)
    first_obj = clean.find('{')
    last_obj = clean.rfind('}')
    if first_obj != -1 and last_obj != -1 and last_obj > first_obj:
        try:
            return json.loads(clean[first_obj:last_obj + 1])
        except json.JSONDecodeError:
            pass

    first_arr = clean.find('[')
    last_arr = clean.rfind(']')
    if first_arr != -1 and last_arr != -1 and last_arr > first_arr:
        try:
            return json.loads(clean[first_arr:last_arr + 1])
        except json.JSONDecodeError:
            pass

    raise json.JSONDecodeError('Could not extract valid JSON from AI response', text, 0)


# def _repair_json_with_gemini(raw_text, max_tokens):
#     repair_prompt = (
#         'Return only valid JSON. Preserve original meaning and fields. '
#         'Do not add markdown fences.\n\n'
#         f'{raw_text}'
#     )
# 
#     last_error = None
#     for model_name in _gemini_model_candidates():
#         try:
#             model = genai.GenerativeModel(model_name=model_name)
#             response = model.generate_content(
#                 repair_prompt,
#                 generation_config={
#                     'max_output_tokens': max_tokens,
#                     'response_mime_type': 'application/json',
#                     'temperature': 0,
#                 },
#             )
#             repaired = _extract_gemini_text(response)
#             return _parse_json_from_text(repaired)
#         except Exception as exc:
#             last_error = exc
# 
#     raise RuntimeError(str(last_error) if last_error else 'Gemini JSON repair failed')


def _get_bedrock_client():
    # In Lambda, boto3 picks credentials/region from IAM role.
    # For local, it picks from environment variables.
    return boto3.client(
        service_name='bedrock-runtime',
        region_name=os.getenv('AWS_REGION', 'us-east-1')
    )


# def _invoke_gemini_json(prompt, max_tokens=600):
#     if genai is None:
#         raise RuntimeError('google-generativeai dependency is not installed')
# 
#     api_key = os.getenv('GEMINI_API_KEY', '').strip()
#     if not api_key:
#         raise RuntimeError('GEMINI_API_KEY is missing')
# 
#     genai.configure(api_key=api_key)
# 
#     response = None
#     last_error = None
#     for model_name in _gemini_model_candidates():
#         try:
#             model = genai.GenerativeModel(model_name=model_name)
#             response = model.generate_content(
#                 prompt,
#                 generation_config={
#                     'max_output_tokens': max_tokens,
#                     'response_mime_type': 'application/json',
#                     'temperature': 0.0,
#                 },
#             )
#             break
#         except Exception as exc:
#             last_error = exc
# 
#     if response is None:
#         raise RuntimeError(str(last_error) if last_error else 'Gemini model invocation failed')
# 
#     text = _extract_gemini_text(response)
#     if not text:
#         raise RuntimeError('Gemini returned empty response')
# 
#     try:
#         return _parse_json_from_text(text)
#     except json.JSONDecodeError:
#         return _repair_json_with_gemini(text, max_tokens=max_tokens)


# def _invoke_gemini_text(prompt, max_tokens=1200):
#     if genai is None:
#         raise RuntimeError('google-generativeai dependency is not installed')
# 
#     api_key = os.getenv('GEMINI_API_KEY', '').strip()
#     if not api_key:
#         raise RuntimeError('GEMINI_API_KEY is missing')
# 
#     genai.configure(api_key=api_key)
# 
#     response = None
#     last_error = None
#     for model_name in _gemini_model_candidates():
#         try:
#             model = genai.GenerativeModel(model_name=model_name)
#             response = model.generate_content(
#                 prompt,
#                 generation_config={
#                     'max_output_tokens': max_tokens,
#                     'temperature': 0.1,
#                 },
#             )
#             break
#         except Exception as exc:
#             last_error = exc
# 
#     if response is None:
#         raise RuntimeError(str(last_error) if last_error else 'Gemini model invocation failed')
#     text = _extract_gemini_text(response)
#     if not text:
#         raise RuntimeError('Gemini returned empty response')
#     return text


def _safe_log(msg):
    print(redact_secrets(str(msg)))


def _json_response(status_code, payload):
    payload = dict(payload) if isinstance(payload, dict) else {"data": payload}
    if "error" in payload and payload["error"]:
        payload["error"] = redact_secrets(str(payload["error"]))
    payload.setdefault("schema_version", SCHEMA_VERSION)
    payload.setdefault("analysis_mode", "unknown")
    payload.setdefault("job_id", None)
    request_id = payload.setdefault("request_id", str(uuid.uuid4()))
    payload.setdefault("degraded", payload.get("analysis_mode") in {"sast-local", "local-fallback", "cascade-clean"})
    payload.setdefault("telemetry", {})
    payload.setdefault("usage", {"estimated": True, "total_tokens": 0})
    return {
        "statusCode": status_code,
        "headers": {
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Credentials": True,
            "X-Request-ID": request_id,
        },
        "body": json.dumps(payload),
    }


def _parse_body(event):
    body_str = event.get('body', '{}')
    if not body_str:
        body_str = '{}'
    return json.loads(body_str) if isinstance(body_str, str) else body_str


def _max_code_size() -> int:
    try:
        return max(1, int(os.getenv("MAX_CODE_SIZE_BYTES", str(1024 * 1024))))
    except (TypeError, ValueError):
        return 1024 * 1024


def healthz(event, context):
    """Return non-sensitive service readiness information."""
    import shutil

    return _json_response(200, {
        "status": "ok",
        "schema_version": SCHEMA_VERSION,
        "provider": _get_model_provider(),
        "model": _current_model_id() or None,
        "features": {
            "sast": True,
            "sandbox": bool(shutil.which("docker")),
            "webhook_signatures": bool(os.getenv("GITHUB_WEBHOOK_SECRET")),
        },
        "cache": {"enabled": True},
        "gate_calibration": {"status": "not_configured"},
    })


def _invoke_bedrock_json(prompt, max_tokens=600):
    request_body = json.dumps({
        "anthropic_version": "bedrock-2023-05-31",
        "max_tokens": max_tokens,
        "messages": [
            {
                "role": "user",
                "content": [{"type": "text", "text": prompt}]
            }
        ]
    })

    bedrock = _get_bedrock_client()
    bedrock_response = bedrock.invoke_model(
        modelId='us.anthropic.claude-sonnet-4-5-20250929-v1:0',
        contentType='application/json',
        accept='application/json',
        body=request_body
    )
    response_body = json.loads(bedrock_response['body'].read())
    content_items = response_body.get('content') or []
    first_item = content_items[0] if isinstance(content_items, list) and content_items else {}
    content = first_item.get('text', '{}') if isinstance(first_item, dict) else '{}'

    try:
        return json.loads(content)
    except json.JSONDecodeError:
        clean_text = content.replace("```json", "").replace("```", "").strip()
        return json.loads(clean_text)


def _invoke_bedrock_text(prompt, max_tokens=1200):
    request_body = json.dumps({
        "anthropic_version": "bedrock-2023-05-31",
        "max_tokens": max_tokens,
        "messages": [
            {
                "role": "user",
                "content": [{"type": "text", "text": prompt}]
            }
        ]
    })

    bedrock = _get_bedrock_client()
    bedrock_response = bedrock.invoke_model(
        modelId='us.anthropic.claude-sonnet-4-5-20250929-v1:0',
        contentType='application/json',
        accept='application/json',
        body=request_body
    )
    response_body = json.loads(bedrock_response['body'].read())
    content_items = response_body.get('content') or []
    first_item = content_items[0] if isinstance(content_items, list) and content_items else {}
    text = first_item.get('text', '') if isinstance(first_item, dict) else ''
    return text.strip()


def _invoke_nvidia_json(prompt, max_tokens=2000):
    if not nvidia_api_key:
        raise RuntimeError('NVIDIA_API_KEY is missing')

    headers = {
        "Authorization": f"Bearer {nvidia_api_key}",
        "Content-Type": "application/json",
        "accept": "application/json"
    }
    
    payload = {
        "model": nvidia_model,
        "messages": [
            {"role": "system", "content": "You are a strict SageArmor API that ONLY outputs perfectly valid JSON. No conversation, no markdown fences, no preamble."},
            {"role": "user", "content": prompt}
        ],
        "max_tokens": max_tokens,
        "temperature": 0,
        "top_p": 0.7,
        "seed": 42
    }
    
    url = "https://integrate.api.nvidia.com/v1/chat/completions"
    response = requests.post(url, headers=headers, json=payload, timeout=30)
    
    if response.status_code != 200:
        raise RuntimeError(f"NVIDIA API request failed: {response.status_code} - {response.text}")
    
    result = response.json()
    text = result['choices'][0]['message']['content']
    return _parse_json_from_text(text)


def _invoke_nvidia_text(prompt, max_tokens=2000):
    if not nvidia_api_key:
        raise RuntimeError('NVIDIA_API_KEY is missing')

    headers = {
        "Authorization": f"Bearer {nvidia_api_key}",
        "Content-Type": "application/json",
        "accept": "application/json"
    }
    
    payload = {
        "model": nvidia_model,
        "messages": [{"role": "user", "content": prompt}],
        "max_tokens": max_tokens,
        "temperature": 0.2
    }
    
    url = "https://integrate.api.nvidia.com/v1/chat/completions"
    response = requests.post(url, headers=headers, json=payload, timeout=30)
    
    if response.status_code != 200:
        raise RuntimeError(f"NVIDIA API request failed: {response.status_code} - {response.text}")
    
    result = response.json()
    return result['choices'][0]['message']['content'].strip()


def _invoke_model_json(prompt, max_tokens=600):
    return create_provider(_get_model_provider()).complete_json(prompt, max_tokens=max_tokens)


def _invoke_model_text(prompt, max_tokens=1200, timeout=None, retries=None):
    provider = create_provider(_get_model_provider())
    # Interactive callers (the copilot) cap the wait so a slow provider falls back quickly.
    if timeout is not None and hasattr(provider, "timeout"):
        provider.timeout = min(float(provider.timeout), float(timeout))
    if retries is not None and hasattr(provider, "retries"):
        provider.retries = min(int(provider.retries), int(retries))
    return provider.complete(prompt, max_tokens=max_tokens).text.strip()


def _local_static_review(code_snippet):
    """Use real SAST scanner instead of mock findings."""
    text = code_snippet or ''
    
    # Use real SAST scanner to detect actual vulnerabilities
    sast_findings = SASTScanner.scan_code(text, file_path='<input>')
    
    # Convert SAST findings to the expected response format
    vulnerabilities = []
    for finding in sast_findings:
        vulnerabilities.append({
            'severity': finding['severity'],
            'issue': finding['issue'],
            'attack_vector': finding['attack_vector'],
            'explanation': finding['explanation'],
            'poc_exploit_scenario': finding['poc_exploit_scenario'],
            'remediation': finding['remediation'],
            'suggested_fix': finding['suggested_fix'],
            'matched_code': finding.get('matched_code', ''),
            'line': finding.get('line', 0),
        })
    
    return {
        'vulnerabilities': vulnerabilities,
        'analysis_mode': 'sast-local',
        'note': 'Real static analysis performed; pattern-based vulnerability detection.',
    }



def _local_copilot_answer(question, intelligence, vulnerabilities=None):
    """
    Rule-based copilot reply used only when the LLM provider fails. It reads the
    question's intent (greeting, help, list, explain, exploit, fix, priority) instead
    of always reciting the top finding, and answers in the same Markdown the model uses.
    """
    import re

    risk_ranking = intelligence.get('risk_ranking', []) if isinstance(intelligence, dict) else []
    vulnerabilities = vulnerabilities if isinstance(vulnerabilities, list) else []
    q = (question or '').strip().lower()
    words = set(re.findall(r"[a-z0-9']+", q))

    def has(*terms):
        return any((t in q) if ' ' in t else (t in words) for t in terms)

    def match_vuln(issue_name):
        target = (issue_name or '').strip().lower()
        for vuln in vulnerabilities:
            if str(vuln.get('issue', '')).strip().lower() == target:
                return vuln
        return vulnerabilities[0] if vulnerabilities else {}

    count = len(risk_ranking)
    capabilities = (
        "I can explain each finding, show how an attacker would exploit it, rank what to fix first, "
        "and give corrected code. Try: *\"Which issue should I fix first?\"* or *\"Show me the fixed code.\"*"
    )

    # Small talk and meta questions get a direct answer, not a recited finding.
    if has('thanks', 'thank', 'thx', 'cheers'):
        return "You're welcome. Re-run the scan after applying a fix to confirm it is resolved."
    if not count:
        return (
            "Hi! There are no scan findings to discuss yet. Run a scan, then ask me about the results.\n\n"
            + capabilities
        )
    summary_lines = [
        f"{i + 1}. **{r.get('issue', 'Unknown issue')}**: {r.get('severity', 'Unknown')} severity, "
        f"priority {r.get('priority_score', 'n/a')}/10"
        for i, r in enumerate(risk_ranking[:5])
    ]
    plural = 's' if count != 1 else ''
    summary = f"The scan found **{count}** issue{plural}:\n\n" + "\n".join(summary_lines)
    if has('hi', 'hello', 'hey', 'yo', 'hola') and len(words) <= 3:
        return f"Hi! {summary}\n\n{capabilities}"
    if has('help', 'what can you do', 'who are you', 'what are you'):
        return f"{capabilities}\n\n{summary}"
    if has('list', 'summary', 'summarize', 'overview', 'how many', 'all issues', 'all findings'):
        return summary

    # Pick the finding the question refers to: an ordinal, else a name it mentions, else the top one.
    target_index = 0
    ordinals = {'first': 0, 'second': 1, 'third': 2, 'fourth': 3, 'fifth': 4,
                '1st': 0, '2nd': 1, '3rd': 2, '4th': 3, '5th': 4}
    picked = next((ordinals[w] for w in ordinals if w in words and not has('fix first', 'first fix')), None)
    if picked is not None:
        target_index = picked
    else:
        for i, r in enumerate(risk_ranking):
            name = str(r.get('issue', '')).lower()
            if ('sql' in q and 'sql' in name) or (('command' in q or 'shell' in q) and 'command' in name) \
                    or (('path' in q or 'traversal' in q) and 'path' in name) or (('xss' in q or 'script' in q) and 'xss' in name):
                target_index = i
                break
    target_index = max(0, min(target_index, count - 1))
    top = risk_ranking[target_index]
    issue = top.get('issue', 'unknown issue')
    score = top.get('priority_score', 'n/a')
    severity = top.get('severity', 'Unknown')
    exploit = top.get('exploitability', {}).get('level', 'Unknown')
    vuln = match_vuln(issue)
    line = vuln.get('line')
    where = f" (line {line})" if line else ""
    remediation = vuln.get('remediation') if isinstance(vuln.get('remediation'), dict) else {}
    patch = (remediation.get('patch') or vuln.get('suggested_fix') or '').strip()
    # Stored patches are often cut from inside a function: the first line has lost its indent but
    # the rest keep theirs. Dedent the remaining lines so the snippet lines up.
    patch_lines = patch.splitlines()
    if len(patch_lines) > 1 and patch_lines[0] == patch_lines[0].lstrip():
        import textwrap
        patch = "\n".join([patch_lines[0], textwrap.dedent("\n".join(patch_lines[1:]))])
    reason = vuln.get('explanation') or 'It combines a dangerous operation with input an attacker can control.'
    attack = vuln.get('poc_exploit_scenario') or vuln.get('attack_vector') or ''
    if patch:
        patch_block = "\n\n```\n" + patch + "\n```"
    else:
        patch_block = "\n\nApply the remediation shown in the Findings tab, then re-run the scan."

    if has('fix', 'patch', 'remediate', 'remediation', 'repair', 'solve', 'secure', 'corrected', 'code'):
        if has('first', 'priority', 'which'):
            return (
                f"Fix **{issue}**{where} first: {severity} severity, {exploit} exploitability, "
                f"priority {score}/10, the highest in this scan.{patch_block}"
            )
        return f"**Fix for {issue}**{where}{patch_block}\n\nRe-run the scan afterwards to confirm it is gone."
    if has('priority', 'prioritize', 'which', 'order', 'worst', 'urgent', 'start'):
        return (
            f"Start with **{issue}**{where}: {severity} severity, {exploit} exploitability, "
            f"priority {score}/10.{patch_block}"
        )
    if has('exploit', 'attack', 'attacker', 'hack', 'payload', 'poc', 'abuse'):
        body = attack or f"An attacker sends crafted input that reaches the vulnerable call{where} unchanged."
        return f"**How {issue} could be exploited**{where}\n\n{body}"
    return (
        f"**{issue}**{where}: {severity} severity, {exploit} exploitability, priority {score}/10.\n\n"
        f"{reason}\n\n**How to fix it:**{patch_block}"
    )


def _extract_vulnerabilities_for_advanced(body):
    vulnerabilities = body.get('vulnerabilities')
    if isinstance(vulnerabilities, list):
        normalized = normalize_findings(
            vulnerabilities,
            file_path=body.get('file', ''),
            language=body.get('language', 'python'),
        )
    else:
        code_snippet = body.get('code', '')
        language = body.get('language', 'python')
        if not code_snippet:
            return []

        prompt = build_security_prompt(code_snippet, language)
        try:
            analysis_result = _invoke_model_json(prompt)
        except Exception as err:
            _safe_log(f"[handler] Advanced endpoints using local fallback: {str(err)}")
            analysis_result = _local_static_review(code_snippet)
        
        if isinstance(analysis_result, list):
            vulns = analysis_result
        else:
            vulns = analysis_result.get('vulnerabilities', []) if isinstance(analysis_result, dict) else []
        normalized = normalize_findings(vulns, language=language)

    # Feed only active non-refuted findings into advanced views
    active = [
        v for v in normalized
        if str(v.get("verification_status", "")).lower() not in ("refuted", "false_positive")
        and not v.get("refuted")
    ]
    if body.get("verified_only"):
        active = [v for v in active if v.get("verified") is True or str(v.get("verification_status", "")).lower() == "confirmed"]
    return active

def verify_signature(event):
    secret = os.getenv('GITHUB_WEBHOOK_SECRET')
    if not secret:
        return True
    
    headers = {k.lower(): v for k, v in event.get('headers', {}).items()}
    signature = headers.get('x-hub-signature-256')
    if not signature:
        return False
    
    body = event.get('body', '{}')
    if not isinstance(body, str):
        body = json.dumps(body, separators=(',', ':'))

    mac = hmac.new(secret.encode('utf-8'), body.encode('utf-8'), hashlib.sha256)
    expected_sig = "sha256=" + mac.hexdigest()
    
    return hmac.compare_digest(expected_sig, signature)

def _execute_deep_pipeline_sync(
    code_snippet: str,
    language: str,
    router_mode: str,
    flags: Dict[str, bool],
    initial_findings: Optional[List[Dict[str, Any]]] = None,
    job_id: Optional[str] = None,
) -> List[Dict[str, Any]]:
    selective_scanner = SelectiveFunctionScanner()
    if flags.get("cache", True):
        partition = selective_scanner.partition_functions(
            code_snippet,
            language=language,
            provider=_get_model_provider(),
            model_id=_current_model_id(),
            router_mode=router_mode,
        )
        cached_vulns = partition.get("cached_vulnerabilities", [])
        funcs_to_scan = partition.get("functions_to_scan", [])
    else:
        from .function_cache import extract_functions
        cached_vulns = []
        funcs_to_scan = extract_functions(code_snippet, language)

    if job_id:
        record_stage_timing(job_id, "cache_partition", 10.0)

    if flags.get("cascade", True):
        cascade = CascadeEngine(cache=selective_scanner.cache)
        triage = cascade.filter_and_triage(funcs_to_scan)
        flagged_functions = triage.get("flagged_functions", [])
    else:
        flagged_functions = [
            {
                "name": f.get("name", "func"),
                "code": f.get("code", ""),
                "start_line": f.get("start_line", 1),
                "end_line": f.get("end_line", 999999),
                "sast_findings": [],
            }
            for f in funcs_to_scan
        ]

    new_vulns = []
    if flagged_functions and flags.get("model", True):
        targeted_code = (
            CascadeEngine.build_targeted_prompt_context(flagged_functions, full_code=code_snippet)
            if flagged_functions
            else code_snippet
        )
        prompt = build_security_prompt(targeted_code, language)
        start_t = time.time()
        try:
            model_res = _invoke_model_json(prompt, max_tokens=2048)
            if isinstance(model_res, list):
                new_vulns = model_res
            elif isinstance(model_res, dict):
                new_vulns = model_res.get('vulnerabilities', [])
        except Exception as e:
            _safe_log(f"[handler] Model call in deep pipeline failed: {e}")
            new_vulns = _local_static_review(targeted_code).get('vulnerabilities', [])
        if job_id:
            record_stage_timing(job_id, "model_triage", (time.time() - start_t) * 1000.0)

    # Anchor new findings first so line numbers and function names are resolved
    new_vulns = anchor_findings(new_vulns, code_snippet)

    # Merge / deduplicate SAST findings from flagged functions
    for f_entry in flagged_functions:
        for sf in f_entry.get("sast_findings", []):
            sf_line = sf.get("line", 0)
            sf_issue = (sf.get("issue") or "").lower()
            matched = False
            for v in new_vulns:
                v_line = v.get("line", 0)
                v_issue = (v.get("issue") or "").lower()
                if (v_line == sf_line and v_line > 0) or (abs(v_line - sf_line) <= 2 and (v_issue in sf_issue or sf_issue in v_issue)):
                    v.setdefault("remediation", sf.get("remediation"))
                    v.setdefault("cwe", sf.get("cwe"))
                    v["provenance"] = "hybrid"
                    matched = True
                    break
            if not matched:
                new_vulns.append(sf)

    # Dynamic sandbox verification gate
    verified_vulns_all = []
    start_v = time.time()
    for func in flagged_functions:
        func_vulns = [
            v for v in new_vulns
            if (func.get("start_line", 1) <= v.get("line", 0) <= func.get("end_line", 999999))
            or (v.get("function_name") == func.get("name"))
        ]
        if func_vulns:
            if flags.get("verification", True):
                func_vulns = apply_verification_gate(
                    vulnerabilities=func_vulns,
                    function_code=func["code"],
                    function_name=func["name"],
                    language=language,
                    function_start_line=func.get("start_line", 1),
                    context_source=code_snippet,
                )
            else:
                for fv in func_vulns:
                    fv.setdefault("verification_status", "unverified")
                    fv["verified"] = False
            verified_vulns_all.extend(func_vulns)

        if flags.get("cache", True):
            selective_scanner.cache.set(
                function_hash=func.get("cache_key", func.get("hash", "")),
                function_name=func["name"],
                language=language,
                scan_result={"vulnerabilities": func_vulns},
                original_start_line=func["start_line"],
                tokens_used=150,
                scan_duration_ms=50.0,
                provider="model",
            )

    if job_id:
        record_stage_timing(job_id, "sandbox_verification", (time.time() - start_v) * 1000.0)

    # Combine with cached
    combined = list(cached_vulns)
    for v in verified_vulns_all:
        if not any(cv.get('issue') == v.get('issue') and cv.get('line') == v.get('line') for cv in combined):
            combined.append(v)

    local_findings = _local_static_review(code_snippet).get('vulnerabilities', [])
    for lf in local_findings:
        if not any(c.get('issue') == lf.get('issue') and c.get('line') == lf.get('line') for c in combined):
            combined.append(lf)

    # Preserve initial finding IDs
    if initial_findings:
        id_map = {f.get("finding_id"): f for f in initial_findings if f.get("finding_id")}
        issue_line_map = {(f.get("issue"), f.get("line")): f for f in initial_findings}
        for v in combined:
            target = None
            if v.get("finding_id") in id_map:
                target = id_map[v["finding_id"]]
            elif (v.get("issue"), v.get("line")) in issue_line_map:
                target = issue_line_map[(v.get("issue"), v.get("line"))]
            
            if target:
                v["finding_id"] = target["finding_id"]
                target.update(v)

        for init_f in initial_findings:
            if not any(c.get("finding_id") == init_f.get("finding_id") for c in combined):
                combined.append(init_f)

    return rank_findings(normalize_findings(combined, language=language))


_REPO_FULL_NAME_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")


def _fetch_pr_python_files(repo_full_name, pr_number, head_sha=""):
    """
    Full contents of the Python files a PR changes, at the PR's head commit. The diff alone
    cannot be executed, so the sandbox gate needs the real files. Returns [(path, source)].
    """
    if not (repo_full_name and _REPO_FULL_NAME_RE.match(str(repo_full_name)) and str(pr_number).isdigit()):
        return []
    if any(part in (".", "..") for part in str(repo_full_name).split("/")):
        return []
    max_files = max(0, int(os.getenv("SAGE_ARMOR_PR_MAX_PY_FILES", "10")))
    headers = {"Accept": "application/vnd.github+json"}
    if os.getenv("GITHUB_TOKEN"):
        headers["Authorization"] = f"token {os.getenv('GITHUB_TOKEN')}"
    api = f"https://api.github.com/repos/{repo_full_name}"
    try:
        listing_resp = requests.get(f"{api}/pulls/{int(pr_number)}/files?per_page=100", headers=headers,
                                    allow_redirects=False, timeout=15)
        listing = listing_resp.json() if listing_resp.status_code == 200 else []
    except Exception as exc:
        _safe_log(f"[handler] Could not list PR files: {exc}")
        return []
    if not isinstance(listing, list):
        return []
    files = []
    ref = f"?ref={quote(str(head_sha), safe='')}" if head_sha and re.fullmatch(r"[0-9a-fA-F]{7,64}", str(head_sha)) else ""
    for item in listing:
        if len(files) >= max_files:
            break
        if not isinstance(item, dict):
            continue
        name = str(item.get("filename") or "")
        if not name.endswith(".py") or item.get("status") == "removed" or ".." in name.split("/"):
            continue
        try:
            raw = requests.get(f"{api}/contents/{quote(name)}{ref}",
                               headers={**headers, "Accept": "application/vnd.github.v3.raw"},
                               allow_redirects=False, timeout=15)
        except Exception as exc:
            _safe_log(f"[handler] Could not fetch {name}: {exc}")
            continue
        text = raw.text if raw.status_code == 200 else None
        if isinstance(text, str) and text.strip() and len(text.encode("utf-8")) <= _max_code_size():
            files.append((name, text))
    return files


def _strip_python_from_diff(diff_text):
    """Drop the Python files' sections from a unified diff (they are scanned as whole files)."""
    blocks = re.split(r"(?m)^(?=diff --git )", diff_text or "")
    kept = [b for b in blocks if not re.match(r"diff --git a/\S+\.py b/\S+\.py", b)]
    return "".join(kept)


def _review_pr_python_files(pr_python_files, router_mode, flags):
    """Run the full pipeline, sandbox gate included, on each changed Python file."""
    findings = []
    mode = router_mode if router_mode in {'rules-only', 'balanced', 'thorough'} else 'balanced'
    for path, source in pr_python_files:
        try:
            file_findings = _execute_deep_pipeline_sync(source, 'python', mode, flags)
        except Exception as exc:
            _safe_log(f"[handler] PR file scan failed for {path}: {exc}")
            continue
        for finding in file_findings:
            finding["file"] = path
            finding["file_path"] = path
        findings.extend(file_findings)
    return findings


def _post_pr_findings(body, repo_full_name, pr_number, vulnerabilities):
    try:
        post_pr_review(
            repo_full_name,
            pr_number,
            vulnerabilities,
            provider=os.getenv('LLM_PROVIDER') or os.getenv('MODEL_PROVIDER') or 'NVIDIA NIM',
            model=os.getenv('LLM_MODEL') or os.getenv('BEDROCK_MODEL_ID') or 'meta/llama3-8b-instruct',
            changed_files=body.get('changed_files'),
        )
    except Exception as comment_err:
        # Never block the response if commenting fails
        _safe_log(f"[handler] PR comment failed (non-fatal): {str(comment_err)}")


def review_code(event, context):
    try:
        # Validate webhook if signature is present
        if not verify_signature(event):
            return _json_response(401, {"error": "Invalid GitHub webhook signature"})

        # Load the body
        body_str = event.get('body', '{}')
        if not body_str:
            body_str = '{}'
        body = json.loads(body_str) if isinstance(body_str, str) else body_str
        job_id = body.get('job_id')

        def _review_response(status_code, payload):
            if job_id is not None and isinstance(payload, dict):
                payload.setdefault("job_id", job_id)
            return _json_response(status_code, payload)

        # Determine language context from dashboard toggle or fallback 
        language = body.get('language', 'python')
        if str(language).lower() not in SUPPORTED_LANGUAGES:
            return _review_response(400, {"error": "Unsupported language."})
        is_webhook = 'pull_request' in body
        
        # 1. Check if it's a GitHub Webhook event
        if 'pull_request' in body:
            action = body.get('action')
            if action and action not in ['opened', 'synchronize']:
                return _review_response(200, {"msg": f"Skipping action {action}"})
            
            diff_url = body['pull_request']['diff_url']
            parsed_diff_url = urlparse(diff_url)
            if not _is_allowed_repo_url(diff_url) and not (
                parsed_diff_url.scheme == 'https'
                and parsed_diff_url.hostname == 'api.github.com'
                and parsed_diff_url.port in (None, 443)
                and not parsed_diff_url.username
                and not parsed_diff_url.password
            ):
                return _review_response(400, {"error": "Unapproved GitHub diff URL."})
            headers = {}
            if os.getenv('GITHUB_TOKEN'):
                headers['Authorization'] = f"token {os.getenv('GITHUB_TOKEN')}"
                
            resp = requests.get(diff_url, headers=headers, allow_redirects=False, timeout=15)
            if resp.status_code != 200:
                raise Exception(f"Failed to fetch PR diff: {resp.status_code}")
                
            code_snippet = resp.text
            
            # Enhanced heuristic for Cloud Configuration Analysis (Code + Config)
            has_cloud = any(ext in code_snippet for ext in ['.tf', '.yml', '.yaml', 'serverless', 'dockerfile'])
            has_code = any(ext in code_snippet for ext in ['.py', '.js', '.ts', '.go', '.java'])
            
            if has_cloud and has_code:
                language = 'mixed'
            elif has_cloud:
                language = 'terraform'
            elif '.js' in code_snippet or '.ts' in code_snippet:
                language = 'javascript'

            # Store PR metadata for auto-commenting after analysis
            repo_full_name = body.get('repository', {}).get('full_name', '')
            pr_number = body['pull_request'].get('number')

            # Changed Python files are scanned whole so the sandbox gate can run them;
            # the diff keeps only the other files.
            head_sha = (body['pull_request'].get('head') or {}).get('sha', '')
            pr_python_files = _fetch_pr_python_files(repo_full_name, pr_number, head_sha)
            if pr_python_files:
                code_snippet = _strip_python_from_diff(code_snippet)
                
        else:
            # 2. Direct code snippet testing (from Frontend Dashboard)
            code_snippet = body.get('code', '')
            repo_full_name = None
            pr_number = None
            pr_python_files = []

        if not code_snippet and not pr_python_files:
            return _review_response(400, {"error": "No code snippet provided."})
        if len(code_snippet.encode("utf-8")) > _max_code_size():
            return _review_response(413, {"error": "Code snippet exceeds the configured size limit."})

        router_mode = body.get('router_mode', body.get('mode', 'balanced'))
        flags = _get_feature_flags(body)

        pr_python_findings = _review_pr_python_files(pr_python_files, router_mode, flags) if pr_python_files else []
        if pr_python_files and not code_snippet.strip():
            analysis_result = {
                "vulnerabilities": rank_findings(pr_python_findings),
                "analysis_mode": "pr-python-verified",
                "telemetry": {"pr_python_files": len(pr_python_files)},
            }
            if repo_full_name and pr_number:
                _post_pr_findings(body, repo_full_name, pr_number, analysis_result["vulnerabilities"])
            return _review_response(200, analysis_result)

        # Asynchronous verification request
        if body.get('async_verify') or body.get('async'):
            static_res = _local_static_review(code_snippet)
            raw_vulns = static_res.get('vulnerabilities', [])
            anchored_initial = normalize_findings(anchor_findings(raw_vulns, code_snippet), language=language)
            for v in anchored_initial:
                v['verification_status'] = 'pending'
                v['verified'] = False

            job_id = create_job(job_id)
            add_job_event(job_id, "async_review_started", "Asynchronous scan and verification queued")
            record_stage_timing(job_id, "static_scan", 12.0)
            update_job_progress(job_id, "queued", 10, "Static analysis complete; queued for deep verification.")

            def _async_worker():
                try:
                    upgraded = _execute_deep_pipeline_sync(
                        code_snippet=code_snippet,
                        language=language,
                        router_mode=router_mode,
                        flags=flags,
                        initial_findings=anchored_initial,
                        job_id=job_id,
                    )
                    mark_completed(
                        job_id,
                        f"Verification complete with {len(upgraded)} findings",
                        {"vulnerabilities": upgraded, "status": "completed"}
                    )
                except Exception as exc:
                    mark_failed(job_id, f"Async verification failed: {str(exc)}")

            submit_job(_async_worker)
            return _review_response(202, {
                "job_id": job_id,
                "status": "pending_verification",
                "analysis_mode": "static-initial",
                "vulnerabilities": anchored_initial,
                "telemetry": {"fast_static": True, "job_id": job_id},
            })

        # Step 1: Function slicing & fingerprint caching
        selective_scanner = SelectiveFunctionScanner()
        router_mode = body.get('router_mode', body.get('mode', 'balanced'))
        if router_mode in {'default', 'model', None, ''}:
            router_mode = 'balanced'
        if router_mode not in {'rules-only', 'balanced', 'thorough'}:
            return _review_response(400, {"error": "router_mode must be rules-only, balanced, or thorough"})
        if router_mode == 'rules-only' or not flags.get("model", True):
            rules_only = _local_static_review(code_snippet)
            rules_only['analysis_mode'] = 'rules-only'
            rules_only['vulnerabilities'] = normalize_findings(
                rules_only.get('vulnerabilities', []), language=language,
            )
            return _review_response(200, rules_only)
        try:
            scan_budget = int(body.get('budget', -1))
        except (TypeError, ValueError):
            return _review_response(400, {"error": "budget must be an integer"})
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        if _DAILY_BUDGET_TRACKER["date"] != today:
            _DAILY_BUDGET_TRACKER["date"] = today
            _DAILY_BUDGET_TRACKER["tokens"] = 0
            _DAILY_BUDGET_TRACKER["requests"] = 0

        daily_exhausted = _DAILY_BUDGET_TRACKER["tokens"] >= MAX_DAILY_TOKENS
        if scan_budget == 0 or daily_exhausted:
            budget_result = _local_static_review(code_snippet)
            budget_result['analysis_mode'] = 'budget-exhausted'
            budget_result['degraded'] = True
            budget_result['degraded_state'] = {"daily_budget_exhausted": daily_exhausted, "tokens_used": _DAILY_BUDGET_TRACKER["tokens"]}
            budget_result['note'] = 'Model analysis skipped because the scan budget or daily budget is exhausted.'
            budget_result['vulnerabilities'] = normalize_findings(
                budget_result.get('vulnerabilities', []), language=language,
            )
            return _review_response(200, budget_result)
        partition = selective_scanner.partition_functions(
            code_snippet,
            language=language,
            provider=_get_model_provider(),
            model_id=_current_model_id(),
            router_mode=router_mode,
        )

        cached_vulns = partition.get("cached_vulnerabilities", [])
        funcs_to_scan = partition.get("functions_to_scan", [])
        telemetry = {
            "total_functions": partition.get("total_functions", 0),
            "cache_hits": partition.get("cache_hits", 0),
            "cache_misses": partition.get("cache_misses", 0),
            "tokens_saved": partition.get("tokens_saved", 0),
            "partition_time_ms": partition.get("partition_time_ms", 0.0),
        }

        # If everything is already cached, reuse cached findings directly
        if partition.get("total_functions", 0) > 0 and len(funcs_to_scan) == 0:
            analysis_result = {
                "vulnerabilities": cached_vulns,
                "analysis_mode": "cached",
                "telemetry": telemetry,
            }
        else:
            # Step 2: Deterministic Fast-First Cascade (Cheap check first, AI second)
            cascade = CascadeEngine(cache=selective_scanner.cache)
            triage = cascade.filter_and_triage(funcs_to_scan)
            flagged_functions = triage.get("flagged_functions", [])
            clean_functions = triage.get("clean_functions", [])

            telemetry["cascade_clean_functions"] = len(clean_functions)
            telemetry["cascade_flagged_functions"] = len(flagged_functions)

            # If all newly submitted functions are clean (no SAST match, no dangerous sinks)
            if len(flagged_functions) == 0 and partition.get("total_functions", 0) > 0:
                analysis_result = {
                    "vulnerabilities": cached_vulns,
                    "analysis_mode": "cascade-clean" if not cached_vulns else "cached",
                    "telemetry": telemetry,
                    "note": f"Classified {len(clean_functions)} functions as safe without invoking LLM.",
                }
            else:
                # LLM is invoked only for the flagged functions
                if router_mode == 'thorough':
                    targeted_code = code_snippet
                elif flagged_functions and partition.get("total_functions", 0) > 0:
                    targeted_code = CascadeEngine.build_targeted_prompt_context(flagged_functions, full_code=code_snippet)
                else:
                    targeted_code = code_snippet

                prompt = build_security_prompt(targeted_code, language)
                start_scan_time = time.time()
                scan_mode = "model"

                # Call AI model using unified invoker
                try:
                    analysis_result = _invoke_model_json(prompt, max_tokens=2048)
                    _DAILY_BUDGET_TRACKER["tokens"] += max(50, len(targeted_code) // 4)
                    _DAILY_BUDGET_TRACKER["requests"] += 1
                except Exception as e:
                    if body.get('require_model') is True or body.get('mode') == 'model':
                        return _review_response(
                            503,
                            {
                                "error": f"Model analysis required by mode '{router_mode}' failed: {str(e)}",
                                "degraded": True,
                                "degraded_state": {
                                    "model_available": False,
                                    "reason": str(e),
                                },
                                "vulnerabilities": [],
                                "analysis_mode": "model-unavailable",
                            },
                        )
                    _safe_log(f"[handler] AI invocation failed, using local fallback: {str(e)}")
                    analysis_result = _local_static_review(code_snippet)
                    scan_mode = analysis_result.get("analysis_mode", "sast-local")
                    analysis_result["degraded"] = True
                    analysis_result["degraded_state"] = {"model_available": False, "reason": str(e)}

                # Normalize: Llama 3 may return a bare array or a dict with 'vulnerabilities' key
                if isinstance(analysis_result, list):
                    analysis_result = {'vulnerabilities': analysis_result}
                elif isinstance(analysis_result, dict) and 'vulnerabilities' not in analysis_result:
                    # Could be a single vuln object or malformed — wrap it
                    analysis_result = {'vulnerabilities': [analysis_result] if analysis_result else []}

                analysis_result.setdefault("analysis_mode", scan_mode)
                scan_duration_ms = round((time.time() - start_scan_time) * 1000, 2)
                new_vulns = analysis_result.get('vulnerabilities', [])
                for model_finding in new_vulns:
                    if isinstance(model_finding, dict):
                        model_finding.setdefault('provenance', 'model')
                new_vulns = anchor_findings(new_vulns, code_snippet)

                # Ensure SAST findings from triage are merged / deduplicated
                for f_entry in flagged_functions:
                    for sf in f_entry.get("sast_findings", []):
                        sf_line = sf.get("line", 0)
                        sf_issue = (sf.get("issue") or "").lower()
                        matched = False
                        for v in new_vulns:
                            v_line = v.get("line", 0)
                            v_issue = (v.get("issue") or "").lower()
                            if (v_line == sf_line and v_line > 0) or (abs(v_line - sf_line) <= 2 and (v_issue in sf_issue or sf_issue in v_issue)):
                                v.setdefault("remediation", sf.get("remediation"))
                                v.setdefault("cwe", sf.get("cwe"))
                                v["provenance"] = "hybrid"
                                matched = True
                                break
                        if not matched:
                            new_vulns.append(sf)

                # Step 3: Dynamic Sandbox Exploit Gate (Prove it's real)
                verified_count = 0
                unconfirmed_count = 0
                verified_vulns_all = []

                # Verify each flagged function in sandbox with execution tracing
                for func in flagged_functions:
                    func_vulns = [
                        v for v in new_vulns
                        if (func.get("start_line", 1) <= v.get("line", 0) <= func.get("end_line", 999999))
                        or (v.get("function_name") == func.get("name"))
                    ]
                    if func_vulns:
                        if flags.get("verification", True):
                            func_vulns = apply_verification_gate(
                                vulnerabilities=func_vulns,
                                function_code=func["code"],
                                function_name=func["name"],
                                language=language,
                                function_start_line=func.get("start_line", 1),
                                context_source=code_snippet,
                            )
                        else:
                            for fv in func_vulns:
                                fv.setdefault("verification_status", "unverified")
                                fv["verified"] = False
                        for fv in func_vulns:
                            if fv.get("verified"):
                                verified_count += 1
                            else:
                                unconfirmed_count += 1
                        verified_vulns_all.extend(func_vulns)

                    cache_kind = "model" if scan_mode == "model" else "rules_only"
                    selective_scanner.cache.set(
                        function_hash=func.get("cache_key", func["hash"]),
                        function_name=func["name"],
                        language=language,
                        scan_result={"vulnerabilities": func_vulns},
                        original_start_line=func["start_line"],
                        tokens_used=150 if scan_mode == "model" else 0,
                        scan_duration_ms=scan_duration_ms,
                        provider=scan_mode,
                        cache_kind=cache_kind,
                    )

                # Catch any findings outside partitioned functions
                for v in new_vulns:
                    if not any(vf.get('issue') == v.get('issue') and vf.get('line') == v.get('line') for vf in verified_vulns_all):
                        verified_vulns_all.append(v)

                telemetry["verified_findings"] = verified_count
                telemetry["unconfirmed_findings"] = unconfirmed_count

                # Combine any cached findings with new findings
                combined_vulns = list(cached_vulns)
                for v in verified_vulns_all:
                    if not any(cv.get('issue') == v.get('issue') and cv.get('line') == v.get('line') for cv in combined_vulns):
                        combined_vulns.append(v)

                # Verified findings rank before unconfirmed findings
                combined_vulns = rank_findings(combined_vulns)

                analysis_result['vulnerabilities'] = combined_vulns
                analysis_result['telemetry'] = telemetry

        # Always preserve deterministic local findings, merging without duplicates
        local_findings = _local_static_review(code_snippet).get('vulnerabilities', [])
        response_vulnerabilities = analysis_result.setdefault('vulnerabilities', [])
        for finding in local_findings:
            f_line = finding.get('line', 0)
            f_issue = (finding.get('issue') or '').lower()
            duplicate = any(
                (existing.get('line') == f_line and existing.get('issue') == finding.get('issue'))
                or (abs(existing.get('line', -999) - f_line) <= 2 and (f_issue in (existing.get('issue') or '').lower() or (existing.get('issue') or '').lower() in f_issue))
                for existing in response_vulnerabilities
            )
            if not duplicate:
                response_vulnerabilities.append(finding)

        response_vulnerabilities.extend(pr_python_findings)

        # Sandbox-confirmed findings first, unconfirmed last; nothing is dropped.
        analysis_result['vulnerabilities'] = rank_findings(normalize_findings(
            response_vulnerabilities,
            language=language,
        ))

        # Fire-and-forget: post findings back to GitHub PR (webhook path only)
        if is_webhook and repo_full_name and pr_number:
            _post_pr_findings(body, repo_full_name, pr_number, analysis_result.get('vulnerabilities', []))

        return _review_response(200, analysis_result)
    except Exception as e:
        import traceback
        traceback.print_exc()
        _safe_log(f"review_code failed: {e}")
        return _json_response(500, {"error": "Internal server error"})


def review_status(event, context):
    try:
        query_params = event.get('queryStringParameters', {}) or {}
        job_id = query_params.get('job_id')
        if not job_id:
            return _json_response(400, {"error": "job_id query parameter is required"})

        job = get_job(job_id)
        if not job:
            return _json_response(404, {"error": "Job not found"})

        return _json_response(200, job)
    except Exception as e:
        print(f"review_status failed: {e}")
        return _json_response(500, {"error": "Internal server error"})


def attack_path(event, context):
    try:
        body = _parse_body(event)
        vulnerabilities = _extract_vulnerabilities_for_advanced(body)
        if not vulnerabilities:
            return _json_response(400, {"error": "No vulnerabilities or code provided for attack path generation"})

        context_text = body.get('code', '')
        intelligence = build_attack_intelligence(vulnerabilities, context_text)
        heuristic_graph = intelligence.get('attack_graph', {})

        # Step 4: AST-derived attack graph (falls back to heuristic if AST empty)
        vuln_fn_names = [v.get('function_name', '') for v in vulnerabilities if v.get('function_name')]
        ast_graph = build_code_graph(context_text, vuln_function_names=vuln_fn_names or None)
        graph = merge_with_heuristic_graph(ast_graph, heuristic_graph)

        return _json_response(200, {
            "attack_graph": {
                "nodes": graph.get('nodes', []),
                "edges": graph.get('edges', []),
                "path_reason": graph.get('path_reason'),
            },
            "attack_paths": graph.get('attack_paths', []),
            "summary": intelligence.get('summary', {}),
            "ast_derived": graph.get('ast_derived', False),
        })
    except Exception as e:
        print(f"attack_path error: {str(e)}")
        return _json_response(500, {"error": str(e)})


def risk_score(event, context):
    try:
        body = _parse_body(event)
        vulnerabilities = _extract_vulnerabilities_for_advanced(body)
        if not vulnerabilities:
            return _json_response(400, {"error": "No vulnerabilities or code provided for risk scoring"})

        context_text = body.get('code', '')
        intelligence = build_attack_intelligence(vulnerabilities, context_text)
        return _json_response(200, {
            "risk_ranking": intelligence.get('risk_ranking', []),
            "summary": intelligence.get('summary', {}),
        })
    except Exception as e:
        print(f"risk_score error: {str(e)}")
        return _json_response(500, {"error": str(e)})


def simulate(event, context):
    try:
        body = _parse_body(event)
        vulnerabilities = _extract_vulnerabilities_for_advanced(body)
        if not vulnerabilities:
            return _json_response(400, {"error": "No vulnerabilities or code provided for simulation"})

        context_text = body.get('code', '')
        intelligence = build_attack_intelligence(vulnerabilities, context_text)
        return _json_response(200, {
            "breach_simulation": intelligence.get('breach_simulation', {}),
            "summary": intelligence.get('summary', {}),
        })
    except Exception as e:
        print(f"simulate error: {str(e)}")
        return _json_response(500, {"error": str(e)})


# Hard wall-clock limit for one copilot reply. The HTTP timeout only bounds each socket
# read, so a slowly trickling provider response could otherwise hang the chat for minutes.
COPILOT_TIMEOUT_SECONDS = float(os.getenv("COPILOT_TIMEOUT_SECONDS", "40"))
_COPILOT_POOL = None


def _invoke_copilot_model(prompt):
    """Run the model call under a hard deadline; raise TimeoutError when it is exceeded."""
    import concurrent.futures
    global _COPILOT_POOL
    if _COPILOT_POOL is None:
        _COPILOT_POOL = concurrent.futures.ThreadPoolExecutor(max_workers=4, thread_name_prefix="copilot")
    # Successful Gemini replies take ~3-10s, while overloaded requests either fail fast (503) or
    # hang for a minute. So cut each attempt short and retry once, then move to a backup model.
    per_attempt_timeout = max(5.0, min(12.0, COPILOT_TIMEOUT_SECONDS / 3))
    future = _COPILOT_POOL.submit(
        _invoke_model_text, prompt, 1500, per_attempt_timeout, 1
    )
    try:
        return future.result(timeout=COPILOT_TIMEOUT_SECONDS)
    except concurrent.futures.TimeoutError:
        future.cancel()
        raise TimeoutError(f"AI model did not answer within {COPILOT_TIMEOUT_SECONDS:.0f}s")


def copilot_chat(event, context):
    try:
        body = _parse_body(event)
        question = body.get('question', '')
        if not question:
            return _json_response(400, {"error": "No question provided"})

        vulnerabilities = _extract_vulnerabilities_for_advanced(body)
        context_text = body.get('code', '')
        intelligence = build_attack_intelligence(vulnerabilities, context_text)

        history = body.get('history') if isinstance(body.get('history'), list) else []
        prompt = build_copilot_prompt(
            question,
            intelligence,
            code=context_text,
            language=body.get('language', ''),
            history=history,
        )
        try:
            answer = _invoke_copilot_model(prompt)
            mode = "model"
            note = None
        except Exception as err:
            print(f"[handler] Copilot using local fallback: {redact_secrets(str(err))}", flush=True)
            answer = _local_copilot_answer(question, intelligence, vulnerabilities)
            mode = "local-fallback"
            note = "The AI model did not respond, so this is a basic built-in answer. Try again in a moment for a full reply."

        payload = {
            "answer": answer,
            "summary": intelligence.get('summary', {}),
            "analysis_mode": mode,
        }
        if note:
            payload["note"] = note

        return _json_response(200, payload)
    except Exception as e:
        print(f"copilot_chat error: {str(e)}")
        return _json_response(500, {"error": str(e)})


def repo_scan(event, context):
    """Synchronous repo scan for direct API clients and integration tests."""
    try:
        body = _parse_body(event)
        repo_url = (body.get('repo_url') or '').strip()
        if not repo_url:
            return _json_response(400, {"error": "repo_url is required"})

        query = body.get('query', '')
        branch = body.get('branch')
        top_k = body.get('top_k', 3)

        try:
            top_k = int(top_k)
        except (TypeError, ValueError):
            return _json_response(400, {"error": "top_k must be an integer"})

        token = body.get('github_token') or os.getenv('GITHUB_TOKEN')
        scan_bundle = selective_repo_scan(
            repo_url=repo_url,
            query=query,
            token=token,
            branch=branch,
            top_k=top_k,
        )

        selected_files = scan_bundle.get('selected_files', [])
        if not selected_files:
            return _json_response(422, {
                "error": "No relevant source files found for analysis",
                "repo_stats": scan_bundle.get('repo_stats', {}),
            })

        combined_context = "\n\n".join(
            [
                f"# FILE: {item.get('path', 'unknown')}\n{item.get('excerpt', '')}"
                for item in selected_files
            ]
        )

        prompt = build_security_prompt(combined_context, 'python')
        try:
            analysis_result = _invoke_model_json(prompt)
        except Exception as err:
            print(f"[handler] Repo scan using local fallback: {str(err)}")
            analysis_result = _local_static_review(combined_context)

        vulnerabilities = normalize_findings(
            analysis_result.get('vulnerabilities', []) if isinstance(analysis_result, dict) else [],
            language='python',
        )
        intelligence = build_attack_intelligence(vulnerabilities, combined_context)

        # Step 4: AST-derived attack graph for repo scan
        vuln_fn_names = [v.get('function_name', '') for v in vulnerabilities if v.get('function_name')]
        ast_graph = build_code_graph(combined_context, vuln_function_names=vuln_fn_names or None)
        merged_graph = merge_with_heuristic_graph(ast_graph, intelligence.get('attack_graph', {}))

        estimated_tokens = len(selected_files) * 250
        cost_estimate_usd = round(estimated_tokens * 0.000002, 6)

        return _json_response(200, {
            "repo_stats": scan_bundle.get('repo_stats', {}),
            "keywords": scan_bundle.get('keywords', []),
            "selected_files": [
                {
                    "path": item.get('path'),
                    "hit_count": item.get('hit_count'),
                }
                for item in selected_files
            ],
            "vulnerabilities": vulnerabilities,
            "risk_ranking": intelligence.get('risk_ranking', []),
            "attack_graph": merged_graph,
            "breach_simulation": intelligence.get('breach_simulation', {}),
            "summary": intelligence.get('summary', {}),
            "cost_estimate": {
                "estimated_tokens": estimated_tokens,
                "estimated_cost_usd": cost_estimate_usd,
            },
            "analysis_mode": analysis_result.get('analysis_mode', 'model') if isinstance(analysis_result, dict) else 'model',
            "note": analysis_result.get('note') if isinstance(analysis_result, dict) else None,
        })
    except Exception as e:
        print(f"repo_scan error: {str(e)}")
        return _json_response(500, {"error": str(e)})


def repo_scan_start(event, context):
    try:
        body = _parse_body(event)
        repo_url = (body.get('repo_url') or '').strip()
        if not repo_url:
            return _json_response(400, {"error": "repo_url is required"})

        query = body.get('query', '')
        branch = body.get('branch')
        top_k = body.get('top_k', 3)

        try:
            top_k = int(top_k)
        except (TypeError, ValueError):
            return _json_response(400, {"error": "top_k must be an integer"})

        token = body.get('github_token') or os.getenv('GITHUB_TOKEN')
        
        job_id = body.get('job_id')
        from .job_manager import create_job
        from .repo_scan_engine import start_progressive_scan
        
        job_id = create_job(job_id)
        
        start_progressive_scan(
            job_id=job_id,
            repo_url=repo_url,
            query=query,
            token=token,
            branch=branch,
            top_k=top_k,
            invoke_fn=_invoke_model_json
        )

        return _json_response(200, {"job_id": job_id, "status": "started"})
    except Exception as e:
        print(f"repo_scan_start error: {str(e)}")
        return _json_response(500, {"error": str(e)})

def repo_scan_status(event, context):
    try:
        query_params = event.get('queryStringParameters', {}) or {}
        job_id = query_params.get('job_id')
        
        if not job_id:
            return _json_response(400, {"error": "job_id query parameter is required"})

        from .job_manager import get_job
        job = get_job(job_id)
        
        if not job:
            return _json_response(404, {"error": "Job not found"})
            
        return _json_response(200, job)
        
    except Exception as e:
        print("repo_scan_status failed")
        return _json_response(500, {"error": "Internal server error"})


def repo_scan_cancel(event, context):
    try:
        body = _parse_body(event)
        job_id = body.get('job_id') or (event.get('queryStringParameters') or {}).get('job_id')
        if not job_id:
            return _json_response(400, {"error": "job_id is required"})
        from .job_manager import cancel_job
        job = cancel_job(job_id)
        if not job:
            return _json_response(404, {"error": "Job not found"})
        return _json_response(200, job)
    except Exception as e:
        print(f"repo_scan_cancel error: {str(e)}")
        return _json_response(500, {"error": "Unable to cancel job"})


def repo_autofix_start(event, context):
    try:
        body = _parse_body(event)
        repo_url = body.get('repo_url')
        code = body.get('code')
        vulnerabilities = body.get('vulnerabilities', [])
        mode = body.get('mode', 'suggest')
        token = body.get('github_token') or os.getenv('GITHUB_TOKEN')
        branch = body.get('branch')
        language = body.get('language', 'python')

        include_drafts = body.get('include_drafts')

        if not vulnerabilities or not isinstance(vulnerabilities, list):
            return _json_response(400, {"error": "vulnerabilities list is required"})
        vulnerabilities = [v for v in vulnerabilities if isinstance(v, dict)][:50]
        if repo_url and not any(v.get('file_path') or v.get('path') for v in vulnerabilities):
            return _json_response(400, {"error": "Repository autofix needs findings with a file_path; run a repository scan first"})

        from .job_manager import create_job
        from .autofix_engine import start_autofix_job
        from .sandbox_verifier import default_exploit_invoker

        job_id = create_job()

        def autofix_llm_callback(file_content, file_vulns, file_path):
            prompt = build_autofix_prompt(file_content, file_vulns, file_path)
            return _invoke_model_json(prompt, max_tokens=3000)

        def fix_llm(prompt):
            # Verified fix loop: the prompt carries the sandbox proof, project helpers and gate feedback.
            return _invoke_model_text(prompt, max_tokens=2000)

        start_autofix_job(
            job_id, repo_url, code, vulnerabilities, token, branch, mode, language, autofix_llm_callback,
            fix_llm_fn=fix_llm,
            model_invoker=default_exploit_invoker(),
            include_drafts=bool(include_drafts) if include_drafts is not None else None,
        )

        return _json_response(200, {"job_id": job_id, "status": "started"})
        
    except Exception as e:
        print("repo_autofix_start failed")
        return _json_response(500, {"error": "Internal server error"})


def repo_autofix_status(event, context):
    try:
        query_params = event.get('queryStringParameters', {}) or {}
        job_id = query_params.get('job_id')
        
        if not job_id:
            return _json_response(400, {"error": "job_id query parameter is required"})

        from .job_manager import get_job
        job = get_job(job_id)
        
        if not job:
            return _json_response(404, {"error": "Job not found"})
            
        return _json_response(200, job)
        
    except Exception as e:
        print(f"repo_autofix_status error: {str(e)}")
        return _json_response(500, {"error": str(e)})
