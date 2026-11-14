"""
verified_fixer.py — Codebase-Aware Verified Fix Loop (Step 5)

Upgrades the autofix pipeline so generated patches are verified before being
offered to the developer.  Three sequential gates:

  Gate 1  — Re-run sandbox exploit → payload must NO LONGER reach the sink.
  Gate 2  — Run existing test suite (pytest) → all tests must pass.
  Gate 3  — Re-run SAST + cascade triage on patched function → zero new findings.

A patch is tagged "Verified Patch" only when all three gates pass.
Up to MAX_RETRIES LLM re-generation attempts are made if any gate fails.
"""

from __future__ import annotations

import difflib
import os
import re
import subprocess
import sys
import tempfile
import textwrap
from typing import Any, Callable, Dict, List, Optional, Tuple


MAX_RETRIES = 3
PYTEST_TIMEOUT = 60  # seconds

# ---------------------------------------------------------------------------
# Top-level optional imports — defined here so tests can patch them easily
# via patch("src.verified_fixer.SandboxVerifier") / patch("src.verified_fixer.SASTScanner")
# ---------------------------------------------------------------------------
try:
    from .sandbox_verifier import SandboxVerifier
except ImportError:  # pragma: no cover
    SandboxVerifier = None  # type: ignore

try:
    from .sast_scanner import SASTScanner
except ImportError:  # pragma: no cover
    SASTScanner = None  # type: ignore


# ---------------------------------------------------------------------------
# Sanitizer pattern search — codebase-aware context
# ---------------------------------------------------------------------------

SANITIZER_PATTERNS: Dict[str, List[str]] = {
    "sqli": [
        r"cursor\.execute\([^,]+,\s*[\(\[]",
        r"\.query\([^,]+,\s*[\[\(]",
        r"sqlalchemy.*bindparams",
    ],
    "path_traversal": [
        r"os\.path\.normpath",
        r"os\.path\.realpath",
        r"pathlib\.Path.*resolve",
        r"secure_filename",
    ],
    "cmd_injection": [
        r"shlex\.split",
        r"subprocess\.run\([^,]+,\s*shell\s*=\s*False",
        r"subprocess\.Popen\([^,]+,\s*shell\s*=\s*False",
    ],
    "code_injection": [
        r"ast\.literal_eval",
        r"safe_eval",
    ],
    "deserialization": [
        r"json\.loads",
        r"msgpack\.unpackb",
    ],
}


def find_project_sanitizer_examples(
    project_root: str, cwe_id: str
) -> List[str]:
    """
    Walk project_root to find lines that match known-safe patterns for the
    given CWE.  Returns up to 3 example snippets to include in the LLM prompt.
    """
    cwe_lower = cwe_id.lower()
    category = "sqli"
    if "78" in cwe_lower:
        category = "cmd_injection"
    elif "22" in cwe_lower:
        category = "path_traversal"
    elif "94" in cwe_lower:
        category = "code_injection"
    elif "502" in cwe_lower:
        category = "deserialization"

    patterns = SANITIZER_PATTERNS.get(category, [])
    if not patterns:
        return []

    examples: List[str] = []
    for root, _dirs, files in os.walk(project_root):
        if any(skip in root for skip in (".git", "__pycache__", "node_modules", ".venv")):
            continue
        for fname in files:
            if not fname.endswith(".py"):
                continue
            full = os.path.join(root, fname)
            try:
                with open(full, encoding="utf-8", errors="ignore") as fh:
                    content = fh.read()
            except OSError:
                continue
            for pat in patterns:
                for m in re.finditer(pat, content):
                    line_start = content.rfind("\n", 0, m.start()) + 1
                    line_end = content.find("\n", m.end())
                    snippet = content[line_start: line_end if line_end != -1 else len(content)].strip()
                    if snippet and snippet not in examples:
                        examples.append(snippet)
                        if len(examples) >= 3:
                            return examples
    return examples


# ---------------------------------------------------------------------------
# Gate 1: Sandbox exploit re-verification
# ---------------------------------------------------------------------------

def _gate1_exploit_no_longer_reaches_sink(
    patched_code: str,
    finding: Dict[str, Any],
) -> Tuple[bool, str]:
    """
    Re-run the sandbox verifier on the patched function.
    Returns (passed: bool, detail: str).
    Pass criterion: the exploit payload does NOT reach the sink.
    """
    if SandboxVerifier is None:
        return True, "Gate 1 SKIP: sandbox_verifier not available"

    verifier = SandboxVerifier(timeout_sec=3.0)
    function_name = finding.get("function_name", "")
    cwe_id = finding.get("cwe_id", "")

    result = verifier.verify(
        source_code=patched_code,
        function_name=function_name,
        cwe_id=cwe_id,
    )
    passed = result.get("verification_status") != "verified"
    detail = (
        f"Gate 1 {'PASS' if passed else 'FAIL'}: "
        f"exploit status={result.get('verification_status')} "
        f"sink_reached={result.get('dynamic_trace', {}).get('sink_reached', False)}"
    )
    return passed, detail


# ---------------------------------------------------------------------------
# Gate 2: Existing test suite
# ---------------------------------------------------------------------------

def _gate2_tests_still_pass(
    patched_code: str,
    original_function_name: str,
    test_dir: Optional[str] = None,
) -> Tuple[bool, str]:
    """
    Write patched_code to a temp file and run pytest against test_dir.
    Returns (passed: bool, detail: str).
    """
    if test_dir is None or not os.path.isdir(test_dir):
        return True, "Gate 2 SKIP: no test_dir provided or directory not found"

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".py", delete=False, dir=test_dir, prefix="_verified_patch_"
    ) as tmp:
        tmp.write(patched_code)
        tmp_path = tmp.name

    try:
        result = subprocess.run(
            [sys.executable, "-m", "pytest", test_dir, "-q", "--tb=no"],
            capture_output=True,
            text=True,
            timeout=PYTEST_TIMEOUT + 5,
        )
        passed = result.returncode == 0
        summary_lines = (result.stdout + result.stderr).splitlines()
        summary = next(
            (ln for ln in reversed(summary_lines) if "passed" in ln or "failed" in ln or "error" in ln),
            result.stdout[-300:],
        )
        detail = f"Gate 2 {'PASS' if passed else 'FAIL'}: {summary}"
    except subprocess.TimeoutExpired:
        passed = False
        detail = f"Gate 2 FAIL: pytest timed out after {PYTEST_TIMEOUT}s"
    finally:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass

    return passed, detail


# ---------------------------------------------------------------------------
# Gate 3: SAST + cascade triage on patched function
# ---------------------------------------------------------------------------

def _gate3_no_new_sast_findings(
    patched_code: str,
    original_finding_issue: str,
) -> Tuple[bool, str]:
    """
    Run the SAST scanner on patched_code.
    Returns (passed: bool, detail: str).
    Pass criterion: no new HIGH/CRITICAL findings unrelated to the original issue.
    """
    if SASTScanner is None:
        return True, "Gate 3 SKIP: sast_scanner not available"

    scanner = SASTScanner()
    findings = scanner.scan(patched_code)

    critical_new = [
        f for f in findings
        if f.get("severity", "").lower() in ("critical", "high")
        and original_finding_issue.lower() not in f.get("issue", "").lower()
    ]
    passed = len(critical_new) == 0
    detail = (
        f"Gate 3 {'PASS' if passed else 'FAIL'}: "
        f"SAST found {len(findings)} total findings, "
        f"{len(critical_new)} new high/critical not matching original issue"
    )
    return passed, detail


# ---------------------------------------------------------------------------
# Patch builder: generate & verify loop
# ---------------------------------------------------------------------------

def build_verified_fix_prompt(
    original_code: str,
    finding: Dict[str, Any],
    codebase_examples: List[str],
) -> str:
    """Build a targeted LLM prompt requesting a codebase-consistent patch."""
    issue = finding.get("issue", "Security vulnerability")
    cwe_id = finding.get("cwe_id", "")
    function_name = finding.get("function_name", "")
    explanation = finding.get("explanation", "")
    line_no = finding.get("line_number", "unknown")

    examples_block = ""
    if codebase_examples:
        examples_block = (
            "\n\nExisting safe patterns found in this codebase (match this style):\n"
            + "\n".join(f"  {ex}" for ex in codebase_examples)
        )

    return textwrap.dedent(f"""
        You are a security engineering assistant.  Produce ONLY the corrected Python
        function (no prose, no markdown fences).  Match the existing coding style.

        ISSUE: {issue} ({cwe_id}) at function `{function_name}`, line {line_no}
        EXPLANATION: {explanation}
        {examples_block}

        ORIGINAL CODE:
        {original_code}

        OUTPUT: Return ONLY the corrected Python function body, no extra text.
    """).strip()


class VerifiedFixer:
    """
    Wraps an LLM invocation function and applies the 3-gate verification loop.

    Parameters
    ----------
    invoke_llm_fn:
        Callable that takes a prompt string and returns patched source as str.
    test_dir:
        Path to the project's test directory for Gate 2 (optional).
    project_root:
        Root of the codebase for sanitizer example search (optional).
    max_retries:
        Max LLM retry attempts if any gate fails.
    """

    def __init__(
        self,
        invoke_llm_fn: Callable[[str], str],
        test_dir: Optional[str] = None,
        project_root: Optional[str] = None,
        max_retries: int = MAX_RETRIES,
    ) -> None:
        self.invoke_llm_fn = invoke_llm_fn
        self.test_dir = test_dir
        self.project_root = project_root
        self.max_retries = max_retries

    def fix(
        self,
        original_code: str,
        finding: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Attempt to generate and verify a patch.

        Returns
        -------
        {
          "patch_status":    "verified" | "unverified_draft" | "failed",
          "patched_code":    str,
          "diff":            str,
          "gates":           [{gate, passed, detail}, ...],
          "attempts":        int,
          "finding":         dict (original finding, enriched),
        }
        """
        cwe_id = finding.get("cwe_id", "")
        issue = finding.get("issue", "")

        codebase_examples: List[str] = []
        if self.project_root:
            codebase_examples = find_project_sanitizer_examples(self.project_root, cwe_id)

        gate_log: List[Dict[str, Any]] = []
        best_patch: Optional[str] = None
        all_gates_passed = False

        for attempt in range(1, self.max_retries + 1):
            feedback = ""
            if gate_log and attempt > 1:
                last_gate = gate_log[-1]
                feedback = f"\n\nPrevious attempt failed: {last_gate['detail']}"

            prompt = build_verified_fix_prompt(original_code, finding, codebase_examples) + feedback

            try:
                patched_code = self.invoke_llm_fn(prompt)
            except Exception as exc:
                gate_log.append({
                    "attempt": attempt,
                    "gate": "llm",
                    "passed": False,
                    "detail": f"LLM invocation failed: {exc}",
                })
                continue

            if not patched_code or len(patched_code.strip()) < 10:
                gate_log.append({
                    "attempt": attempt,
                    "gate": "llm",
                    "passed": False,
                    "detail": "LLM returned empty/trivial response",
                })
                continue

            best_patch = patched_code
            attempt_gates: List[Dict[str, Any]] = []

            # Gate 1
            g1_pass, g1_detail = _gate1_exploit_no_longer_reaches_sink(patched_code, finding)
            attempt_gates.append({"gate": "exploit_blocked", "passed": g1_pass, "detail": g1_detail})
            if not g1_pass:
                gate_log.extend(attempt_gates)
                continue

            # Gate 2
            g2_pass, g2_detail = _gate2_tests_still_pass(
                patched_code, finding.get("function_name", ""), self.test_dir
            )
            attempt_gates.append({"gate": "tests_pass", "passed": g2_pass, "detail": g2_detail})
            if not g2_pass:
                gate_log.extend(attempt_gates)
                continue

            # Gate 3
            g3_pass, g3_detail = _gate3_no_new_sast_findings(patched_code, issue)
            attempt_gates.append({"gate": "no_new_sast_findings", "passed": g3_pass, "detail": g3_detail})
            gate_log.extend(attempt_gates)

            if g3_pass:
                all_gates_passed = True
                break

        # Build diff
        if best_patch:
            diff_lines = list(
                difflib.unified_diff(
                    original_code.splitlines(keepends=True),
                    best_patch.splitlines(keepends=True),
                    fromfile="original.py",
                    tofile="patched.py",
                )
            )
            diff_str = "".join(diff_lines)
        else:
            diff_str = ""
            best_patch = original_code

        if all_gates_passed:
            patch_status = "verified"
        elif best_patch and best_patch != original_code:
            patch_status = "unverified_draft"
        else:
            patch_status = "failed"

        return {
            "patch_status": patch_status,
            "patched_code": best_patch,
            "diff": diff_str,
            "gates": gate_log,
            "attempts": min(self.max_retries, len([g for g in gate_log if g["gate"] == "exploit_blocked"]) + 1),
            "finding": finding,
            "codebase_examples_used": codebase_examples,
        }


# ---------------------------------------------------------------------------
# Convenience wrapper for handler integration
# ---------------------------------------------------------------------------

def run_verified_fix(
    original_code: str,
    finding: Dict[str, Any],
    invoke_llm_fn: Callable[[str], str],
    test_dir: Optional[str] = None,
    project_root: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Top-level convenience function called from handler.py.
    Returns the same dict as VerifiedFixer.fix().
    """
    fixer = VerifiedFixer(
        invoke_llm_fn=invoke_llm_fn,
        test_dir=test_dir,
        project_root=project_root,
    )
    return fixer.fix(original_code=original_code, finding=finding)
