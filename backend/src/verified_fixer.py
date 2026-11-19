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

import ast
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


def _gate_status(passed: bool, error: bool = False, skipped: bool = False) -> str:
    if skipped:
        return "skipped"
    if error:
        return "error"
    return "pass" if passed else "fail"

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
# Gate A: Parse & Compile Validation
# ---------------------------------------------------------------------------

def gate_a_parse_compile(patched_code: str) -> Tuple[bool, str, str]:
    """
    Validates that the patch parses cleanly as Python AST and compiles.
    Returns (passed: bool, status: 'pass' | 'fail' | 'error' | 'skipped', detail: str).
    """
    if not patched_code or not patched_code.strip():
        return False, "fail", "Gate A FAIL: Patch is empty"
    try:
        tree = ast.parse(patched_code)
        compile(patched_code, "<patch>", "exec")
        if not tree.body:
            return False, "fail", "Gate A FAIL: Patch parsed to empty AST"
        return True, "pass", "Gate A PASS: Patch parsed and compiled successfully"
    except SyntaxError as e:
        return False, "fail", f"Gate A FAIL: Syntax error: {e}"
    except Exception as e:
        return False, "error", f"Gate A ERROR: Parse failed: {e}"


# ---------------------------------------------------------------------------
# Gate B: Differential Exploit Validation (Requires Refuted)
# ---------------------------------------------------------------------------

def gate_b_differential_exploit(
    patched_code: str,
    finding: Dict[str, Any],
    verifier: Optional[Any] = None,
) -> Tuple[bool, str, str]:
    """
    Re-run dynamic exploit test in sandbox.
    Pass criterion: exploit status is 'refuted' or 'unconfirmed' and sink is not reached.
    If sandbox runtime is unavailable, returns 'skipped' or 'error' (which keeps patch unverified).
    """
    if SandboxVerifier is None and verifier is None:
        return False, "error", "Gate B ERROR: sandbox_verifier not available"

    v = verifier or SandboxVerifier(timeout_sec=3.0)
    if hasattr(v, "isolation_available") and not v.isolation_available():
        return False, "skipped", "Gate B SKIPPED: Sandbox isolation runtime is unavailable"

    function_name = finding.get("function_name", "")
    cwe_id = finding.get("cwe_id", "")

    try:
        result = v.verify(
            source_code=patched_code,
            function_name=function_name,
            cwe_id=cwe_id,
        )
        status = result.get("verification_status")
        sink_reached = result.get("dynamic_trace", {}).get("sink_reached", False)
        passed = (status in {"unconfirmed", "refuted"}) and not sink_reached
        gate_st = "pass" if passed else "fail"
        detail = (
            f"Gate B {'PASS' if passed else 'FAIL'}: "
            f"exploit status={status} sink_reached={sink_reached}"
        )
        return passed, gate_st, detail
    except Exception as exc:
        return False, "error", f"Gate B ERROR: Sandbox verifier error: {exc}"


def _gate1_exploit_no_longer_reaches_sink(
    patched_code: str,
    finding: Dict[str, Any],
) -> Tuple[bool, str]:
    passed, _, detail = gate_b_differential_exploit(patched_code, finding)
    return passed, detail


# ---------------------------------------------------------------------------
# Gate C: Project Tests & Benign Input Checks
# ---------------------------------------------------------------------------

def gate_c_project_tests(
    patched_code: str,
    original_function_name: str,
    test_dir: Optional[str] = None,
    benign_check_fn: Optional[Callable[[str, str], bool]] = None,
    target_file_path: Optional[str] = None,
) -> Tuple[bool, str, str]:
    """
    Runs existing project test suite against patched file, plus benign input check.
    If test_dir is not provided or doesn't exist, returns 'skipped'.
    Executes in a safe isolated environment with active module replacement.
    """
    if benign_check_fn:
        try:
            benign_ok = benign_check_fn(patched_code, original_function_name)
            if not benign_ok:
                return False, "fail", "Gate C FAIL: Benign-input check failed"
        except Exception as e:
            return False, "error", f"Gate C ERROR: Benign-input check crashed: {e}"

    if test_dir is None or not os.path.isdir(test_dir):
        if benign_check_fn:
            return True, "pass", "Gate C PASS: Benign input checks passed (project test_dir not specified)"
        return False, "skipped", "Gate C SKIPPED: No test_dir provided or directory not found"

    from .sandbox_verifier import SandboxVerifier
    use_docker = SandboxVerifier._is_docker_live() if hasattr(SandboxVerifier, "_is_docker_live") else False
    if not use_docker and os.getenv("SAGE_ARMOR_UNSAFE_LOCAL_SANDBOX") != "1":
        return False, "skipped", "Gate C SKIPPED: Docker sandbox unavailable and unsafe local fallback disabled"

    backup_content = None
    target_to_restore = None

    try:
        if target_file_path and os.path.isfile(target_file_path):
            target_to_restore = target_file_path
            with open(target_file_path, "r", encoding="utf-8") as f:
                backup_content = f.read()
            with open(target_file_path, "w", encoding="utf-8") as f:
                f.write(patched_code)

        if use_docker:
            project_dir = os.path.abspath(os.path.join(test_dir, ".."))
            cmd = [
                "docker", "run", "--rm", "--network", "none",
                "--pids-limit", "64", "--memory", "256m", "--cpus", "1.0",
                "-v", f"{project_dir}:/workspace",
                "-w", "/workspace", "python:3.11-slim",
                "python", "-m", "pytest", test_dir, "-q", "--tb=no"
            ]
            clean_env = None
        else:
            cmd = [sys.executable, "-m", "pytest", test_dir, "-q", "--tb=no"]
            clean_env = {
                "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
                "PYTHONUNBUFFERED": "1",
                "PYTHONPATH": os.path.abspath(test_dir),
            }

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            env=clean_env,
            timeout=PYTEST_TIMEOUT + 5,
        )
        passed = result.returncode == 0
        summary_lines = (result.stdout + result.stderr).splitlines()
        summary = next(
            (ln for ln in reversed(summary_lines) if "passed" in ln or "failed" in ln or "error" in ln),
            result.stdout[-300:],
        )
        gate_st = "pass" if passed else "fail"
        detail = f"Gate C {'PASS' if passed else 'FAIL'}: {summary}"
        return passed, gate_st, detail
    except subprocess.TimeoutExpired:
        return False, "error", f"Gate C ERROR: pytest timed out after {PYTEST_TIMEOUT}s"
    except Exception as exc:
        return False, "error", f"Gate C ERROR: Test execution failed: {exc}"
    finally:
        if target_to_restore and backup_content is not None:
            try:
                with open(target_to_restore, "w", encoding="utf-8") as f:
                    f.write(backup_content)
            except Exception:
                pass


def _gate2_tests_still_pass(
    patched_code: str,
    original_function_name: str,
    test_dir: Optional[str] = None,
) -> Tuple[bool, str]:
    passed, _, detail = gate_c_project_tests(patched_code, original_function_name, test_dir)
    return passed, detail


# ---------------------------------------------------------------------------
# Gate D: Rescan Validation
# ---------------------------------------------------------------------------

def gate_d_rescan_validation(
    patched_code: str,
    original_finding_issue: str,
    scanner: Optional[Any] = None,
) -> Tuple[bool, str, str]:
    """
    Run SAST scanner on patched_code.
    Pass criterion: no original finding and no new High/Critical findings.
    """
    if SASTScanner is None and scanner is None:
        return False, "error", "Gate D ERROR: sast_scanner not available"

    s = scanner or SASTScanner()
    try:
        findings = s.scan(patched_code) if hasattr(s, "scan") else s.scan_code(patched_code)
    except Exception as exc:
        return False, "error", f"Gate D ERROR: SAST scan failed: {exc}"

    orig_remaining = [
        f for f in findings
        if original_finding_issue.lower() in f.get("issue", "").lower()
    ]
    new_severe = [
        f for f in findings
        if f.get("severity", "").lower() in ("critical", "high")
        and original_finding_issue.lower() not in f.get("issue", "").lower()
    ]

    passed = len(orig_remaining) == 0 and len(new_severe) == 0
    gate_st = "pass" if passed else "fail"
    detail = (
        f"Gate D {'PASS' if passed else 'FAIL'}: "
        f"SAST found {len(findings)} total findings, "
        f"{len(orig_remaining)} remaining original issues, "
        f"{len(new_severe)} new high/critical issues"
    )
    return passed, gate_st, detail


def _gate3_no_new_sast_findings(
    patched_code: str,
    original_finding_issue: str,
) -> Tuple[bool, str]:
    passed, _, detail = gate_d_rescan_validation(patched_code, original_finding_issue)
    return passed, detail


# ---------------------------------------------------------------------------
# Gate E: Diff and Path Constraints
# ---------------------------------------------------------------------------

def gate_e_diff_path_constraints(
    original_code: str,
    patched_code: str,
    function_name: str = "",
    file_path: Optional[str] = None,
    allowed_root: Optional[str] = None,
    max_diff_lines: int = 60,
) -> Tuple[bool, str, str]:
    """
    Validates diff, signature, and path constraints:
    - Rejects path outside allowed root
    - Rejects markdown prose or code fences
    - Rejects truncation / placeholders ('...', '# TODO', '# rest of code')
    - Rejects signature changes
    - Rejects excessive diffs
    """
    # Path boundary check
    if file_path and allowed_root:
        norm_path = os.path.realpath(file_path)
        norm_root = os.path.realpath(allowed_root)
        if not norm_path.startswith(norm_root):
            return False, "fail", f"Gate E FAIL: Target path {file_path} escapes root {allowed_root}"

    # Markdown prose / code fences check
    trimmed = patched_code.strip()
    if trimmed.startswith("```") or "```" in trimmed:
        return False, "fail", "Gate E FAIL: Patch contains markdown code fences"
    first_line = trimmed.splitlines()[0].lower() if trimmed.splitlines() else ""
    for prose_hint in ["here is", "here's", "in this fix", "explanation:", "modified function"]:
        if prose_hint in first_line:
            return False, "fail", f"Gate E FAIL: Patch contains markdown prose explanation"

    # Placeholders / truncation
    placeholder_patterns = [
        r"#\s*\.\.\.",
        r"\.\.\.",
        r"#\s*TODO",
        r"#\s*FIXME",
        r"#\s*rest of code",
        r"#\s*remaining code",
        r"#\s*existing code",
    ]
    for pat in placeholder_patterns:
        if re.search(pat, patched_code, re.IGNORECASE):
            return False, "fail", f"Gate E FAIL: Patch contains placeholder/truncation ({pat})"

    # Signature changes
    if function_name:
        try:
            orig_ast = ast.parse(original_code)
            patch_ast = ast.parse(patched_code)
            orig_funcs = [n for n in ast.walk(orig_ast) if isinstance(n, ast.FunctionDef) and n.name == function_name]
            patch_funcs = [n for n in ast.walk(patch_ast) if isinstance(n, ast.FunctionDef) and n.name == function_name]
            if orig_funcs and patch_funcs:
                orig_args = [a.arg for a in orig_funcs[0].args.args]
                patch_args = [a.arg for a in patch_funcs[0].args.args]
                if orig_args != patch_args:
                    return False, "fail", f"Gate E FAIL: Function signature changed from {orig_args} to {patch_args}"
            elif orig_funcs and not patch_funcs:
                return False, "fail", f"Gate E FAIL: Target function {function_name} not found in patch"
        except Exception as e:
            return False, "fail", f"Gate E FAIL: Signature check parsing failed: {e}"

    # Excessive diffs
    diff_lines = list(
        difflib.unified_diff(
            original_code.splitlines(),
            patched_code.splitlines(),
            lineterm="",
        )
    )
    changed = [l for l in diff_lines if (l.startswith("+") or l.startswith("-")) and not l.startswith("---") and not l.startswith("+++")]
    threshold = max(max_diff_lines, len(original_code.splitlines()) * 2)
    if len(changed) > threshold:
        return False, "fail", f"Gate E FAIL: Excessive diff size ({len(changed)} changes > limit {threshold})"

    return True, "pass", "Gate E PASS: Diff and path constraints satisfied"


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
        benign_check_fn: Optional[Callable[[str, str], bool]] = None,
    ) -> None:
        self.invoke_llm_fn = invoke_llm_fn
        self.test_dir = test_dir
        self.project_root = project_root
        self.max_retries = max_retries
        self.benign_check_fn = benign_check_fn

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
                    "status": "error",
                    "detail": f"LLM invocation failed: {exc}",
                })
                continue

            if not patched_code or len(patched_code.strip()) < 10:
                gate_log.append({
                    "attempt": attempt,
                    "gate": "llm",
                    "passed": False,
                    "status": "fail",
                    "detail": "LLM returned empty/trivial response",
                })
                continue

            best_patch = patched_code
            attempt_gates: List[Dict[str, Any]] = []

            # Gate A: Parse & Compile
            ga_pass, ga_status, ga_detail = gate_a_parse_compile(patched_code)
            attempt_gates.append({"gate": "gate_a_parse_compile", "passed": ga_pass, "status": ga_status, "detail": ga_detail})
            if not ga_pass:
                gate_log.extend(attempt_gates)
                continue

            # Gate E: Diff, signature, and constraints
            ge_pass, ge_status, ge_detail = gate_e_diff_path_constraints(
                original_code=original_code,
                patched_code=patched_code,
                function_name=finding.get("function_name", ""),
                file_path=finding.get("file_path"),
                allowed_root=self.project_root,
            )
            attempt_gates.append({"gate": "gate_e_diff_constraints", "passed": ge_pass, "status": ge_status, "detail": ge_detail})
            if not ge_pass:
                gate_log.extend(attempt_gates)
                continue

            # Gate B (exploit blocked / refuted)
            g1_pass, g1_status, g1_detail = gate_b_differential_exploit(patched_code, finding)
            attempt_gates.append({"gate": "exploit_blocked", "passed": g1_pass, "status": g1_status, "detail": g1_detail})
            if not g1_pass and g1_status != "skipped":
                gate_log.extend(attempt_gates)
                continue

            # Gate C (tests pass & benign input)
            g2_pass, g2_status, g2_detail = gate_c_project_tests(
                patched_code,
                finding.get("function_name", ""),
                self.test_dir,
                benign_check_fn=self.benign_check_fn,
            )
            attempt_gates.append({"gate": "tests_pass", "passed": g2_pass, "status": g2_status, "detail": g2_detail})
            if not g2_pass and g2_status != "skipped":
                gate_log.extend(attempt_gates)
                continue

            # Gate D (no new SAST findings)
            g3_pass, g3_status, g3_detail = gate_d_rescan_validation(patched_code, issue)
            attempt_gates.append({"gate": "no_new_sast_findings", "passed": g3_pass, "status": g3_status, "detail": g3_detail})
            gate_log.extend(attempt_gates)

            # A patch is verified ONLY if all 5 gates returned status 'pass'
            required_gate_names = {"gate_a_parse_compile", "gate_e_diff_constraints", "exploit_blocked", "tests_pass", "no_new_sast_findings"}
            gates_by_name = {g["gate"]: g["status"] for g in attempt_gates}
            if all(gates_by_name.get(name) == "pass" for name in required_gate_names):
                all_gates_passed = True
                break
            elif g3_pass:
                # If SAST passed but a gate was skipped (e.g. tests_pass skipped), break without verified
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
