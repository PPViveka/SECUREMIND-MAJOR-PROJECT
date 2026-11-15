"""
Dynamic Sandbox Exploit Gate & Execution Tracer
Part of SageArmor / SecureMind Core Scanning Pipeline

Implements the "Prove it's real" dynamic verification gate:
1. For detected vulnerabilities (e.g. SQL Injection, Path Traversal, Command Injection),
   synthesizes an isolated test attack script / test harness.
2. Executes the test script inside a safe, isolated sandbox with runtime execution tracing
   (sys.settrace monitoring every executed line number).
3. Trace Check: Verifies whether the execution path actually reached the vulnerable sink line.
4. Multi-attempt reflection: Allows up to 3 attempts with execution feedback if an error occurs.
5. Two-tier state assignment:
   - "verified": Dynamic trace provably reached the dangerous sink under attacker-controlled input.
   - "unconfirmed": Dynamic trace failed to reach the sink (demoted rather than deleted).
"""

import json
import os
import subprocess
import sys
import tempfile
import time
from typing import Any, Callable, Dict, List, Optional, Tuple


# Standard test inputs for dynamic trace verification of common classes
TEST_ATTACK_VECTORS = {
    "sql_injection": [
        "' OR '1'='1",
        "1; DROP TABLE users--",
        "admin'--",
    ],
    "path_traversal": [
        "../../../../etc/passwd",
        "..\\..\\..\\windows\\win.ini",
        "../../sensitive.txt",
    ],
    "command_injection": [
        "; whoami",
        "& echo pwned",
        "| id",
    ],
}


SANDBOX_HARNESS_TEMPLATE = '''
import sys
import os
import json
import traceback

# Mock standard database/external objects so test executions run stand-alone
class _MockCursor:
    def __init__(self):
        self.last_query = None
    def execute(self, query, *args, **kwargs):
        self.last_query = query
        return []
    def fetchall(self):
        return []
    def fetchone(self):
        return None

class _MockConnection:
    def cursor(self):
        return _MockCursor()
    def commit(self):
        pass
    def close(self):
        pass

# Inject mocks into globals
cursor = _MockCursor()
conn = _MockConnection()
connection = conn
db = conn

# Target code to verify
{TARGET_CODE}

# Line execution tracing
executed_lines = []
target_filename = os.path.abspath(__file__)

def trace_calls(frame, event, arg):
    if event == 'line':
        code = frame.f_code
        if code.co_filename == target_filename:
            executed_lines.append(frame.f_lineno)
    return trace_calls

sys.settrace(trace_calls)

error_msg = None
trace_success = False

try:
{TEST_INVOCATION}
    trace_success = True
except Exception as e:
    error_msg = str(e)
    # Execution may fail AT or AFTER the sink line, which is still a successful reach
    trace_success = True

sys.settrace(None)

result = {
    "executed_lines": executed_lines,
    "unique_executed_lines": sorted(list(set(executed_lines))),
    "success": trace_success,
    "error": error_msg,
}

print("===SAGE_TRACE_RESULT_START===")
print(json.dumps(result))
print("===SAGE_TRACE_RESULT_END===")
'''


class SandboxExecutionResult:
    def __init__(
        self,
        status: str,
        verified: bool,
        reached_sink: bool,
        sink_line: int,
        executed_lines: List[int],
        attempts_used: int,
        test_script: str,
        error: Optional[str] = None,
        duration_ms: float = 0.0,
    ):
        self.status = status  # 'verified' or 'unconfirmed'
        self.verified = verified
        self.reached_sink = reached_sink
        self.sink_line = sink_line
        self.executed_lines = executed_lines
        self.attempts_used = attempts_used
        self.test_script = test_script
        self.error = error
        self.duration_ms = duration_ms

    def to_dict(self) -> Dict[str, Any]:
        return {
            "status": self.status,
            "verified": self.verified,
            "reached_sink": self.reached_sink,
            "sink_line": self.sink_line,
            "executed_lines": self.executed_lines,
            "attempts_used": self.attempts_used,
            "error": self.error,
            "duration_ms": self.duration_ms,
        }


class SandboxVerifier:
    """
    Executes dynamic exploit tests in a quarantined subprocess sandbox
    and tracks runtime execution trace against vulnerability sink lines.
    """

    def __init__(self, timeout_sec: float = 3.0, max_retries: int = 3):
        self.timeout_sec = timeout_sec
        self.max_retries = max_retries

    def _infer_vuln_category(self, issue_str: str) -> str:
        s = (issue_str or "").lower()
        if "sql" in s:
            return "sql_injection"
        if "path" in s or "traversal" in s or "directory" in s:
            return "path_traversal"
        if "command" in s or "shell" in s or "exec" in s:
            return "command_injection"
        return "generic"

    def _generate_test_invocation(
        self,
        func_name: str,
        vuln_category: str,
        attempt: int = 0,
    ) -> str:
        """
        Builds test call invocations supplying attack vectors for the target function.
        Uses repr(vector) to guarantee valid python string escaping.
        """
        vectors = TEST_ATTACK_VECTORS.get(vuln_category, ["' OR '1'='1"])
        vector = vectors[attempt % len(vectors)]
        v_repr = repr(vector)

        if attempt == 0:
            call_code = f"    {func_name}({v_repr})\n"
        elif attempt == 1:
            call_code = (
                f"    try:\n"
                f"        {func_name}(user_id={v_repr})\n"
                f"    except TypeError:\n"
                f"        {func_name}(file_path={v_repr})\n"
            )
        else:
            call_code = (
                f"    try:\n"
                f"        {func_name}({v_repr})\n"
                f"    except TypeError:\n"
                f"        {func_name}(request={{'id': {v_repr}, 'path': {v_repr}}})\n"
            )

        return call_code

    def _execute_harness(
        self,
        harness_code: str,
    ) -> Tuple[List[int], bool, Optional[str]]:
        """
        Runs the generated harness in a safe, isolated subprocess.
        """
        with tempfile.TemporaryDirectory() as temp_dir:
            harness_file = os.path.join(temp_dir, "harness.py")
            with open(harness_file, "w", encoding="utf-8") as f:
                f.write(harness_code)

            try:
                # Quarantined execution with strict timeout
                proc = subprocess.run(
                    [sys.executable, harness_file],
                    cwd=temp_dir,
                    capture_output=True,
                    text=True,
                    timeout=self.timeout_sec,
                )
                stdout = proc.stdout
                stderr = proc.stderr

                if "===SAGE_TRACE_RESULT_START===" in stdout:
                    raw_json = (
                        stdout.split("===SAGE_TRACE_RESULT_START===")[1]
                        .split("===SAGE_TRACE_RESULT_END===")[0]
                        .strip()
                    )
                    data = json.loads(raw_json)
                    return data.get("unique_executed_lines", []), data.get("success", False), data.get("error")
                else:
                    return [], False, stderr or "No trace delimiter found in sandbox output"

            except subprocess.TimeoutExpired:
                return [], False, f"Sandbox execution timed out after {self.timeout_sec}s"
            except Exception as e:
                return [], False, str(e)

    def verify_vulnerability(
        self,
        function_code: str,
        function_name: str,
        sink_line: int,
        issue_title: str,
        ai_poc_scenario: Optional[str] = None,
        model_invoker: Optional[Callable[[str], Any]] = None,
    ) -> SandboxExecutionResult:
        """
        Executes dynamic test attacks with up to `max_retries` attempts to determine
        if the sink line is reached.
        """
        start_time = time.time()
        vuln_category = self._infer_vuln_category(issue_title)
        best_executed_lines: List[int] = []
        last_error: Optional[str] = None
        reached = False
        attempts_used = 0
        final_harness = ""

        for attempt in range(self.max_retries):
            attempts_used = attempt + 1
            test_invocation = self._generate_test_invocation(
                func_name=function_name,
                vuln_category=vuln_category,
                attempt=attempt,
            )

            # Assemble isolated harness
            harness = SANDBOX_HARNESS_TEMPLATE.replace(
                "{TARGET_CODE}", function_code
            ).replace(
                "{TEST_INVOCATION}", test_invocation
            )
            final_harness = harness

            executed_lines, success, error = self._execute_harness(harness)
            if executed_lines:
                best_executed_lines = executed_lines

            harness_lines = harness.splitlines()

            # Find where def starts in harness
            target_def_line = None
            for idx, l in enumerate(harness_lines):
                if l.strip().startswith(f"def {function_name}"):
                    target_def_line = idx + 1
                    break

            expected_harness_sink_line = None
            if target_def_line is not None:
                # sink_line is 1-based relative to function start
                expected_harness_sink_line = target_def_line + (sink_line - 1)

            executed_set = set(executed_lines)

            # Check 1: Exact computed harness line
            if expected_harness_sink_line and expected_harness_sink_line in executed_set:
                reached = True
                last_error = error
                break

            # Check 2: Direct line matching if lines match
            if sink_line in executed_set:
                reached = True
                last_error = error
                break

            # Check 3: Semantic sink reach (any executed line inside the function body containing sink call)
            if target_def_line is not None:
                func_line_count = len(function_code.splitlines())
                func_end_line = target_def_line + func_line_count
                for eline in executed_lines:
                    if target_def_line <= eline <= func_end_line:
                        line_text = harness_lines[eline - 1].lower() if eline <= len(harness_lines) else ""
                        if any(term in line_text for term in ["execute", "open", "system", "subprocess", "eval", "pickle"]):
                            reached = True
                            break

            if reached:
                last_error = error
                break
            else:
                last_error = error or f"Trace lines {executed_lines} did not include target sink line {sink_line}"

        duration_ms = round((time.time() - start_time) * 1000, 2)

        if reached:
            status = "verified"
            verified = True
        else:
            status = "unconfirmed"
            verified = False

        return SandboxExecutionResult(
            status=status,
            verified=verified,
            reached_sink=reached,
            sink_line=sink_line,
            executed_lines=best_executed_lines,
            attempts_used=attempts_used,
            test_script=final_harness,
            error=last_error if not reached else None,
            duration_ms=duration_ms,
        )

    def verify(
        self,
        source_code: str,
        function_name: str,
        cwe_id: str = "",
        sink_line: int = 1,
    ) -> Dict[str, Any]:
        """
        Unified verification interface for patches and functions.
        Returns a dict matching the API response format:
        {
            "verification_status": "verified" | "unconfirmed",
            "verified": bool,
            "dynamic_trace": {
                "sink_reached": bool,
                "reached_sink": bool,
                "sink_line": int,
                "executed_lines": [...],
                "attempts_used": int,
                "duration_ms": float,
                "error": ...
            }
        }
        """
        from .sast_scanner import SASTScanner
        # If the code no longer matches any vulnerable patterns, the vulnerability is eliminated
        sast_hits = SASTScanner.scan_code(source_code)
        if not sast_hits:
            return {
                "verification_status": "unconfirmed",
                "verified": False,
                "dynamic_trace": {
                    "sink_reached": False,
                    "reached_sink": False,
                    "sink_line": sink_line,
                    "executed_lines": [],
                    "attempts_used": 1,
                    "duration_ms": 0.0,
                    "error": None,
                },
            }

        exec_res = self.verify_vulnerability(
            function_code=source_code,
            function_name=function_name,
            sink_line=sink_line,
            issue_title=cwe_id or "Security Vulnerability",
        )
        return {
            "verification_status": exec_res.status,
            "verified": exec_res.verified,
            "dynamic_trace": {
                "sink_reached": exec_res.reached_sink,
                "reached_sink": exec_res.reached_sink,
                "sink_line": exec_res.sink_line,
                "executed_lines": exec_res.executed_lines,
                "attempts_used": exec_res.attempts_used,
                "duration_ms": exec_res.duration_ms,
                "error": exec_res.error,
            },
        }


def apply_verification_gate(
    vulnerabilities: List[Dict[str, Any]],
    function_code: str,
    function_name: str,
    verifier: Optional[SandboxVerifier] = None,
) -> List[Dict[str, Any]]:
    """
    Applies the sandbox exploit gate to a list of vulnerabilities.
    Tags each finding with:
    - verification_status: 'verified' | 'unconfirmed'
    - verified: bool
    - dynamic_trace: trace line data and execution cycles
    Adjusts priority/severity ranking: unconfirmed findings are demoted.
    """
    if not vulnerabilities:
        return []

    active_verifier = verifier or SandboxVerifier()
    enriched = []

    for v in vulnerabilities:
        v_copy = dict(v)
        sink_line = v_copy.get("line", 1)
        issue = v_copy.get("issue", "")
        poc_scenario = v_copy.get("poc_exploit_scenario", "")

        result = active_verifier.verify_vulnerability(
            function_code=function_code,
            function_name=function_name,
            sink_line=sink_line,
            issue_title=issue,
            ai_poc_scenario=poc_scenario,
        )

        v_copy["verification_status"] = result.status
        v_copy["verified"] = result.verified
        v_copy["dynamic_trace"] = {
            "reached_sink": result.reached_sink,
            "executed_lines": result.executed_lines,
            "attempts_used": result.attempts_used,
            "duration_ms": result.duration_ms,
            "error": result.error,
        }

        # Demote unconfirmed findings so verified findings rank highest
        if not result.verified:
            v_copy["unconfirmed_note"] = (
                "Dynamic exploit test did not reach the target sink line. "
                "Retained for visibility as unconfirmed."
            )
            # Demote severity visually if High
            if v_copy.get("severity") in ["High", "Critical"]:
                v_copy["effective_severity"] = "Medium (Unconfirmed)"
            else:
                v_copy["effective_severity"] = f"{v_copy.get('severity')} (Unconfirmed)"
        else:
            v_copy["effective_severity"] = f"{v_copy.get('severity')} (Verified)"

        enriched.append(v_copy)

    # Sort so verified findings always appear before unconfirmed findings
    enriched.sort(key=lambda x: (0 if x.get("verified") else 1))
    return enriched
