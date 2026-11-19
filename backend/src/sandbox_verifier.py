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
import builtins
import io
import sys
import tempfile
import time
import shutil
import ast
import hashlib
import re
from typing import Any, Callable, Dict, List, Optional, Tuple

try:
    from .llm_provider import redact_secrets
except ImportError:
    def redact_secrets(text: str) -> str:
        return text


def _safe_log(msg: Any) -> None:
    """Print a log line with any secrets redacted."""
    print(redact_secrets(str(msg)))


# Pinned sandbox image; its real digest is recorded in every audit record.
SANDBOX_IMAGE = "python:3.11-slim"
_IMAGE_DIGEST_CACHE: Dict[str, str] = {}


def sandbox_image_digest(image: str = SANDBOX_IMAGE) -> str:
    """Return the local Docker image digest (cached), or 'unavailable:<image>'."""
    if image in _IMAGE_DIGEST_CACHE:
        return _IMAGE_DIGEST_CACHE[image]
    digest = f"unavailable:{image}"
    if shutil.which("docker"):
        try:
            out = subprocess.run(
                ["docker", "image", "inspect", "--format", "{{json .RepoDigests}}|{{.Id}}", image],
                capture_output=True, text=True, timeout=3.0,
            )
            if out.returncode == 0 and out.stdout.strip():
                repo_digests, _, image_id = out.stdout.strip().partition("|")
                found = re.search(r"sha256:[0-9a-f]{64}", repo_digests)
                digest = found.group(0) if found else (image_id.strip() or digest)
        except Exception:
            pass
    _IMAGE_DIGEST_CACHE[image] = digest
    return digest


def to_function_relative_line(file_line: int, function_code: str, function_name: str, function_start_line: int = 1) -> int:
    """
    Convert a file-absolute line number into a 1-based line relative to the
    function's ``def`` line, which is what ``verify_vulnerability`` expects.
    Lines that already fall inside the function body are passed through.
    """
    try:
        file_line = int(file_line or 1)
    except (TypeError, ValueError):
        return 1
    lines = function_code.splitlines() or [""]
    def_pattern = re.compile(r"^\s*(?:async\s+)?def\s+" + re.escape(function_name or "") + r"\s*\(")
    def_offset = next((i for i, line in enumerate(lines) if def_pattern.match(line)), 0)
    if function_start_line and function_start_line > 1:
        relative = file_line - (function_start_line + def_offset) + 1
        if 1 <= relative <= len(lines) - def_offset:
            return relative
    return max(1, min(file_line, len(lines)))


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
    "code_evaluation": [
        "__import__('os').system('id')",
        "7 * 7",
        "True",
    ],
}


SANDBOX_HARNESS_TEMPLATE = '''
import sys
import os
import json
import traceback
import subprocess
import builtins
import io

# Mock standard database/external objects so test executions run stand-alone
class _MockCursor:
    def __init__(self):
        self.last_query = None
    def execute(self, query, *args, **kwargs):
        self.last_query = query
        hook_records.append({"kind": "sql", "query": str(query), "bound_args": repr(args)})
        return self
    def fetchall(self):
        return []
    def fetchone(self):
        return None

class _MockConnection:
    def cursor(self):
        return _MockCursor()
    def execute(self, query, *args, **kwargs):
        c = _MockCursor()
        return c.execute(query, *args, **kwargs)
    def commit(self):
        pass
    def close(self):
        pass

# Inject mocks into globals
cursor = _MockCursor()
conn = _MockConnection()
connection = conn
db = conn
hook_records = []

try:
    import sqlite3
    sqlite3.connect = lambda *a, **kw: _MockConnection()
except Exception:
    pass

# Dynamic stub meta path finder for unresolved third-party imports
class _StubModule:
    def __init__(self, name, is_module=False):
        self.__name__ = name
        self._is_module = is_module
    def __getattr__(self, item):
        # Import-machinery probes (__path__, __loader__, __spec__, ...) are not code using the stub.
        if item.startswith("__") and item.endswith("__"):
            raise AttributeError(item)
        # `from flask import request` reads a name off the stubbed module: binding it is not use.
        # Using it (request.args, Flask(...)) goes through the returned child stub and is recorded.
        if not object.__getattribute__(self, "_is_module"):
            hook_records.append({"kind": "stub_access", "module": self.__name__, "attr": str(item)})
        return _StubModule(f"{self.__name__}.{item}")
    def __call__(self, *args, **kwargs):
        hook_records.append({"kind": "stub_call", "module": self.__name__})
        return _StubModule(f"{self.__name__}()")

class _StubFinder:
    def find_spec(self, fullname, path, target=None):
        import importlib.util
        if fullname in sys.modules or fullname in sys.builtin_module_names:
            return None
        # Platform-specific stdlib modules must fail to import normally, never be stubbed.
        if fullname in ("nt", "dos", "os2", "mac", "ce", "riscos", "org", "_winapi", "winreg",
                        "posix", "pwd", "grp", "fcntl", "termios", "resource", "_posixsubprocess",
                        "_posixshmem", "_scproxy", "msvcrt", "_overlapped"):
            return None
        return importlib.util.spec_from_loader(fullname, self)
    def create_module(self, spec):
        return _StubModule(spec.name, is_module=True)
    def exec_module(self, module):
        pass

sys.meta_path.append(_StubFinder())

def _mock_system(command):
    hook_records.append({"kind": "system", "command": str(command), "shell": True, "argv": ""})
    return 0

def _mock_subp(*args, **kwargs):
    cmd_repr = repr(args[0]) if args else repr(kwargs.get("args", ""))
    hook_records.append({
        "kind": "subprocess",
        "command": cmd_repr,
        "shell": kwargs.get("shell", False),
        "argv": repr(args[0] if args else kwargs.get("args", "")),
    })
    res_cls = type("_Result", (), {
        "returncode": 0,
        "stdout": "",
        "stderr": "",
        "communicate": lambda self, *a, **kw: ("", ""),
        "wait": lambda self, *a, **kw: 0,
        "poll": lambda self: 0,
    })
    return res_cls()

os.system = _mock_system
os.popen = lambda cmd: (_mock_system(cmd), io.StringIO(""))[1]
subprocess.run = _mock_subp
subprocess.call = lambda *a, **kw: (_mock_subp(*a, **kw), 0)[1]
subprocess.check_call = lambda *a, **kw: (_mock_subp(*a, **kw), 0)[1]
subprocess.check_output = lambda *a, **kw: (_mock_subp(*a, **kw), b"")[1]
subprocess.Popen = _mock_subp

def _mock_open(path, *args, **kwargs):
    p_str = str(path)
    escapes = ".." in p_str.split(os.sep) or ".." in p_str or os.path.isabs(p_str)
    hook_records.append({"kind": "open", "path": p_str, "escapes_root": escapes})
    return io.StringIO("")

builtins.open = _mock_open

try:
    import pathlib
    def _mock_path_open(self, *args, **kwargs):
        return _mock_open(str(self), *args, **kwargs)
    pathlib.Path.open = _mock_path_open
    pathlib.Path.read_text = lambda self, *a, **kw: (_mock_open(str(self)), "")[1]
    pathlib.Path.read_bytes = lambda self, *a, **kw: (_mock_open(str(self)), b"")[1]
    pathlib.Path.write_text = lambda self, data, *a, **kw: (_mock_open(str(self)), len(data))[1]
    pathlib.Path.write_bytes = lambda self, data, *a, **kw: (_mock_open(str(self)), len(data))[1]
except Exception:
    pass

_real_eval = builtins.eval
def _mock_eval(expr, *args, **kwargs):
    hook_records.append({"kind": "eval", "expression": str(expr), "expr": str(expr)})
    try:
        return _real_eval(expr, *args, **kwargs)
    except Exception:
        return None

builtins.eval = _mock_eval

_real_exec = builtins.exec
def _mock_exec(code, *args, **kwargs):
    hook_records.append({"kind": "exec", "expression": str(code), "expr": str(code)})
    try:
        return _real_exec(code, *args, **kwargs)
    except Exception:
        return None

builtins.exec = _mock_exec

# Target code to verify
{TARGET_CODE}

# Line execution tracing
executed_lines = []
_main_file = getattr(sys.modules.get('__main__'), '__file__', '<stdin>') or '<stdin>'
target_filenames = {'<stdin>', _main_file, os.path.abspath(_main_file)}

def trace_calls(frame, event, arg):
    if event == 'line':
        code = frame.f_code
        if code.co_filename in target_filenames or os.path.basename(code.co_filename) in ('<stdin>', os.path.basename(_main_file)):
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
    "hook_records": hook_records,
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
        audit_record: Optional[Dict[str, Any]] = None,
    ):
        self.status = status  # 'verified', 'unconfirmed', or 'inconclusive'
        self.verified = verified
        self.reached_sink = reached_sink
        self.sink_line = sink_line
        self.executed_lines = executed_lines
        self.attempts_used = attempts_used
        self.test_script = test_script
        self.error = error
        self.duration_ms = duration_ms
        self.audit_record = audit_record or {}

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
            "audit_record": self.audit_record,
        }


class SandboxVerifier:
    """
    Executes dynamic exploit tests in a quarantined subprocess sandbox
    and tracks runtime execution trace against vulnerability sink lines.
    """

    REFERENCE_FUNCTIONS = {
        "sql_injection": {
            "vulnerable": "def fetch(val):\n    cursor.execute('SELECT * FROM t WHERE id=' + val)",
            "safe": "def fetch(val):\n    cursor.execute('SELECT * FROM t WHERE id=?', (val,))",
        },
        "command_injection": {
            "vulnerable": "def run(val):\n    os.system('ping ' + val)",
            "safe": "def run(val):\n    subprocess.run(['ping', str(val)], shell=False)",
        },
        "path_traversal": {
            "vulnerable": "def read(val):\n    return open(val).read()",
            "safe": "def read(val):\n    if '..' in val: raise ValueError\n    return open('/data/' + val).read()",
        },
        "code_evaluation": {
            "vulnerable": "def calculate(val):\n    return eval(val)",
            "safe": "def calculate(val):\n    return int(val)",
        },
    }

    def __init__(self, timeout_sec: float = 3.0, max_retries: int = 3, runtime: Optional[str] = None, max_output_bytes: int = 65536):
        self.timeout_sec = timeout_sec
        self.max_retries = max_retries
        # One isolation setting: explicit argument, else SAGE_ARMOR_ISOLATION_RUNTIME (docker | gvisor | host).
        self.runtime = (runtime or os.getenv("SAGE_ARMOR_ISOLATION_RUNTIME") or "docker").strip().lower()
        self.max_output_bytes = max(1024, max_output_bytes)

    _docker_live_cache: Tuple[float, bool] = (0.0, False)
    _DOCKER_PROBE_TTL_SEC = 30.0

    @staticmethod
    def _is_docker_live() -> bool:
        # `docker info` takes ~0.7-0.9s on Docker Desktop (Windows/macOS), so a sub-second
        # timeout wrongly reported Docker as down. Probe with a sane timeout and cache briefly,
        # since this is checked on every sandbox attempt.
        checked_at, live = SandboxVerifier._docker_live_cache
        if time.time() - checked_at < SandboxVerifier._DOCKER_PROBE_TTL_SEC:
            return live
        live = False
        if shutil.which("docker"):
            try:
                chk = subprocess.run(["docker", "info"], capture_output=True, timeout=5.0)
                live = chk.returncode == 0
            except Exception:
                live = False
        SandboxVerifier._docker_live_cache = (time.time(), live)
        return live

    @staticmethod
    def _is_gvisor_live() -> bool:
        """Checks if Docker daemon has runsc (gVisor) runtime configured."""
        if not SandboxVerifier._is_docker_live():
            return False
        try:
            chk = subprocess.run(["docker", "info", "--format", "{{json .Runtimes}}"], capture_output=True, text=True, timeout=1.0)
            return "runsc" in chk.stdout
        except Exception:
            return False

    def isolation_available(self) -> bool:
        """Return whether the configured production isolation runtime is usable."""
        if self.runtime == "host":
            return True
        if os.getenv("SAGE_ARMOR_UNSAFE_LOCAL_SANDBOX") == "1":
            return True
        if self.runtime in ("docker", "gvisor"):
            return self._is_docker_live()
        return False

    def _build_js_context_bundle(self, source_code: str, function_name: str) -> str:
        """Extract JavaScript / TypeScript functions, imports, and constants (FR-109)."""
        lines = source_code.splitlines()
        extracted = []
        in_target_fn = False
        brace_count = 0
        fn_regex = re.compile(
            r"^(?:\s*(?:export\s+)?(?:async\s+)?function\s+" + re.escape(function_name) +
            r"|\s*(?:export\s+)?(?:const|let|var)\s+" + re.escape(function_name) +
            r"\s*=\s*(?:async\s*)?(?:\([^)]*\)|[a-zA-Z0-9_$]+)\s*=>)"
        )

        for line in lines:
            stripped = line.strip()
            # Retain imports and requires
            if stripped.startswith(("import ", "require(", "const ", "let ", "var ")) and ("=" in stripped or "from" in stripped):
                if not in_target_fn and any(tok in stripped for tok in ["require", "import", "config", "PORT", "URL", "DB"]):
                    extracted.append(line)
                    continue

            if not in_target_fn and fn_regex.search(line):
                in_target_fn = True
                brace_count = line.count("{") - line.count("}")
                extracted.append(line)
                if brace_count == 0 and "=>" in line and "{" not in line:
                    in_target_fn = False
                continue

            if in_target_fn:
                extracted.append(line)
                brace_count += line.count("{") - line.count("}")
                if brace_count <= 0:
                    in_target_fn = False

        return "\n".join(extracted) if extracted else source_code

    def build_context_bundle(self, source_code: str, function_name: str) -> str:
        """Keep imports, literal constants, the target, and local helper functions only."""
        try:
            tree = ast.parse(source_code)
        except SyntaxError:
            return self._build_js_context_bundle(source_code, function_name)

        functions = {
            node.name: node
            for node in ast.walk(tree)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        }
        target = functions.get(function_name)
        if target is None:
            return source_code

        selected = []
        for node in tree.body:
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                selected.append(node)
            elif isinstance(node, ast.Assign) and isinstance(node.value, ast.Constant):
                selected.append(node)

        required = {function_name}
        pending = [function_name]
        while pending:
            current = pending.pop()
            for node in ast.walk(functions[current]):
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in functions:
                    if node.func.id not in required:
                        required.add(node.func.id)
                        pending.append(node.func.id)

        selected.extend(functions[name] for name in functions if name in required)
        segments = [ast.get_source_segment(source_code, node) for node in selected]
        return "\n\n".join(segment for segment in segments if segment)

    def _infer_vuln_category(self, issue_str: str) -> str:
        s = (issue_str or "").lower()
        if "sql" in s or "cwe-89" in s:
            return "sql_injection"
        if "path" in s or "traversal" in s or "directory" in s or "cwe-22" in s:
            return "path_traversal"
        if "command" in s or "shell" in s or "cwe-78" in s:
            return "command_injection"
        if "eval" in s or "code execution" in s or "code injection" in s or "cwe-94" in s:
            return "code_evaluation"
        if "exec" in s:
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
        self.last_hook_records = []
        with tempfile.TemporaryDirectory() as temp_dir:
            harness_file = os.path.join(temp_dir, "harness.py")
            with open(harness_file, "w", encoding="utf-8") as f:
                f.write(harness_code)

            try:
                use_docker = False
                if self.runtime in ("docker", "gvisor"):
                    use_docker = self._is_docker_live()

                if use_docker:
                    use_runsc = self.runtime == "gvisor"
                    if use_runsc and not self._is_gvisor_live():
                        _safe_log("[sandbox] Warning: gVisor runtime requested but 'runsc' not found in Docker daemon. Running in default hardened container.")
                        use_runsc = False
                    runtime_opt = ["--runtime", "runsc"] if use_runsc else []
                    command = [
                        "docker", "run", "-i", "--rm", "--network", "none", "--read-only",
                    ] + runtime_opt + [
                        "--tmpfs", "/tmp:rw,noexec,nosuid,size=16m",  # nosec B108
                        "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
                        "--pids-limit", "64", "--memory", "128m", "--cpus", "0.5",
                        "--env", "PATH=/usr/local/bin:/usr/bin:/bin",
                        "--env", "PYTHONUNBUFFERED=1",
                        "--user", "65534:65534",
                        SANDBOX_IMAGE, "python", "-",
                    ]
                    clean_env = None
                    input_text = harness_code
                else:
                    if self.runtime != "host" and os.getenv("SAGE_ARMOR_UNSAFE_LOCAL_SANDBOX") != "1":
                        return [], False, "Docker isolation runtime is unavailable and unsafe host fallback is disabled"
                    command = [sys.executable, harness_file]
                    clean_env = {
                        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
                        "PYTHONUNBUFFERED": "1",
                        "PYTHONPATH": os.path.abspath(temp_dir),
                    }
                    input_text = None

                proc = subprocess.run(
                    command,
                    cwd=temp_dir,
                    env=clean_env,
                    input=input_text,
                    capture_output=True,
                    text=True,
                    timeout=self.timeout_sec,
                )
                stdout = proc.stdout
                stderr = proc.stderr

                if len(stdout.encode("utf-8")) > self.max_output_bytes or len(stderr.encode("utf-8")) > self.max_output_bytes:
                    return [], False, "Sandbox output exceeded configured limit"

                if "===SAGE_TRACE_RESULT_START===" in stdout:
                    raw_json = (
                        stdout.split("===SAGE_TRACE_RESULT_START===")[1]
                        .split("===SAGE_TRACE_RESULT_END===")[0]
                        .strip()
                    )
                    data = json.loads(raw_json)
                    self.last_hook_records = data.get("hook_records", [])
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
        if not self.isolation_available():
            return SandboxExecutionResult(
                status="not_applicable",
                verified=False,
                reached_sink=False,
                sink_line=sink_line,
                executed_lines=[],
                attempts_used=0,
                test_script="",
                error="Docker isolation runtime is unavailable",
                duration_ms=round((time.time() - start_time) * 1000, 2),
            )
        vuln_category = self._infer_vuln_category(issue_title)
        function_code = self.build_context_bundle(function_code, function_name)
        best_executed_lines: List[int] = []
        last_error: Optional[str] = None
        reached = False
        attempts_used = 0
        final_harness = ""
        last_attack_input = ""

        for attempt in range(self.max_retries):
            attempts_used = attempt + 1
            vectors = TEST_ATTACK_VECTORS.get(vuln_category, ["' OR '1'='1"])
            last_attack_input = vectors[attempt % len(vectors)]
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

            # Find where def starts in harness using exact regex
            target_def_line = None
            fn_pattern = re.compile(r"^\s*(?:async\s+)?def\s+" + re.escape(function_name) + r"\s*\(")
            for idx, l in enumerate(harness_lines):
                if fn_pattern.match(l):
                    target_def_line = idx + 1
                    break

            expected_harness_sink_line = None
            if target_def_line is not None:
                # sink_line is 1-based relative to function start
                expected_harness_sink_line = target_def_line + (sink_line - 1)

            executed_set = set(executed_lines)

            differential_reached = True
            if vuln_category == "sql_injection":
                attack_vector = TEST_ATTACK_VECTORS[vuln_category][attempt % len(TEST_ATTACK_VECTORS[vuln_category])]
                differential_reached = any(
                    attack_vector in record.get("query", "")
                    and attack_vector not in record.get("bound_args", "")
                    for record in self.last_hook_records
                )
            elif vuln_category == "command_injection":
                attack_vector = TEST_ATTACK_VECTORS[vuln_category][attempt % len(TEST_ATTACK_VECTORS[vuln_category])]
                differential_reached = any(
                    attack_vector in record.get("command", "")
                    and (
                        record.get("kind") in ("system", "popen")
                        or record.get("shell") is True
                    )
                    for record in self.last_hook_records
                )
            elif vuln_category == "path_traversal":
                attack_vector = TEST_ATTACK_VECTORS[vuln_category][attempt % len(TEST_ATTACK_VECTORS[vuln_category])]
                differential_reached = any(
                    record.get("kind") == "open"
                    and (
                        record.get("escapes_root") is True
                        or ".." in record.get("path", "").split(os.sep)
                        or ".." in record.get("path", "")
                    )
                    for record in self.last_hook_records
                )
            elif vuln_category == "code_evaluation":
                attack_vector = TEST_ATTACK_VECTORS[vuln_category][attempt % len(TEST_ATTACK_VECTORS[vuln_category])]
                differential_reached = any(
                    record.get("kind") in ("eval", "exec")
                    and attack_vector in record.get("expr", "")
                    for record in self.last_hook_records
                )
            if not differential_reached:
                last_error = error or "Differential canary did not prove the exploit predicate"
                continue

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

        # Check if execution was influenced by stubs
        stub_accessed = any(
            isinstance(r, dict) and r.get("kind") in ("stub_access", "stub_call")
            for r in (self.last_hook_records or [])
        )

        if reached:
            if stub_accessed:
                status = "inconclusive"
                verified = False
            else:
                status = "verified"
                verified = True
        else:
            if stub_accessed:
                status = "inconclusive"
            else:
                status = "unconfirmed"
            verified = False

        # Build secure verification audit record
        cleaned_hook_records = []
        for r in (self.last_hook_records or []):
            if isinstance(r, dict):
                cleaned_r = {k: redact_secrets(str(v)) if isinstance(v, str) else v for k, v in r.items()}
                cleaned_hook_records.append(cleaned_r)
            else:
                cleaned_hook_records.append(r)

        input_hash = hashlib.sha256(last_attack_input.encode("utf-8", errors="replace")).hexdigest() if last_attack_input else ""
        context_hash = hashlib.sha256(function_code.encode("utf-8", errors="replace")).hexdigest()
        harness_hash = hashlib.sha256((final_harness or "").encode("utf-8", errors="replace")).hexdigest()

        audit_record = {
            "input_hash": input_hash,
            "context_hash": context_hash,
            "sandbox_image_digest": sandbox_image_digest(),
            "harness_hash": harness_hash,
            "canary": redact_secrets(last_attack_input) if last_attack_input else "",
            "hook_records": cleaned_hook_records,
            "verdict": status,
            "duration_ms": duration_ms,
            "failure_reason": redact_secrets(last_error) if (not reached and last_error) else None,
        }

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
            audit_record=audit_record,
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
        # Always execute the sandbox: a clean regex scan is not proof that the exploit is gone.
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
            "audit_record": exec_res.audit_record,
        }


def apply_verification_gate(
    vulnerabilities: List[Dict[str, Any]],
    function_code: str,
    function_name: str,
    verifier: Optional[SandboxVerifier] = None,
    language: str = "python",
    function_start_line: int = 1,
    context_source: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """
    Applies the sandbox exploit gate to a list of vulnerabilities.
    Tags each finding with:
    - verification_status: 'verified' | 'unconfirmed'
    - verified: bool
    - dynamic_trace: trace line data and execution cycles
    Adjusts priority/severity ranking: unconfirmed findings are demoted.

    ``context_source`` is the whole file: the sandbox keeps its imports, constants and the
    local helpers the target calls (e.g. ``get_db``), so the function can actually run.
    Without it only ``function_code`` is executed and calls to helpers fail with NameError.
    """
    if not vulnerabilities:
        return []

    active_verifier = verifier or SandboxVerifier()
    enriched = []

    for v in vulnerabilities:
        v_copy = dict(v)
        if (language or "python").lower() not in {"python", "py"}:
            v_copy["verification_status"] = "not_applicable"
            v_copy["verified"] = False
            v_copy["dynamic_trace"] = {
                "reached_sink": False,
                "executed_lines": [],
                "attempts_used": 0,
                "duration_ms": 0.0,
                "error": "Dynamic verification is unavailable for this language tier.",
            }
            v_copy["unconfirmed_note"] = "Static finding retained; dynamic verification is not applicable."
            enriched.append(v_copy)
            continue
        sink_line = to_function_relative_line(
            v_copy.get("line", 1), function_code, function_name, function_start_line
        )
        issue = v_copy.get("issue", "")
        poc_scenario = v_copy.get("poc_exploit_scenario", "")

        result = active_verifier.verify_vulnerability(
            function_code=context_source or function_code,
            function_name=function_name,
            sink_line=sink_line,
            issue_title=issue,
            ai_poc_scenario=poc_scenario,
        )

        v_copy["verification_status"] = result.status
        v_copy["verified"] = result.verified
        v_copy["audit_record"] = result.audit_record
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
