"""
Dynamic Sandbox Exploit Gate & Execution Tracer
Part of SageArmor / SecureMind Core Scanning Pipeline

"Prove it's real": a finding is confirmed only when an attack actually works.
1. The target function (plus the imports, constants and helpers it needs) runs in an isolated
   container where every dangerous sink is a recorder (see sandbox_harness.py).
2. Each attack input carries a unique canary. Fixed attack strings are tried first; if they
   fail, the LLM writes new inputs using the previous run's trace (lines executed, where it
   stopped, what each sink received). Model output is data only, never executed as code.
3. Verified = the canary reached a sink argument with its attack syntax intact (e.g. the quote
   is still inside the SQL text, the ';' is still in the shell command).
4. Verdicts: verified, unconfirmed (tested, not exploitable), inconclusive (stubbed code ran),
   not_run (no Docker), not_applicable (no runtime check for this language / finding type).
   Unconfirmed findings are demoted, never deleted, and each finding keeps its evidence.
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
import secrets
from typing import Any, Callable, Dict, List, Optional, Tuple

try:
    from .llm_provider import redact_secrets
except ImportError:
    def redact_secrets(text: str) -> str:
        return text

try:
    from .finding_schema import rank_findings
except ImportError:
    from finding_schema import rank_findings  # type: ignore


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

try:
    from .sandbox_harness import (
        CANARY_PLACEHOLDER, CATEGORY_SPECS, HARNESS_TEMPLATE, SINK_KINDS, SUPPORTED_CATEGORIES,
        build_invocation, candidate_strings, fixed_vectors, infer_category, match_sink_evidence, sink_argument,
    )
except ImportError:  # imported as a top-level module
    from sandbox_harness import (  # type: ignore
        CANARY_PLACEHOLDER, CATEGORY_SPECS, HARNESS_TEMPLATE, SINK_KINDS, SUPPORTED_CATEGORIES,
        build_invocation, candidate_strings, fixed_vectors, infer_category, match_sink_evidence, sink_argument,
    )

# Kept for callers that import the old names.
SANDBOX_HARNESS_TEMPLATE = HARNESS_TEMPLATE
TEST_ATTACK_VECTORS = {cat: spec["vectors"] for cat, spec in CATEGORY_SPECS.items()}

# Verdicts a finding can carry after the gate.
STATUS_VERIFIED = "verified"          # canary reached the sink argument with attack syntax intact
STATUS_UNCONFIRMED = "unconfirmed"    # every attempt ran, none reached the sink
STATUS_INCONCLUSIVE = "inconclusive"  # reached the sink, but only through stubbed (unknown) code
STATUS_NOT_RUN = "not_run"            # the sandbox could not run (Docker unavailable)
STATUS_NOT_APPLICABLE = "not_applicable"  # no runtime check exists for this language / finding type

_MAX_EVIDENCE_TEXT = 600


def _clip(value: Any, limit: int = _MAX_EVIDENCE_TEXT) -> str:
    text = value if isinstance(value, str) else json.dumps(value, default=str)
    text = redact_secrets(text)
    return text if len(text) <= limit else text[:limit] + "…"


def _env_flag(name: str, default: str = "1") -> bool:
    return os.getenv(name, default).strip().lower() not in ("0", "false", "no", "off", "")


def default_exploit_invoker() -> Optional[Callable[[str], Any]]:
    """
    Model invoker for LLM-written exploit inputs, or None when no real provider is configured
    (or SAGE_ARMOR_LLM_EXPLOITS=0). The model only ever supplies data (strings); its output is
    passed to the harness as Python literals and never executed as code.
    """
    if not _env_flag("SAGE_ARMOR_LLM_EXPLOITS"):
        return None
    provider_name = (os.getenv("LLM_PROVIDER") or os.getenv("MODEL_PROVIDER") or "").strip().lower()
    if provider_name in ("", "mock", "recorded"):
        return None

    def _invoke(prompt: str) -> str:
        try:
            from .llm_provider import create_provider
        except ImportError:
            from llm_provider import create_provider  # type: ignore
        provider = create_provider(provider_name)
        if hasattr(provider, "timeout"):
            provider.timeout = min(float(provider.timeout), float(os.getenv("SAGE_ARMOR_LLM_EXPLOIT_TIMEOUT", "20")))
        if hasattr(provider, "retries"):
            provider.retries = min(int(provider.retries), 1)
        return provider.complete(prompt, max_tokens=700, as_json=True).text

    return _invoke


def _parse_model_json(raw: Any) -> Dict[str, Any]:
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, list) and raw and isinstance(raw[0], dict):
        return raw[0]
    text = str(raw or "")
    match = re.search(r"\{.*\}", text, re.DOTALL)
    if not match:
        return {}
    try:
        data = json.loads(match.group(0))
    except (ValueError, TypeError):
        return {}
    return data if isinstance(data, dict) else {}


def _sanitize_model_value(value: Any, canary: str, depth: int = 0) -> Any:
    """Keep only JSON data (no objects, no code) and swap the placeholder for the canary."""
    if depth > 3:
        return None
    if isinstance(value, str):
        return value.replace(CANARY_PLACEHOLDER, canary)[:2000]
    if isinstance(value, bool) or value is None or isinstance(value, (int, float)):
        return value
    if isinstance(value, list):
        return [_sanitize_model_value(v, canary, depth + 1) for v in value[:20]]
    if isinstance(value, dict):
        return {
            str(k)[:64]: _sanitize_model_value(v, canary, depth + 1)
            for k, v in list(value.items())[:20]
        }
    return str(value)[:2000]


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
        evidence: Optional[Dict[str, Any]] = None,
    ):
        # 'verified' | 'unconfirmed' | 'inconclusive' | 'not_run' | 'not_applicable'
        self.status = status
        self.verified = verified
        self.reached_sink = reached_sink
        self.sink_line = sink_line
        self.executed_lines = executed_lines
        self.attempts_used = attempts_used
        self.test_script = test_script
        self.error = error
        self.duration_ms = duration_ms
        self.audit_record = audit_record or {}
        self.evidence = evidence or {}

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
            "evidence": self.evidence,
        }


class SandboxVerifier:
    """
    Proves findings by attack: runs the target function in an isolated container with fake
    sinks, feeds it canary-tagged attack inputs (fixed strings first, then LLM-written ones
    informed by the previous run's trace), and confirms only when the canary reaches a sink
    argument with its attack syntax intact.
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
            "vulnerable": "def read(val):\n    return open('/data/' + val).read()",
            "safe": "def read(val):\n    if '..' in val: raise ValueError\n    return open('/data/' + val).read()",
        },
        "code_evaluation": {
            "vulnerable": "def calculate(val):\n    return eval(val)",
            "safe": "def calculate(val):\n    return int(val)",
        },
        "ssrf": {
            "vulnerable": "import requests\ndef fetch(url):\n    return requests.get(url).text",
            "safe": "import requests\ndef fetch(q):\n    return requests.get('https://api.example.com/search', params={'q': q}).text",
        },
        "deserialization": {
            "vulnerable": "import pickle, base64\ndef load(blob):\n    return pickle.loads(base64.b64decode(blob))",
            "safe": "import json\ndef load(blob):\n    return json.loads(blob)",
        },
        "template_injection": {
            "vulnerable": "from flask import render_template_string\ndef page(name):\n    return render_template_string('Hello ' + name)",
            "safe": "from flask import render_template_string\ndef page(name):\n    return render_template_string('Hello {{ name }}', name=name)",
        },
        "xss": {
            "vulnerable": "def page(name):\n    return '<h1>Hello ' + name + '</h1>'",
            "safe": "import html\ndef page(name):\n    return '<h1>Hello ' + html.escape(name) + '</h1>'",
        },
        "open_redirect": {
            "vulnerable": "from flask import redirect, request\ndef go():\n    return redirect(request.args.get('next'))",
            "safe": "from flask import redirect, url_for\ndef go():\n    return redirect(url_for('home'))",
        },
    }

    def __init__(
        self,
        timeout_sec: float = 3.0,
        max_retries: int = 3,
        runtime: Optional[str] = None,
        max_output_bytes: int = 65536,
        llm_attempts: Optional[int] = None,
    ):
        self.timeout_sec = timeout_sec
        # Number of fixed attack strings tried before asking the model.
        self.max_retries = max_retries
        # One isolation setting: explicit argument, else SAGE_ARMOR_ISOLATION_RUNTIME (docker | gvisor | host).
        self.runtime = (runtime or os.getenv("SAGE_ARMOR_ISOLATION_RUNTIME") or "docker").strip().lower()
        self.max_output_bytes = max(1024, max_output_bytes)
        if llm_attempts is None:
            try:
                llm_attempts = int(os.getenv("SAGE_ARMOR_LLM_EXPLOIT_ATTEMPTS", "3"))
            except ValueError:
                llm_attempts = 3
        self.llm_attempts = max(0, min(5, llm_attempts))
        self.last_hook_records: List[Dict[str, Any]] = []

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

    @staticmethod
    def _node_source(source_code: str, node: ast.AST, include_decorators: bool = False) -> Optional[str]:
        segment = ast.get_source_segment(source_code, node)
        if not include_decorators or not getattr(node, "decorator_list", None):
            return segment
        lines = source_code.splitlines()
        first = min(d.lineno for d in node.decorator_list)
        return "\n".join(lines[first - 1:node.end_lineno])

    def build_context_bundle(self, source_code: str, function_name: str) -> str:
        """
        Keep what the target needs to run, in source order: imports, module-level constants,
        other module-level assignments and classes (each wrapped in try/except so a failing
        one cannot stop the harness), the target, and the local helpers it calls.
        Bare statements with side effects (e.g. ``open(...).write(...)``, ``app.run()``) and
        function decorators are dropped.
        """
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

        required = {function_name}
        pending = [function_name]
        while pending:
            current = pending.pop()
            for node in ast.walk(functions[current]):
                ref = None
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                    ref = node.func.id
                elif isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
                    ref = node.id  # helpers passed as callbacks
                if ref in functions and ref not in required:
                    required.add(ref)
                    pending.append(ref)

        pieces: List[Tuple[int, str]] = []
        for node in tree.body:
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                seg = ast.get_source_segment(source_code, node)
            elif isinstance(node, ast.Assign) and isinstance(node.value, ast.Constant):
                seg = ast.get_source_segment(source_code, node)
            elif isinstance(node, (ast.Assign, ast.AnnAssign, ast.ClassDef)):
                if isinstance(node, ast.AnnAssign) and node.value is None:
                    continue
                inner = self._node_source(source_code, node, include_decorators=isinstance(node, ast.ClassDef))
                if not inner:
                    continue
                seg = "try:\n" + "\n".join("    " + line for line in inner.splitlines()) + "\nexcept Exception:\n    pass"
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name in required:
                seg = ast.get_source_segment(source_code, node)
            else:
                continue
            if seg:
                pieces.append((node.lineno, seg))

        # Required functions nested in classes (methods) are emitted as plain functions.
        top_level = {id(n) for n in tree.body}
        for name in required:
            node = functions[name]
            if id(node) not in top_level:
                seg = ast.get_source_segment(source_code, node)
                if seg:
                    pieces.append((node.lineno, seg))

        pieces.sort(key=lambda item: item[0])
        return "\n\n".join(seg for _, seg in pieces)

    def _infer_vuln_category(self, issue_str: str) -> str:
        return infer_category(issue_str)

    def _generate_test_invocation(self, func_name: str, vuln_category: str, attempt: int = 0, canary: str = "SAGE_0000") -> str:
        """Harness call line for the given fixed attack string (kept for older callers)."""
        vectors = fixed_vectors(vuln_category, canary) or [canary]
        return build_invocation(func_name, vectors[attempt % len(vectors)], canary)

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


    # ------------------------------------------------------------------ attempts
    @staticmethod
    def _assemble(bundle: str, invocation: str) -> Tuple[str, int]:
        """Fill the template in one pass (so payload text can never be re-substituted).
        Returns the harness and the harness line number of the bundle's first line."""
        pre, rest = HARNESS_TEMPLATE.split("{TARGET_CODE}", 1)
        mid, post = rest.split("{TEST_INVOCATION}", 1)
        return pre + bundle + mid + invocation + post, pre.count("\n") + 1

    @staticmethod
    def _target_span(bundle: str, function_name: str) -> Tuple[Optional[int], Optional[int]]:
        """1-based (def line, end line) of the target inside the bundle."""
        try:
            tree = ast.parse(bundle)
        except SyntaxError:
            return None, None
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == function_name:
                return node.lineno, getattr(node, "end_lineno", node.lineno)
        return None, None

    def _run_attempt(
        self,
        n: int,
        source: str,
        bundle: str,
        function_name: str,
        category: str,
        canary: str,
        payload: str,
        kwargs: Dict[str, Any],
        sink_line: int,
    ) -> Dict[str, Any]:
        harness, bundle_offset = self._assemble(bundle, build_invocation(function_name, payload, canary, kwargs))
        executed, _success, error = self._execute_harness(harness)
        records = list(self.last_hook_records or [])

        def_line, end_line = self._target_span(bundle, function_name)
        bundle_lines = bundle.splitlines()
        func_lines: List[int] = []
        sink_line_reached = False
        stopped_at = None
        if def_line is not None:
            h_def = bundle_offset + def_line - 1
            h_end = bundle_offset + (end_line or def_line) - 1
            func_lines = sorted({ln - h_def + 1 for ln in executed if h_def <= ln <= h_end})
            sink_line_reached = sink_line in func_lines
            if func_lines:
                last_rel = func_lines[-1]
                text_idx = def_line - 1 + last_rel - 1
                code = bundle_lines[text_idx].strip() if 0 <= text_idx < len(bundle_lines) else ""
                stopped_at = {"line": last_rel, "code": _clip(code, 160)}

        candidates = candidate_strings(payload, kwargs, canary)
        match_idx = match_sink_evidence(category, records, candidates, canary)
        upto = records if match_idx is None else records[:match_idx]
        stubbed = any(
            isinstance(r, dict) and r.get("during_call") and r.get("kind") in ("stub_access", "stub_call")
            for r in upto
        )
        if match_idx is not None:
            status = STATUS_INCONCLUSIVE if stubbed else STATUS_VERIFIED
        else:
            status = "failed"

        sinks_seen = [
            {"kind": r.get("kind"), "argument": _clip(sink_argument(r), 200)}
            for r in records
            if isinstance(r, dict) and r.get("during_call") and r.get("kind") in SINK_KINDS
        ][:6]
        matched = records[match_idx] if match_idx is not None else None
        return {
            "n": n,
            "source": source,
            "payload": payload,
            "kwargs": kwargs,
            "status": status,
            "stubbed": stubbed,
            "error": _clip(error, 300) if error else None,
            "executed_function_lines": func_lines,
            "stopped_at": stopped_at,
            "sink_line_reached": sink_line_reached,
            "sinks_seen": sinks_seen,
            "matched": matched,
            "executed_lines": executed,
            "records": records,
            "harness": harness,
        }

    def _llm_prompt(
        self,
        category: str,
        bundle: str,
        function_name: str,
        issue_title: str,
        sink_line: int,
        attempts: List[Dict[str, Any]],
        scenario: Optional[str],
    ) -> str:
        spec = CATEGORY_SPECS[category]
        history = []
        for att in attempts[-4:]:
            line = f"{att['n']}. ({att['source']}) payload={json.dumps(att['payload'])[:300]}"
            if att.get("kwargs"):
                line += f" kwargs={json.dumps(att['kwargs'], default=str)[:300]}"
            if att.get("stopped_at"):
                line += f" -> last line run in the function: {att['stopped_at']['line']} `{att['stopped_at']['code']}`"
            else:
                line += " -> the function body never ran"
            if att.get("error"):
                line += f"; raised {att['error']}"
            if att.get("sinks_seen"):
                line += "; sinks received: " + "; ".join(f"{s['kind']}: {s['argument']}" for s in att["sinks_seen"][:3])
            else:
                line += "; no sink received anything"
            history.append(line)
        code = bundle if len(bundle) <= 6000 else bundle[:6000] + "\n# ... (truncated)"
        parts = [
            "You are checking whether a reported vulnerability is really exploitable. Propose ONE attack input.",
            f"Finding: {issue_title} (class: {category}), reported at line {sink_line} of `{function_name}` (line 1 is the def line).",
            "Code under test:\n```python\n" + code + "\n```",
            "How the test harness runs it:",
            f"- `{function_name}` is called once. Each parameter with no default, or a None/str default, receives your `payload`; a parameter named request/req receives a fake web request.",
            "- Every web request field returns your payload: request.args/form/values/cookies/headers/json/get_json() (Flask), request.GET/POST (Django), and FastAPI Query()/Body() parameters.",
            "- Use `kwargs` to give a specific parameter or request field its own value (key = parameter or field name). Values must be JSON strings, numbers, booleans, lists or objects.",
            f"- Databases, files, shells, HTTP and deserializers are fakes that record their input. Fake sink for this class: {spec['sink']}.",
            f"- Success: {spec['goal']}. Put the literal text {CANARY_PLACEHOLDER} inside your attack string; it is replaced by a unique marker that must reach the sink.",
            "Previous attempts (all failed):\n" + "\n".join(history),
        ]
        if scenario:
            parts.append("Reported attack scenario: " + _clip(scenario, 400))
        parts.append(
            "Use the feedback: if execution stopped at a check, craft input that passes it; if the sink got an "
            "escaped or parameterized value, target a different parameter or request field."
        )
        parts.append('Reply with JSON only: {"payload": "...", "kwargs": {}, "reasoning": "one short sentence"}')
        return "\n".join(parts)

    def _llm_proposal(
        self,
        invoker: Callable[[str], Any],
        category: str,
        bundle: str,
        function_name: str,
        issue_title: str,
        sink_line: int,
        canary: str,
        attempts: List[Dict[str, Any]],
        scenario: Optional[str],
    ) -> Optional[Tuple[str, Dict[str, Any], str]]:
        prompt = self._llm_prompt(category, bundle, function_name, issue_title, sink_line, attempts, scenario)
        try:
            raw = invoker(prompt)
        except Exception as exc:
            _safe_log(f"[sandbox] LLM exploit generation failed: {exc}")
            return None
        data = _parse_model_json(raw)
        payload = _sanitize_model_value(data.get("payload", ""), canary)
        if not isinstance(payload, str):
            payload = json.dumps(payload, default=str) if payload is not None else ""
        kwargs = data.get("kwargs") if isinstance(data.get("kwargs"), dict) else {}
        kwargs = {
            k: v for k, v in _sanitize_model_value(kwargs, canary).items()
            if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,63}", k)
        }
        if not payload and not kwargs:
            return None
        if not candidate_strings(payload, kwargs, canary):
            payload = payload + canary
        reasoning = _clip(str(data.get("reasoning", "")), 200)
        return payload, kwargs, reasoning

    # ------------------------------------------------------------------ verify
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
        Try to exploit the finding: fixed canary-tagged attack strings first, then up to
        ``llm_attempts`` model-written inputs, each informed by the previous trace.
        Verified only when the canary reaches a sink argument with its attack syntax intact.
        """
        start_time = time.time()
        category = infer_category(issue_title)

        def _early(status: str, reason: str) -> SandboxExecutionResult:
            duration = round((time.time() - start_time) * 1000, 2)
            return SandboxExecutionResult(
                status=status, verified=False, reached_sink=False, sink_line=sink_line,
                executed_lines=[], attempts_used=0, test_script="", error=reason, duration_ms=duration,
                audit_record={"verdict": status, "failure_reason": reason, "duration_ms": duration,
                              "sandbox_image_digest": sandbox_image_digest() if status != STATUS_NOT_RUN else ""},
                evidence={"category": category, "reason": reason, "attempts": []},
            )

        if category not in SUPPORTED_CATEGORIES:
            return _early(STATUS_NOT_APPLICABLE, "No runtime exploit check exists for this finding type (for example secrets, weak crypto or configuration).")
        if not self.isolation_available():
            return _early(STATUS_NOT_RUN, "Sandbox not run: the Docker isolation runtime is unavailable.")

        bundle = self.build_context_bundle(function_code, function_name)
        canary = "SAGE_" + secrets.token_hex(4)
        attempts: List[Dict[str, Any]] = []
        proof: Optional[Dict[str, Any]] = None
        tried = set()

        def _try(source: str, payload: str, kwargs: Dict[str, Any]) -> Optional[Dict[str, Any]]:
            key = (payload, json.dumps(kwargs, sort_keys=True, default=str))
            if key in tried:
                return None
            tried.add(key)
            att = self._run_attempt(len(attempts) + 1, source, bundle, function_name, category, canary, payload, kwargs, sink_line)
            attempts.append(att)
            return att if att["status"] in (STATUS_VERIFIED, STATUS_INCONCLUSIVE) else None

        for vector in fixed_vectors(category, canary)[: max(1, self.max_retries)]:
            proof = _try("fixed", vector, {})
            if proof:
                break

        llm_used = False
        if proof is None and model_invoker is not None and self.llm_attempts > 0:
            for _ in range(self.llm_attempts):
                proposal = self._llm_proposal(
                    model_invoker, category, bundle, function_name, issue_title,
                    sink_line, canary, attempts, ai_poc_scenario,
                )
                if proposal is None:
                    break
                llm_used = True
                payload, kwargs, reasoning = proposal
                proof = _try("llm", payload, kwargs)
                if attempts and attempts[-1]["source"] == "llm":
                    attempts[-1]["reasoning"] = reasoning
                if proof:
                    break

        final = proof or (attempts[-1] if attempts else None)
        if proof is not None:
            status = proof["status"]
        elif any(a.get("stubbed") for a in attempts):
            status = STATUS_INCONCLUSIVE  # unknown (stubbed) code ran on the way: it may have hidden the path
        else:
            status = STATUS_UNCONFIRMED
        verified = status == STATUS_VERIFIED
        reached = proof is not None
        duration_ms = round((time.time() - start_time) * 1000, 2)

        last_error = None
        if not reached and final is not None:
            last_error = final.get("error") or (
                "No attack input carried the canary into a sink argument"
                + (f" (last line run: {final['stopped_at']['line']})" if final.get("stopped_at") else "")
            )

        matched = (final or {}).get("matched")
        digest = sandbox_image_digest()
        harness_hash = hashlib.sha256(((final or {}).get("harness") or "").encode("utf-8", errors="replace")).hexdigest()
        evidence = {
            "category": category,
            "canary": canary,
            "payload": _clip((final or {}).get("payload", "")),
            "kwargs": {k: (_clip(v, 200) if isinstance(v, str) else v) for k, v in ((final or {}).get("kwargs") or {}).items()},
            "payload_source": (final or {}).get("source"),
            "sink": {"kind": matched.get("kind"), "argument": _clip(sink_argument(matched))} if matched else None,
            "sink_line": sink_line,
            "sink_line_reached": bool((final or {}).get("sink_line_reached")),
            "executed_lines": (final or {}).get("executed_function_lines", []),
            "llm_used": llm_used,
            "attempts": [
                {
                    "n": a["n"],
                    "source": a["source"],
                    "payload": _clip(a["payload"], 200),
                    **({"kwargs": {k: (_clip(v, 120) if isinstance(v, str) else v) for k, v in a["kwargs"].items()}} if a.get("kwargs") else {}),
                    "status": "proved" if a["status"] in (STATUS_VERIFIED, STATUS_INCONCLUSIVE) else "failed",
                    "stopped_at": a.get("stopped_at"),
                    "error": a.get("error"),
                    **({"reasoning": a["reasoning"]} if a.get("reasoning") else {}),
                }
                for a in attempts
            ],
            "sandbox": {"runtime": self.runtime, "image": SANDBOX_IMAGE, "image_digest": digest, "harness_hash": harness_hash},
        }
        if status == STATUS_INCONCLUSIVE:
            evidence["reason"] = "Code from an unresolved import (stubbed in the sandbox) ran during the attack, so the result cannot be trusted either way."

        cleaned_records = [
            {k: (_clip(v, 300) if isinstance(v, str) else v) for k, v in r.items()}
            for r in ((final or {}).get("records") or [])
            if isinstance(r, dict) and r.get("during_call")
        ][:25]
        payload_text = (final or {}).get("payload", "")
        audit_record = {
            "input_hash": hashlib.sha256(payload_text.encode("utf-8", errors="replace")).hexdigest() if payload_text else "",
            "context_hash": hashlib.sha256(bundle.encode("utf-8", errors="replace")).hexdigest(),
            "sandbox_image_digest": digest,
            "harness_hash": harness_hash,
            "canary": canary,
            "hook_records": cleaned_records,
            "verdict": status,
            "duration_ms": duration_ms,
            "failure_reason": redact_secrets(last_error) if last_error else None,
        }

        return SandboxExecutionResult(
            status=status,
            verified=verified,
            reached_sink=reached,
            sink_line=sink_line,
            executed_lines=sorted(set((final or {}).get("executed_lines") or [])),
            attempts_used=len(attempts),
            test_script=(final or {}).get("harness", ""),
            error=last_error,
            duration_ms=duration_ms,
            audit_record=audit_record,
            evidence=evidence,
        )

    def verify(
        self,
        source_code: str,
        function_name: str,
        cwe_id: str = "",
        sink_line: int = 1,
        model_invoker: Optional[Callable[[str], Any]] = None,
    ) -> Dict[str, Any]:
        """Unified interface used by patch validation; same verdicts as verify_vulnerability."""
        exec_res = self.verify_vulnerability(
            function_code=source_code,
            function_name=function_name,
            sink_line=sink_line,
            issue_title=cwe_id or "Security Vulnerability",
            model_invoker=model_invoker,
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
            "evidence": exec_res.evidence,
        }


_GATE_NOTES = {
    STATUS_UNCONFIRMED: "The sandbox attacked this function and no input reached the dangerous call. Retained for review as unconfirmed.",
    STATUS_INCONCLUSIVE: "The sandbox could not decide: code from an unresolved import ran during the attack.",
    STATUS_NOT_RUN: "Sandbox not run: Docker is unavailable, so this finding has not been tested.",
    STATUS_NOT_APPLICABLE: "Static finding retained; no runtime exploit check exists for this finding type.",
}


def apply_verification_gate(
    vulnerabilities: List[Dict[str, Any]],
    function_code: str,
    function_name: str,
    verifier: Optional[SandboxVerifier] = None,
    language: str = "python",
    function_start_line: int = 1,
    context_source: Optional[str] = None,
    model_invoker: Optional[Callable[[str], Any]] = None,
    use_llm: bool = True,
) -> List[Dict[str, Any]]:
    """
    Applies the sandbox exploit gate to the findings of one function and ranks the result
    (verified first). Unconfirmed findings are demoted, never removed.

    ``context_source`` is the whole file: the sandbox keeps its imports, constants and the
    local helpers the target calls (e.g. ``get_db``), so the function can actually run.
    ``model_invoker`` writes exploit inputs when the fixed ones fail; by default it is built
    from the configured LLM provider (disable with SAGE_ARMOR_LLM_EXPLOITS=0 or use_llm=False).
    """
    if not vulnerabilities:
        return []

    active_verifier = verifier or SandboxVerifier()
    invoker = model_invoker if model_invoker is not None else (default_exploit_invoker() if use_llm else None)
    enriched = []

    for v in vulnerabilities:
        v_copy = dict(v)
        if (language or "python").lower() not in {"python", "py"}:
            v_copy["verification_status"] = STATUS_NOT_APPLICABLE
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
        result = active_verifier.verify_vulnerability(
            function_code=context_source or function_code,
            function_name=function_name,
            sink_line=sink_line,
            issue_title=" ".join(str(v_copy.get(k) or "") for k in ("issue", "cwe", "cwe_id")),
            ai_poc_scenario=v_copy.get("poc_exploit_scenario", ""),
            model_invoker=invoker,
        )

        v_copy["verification_status"] = result.status
        v_copy["verified"] = result.verified
        v_copy["audit_record"] = result.audit_record
        v_copy["evidence"] = result.evidence
        v_copy["dynamic_trace"] = {
            "reached_sink": result.reached_sink,
            "sink_reached": result.reached_sink,
            "sink_line": result.sink_line,
            "sink_line_reached": bool(result.evidence.get("sink_line_reached")),
            "executed_lines": result.evidence.get("executed_lines", []),
            "attempts_used": result.attempts_used,
            "duration_ms": result.duration_ms,
            "error": result.error,
        }

        severity = v_copy.get("severity")
        if result.verified:
            v_copy["effective_severity"] = f"{severity} (Verified)"
            v_copy.pop("unconfirmed_note", None)
        elif result.status == STATUS_UNCONFIRMED:
            v_copy["effective_severity"] = "Medium (Unconfirmed)" if severity in ("High", "Critical") else f"{severity} (Unconfirmed)"
            v_copy["unconfirmed_note"] = _GATE_NOTES[STATUS_UNCONFIRMED]
        elif result.status == STATUS_INCONCLUSIVE:
            v_copy["effective_severity"] = f"{severity} (Inconclusive)"
            v_copy["unconfirmed_note"] = _GATE_NOTES[STATUS_INCONCLUSIVE]
        elif result.status == STATUS_NOT_RUN:
            v_copy["effective_severity"] = f"{severity} (Sandbox not run)"
            v_copy["unconfirmed_note"] = _GATE_NOTES[STATUS_NOT_RUN]
        else:
            v_copy["effective_severity"] = f"{severity}"
            v_copy["unconfirmed_note"] = _GATE_NOTES[STATUS_NOT_APPLICABLE]

        enriched.append(v_copy)

    return rank_findings(enriched)


def _python_functions(source: str) -> List[Dict[str, Any]]:
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return []
    found = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            found.append({
                "name": node.name,
                "start_line": node.lineno,
                "end_line": getattr(node, "end_lineno", node.lineno),
                "code": ast.get_source_segment(source, node) or "",
            })
    return found


def verify_finding_in_source(
    finding: Dict[str, Any],
    source: str,
    verifier: Optional[SandboxVerifier] = None,
    model_invoker: Optional[Callable[[str], Any]] = None,
    use_llm: bool = True,
) -> Dict[str, Any]:
    """
    Run the gate on one finding from a whole Python file (repo scans, PR webhooks): locate
    the function that contains the finding's line (or its matched code), then verify it.
    """
    functions = _python_functions(source)
    try:
        line = int(finding.get("line") or finding.get("line_number") or 0)
    except (TypeError, ValueError):
        line = 0
    containing = [f for f in functions if f["start_line"] <= line <= f["end_line"]]
    target = min(containing, key=lambda f: f["end_line"] - f["start_line"]) if containing else None
    if target is None:
        snippet = str(finding.get("matched_code") or "").strip()
        if snippet and snippet != "Not provided":
            first = snippet.splitlines()[0].strip()
            target = next((f for f in functions if first and first in f["code"]), None)
            if target is not None:
                offset = next((i for i, l in enumerate(target["code"].splitlines()) if first in l), 0)
                finding = dict(finding, line=target["start_line"] + offset)
    if target is None:
        enriched = dict(finding)
        enriched.update({
            "verification_status": STATUS_NOT_APPLICABLE,
            "verified": False,
            "unconfirmed_note": "The finding is not inside a function the sandbox can call.",
            "evidence": {"reason": "No enclosing function found for the reported line.", "attempts": []},
        })
        return enriched
    return apply_verification_gate(
        [finding],
        function_code=target["code"],
        function_name=target["name"],
        verifier=verifier,
        language="python",
        function_start_line=target["start_line"],
        context_source=source,
        model_invoker=model_invoker,
        use_llm=use_llm,
    )[0]
