"""
verified_fixer.py — Codebase-aware, verified fix loop (Feature 2)

A generated patch is called "verified" only when every gate passes on the patched file:

  Gate A  Parse & compile: the patched file is valid Python.
  Gate E  Diff constraints: same signature, no placeholders/prose, small diff, inside the repo.
  Gate B  Exploit blocked: the exact inputs that proved the finding (stored as evidence by the
          exploit gate), the other recorded attempts, fresh fixed attacks and new AI-written
          attacks are all run against the patched code; every one must fail to reach the sink.
  Gate C  Behaviour & tests: normal inputs are run through the original and the patched
          function in the sandbox and their fake-sink logs and return values compared; for
          repositories the project's own tests are also run (in the hardened container, on the
          clone itself) before and after the patch, and no test that passed may fail.
  Gate D  Security rescan: SAST on the patched file finds neither the original issue in the
          patched function nor any new high/critical issue.

Codebase awareness: the prompt carries the sandbox proof, the project's own sanitizer helpers
(preferred over new code) and existing safe patterns; the patched function is spliced back into
the real file (new imports added at the top) and formatted with the project's black/ruff
configuration before the gates run. Failed gates are fed back to the model for up to
MAX_RETRIES attempts.
"""

from __future__ import annotations

import ast
import difflib
import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import textwrap
from typing import Any, Callable, Dict, List, Optional, Tuple


MAX_RETRIES = 3
PYTEST_TIMEOUT = 90  # seconds per project test run

GATE_LABELS = {
    "formatter": "Project formatter",
    "gate_a_parse_compile": "Parses and compiles",
    "gate_e_diff_constraints": "Small, in-bounds diff",
    "exploit_blocked": "Exploit blocked",
    "tests_pass": "Behaviour and tests preserved",
    "no_new_sast_findings": "Security rescan clean",
}
REQUIRED_GATES = ("gate_a_parse_compile", "gate_e_diff_constraints", "exploit_blocked", "tests_pass", "no_new_sast_findings")


def _gate_status(passed: bool, error: bool = False, skipped: bool = False) -> str:
    if skipped:
        return "skipped"
    if error:
        return "error"
    return "pass" if passed else "fail"


def _clip(text: Any, limit: int = 300) -> str:
    s = text if isinstance(text, str) else json.dumps(text, default=str)
    return s if len(s) <= limit else s[:limit] + "…"


# ---------------------------------------------------------------------------
# Optional imports, module-level so tests can patch them
# ---------------------------------------------------------------------------
try:
    from .sandbox_verifier import SandboxVerifier
except ImportError:  # pragma: no cover
    SandboxVerifier = None  # type: ignore

try:
    from .sast_scanner import SASTScanner
except ImportError:  # pragma: no cover
    SASTScanner = None  # type: ignore

try:
    from .sandbox_harness import infer_category
except ImportError:  # pragma: no cover
    from sandbox_harness import infer_category  # type: ignore


def _issue_title(finding: Dict[str, Any]) -> str:
    return " ".join(str(finding.get(k) or "") for k in ("cwe_id", "cwe", "issue", "title")).strip()


# ---------------------------------------------------------------------------
# Codebase awareness: safe patterns and project helpers
# ---------------------------------------------------------------------------

SANITIZER_PATTERNS: Dict[str, List[str]] = {
    "sqli": [
        r"cursor\.execute\([^,]+,\s*[\(\[]",
        r"\.execute\([^,]+,\s*[\(\[\{]",
        r"\.query\([^,]+,\s*[\[\(]",
        r"sqlalchemy.*bindparams",
        r"text\([^)]*:\w+",
    ],
    "path_traversal": [
        r"os\.path\.normpath",
        r"os\.path\.realpath",
        r"os\.path\.commonpath",
        r"pathlib\.Path.*resolve",
        r"\.resolve\(\)\.is_relative_to",
        r"secure_filename",
        r"safe_join",
    ],
    "cmd_injection": [
        r"shlex\.quote",
        r"shlex\.split",
        r"subprocess\.run\(\s*\[",
        r"subprocess\.\w+\([^)]*shell\s*=\s*False",
    ],
    "code_injection": [
        r"ast\.literal_eval",
        r"safe_eval",
    ],
    "deserialization": [
        r"json\.loads",
        r"yaml\.safe_load",
        r"msgpack\.unpackb",
    ],
    "ssrf": [
        r"urlparse\(.*\)\.(hostname|netloc)",
        r"ALLOWED_HOSTS",
        r"allowed_hosts",
        r"ipaddress\.ip_address",
    ],
    "redirect": [
        r"url_has_allowed_host_and_scheme",
        r"is_safe_url",
        r"url_for\(",
        r"urlparse\(.*\)\.netloc",
    ],
    "xss": [
        r"html\.escape",
        r"markupsafe\.escape",
        r"escape\(",
        r"render_template\(",
    ],
    "template": [
        r"render_template\(",
        r"render_template_string\(\s*['\"][^'\"]*\{\{",
        r"SandboxedEnvironment",
    ],
}

_CATEGORY_TO_PATTERN_KEY = {
    "sql_injection": "sqli",
    "command_injection": "cmd_injection",
    "path_traversal": "path_traversal",
    "code_evaluation": "code_injection",
    "deserialization": "deserialization",
    "ssrf": "ssrf",
    "open_redirect": "redirect",
    "xss": "xss",
    "template_injection": "template",
}

_SKIP_DIRS = {".git", "__pycache__", "node_modules", ".venv", "venv", "env", ".tox", "build", "dist", "site-packages", ".mypy_cache", ".pytest_cache"}


def _pattern_key(cwe_or_title: str) -> str:
    category = infer_category(cwe_or_title)
    if category in _CATEGORY_TO_PATTERN_KEY:
        return _CATEGORY_TO_PATTERN_KEY[category]
    s = (cwe_or_title or "").lower()
    if "78" in s:
        return "cmd_injection"
    if "22" in s:
        return "path_traversal"
    if "94" in s:
        return "code_injection"
    if "502" in s:
        return "deserialization"
    return "sqli"


def _iter_py_files(root: str, limit: int = 400):
    count = 0
    for dirpath, dirs, files in os.walk(root):
        dirs[:] = sorted(d for d in dirs if d not in _SKIP_DIRS and not d.startswith("."))
        for fname in sorted(files):
            if not fname.endswith(".py"):
                continue
            full = os.path.join(dirpath, fname)
            if os.path.islink(full):
                continue
            try:
                if os.path.getsize(full) > 400_000:
                    continue
            except OSError:
                continue
            yield full
            count += 1
            if count >= limit:
                return


def _read(path: str) -> str:
    try:
        with open(path, encoding="utf-8", errors="ignore") as fh:
            return fh.read()
    except OSError:
        return ""


def _examples_in_text(content: str, patterns: List[str], examples: List[str], limit: int) -> None:
    for pat in patterns:
        for m in re.finditer(pat, content):
            line_start = content.rfind("\n", 0, m.start()) + 1
            line_end = content.find("\n", m.end())
            snippet = content[line_start: line_end if line_end != -1 else len(content)].strip()
            if snippet and snippet not in examples and len(snippet) < 200:
                examples.append(snippet)
                if len(examples) >= limit:
                    return


def find_project_sanitizer_examples(
    project_root: str, cwe_id: str, extra_source: Optional[str] = None, limit: int = 3
) -> List[str]:
    """Lines in the project (or in ``extra_source``) that already use a safe pattern for this
    class of bug. Returned to the model as style examples."""
    patterns = SANITIZER_PATTERNS.get(_pattern_key(cwe_id), [])
    if not patterns:
        return []
    examples: List[str] = []
    if extra_source:
        _examples_in_text(extra_source, patterns, examples, limit)
    if project_root and os.path.isdir(project_root):
        for full in _iter_py_files(project_root):
            if len(examples) >= limit:
                break
            _examples_in_text(_read(full), patterns, examples, limit)
    return examples[:limit]


_HELPER_NAME_RE = re.compile(r"(saniti|escape|clean|valid|safe|quote|allow|whitelist|normali|secure|verify|check|is_)", re.I)
_CATEGORY_HINTS = {
    "sql_injection": r"(sql|query|param|db|ident)",
    "command_injection": r"(cmd|command|shell|host|arg)",
    "path_traversal": r"(path|file|dir|name|join)",
    "ssrf": r"(url|host|domain|ip)",
    "open_redirect": r"(url|redirect|next|host)",
    "xss": r"(html|escape|markup)",
    "template_injection": r"(template|render)",
    "code_evaluation": r"(expr|eval|literal|number|parse|math)",
    "deserialization": r"(load|json|deserial|parse)",
}


def _helpers_in_source(source: str, rel_path: str, category: str, exclude: str) -> List[Tuple[int, Dict[str, str]]]:
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError):
        return []
    hint = re.compile(_CATEGORY_HINTS.get(category, r"$^"), re.I)
    found = []
    for node in tree.body:
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) or node.name == exclude:
            continue
        if not _HELPER_NAME_RE.search(node.name):
            continue
        score = 1 + (2 if hint.search(node.name) else 0)
        try:
            sig = f"{node.name}({ast.unparse(node.args)})"
        except Exception:
            sig = f"{node.name}(...)"
        doc = (ast.get_docstring(node) or "").strip().splitlines()
        found.append((score, {"name": node.name, "signature": sig, "path": rel_path, "doc": doc[0][:120] if doc else ""}))
    return found


def find_project_helpers(
    project_root: Optional[str],
    category: str,
    extra_source: Optional[str] = None,
    exclude_function: str = "",
    limit: int = 5,
) -> List[Dict[str, str]]:
    """Sanitizer/validator functions the project already defines (by name), best match first.
    The fix prompt asks the model to call these instead of writing new checks."""
    scored: List[Tuple[int, Dict[str, str]]] = []
    if extra_source:
        scored.extend(_helpers_in_source(extra_source, "this file", category, exclude_function))
    if project_root and os.path.isdir(project_root):
        for full in _iter_py_files(project_root):
            rel = os.path.relpath(full, project_root).replace(os.sep, "/")
            base = os.path.basename(rel)
            if base.startswith("test_") or base.endswith("_test.py") or "/tests/" in f"/{rel}":
                continue
            scored.extend(_helpers_in_source(_read(full), rel, category, exclude_function))
    seen = set()
    out = []
    for _score, helper in sorted(scored, key=lambda x: -x[0]):
        key = (helper["name"], helper["path"])
        if key in seen:
            continue
        seen.add(key)
        out.append(helper)
        if len(out) >= limit:
            break
    return out


# ---------------------------------------------------------------------------
# Locating, splicing and formatting the patched function
# ---------------------------------------------------------------------------

def _node_span(node: ast.AST) -> Tuple[int, int]:
    start = min([d.lineno for d in getattr(node, "decorator_list", [])] + [node.lineno])
    return start, getattr(node, "end_lineno", node.lineno)


def locate_function(source: str, function_name: str = "", line_number: Optional[int] = None) -> Optional[Dict[str, Any]]:
    """The function to fix: the innermost function containing ``line_number`` (preferring
    ``function_name``), else the first function with that name."""
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError):
        return None
    nodes = [n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]
    chosen = None
    if line_number:
        containing = [n for n in nodes if _node_span(n)[0] <= line_number <= _node_span(n)[1]]
        if function_name:
            containing = [n for n in containing if n.name == function_name] or containing
        if containing:
            chosen = max(containing, key=lambda n: _node_span(n)[0])
    if chosen is None and function_name:
        named = [n for n in nodes if n.name == function_name]
        chosen = named[0] if named else None
    if chosen is None:
        return None
    start, end = _node_span(chosen)
    lines = source.splitlines()
    first = lines[start - 1] if start - 1 < len(lines) else ""
    args = chosen.args
    return {
        "name": chosen.name,
        "start": start,
        "end": end,
        "def_line": chosen.lineno,
        "indent": first[: len(first) - len(first.lstrip())],
        "code": "\n".join(lines[start - 1: end]),
        "params": [a.arg for a in list(args.posonlyargs) + list(args.args) + list(args.kwonlyargs)],
    }


def _strip_fences(text: str) -> str:
    m = re.search(r"```[a-zA-Z0-9_+-]*[ \t]*\r?\n(.*?)```", text, re.S)
    return m.group(1) if m else text


def _top_level_import_texts(tree: ast.Module) -> set:
    out = set()
    for node in tree.body:
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            try:
                out.add(ast.unparse(node))
            except Exception:
                pass
    return out


def _import_insert_line(original: str) -> int:
    """0-based line index after the module's last top-level import (or docstring/__future__)."""
    try:
        tree = ast.parse(original)
    except (SyntaxError, ValueError):
        return 0
    idx = 0
    for i, node in enumerate(tree.body):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            idx = node.end_lineno
        elif i == 0 and isinstance(node, ast.Expr) and isinstance(getattr(node, "value", None), ast.Constant) and isinstance(node.value.value, str):
            idx = node.end_lineno
        else:
            break
    return idx


def apply_model_output(original: str, loc: Optional[Dict[str, Any]], raw: Any) -> Dict[str, Any]:
    """Turn the model's reply into a full patched file. With a located function the reply's
    version of that function replaces the original lines, keeping indentation; new top-level
    imports go below the file's imports, and new module-level helpers above the function."""
    text = _strip_fences(str(raw or "")).strip("\n")
    nl = "\r\n" if "\r\n" in original else "\n"
    if loc is None:
        patched = text.replace("\r\n", "\n").replace("\n", nl)
        if original.endswith(("\n", "\r\n")) and not patched.endswith("\n"):
            patched += nl
        return {"patched": patched, "start": None, "end": None, "added_imports": [], "function_code": patched}

    dedented = textwrap.dedent(text.replace("\r\n", "\n"))
    fn_src = dedented
    new_imports: List[str] = []
    helpers: List[str] = []
    try:
        tree = ast.parse(dedented)
    except SyntaxError:
        tree = None  # splice as-is; Gate A reports the syntax error to the model
    if tree is not None:
        dl = dedented.splitlines()
        targets = [n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == loc["name"]]
        if not targets:
            return {"error": f"The reply did not contain the function `{loc['name']}`."}
        target = targets[0]
        s, e = _node_span(target)
        fn_src = textwrap.dedent("\n".join(dl[s - 1: e]))
        try:
            existing = _top_level_import_texts(ast.parse(original))
        except (SyntaxError, ValueError):
            existing = set()
        original_names = {
            n.name for n in ast.walk(ast.parse(original))
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
        } if existing is not None else set()
        for node in tree.body:
            if node is target:
                continue
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                imp = ast.unparse(node)
                if imp not in existing and imp not in new_imports:
                    new_imports.append(imp)
            elif loc["indent"] == "" and isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Assign)):
                name = getattr(node, "name", None)
                if name and name in original_names:
                    continue  # never redefine an existing function
                hs, he = _node_span(node) if hasattr(node, "decorator_list") else (node.lineno, node.end_lineno)
                helpers.append("\n".join(dl[hs - 1: he]))

    indent = loc["indent"]
    func_lines = [(indent + ln) if ln.strip() else "" for ln in fn_src.strip("\n").split("\n")]
    block = nl.join(func_lines)
    helper_lines = 0
    if helpers:
        helper_text = (nl + nl).join(helpers) + nl + nl + nl
        helper_lines = helper_text.count(nl)
        block = helper_text + block

    lines = original.splitlines(keepends=True)
    before = "".join(lines[: loc["start"] - 1])
    after = "".join(lines[loc["end"]:])
    tail = nl if (after or original.endswith(("\n", "\r\n"))) else ""
    patched = before + block + tail + after

    shift = 0
    if new_imports:
        insert_at = _import_insert_line(original)
        if insert_at >= loc["start"]:
            insert_at = 0
        plines = patched.splitlines(keepends=True)
        add = [imp + nl for imp in new_imports]
        if insert_at == 0 and plines and not plines[0].strip().startswith(("import", "from")):
            add.append(nl)
        patched = "".join(plines[:insert_at] + add + plines[insert_at:])
        shift = len(add)

    start = loc["start"] + shift + helper_lines
    end = start + len(func_lines) - 1
    return {
        "patched": patched,
        "start": start,
        "end": end,
        "added_imports": new_imports,
        "added_helpers": len(helpers),
        "function_code": "\n".join(func_lines),
    }


def detect_formatter(project_root: Optional[str]) -> Optional[str]:
    """'ruff' or 'black' when the project configures one, else None."""
    if not project_root or not os.path.isdir(project_root):
        return None
    for name in ("ruff.toml", ".ruff.toml"):
        if os.path.isfile(os.path.join(project_root, name)):
            return "ruff"
    text = _read(os.path.join(project_root, "pyproject.toml"))
    if re.search(r"^\[tool\.ruff(\.format)?\]", text, re.M):
        return "ruff"
    if re.search(r"^\[tool\.black\]", text, re.M):
        return "black"
    return None


def _formatter_command(tool: str) -> Optional[List[str]]:
    exe = shutil.which(tool)
    if exe:
        return [exe]
    if importlib.util.find_spec(tool) is not None:
        return [sys.executable, "-m", tool]
    return None


def _tool_env() -> Dict[str, str]:
    return {k: v for k, v in os.environ.items() if not re.search(r"KEY|TOKEN|SECRET|PASSWORD", k, re.I)}


def format_patched_region(
    code: str, start: int, end: int, project_root: Optional[str], rel_path: str = "patched.py"
) -> Tuple[str, Dict[str, Any]]:
    """Format only the patched lines with the project's black/ruff configuration."""
    tool = detect_formatter(project_root)
    step = {"gate": "formatter", "label": GATE_LABELS["formatter"], "tool": tool}
    if not tool:
        return code, {**step, "passed": False, "status": "skipped", "detail": "No black/ruff configuration in the project"}
    base = _formatter_command(tool)
    if not base:
        return code, {**step, "passed": False, "status": "skipped",
                      "detail": f"The project uses {tool}, but {tool} is not installed on the server; patch left unformatted"}
    if tool == "black":
        cmd = base + ["--quiet", f"--line-ranges={start}-{end}", "--stdin-filename", rel_path, "-"]
    else:
        cmd = base + ["format", f"--range={start}-{end}", "--stdin-filename", rel_path, "-"]
    try:
        proc = subprocess.run(cmd, input=code, cwd=project_root, capture_output=True, text=True, timeout=30, env=_tool_env())
    except Exception as exc:
        return code, {**step, "passed": False, "status": "error", "detail": f"{tool} failed to run: {exc}"}
    if proc.returncode != 0 or not proc.stdout.strip():
        return code, {**step, "passed": False, "status": "error", "detail": f"{tool} rejected the patch: {_clip(proc.stderr.strip(), 200)}"}
    changed = proc.stdout != code
    return proc.stdout, {**step, "passed": True, "status": "pass",
                         "detail": f"Formatted the patched function with {tool} using the project's configuration" + ("" if changed else " (already formatted)")}


# ---------------------------------------------------------------------------
# Gate A: Parse & Compile
# ---------------------------------------------------------------------------

def gate_a_parse_compile(patched_code: str) -> Tuple[bool, str, str]:
    """(passed, 'pass'|'fail'|'error', detail)."""
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
# Gate B: the recorded exploit and fresh attacks must all fail
# ---------------------------------------------------------------------------

def replay_inputs(finding: Dict[str, Any]) -> Tuple[List[Dict[str, Any]], Optional[str]]:
    """Inputs recorded by the exploit gate for this finding: the proving input first, then the
    other attempts. Returned with the canary they were recorded with."""
    ev = finding.get("evidence") if isinstance(finding.get("evidence"), dict) else {}
    out: List[Dict[str, Any]] = []
    seen = set()

    def add(payload: Any, kwargs: Any) -> None:
        if not isinstance(payload, str) or not payload:
            return
        kw = kwargs if isinstance(kwargs, dict) else {}
        key = (payload, json.dumps(kw, sort_keys=True, default=str))
        if key not in seen:
            seen.add(key)
            out.append({"payload": payload, "kwargs": kw})

    if ev.get("sink"):
        add(ev.get("payload"), ev.get("kwargs"))
    attempts = [a for a in (ev.get("attempts") or []) if isinstance(a, dict)]
    for a in sorted(attempts, key=lambda a: 0 if a.get("status") == "proved" else 1):
        add(a.get("payload"), a.get("kwargs"))
    return out, ev.get("canary")


def run_gate_b(
    patched_code: str,
    finding: Dict[str, Any],
    verifier: Optional[Any] = None,
    model_invoker: Optional[Callable[[str], Any]] = None,
    sink_line: int = 1,
) -> Dict[str, Any]:
    entry = {"gate": "exploit_blocked", "label": GATE_LABELS["exploit_blocked"]}
    if SandboxVerifier is None and verifier is None:
        return {**entry, "passed": False, "status": "error", "detail": "Gate B ERROR: sandbox_verifier not available"}
    v = verifier or SandboxVerifier(timeout_sec=15.0)
    if hasattr(v, "isolation_available") and not v.isolation_available():
        return {**entry, "passed": False, "status": "skipped", "detail": "Gate B SKIPPED: Sandbox isolation runtime is unavailable"}

    replay, canary = replay_inputs(finding)
    try:
        result = v.verify(
            source_code=patched_code,
            function_name=finding.get("function_name", ""),
            cwe_id=_issue_title(finding),
            sink_line=max(1, int(sink_line or 1)),
            model_invoker=model_invoker,
            replay=replay,
            canary=canary,
        )
    except Exception as exc:
        return {**entry, "passed": False, "status": "error", "detail": f"Gate B ERROR: Sandbox verifier error: {exc}"}
    if not isinstance(result, dict):
        return {**entry, "passed": False, "status": "error", "detail": "Gate B ERROR: verifier returned no result"}

    status = result.get("verification_status")
    evidence = result.get("evidence") if isinstance(result.get("evidence"), dict) else {}
    attempts = evidence.get("attempts") or []
    n_replay = sum(1 for a in attempts if a.get("source") == "replay")
    n_fixed = sum(1 for a in attempts if a.get("source") == "fixed")
    n_llm = sum(1 for a in attempts if a.get("source") == "llm")
    out = {**entry, "evidence": {k: evidence.get(k) for k in ("payload", "kwargs", "payload_source", "sink", "attempts") if k in evidence}}

    if status in {"not_applicable", "not_run"}:
        return {**out, "passed": False, "status": "skipped", "detail": f"Gate B SKIPPED: exploit re-test {status.replace('_', ' ')}"}
    if status == "inconclusive":
        return {**out, "passed": False, "status": "skipped",
                "detail": "Gate B SKIPPED: inconclusive — code from an unresolved import ran during the attack, so the sandbox cannot confirm the exploit is blocked"}
    sink_reached = bool((result.get("dynamic_trace") or {}).get("sink_reached", False))
    if status in {"unconfirmed", "refuted"} and not sink_reached:
        tried = []
        if n_replay:
            tried.append(f"{n_replay} recorded attack{'s' if n_replay != 1 else ''}" + (" (including the input that proved the finding)" if (finding.get("evidence") or {}).get("sink") else ""))
        if n_fixed:
            tried.append(f"{n_fixed} fixed attack{'s' if n_fixed != 1 else ''}")
        if n_llm:
            tried.append(f"{n_llm} new AI-written attack{'s' if n_llm != 1 else ''}")
        summary = ", ".join(tried) if tried else "the attack inputs"
        return {**out, "passed": True, "status": "pass",
                "detail": f"Gate B PASS: ran {summary}; none reached the dangerous call (re-test verdict: {status})"}
    sink = evidence.get("sink") or {}
    src = {"replay": "the recorded attack", "fixed": "a fixed attack", "llm": "an AI-written attack"}.get(evidence.get("payload_source"), "an attack")
    detail = f"Gate B FAIL: exploit status={status} sink_reached={sink_reached}"
    if sink:
        detail += f" — {src} `{_clip(evidence.get('payload', ''), 160)}` still reached the {sink.get('kind')} call as `{_clip(sink.get('argument', ''), 200)}`"
    return {**out, "passed": False, "status": "fail", "detail": detail}


def gate_b_differential_exploit(
    patched_code: str,
    finding: Dict[str, Any],
    verifier: Optional[Any] = None,
    model_invoker: Optional[Callable[[str], Any]] = None,
) -> Tuple[bool, str, str]:
    r = run_gate_b(patched_code, finding, verifier=verifier, model_invoker=model_invoker)
    return r["passed"], r["status"], r["detail"]


def _gate1_exploit_no_longer_reaches_sink(patched_code: str, finding: Dict[str, Any]) -> Tuple[bool, str]:
    passed, _, detail = gate_b_differential_exploit(patched_code, finding)
    return passed, detail


# ---------------------------------------------------------------------------
# Gate C (1/2): behaviour on normal inputs, original vs patched
# ---------------------------------------------------------------------------

_BENIGN_VALUES = {
    "sql_injection": ["alice_sageok1", "42"],
    "command_injection": ["example.com", "sageok1.local"],
    "path_traversal": ["report_sageok1.txt", "notes_sageok1.md"],
    "code_evaluation": ["[1, 2, 3]", "42"],
    "ssrf": ["https://example.com/sageok1", "https://example.org/api/sageok1"],
    "open_redirect": ["/dashboard", "/profile/sageok1"],
    "deserialization": ['{"name": "sageok1"}', "[1, 2]"],
    "template_injection": ["sageok1", "Alice"],
    "xss": ["sageok1", "Alice Smith"],
}
# Fixes for these classes legitimately reject some inputs (allowlists), so behaviour fails only
# when every normal input is rejected.
_LENIENT = {"ssrf", "open_redirect", "code_evaluation", "deserialization"}
# The fix replaces the sink by design (eval -> literal_eval, pickle -> json).
_NO_SINK_CHECK = {"code_evaluation", "deserialization"}
_NO_PRESENCE_CHECK = {"template_injection", "code_evaluation", "deserialization"}
_NO_RETURN_CHECK = {"template_injection", "code_evaluation", "deserialization"}
_NUMERIC_PARAM = re.compile(r"(^|_)(id|count|limit|page|port|size|num|n|age|qty|quantity|amount|year|offset)$", re.I)


def benign_cases(category: str, params: List[str], source: str = "") -> List[Tuple[str, Dict[str, Any]]]:
    """Normal inputs for behaviour tests: per-class defaults, numbers for numeric-looking
    parameters, and for URL classes a URL the code itself mentions."""
    values = list(_BENIGN_VALUES.get(category, ["sageok1", "42"]))
    if category in ("ssrf", "open_redirect"):
        urls = re.findall(r"https?://[A-Za-z0-9.-]+(?::\d+)?(?:/[^\s'\"<>]*)?", source or "")
        urls = [u for u in urls if "example" not in u][:1]
        values = urls + values
    kwargs = {p: "7" for p in params if _NUMERIC_PARAM.search(p)}
    return [(v, dict(kwargs)) for v in values[:2]]


def _json_or_none(text: Any) -> Tuple[bool, Any]:
    if not isinstance(text, str):
        return False, None
    try:
        return True, json.loads(text)
    except (ValueError, TypeError):
        return False, None


def _compare_case(category: str, payload: str, kwargs: Dict[str, Any], old: Dict[str, Any], new: Dict[str, Any]) -> List[str]:
    issues: List[str] = []
    if new.get("error"):
        return [f"raises {new['error']}"]
    values = [payload] + [v for v in kwargs.values() if isinstance(v, str)]
    if category not in _NO_SINK_CHECK:
        old_kinds = {s["kind"] for s in old.get("sinks", [])}
        new_kinds = {s["kind"] for s in new.get("sinks", [])}
        for kind in sorted(old_kinds - new_kinds):
            issues.append(f"no longer makes the {kind} call")
        if category not in _NO_PRESENCE_CHECK:
            for kind in sorted(old_kinds & new_kinds):
                for val in values:
                    in_old = any(val in s["argument"] or val in s.get("bound", "") for s in old["sinks"] if s["kind"] == kind)
                    in_new = any(val in s["argument"] or val in s.get("bound", "") for s in new["sinks"] if s["kind"] == kind)
                    if in_old and not in_new:
                        issues.append(f"the input no longer reaches the {kind} call")
                        break
    if category not in _NO_RETURN_CHECK and old.get("returned_set") and new.get("returned_set"):
        ok_old, val_old = _json_or_none(old.get("returned"))
        ok_new, val_new = _json_or_none(new.get("returned"))
        if ok_old and ok_new and type(val_old) is type(val_new) and val_old != val_new:
            issues.append(f"returns {_clip(json.dumps(val_new), 80)} instead of {_clip(json.dumps(val_old), 80)}")
    return issues


def run_behaviour_check(
    original_code: str,
    patched_code: str,
    function_name: str,
    category: str,
    verifier: Optional[Any] = None,
    cases: Optional[List[Tuple[str, Dict[str, Any]]]] = None,
) -> Dict[str, Any]:
    """Run normal inputs through the original and the patched function in the sandbox and
    compare what each fake sink received and what the function returned."""
    v = verifier
    if v is None:
        if SandboxVerifier is None:
            return {"status": "skipped", "detail": "sandbox unavailable", "cases": []}
        v = SandboxVerifier(timeout_sec=15.0)
    if hasattr(v, "isolation_available") and not v.isolation_available():
        return {"status": "skipped", "detail": "behaviour tests not run: Docker isolation runtime is unavailable", "cases": []}
    if cases is None:
        loc = locate_function(original_code, function_name)
        cases = benign_cases(category, (loc or {}).get("params", []), original_code)
    if not cases or not hasattr(v, "run_cases"):
        return {"status": "skipped", "detail": "no behaviour tests could be built", "cases": []}
    try:
        old = v.run_cases(original_code, function_name, cases)
        new = v.run_cases(patched_code, function_name, cases)
    except Exception as exc:
        return {"status": "skipped", "detail": f"behaviour tests failed to run: {exc}", "cases": []}
    if not isinstance(old, dict) or not isinstance(new, dict) or not old.get("ran") or not new.get("ran"):
        err = (old.get("error") if isinstance(old, dict) else None) or (new.get("error") if isinstance(new, dict) else None)
        return {"status": "skipped", "detail": f"behaviour tests did not run{': ' + _clip(err, 160) if err else ''}", "cases": []}

    report = []
    counted = failed = 0
    for i, (payload, kwargs) in enumerate(cases):
        o = old["cases"][i] if i < len(old.get("cases", [])) else {}
        n = new["cases"][i] if i < len(new.get("cases", [])) else {}
        case = {"input": payload, "kwargs": kwargs,
                "original": {"error": o.get("error"), "sinks": o.get("sinks", []), "returned": o.get("returned")},
                "patched": {"error": n.get("error"), "sinks": n.get("sinks", []), "returned": n.get("returned")}}
        if o.get("error"):
            case.update(verdict="not_compared", reason=f"the original code raised {o['error']}")
            report.append(case)
            continue
        counted += 1
        issues = _compare_case(category, payload, kwargs, o, n)
        if issues:
            failed += 1
            case.update(verdict="changed", reason="; ".join(issues))
        else:
            case.update(verdict="same", reason="same calls and return value")
        report.append(case)

    if counted == 0:
        return {"status": "skipped", "cases": report,
                "detail": "the original code raised on every normal input, so behaviour could not be compared"}
    lenient = category in _LENIENT
    if failed and (not lenient or failed == counted):
        first = next(c for c in report if c.get("verdict") == "changed")
        return {"status": "fail", "cases": report,
                "detail": f"on normal input `{_clip(first['input'], 60)}` the patched code {first['reason']}"}
    note = f"behaviour preserved on {counted - failed}/{counted} normal input{'s' if counted != 1 else ''}"
    if failed:
        note += f" ({failed} rejected by the new check, allowed for this class)"
    return {"status": "pass", "detail": note, "cases": report}


# ---------------------------------------------------------------------------
# Gate C (2/2): the project's own tests, before and after, in the hardened container
# ---------------------------------------------------------------------------

_TEST_RUNNER = r'''
import sys, os, json, importlib.util, inspect, unittest
ROOT = os.getcwd()
TEST_DIR = __TEST_DIR__
sys.path.insert(0, ROOT)
results = {}
mode = "builtin"
if importlib.util.find_spec("pytest") is not None:
    mode = "pytest"
    import pytest
    class _SageCollector:
        def pytest_runtest_logreport(self, report):
            if report.when == "call" or report.outcome != "passed":
                if results.get(report.nodeid) in (None, "passed"):
                    results[report.nodeid] = report.outcome
        def pytest_collectreport(self, report):
            if report.outcome != "passed":
                results[(report.nodeid or "collect") + "::<collect>"] = "error"
    pytest.main([TEST_DIR, "-q", "-p", "no:cacheprovider", "-W", "ignore"], plugins=[_SageCollector()])
else:
    files = []
    target = os.path.join(ROOT, TEST_DIR)
    if os.path.isfile(target):
        files = [target]
    else:
        for d, dirs, fs in os.walk(target):
            dirs[:] = sorted(x for x in dirs if not x.startswith(".") and x not in ("node_modules", "__pycache__", "venv"))
            for f in sorted(fs):
                if f.endswith(".py") and (f.startswith("test_") or f.endswith("_test.py")):
                    files.append(os.path.join(d, f))
    for path in files[:200]:
        rel = os.path.relpath(path, ROOT).replace(os.sep, "/")
        folder = os.path.dirname(path)
        if folder not in sys.path:
            sys.path.insert(0, folder)
        name = "sage_t_" + "".join(c if c.isalnum() else "_" for c in rel)
        try:
            spec = importlib.util.spec_from_file_location(name, path)
            mod = importlib.util.module_from_spec(spec)
            sys.modules[name] = mod
            spec.loader.exec_module(mod)
        except BaseException:
            results[rel + "::<import>"] = "error"
            continue
        for attr, obj in sorted(vars(mod).items()):
            if attr.startswith("test") and inspect.isfunction(obj) and obj.__module__ == name:
                if inspect.iscoroutinefunction(obj):
                    continue
                try:
                    required = [p for p in inspect.signature(obj).parameters.values() if p.default is p.empty]
                except (TypeError, ValueError):
                    required = []
                if required:
                    continue  # needs pytest fixtures
                try:
                    obj()
                    results[rel + "::" + attr] = "passed"
                except BaseException:
                    results[rel + "::" + attr] = "failed"
            elif inspect.isclass(obj) and issubclass(obj, unittest.TestCase) and obj.__module__ == name:
                for case in unittest.defaultTestLoader.loadTestsFromTestCase(obj):
                    res = unittest.TestResult()
                    case.run(res)
                    tid = rel + "::" + obj.__name__ + "::" + case._testMethodName
                    results[tid] = "skipped" if res.skipped else ("passed" if res.wasSuccessful() else "failed")
sys.stdout.write("\n===SAGE_TESTS===" + json.dumps({"mode": mode, "results": results}) + "===SAGE_TESTS===\n")
'''


def find_test_dir(project_root: Optional[str]) -> Optional[str]:
    """The project's test directory (absolute), if it has one."""
    if not project_root or not os.path.isdir(project_root):
        return None
    for name in ("tests", "test", "testing"):
        cand = os.path.join(project_root, name)
        if os.path.isdir(cand):
            return cand
    try:
        if any(f.startswith("test_") and f.endswith(".py") for f in os.listdir(project_root)):
            return project_root
    except OSError:
        pass
    return None


def _parse_test_output(proc: subprocess.CompletedProcess) -> Dict[str, Any]:
    out = (proc.stdout or "") + (proc.stderr or "")
    m = re.search(r"===SAGE_TESTS===(.*?)===SAGE_TESTS===", out, re.S)
    if m:
        try:
            data = json.loads(m.group(1))
            return {"mode": data.get("mode"), "results": data.get("results") or {}}
        except ValueError:
            pass
    summary = next((ln for ln in reversed(out.splitlines()) if "passed" in ln or "failed" in ln or "error" in ln), out[-200:])
    return {"mode": "exit-code", "results": {"<test run>": "passed" if proc.returncode == 0 else "failed"}, "summary": summary}


def _run_project_tests(project_root: str, test_rel: str, overlay: Optional[Tuple[str, str]], use_docker: bool) -> Dict[str, Any]:
    """Run the project's tests once. ``overlay`` = (relative path, content) replaces one file."""
    from .sandbox_verifier import SANDBOX_IMAGE
    runner = _TEST_RUNNER.replace("__TEST_DIR__", repr(test_rel.replace(os.sep, "/") or "."))
    tmp_paths: List[str] = []
    try:
        if use_docker:
            image = os.getenv("SAGE_ARMOR_TEST_IMAGE") or SANDBOX_IMAGE
            cmd = [
                "docker", "run", "-i", "--rm", "--network", "none", "--read-only",
                "--tmpfs", "/tmp:rw,noexec,nosuid,size=64m",  # nosec B108
                "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
                "--pids-limit", "128", "--memory", "512m", "--cpus", "1.0",
                "--user", "65534:65534",
                "--env", "HOME=/tmp", "--env", "PYTHONDONTWRITEBYTECODE=1", "--env", "PYTHONUNBUFFERED=1",
                "-v", f"{os.path.abspath(project_root)}:/workspace:ro",
            ]
            if overlay:
                fd, tmp = tempfile.mkstemp(suffix=".py")
                with os.fdopen(fd, "w", encoding="utf-8", newline="") as fh:
                    fh.write(overlay[1])
                tmp_paths.append(tmp)
                cmd += ["-v", f"{tmp}:/workspace/{overlay[0].replace(os.sep, '/')}:ro"]
            cmd += ["-w", "/workspace", image, "python", "-"]
            proc = subprocess.run(cmd, input=runner, capture_output=True, text=True, timeout=PYTEST_TIMEOUT)
        else:
            work = tempfile.mkdtemp(prefix="sage_tests_")
            tmp_paths.append(work)
            copy = os.path.join(work, "repo")
            shutil.copytree(project_root, copy, ignore=shutil.ignore_patterns(".git", "node_modules", "__pycache__", ".venv", "venv"), symlinks=True)
            if overlay:
                with open(os.path.join(copy, overlay[0]), "w", encoding="utf-8", newline="") as fh:
                    fh.write(overlay[1])
            env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "PYTHONUNBUFFERED": "1", "PYTHONDONTWRITEBYTECODE": "1",
                   "SYSTEMROOT": os.environ.get("SYSTEMROOT", "")}
            proc = subprocess.run([sys.executable, "-"], input=runner, cwd=copy, capture_output=True, text=True, timeout=PYTEST_TIMEOUT, env=env)
        return _parse_test_output(proc)
    finally:
        for p in tmp_paths:
            if os.path.isdir(p):
                shutil.rmtree(p, ignore_errors=True)
            else:
                try:
                    os.remove(p)
                except OSError:
                    pass


def gate_c_project_tests(
    patched_code: str,
    original_function_name: str,
    test_dir: Optional[str] = None,
    benign_check_fn: Optional[Callable[[str, str], bool]] = None,
    target_file_path: Optional[str] = None,
    project_root: Optional[str] = None,
) -> Tuple[bool, str, str]:
    """Run the project's tests on the original and on the patched file (in the hardened
    container, with the clone mounted read-only and the patched file mounted over the original).
    Fails when a test that passed before the patch fails after it."""
    if benign_check_fn:
        try:
            if not benign_check_fn(patched_code, original_function_name):
                return False, "fail", "Gate C FAIL: Benign-input check failed"
        except Exception as e:
            return False, "error", f"Gate C ERROR: Benign-input check crashed: {e}"

    if test_dir is None or not os.path.isdir(test_dir):
        if benign_check_fn:
            return True, "pass", "Gate C PASS: Benign input checks passed (project test_dir not specified)"
        return False, "skipped", "Gate C SKIPPED: No test_dir provided or directory not found"

    from .sandbox_verifier import SandboxVerifier as _RealVerifier
    use_docker = _RealVerifier._is_docker_live()
    if not use_docker and os.getenv("SAGE_ARMOR_UNSAFE_LOCAL_SANDBOX") != "1":
        return False, "skipped", "Gate C SKIPPED: Docker sandbox unavailable and unsafe local fallback disabled"

    root = os.path.abspath(project_root or os.path.join(test_dir, ".."))
    target_rel = None
    if target_file_path:
        target_abs = target_file_path if os.path.isabs(target_file_path) else os.path.join(root, target_file_path)
        target_abs = os.path.abspath(target_abs)
        try:
            if os.path.commonpath([root, target_abs]) == root and os.path.isfile(target_abs):
                target_rel = os.path.relpath(target_abs, root)
        except ValueError:
            target_rel = None
    if target_rel is None:
        if benign_check_fn:
            return True, "pass", "Gate C PASS: Benign input checks passed (patched file is not inside the project)"
        return False, "skipped", "Gate C SKIPPED: the patched file could not be mapped onto the project, so its tests would not exercise the patch"

    test_rel = os.path.relpath(os.path.abspath(test_dir), root)
    try:
        before = _run_project_tests(root, test_rel, None, use_docker)
        after = _run_project_tests(root, test_rel, (target_rel, patched_code), use_docker)
    except subprocess.TimeoutExpired:
        return False, "error", f"Gate C ERROR: project tests timed out after {PYTEST_TIMEOUT}s"
    except Exception as exc:
        return False, "error", f"Gate C ERROR: Test execution failed: {exc}"

    passed_before = {t for t, o in before["results"].items() if o == "passed"}
    if not passed_before:
        return False, "skipped", (
            f"Gate C SKIPPED: no project test passes on the original code inside the sandbox "
            f"({len(before['results'])} collected; missing dependencies are the usual cause)"
        )
    regressed = sorted(t for t in passed_before if after["results"].get(t) != "passed")
    runner = before.get("mode") or "runner"
    if regressed:
        names = ", ".join(regressed[:3]) + (f" and {len(regressed) - 3} more" if len(regressed) > 3 else "")
        return False, "fail", f"Gate C FAIL: {len(regressed)} project test(s) that passed before the patch now fail: {names}"
    return True, "pass", f"Gate C PASS: all {len(passed_before)} project tests that passed on the original code still pass ({runner})"


def _gate2_tests_still_pass(patched_code: str, original_function_name: str, test_dir: Optional[str] = None) -> Tuple[bool, str]:
    passed, _, detail = gate_c_project_tests(patched_code, original_function_name, test_dir)
    return passed, detail


# ---------------------------------------------------------------------------
# Gate D: Security rescan
# ---------------------------------------------------------------------------

def _finding_line(f: Dict[str, Any]) -> Optional[int]:
    for key in ("line", "line_number", "start_line"):
        try:
            v = int(f.get(key))
            if v > 0:
                return v
        except (TypeError, ValueError):
            continue
    return None


def _same_issue(a: str, b: str) -> bool:
    a, b = (a or "").lower(), (b or "").lower()
    if not a or not b:
        return False
    if a in b or b in a:
        return True
    ca, cb = infer_category(a), infer_category(b)
    return ca == cb and ca != "generic"


def gate_d_rescan_validation(
    patched_code: str,
    original_finding_issue: str,
    scanner: Optional[Any] = None,
    original_code: Optional[str] = None,
    function_range: Optional[Tuple[int, int]] = None,
    file_path: str = "<input>",
) -> Tuple[bool, str, str]:
    """SAST on the patched file. Fails if the original issue is still reported (inside the
    patched function, when its range is known) or if a high/critical issue appears that the
    original file did not have."""
    if SASTScanner is None and scanner is None:
        return False, "error", "Gate D ERROR: sast_scanner not available"
    s = scanner or SASTScanner()

    def _scan(code: str) -> List[Dict[str, Any]]:
        return list(s.scan(code) if hasattr(s, "scan") else s.scan_code(code))

    try:
        findings = _scan(patched_code)
        baseline = _scan(original_code) if original_code is not None else None
    except Exception as exc:
        return False, "error", f"Gate D ERROR: SAST scan failed: {exc}"

    def _key(f: Dict[str, Any], code: str) -> Tuple[str, str]:
        ln = _finding_line(f)
        lines = code.splitlines()
        text = lines[ln - 1].strip() if ln and ln - 1 < len(lines) else str(f.get("code") or f.get("matched_code") or "")
        return (str(f.get("issue", "")).lower(), text)

    baseline_keys = {_key(f, original_code) for f in baseline} if baseline is not None else set()

    def _in_range(f: Dict[str, Any]) -> bool:
        if not function_range:
            return True
        ln = _finding_line(f)
        return ln is None or function_range[0] <= ln <= function_range[1]

    orig_remaining = [f for f in findings if _same_issue(original_finding_issue, f.get("issue", "")) and _in_range(f)]
    new_severe = [
        f for f in findings
        if str(f.get("severity", "")).lower() in ("critical", "high")
        and f not in orig_remaining
        and (baseline is None or _key(f, patched_code) not in baseline_keys)
        and not (baseline is None and _same_issue(original_finding_issue, f.get("issue", "")))
    ]
    passed = not orig_remaining and not new_severe
    detail = (
        f"Gate D {'PASS' if passed else 'FAIL'}: "
        f"SAST found {len(findings)} total findings, "
        f"{len(orig_remaining)} remaining original issues, "
        f"{len(new_severe)} new high/critical issues"
    )
    if orig_remaining:
        f = orig_remaining[0]
        detail += f" — still reported: {f.get('issue')}" + (f" at line {_finding_line(f)}" if _finding_line(f) else "")
    elif new_severe:
        f = new_severe[0]
        detail += f" — introduced: {f.get('issue')}" + (f" at line {_finding_line(f)}" if _finding_line(f) else "")
    return passed, ("pass" if passed else "fail"), detail


def _gate3_no_new_sast_findings(patched_code: str, original_finding_issue: str) -> Tuple[bool, str]:
    passed, _, detail = gate_d_rescan_validation(patched_code, original_finding_issue)
    return passed, detail


# ---------------------------------------------------------------------------
# Gate E: Diff and path constraints
# ---------------------------------------------------------------------------

_PLACEHOLDER_PATTERNS = [
    r"^\s*(#\s*)?\.\.\.\s*$",
    r"#\s*\.\.\.",
    r"#\s*TODO",
    r"#\s*FIXME",
    r"#\s*rest of (the )?code",
    r"#\s*remaining code",
    r"#\s*existing code",
    r"#\s*\(?unchanged\)?",
]


def gate_e_diff_path_constraints(
    original_code: str,
    patched_code: str,
    function_name: str = "",
    file_path: Optional[str] = None,
    allowed_root: Optional[str] = None,
    max_diff_lines: int = 60,
) -> Tuple[bool, str, str]:
    """Path inside the repo; no fences/prose/placeholders in the added lines; unchanged
    signature; diff not excessive."""
    if file_path and allowed_root:
        root = os.path.realpath(allowed_root)
        target = os.path.realpath(file_path if os.path.isabs(file_path) else os.path.join(root, file_path))
        try:
            inside = os.path.commonpath([root, target]) == root
        except ValueError:
            inside = False
        if not inside:
            return False, "fail", f"Gate E FAIL: Target path {file_path} escapes root {allowed_root}"

    diff_lines = list(difflib.unified_diff(original_code.splitlines(), patched_code.splitlines(), lineterm=""))
    added = [l[1:] for l in diff_lines if l.startswith("+") and not l.startswith("+++")]
    removed = [l for l in diff_lines if l.startswith("-") and not l.startswith("---")]

    if any("```" in l for l in added):
        return False, "fail", "Gate E FAIL: Patch contains markdown code fences"
    first_added = next((l.strip().lower() for l in added if l.strip()), "")
    for prose_hint in ("here is", "here's", "in this fix", "explanation:", "modified function", "corrected function"):
        if first_added.startswith(prose_hint) or (prose_hint in first_added and not re.match(r"^\s*(#|def |class |@|\w+\s*=|return|import|from)", first_added)):
            return False, "fail", "Gate E FAIL: Patch contains markdown prose explanation"

    for pat in _PLACEHOLDER_PATTERNS:
        for line in added:
            if re.search(pat, line, re.IGNORECASE):
                return False, "fail", f"Gate E FAIL: Patch contains placeholder/truncation ({line.strip()[:60]})"

    if function_name:
        try:
            orig_funcs = [n for n in ast.walk(ast.parse(original_code)) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == function_name]
            patch_funcs = [n for n in ast.walk(ast.parse(patched_code)) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == function_name]
            if orig_funcs and patch_funcs:
                def _sig(n):
                    a = n.args
                    return [x.arg for x in list(a.posonlyargs) + list(a.args)] + ["*"] + [x.arg for x in a.kwonlyargs]
                if _sig(orig_funcs[0]) != _sig(patch_funcs[0]):
                    return False, "fail", f"Gate E FAIL: Function signature changed from {_sig(orig_funcs[0])} to {_sig(patch_funcs[0])}"
            elif orig_funcs and not patch_funcs:
                return False, "fail", f"Gate E FAIL: Target function {function_name} not found in patch"
        except Exception as e:
            return False, "fail", f"Gate E FAIL: Signature check parsing failed: {e}"

    changed = len(added) + len(removed)
    threshold = max(max_diff_lines, len(original_code.splitlines()) * 2)
    if changed > threshold:
        return False, "fail", f"Gate E FAIL: Excessive diff size ({changed} changes > limit {threshold})"
    return True, "pass", "Gate E PASS: Diff and path constraints satisfied"


# ---------------------------------------------------------------------------
# Prompt
# ---------------------------------------------------------------------------

def build_verified_fix_prompt(
    original_code: str,
    finding: Dict[str, Any],
    codebase_examples: List[str],
    project_helpers: Optional[List[Dict[str, str]]] = None,
    function_code: Optional[str] = None,
    feedback: Optional[str] = None,
    file_path: Optional[str] = None,
) -> str:
    """Prompt for a codebase-consistent patch of one function (or of the whole file when
    ``function_code`` is None and the finding is not inside a function)."""
    issue = finding.get("issue") or finding.get("title") or "Security vulnerability"
    cwe_id = finding.get("cwe_id") or finding.get("cwe") or ""
    function_name = finding.get("function_name", "")
    explanation = finding.get("explanation") or finding.get("description") or ""
    line_no = finding.get("line_number") or finding.get("line") or "unknown"
    where = f" in `{file_path}`" if file_path else ""

    parts = [
        "You are fixing one security vulnerability in an existing Python codebase.",
        f"FINDING: {issue} ({cwe_id}) in function `{function_name}`{where}, line {line_no}.",
    ]
    if explanation:
        parts.append(f"WHY IT IS VULNERABLE: {_clip(explanation, 600)}")

    ev = finding.get("evidence") if isinstance(finding.get("evidence"), dict) else {}
    if ev.get("sink"):
        parts.append(
            "SANDBOX PROOF: this attack input reached the dangerous call during a real run:\n"
            f"  input: {_clip(ev.get('payload', ''), 300)}"
            + (f"  (other arguments: {_clip(json.dumps(ev.get('kwargs'), default=str), 200)})" if ev.get("kwargs") else "")
            + f"\n  {ev['sink'].get('kind')} call received: {_clip(ev['sink'].get('argument', ''), 300)}\n"
            "The patched code will be attacked again with this input and new variations; none may reach the call."
        )

    if project_helpers:
        lines = [
            f"  - {h['signature']}  ({h['path']})" + (f": {h['doc']}" if h.get("doc") else "")
            for h in project_helpers
        ]
        parts.append("PROJECT HELPERS: prefer calling these existing functions over writing new checks:\n" + "\n".join(lines))
    if codebase_examples:
        parts.append(
            "Existing safe patterns found in this codebase (match this style):\n"
            + "\n".join(f"  {ex}" for ex in codebase_examples)
        )

    parts.append(
        "RULES:\n"
        "- Keep the function name, parameters and normal behaviour unchanged; change as little as possible.\n"
        "- Normal inputs must still reach the same database/shell/file/HTTP calls and return the same values.\n"
        "- Use the standard library, a helper above, or a library this file already imports; add no new dependencies.\n"
        "- No placeholders, TODOs, '...' or explanations."
    )

    if function_code is not None and function_code.strip() != original_code.strip():
        context = original_code if len(original_code) <= 6000 else original_code[:6000] + "\n# (file truncated)"
        parts.append("FILE (for reference, do not return it):\n" + context)
        parts.append("FUNCTION TO FIX:\n" + function_code)
    else:
        parts.append("ORIGINAL CODE:\n" + (function_code or original_code))

    if feedback:
        parts.append(
            "YOUR PREVIOUS PATCH WAS REJECTED by an automatic check:\n"
            f"  {_clip(feedback, 600)}\n"
            "Produce a new patch that fixes this problem."
        )

    if function_name and function_code is not None:
        parts.append(
            f"OUTPUT: only Python code — any new import lines first, then the complete corrected "
            f"`{function_name}` function (with its decorators). No markdown fences, no prose."
        )
    else:
        parts.append("OUTPUT: Return ONLY the complete corrected Python code, no markdown fences, no extra text.")
    return "\n\n".join(parts)


# ---------------------------------------------------------------------------
# The loop
# ---------------------------------------------------------------------------

class VerifiedFixer:
    """
    Generate a patch with ``invoke_llm_fn`` (prompt -> text) and run it through gates A, E, B,
    C and D; failed gates are fed back to the model for up to ``max_retries`` attempts.

    project_root / target_file_path: the repository clone and the file being fixed (relative
    or absolute). Enable project helpers, formatter, project tests and the path check.
    model_invoker: optional prompt -> text callable for new AI-written attacks in Gate B.
    """

    def __init__(
        self,
        invoke_llm_fn: Callable[[str], str],
        test_dir: Optional[str] = None,
        project_root: Optional[str] = None,
        max_retries: int = MAX_RETRIES,
        benign_check_fn: Optional[Callable[[str, str], bool]] = None,
        model_invoker: Optional[Callable[[str], Any]] = None,
        target_file_path: Optional[str] = None,
        verifier: Optional[Any] = None,
        scanner: Optional[Any] = None,
        run_formatter: bool = True,
    ) -> None:
        self.invoke_llm_fn = invoke_llm_fn
        self.test_dir = test_dir
        self.project_root = project_root
        self.max_retries = max(1, max_retries)
        self.benign_check_fn = benign_check_fn
        self.model_invoker = model_invoker
        self.target_file_path = target_file_path
        self._verifier = verifier
        self.scanner = scanner
        self.run_formatter = run_formatter

    def _get_verifier(self) -> Optional[Any]:
        if self._verifier is None and SandboxVerifier is not None:
            self._verifier = SandboxVerifier(timeout_sec=15.0)
        return self._verifier

    def _rel_path(self) -> Optional[str]:
        if not self.target_file_path:
            return None
        if self.project_root and os.path.isabs(self.target_file_path):
            return os.path.relpath(self.target_file_path, self.project_root).replace(os.sep, "/")
        return self.target_file_path.replace(os.sep, "/")

    def _abs_path(self) -> Optional[str]:
        if not self.target_file_path:
            return None
        if os.path.isabs(self.target_file_path) or not self.project_root:
            return self.target_file_path
        return os.path.join(self.project_root, self.target_file_path)

    def _gate_c(self, original_code: str, patched_code: str, function_name: str, category: str,
                cases: Optional[List[Tuple[str, Dict[str, Any]]]]) -> Dict[str, Any]:
        entry: Dict[str, Any] = {"gate": "tests_pass", "label": GATE_LABELS["tests_pass"]}
        parts: List[Tuple[str, str]] = []  # (status, text)
        if self.benign_check_fn:
            try:
                ok = self.benign_check_fn(patched_code, function_name)
                parts.append(("pass" if ok else "fail", "custom behaviour check " + ("passed" if ok else "failed")))
            except Exception as exc:
                parts.append(("error", f"custom behaviour check crashed: {exc}"))
        else:
            behaviour = run_behaviour_check(original_code, patched_code, function_name, category, self._get_verifier(), cases)
            entry["behaviour"] = behaviour.get("cases", [])
            parts.append((behaviour["status"], behaviour["detail"]))
        if self.test_dir:
            _p, t_status, t_detail = gate_c_project_tests(
                patched_code, function_name, self.test_dir,
                target_file_path=self._abs_path(), project_root=self.project_root,
            )
            parts.append((t_status, "project tests: " + re.sub(r"^Gate C \w+: ", "", t_detail)))
        else:
            parts.append(("skipped", "project tests: none (no test directory)"))

        statuses = [s for s, _ in parts]
        if "fail" in statuses:
            status = "fail"
        elif "error" in statuses:
            status = "error"
        elif "pass" in statuses:
            status = "pass"
        else:
            status = "skipped"
        word = {"pass": "PASS", "fail": "FAIL", "error": "ERROR", "skipped": "SKIPPED"}[status]
        return {**entry, "passed": status == "pass", "status": status, "detail": f"Gate C {word}: " + "; ".join(t for _, t in parts)}

    def fix(self, original_code: str, finding: Dict[str, Any]) -> Dict[str, Any]:
        """
        Returns {patch_status: verified|unverified_draft|failed, patched_code (full file),
        patched_function, original_function, diff, gates (every attempt), final_gates,
        failed_gate, attempts, finding, codebase_examples_used, project_helpers_used, ...}.
        """
        try:
            line = int(finding.get("line_number") or finding.get("line") or 0) or None
        except (TypeError, ValueError):
            line = None
        loc = locate_function(original_code, finding.get("function_name", "") or "", line)
        if loc:
            finding = {**finding, "function_name": loc["name"]}
        function_name = finding.get("function_name", "") or ""
        category = infer_category(_issue_title(finding))
        rel_path = self._rel_path()

        codebase_examples = find_project_sanitizer_examples(
            self.project_root or "", _issue_title(finding),
            extra_source=None if self.project_root else original_code,
        )
        helpers = find_project_helpers(
            self.project_root, category,
            extra_source=None if self.project_root else original_code,
            exclude_function=function_name,
        )
        sink_rel_line = (line - loc["def_line"] + 1) if (loc and line and line >= loc["def_line"]) else 1
        cases = benign_cases(category, loc["params"], original_code) if loc else None

        gate_log: List[Dict[str, Any]] = []
        best: Optional[Dict[str, Any]] = None
        verified = False
        feedback: Optional[str] = None
        attempts_made = 0

        for attempt in range(1, self.max_retries + 1):
            attempts_made = attempt
            prompt = build_verified_fix_prompt(
                original_code, finding, codebase_examples,
                project_helpers=helpers,
                function_code=loc["code"] if loc else None,
                feedback=feedback,
                file_path=rel_path,
            )
            try:
                raw = self.invoke_llm_fn(prompt)
            except Exception as exc:
                gate_log.append({"attempt": attempt, "gate": "llm", "passed": False, "status": "error",
                                 "detail": f"LLM invocation failed: {exc}"})
                continue
            if not raw or len(str(raw).strip()) < 10:
                gate_log.append({"attempt": attempt, "gate": "llm", "passed": False, "status": "fail",
                                 "detail": "LLM returned empty/trivial response"})
                continue

            applied = apply_model_output(original_code, loc, raw)
            if applied.get("error"):
                gate_log.append({"attempt": attempt, "gate": "llm", "passed": False, "status": "fail", "detail": applied["error"]})
                feedback = applied["error"]
                continue
            patched = applied["patched"]
            attempt_gates: List[Dict[str, Any]] = []

            if self.run_formatter and self.project_root and applied.get("start"):
                patched, fmt = format_patched_region(patched, applied["start"], applied["end"], self.project_root, rel_path or "patched.py")
                attempt_gates.append(fmt)
                if fmt.get("status") == "pass":
                    relocated = locate_function(patched, function_name, applied["start"])
                    if relocated:
                        applied = {**applied, "start": relocated["start"], "end": relocated["end"], "function_code": relocated["code"]}

            def record(name: str, passed: bool, status: str, detail: str, **extra: Any) -> Dict[str, Any]:
                e = {"gate": name, "label": GATE_LABELS.get(name, name), "passed": passed, "status": status, "detail": detail, **extra}
                attempt_gates.append(e)
                return e

            stop: Optional[Dict[str, Any]] = None
            ga = record("gate_a_parse_compile", *gate_a_parse_compile(patched))
            if ga["status"] != "pass":
                stop = ga
            if stop is None:
                ge = record("gate_e_diff_constraints", *gate_e_diff_path_constraints(
                    original_code=original_code, patched_code=patched, function_name=function_name,
                    file_path=self._abs_path() if self.project_root else None, allowed_root=self.project_root,
                ))
                if ge["status"] != "pass":
                    stop = ge
            if stop is None:
                gb = run_gate_b(patched, finding, verifier=self._get_verifier(), model_invoker=self.model_invoker, sink_line=sink_rel_line)
                attempt_gates.append(gb)
                if gb["status"] in ("fail", "error"):
                    stop = gb
            if stop is None:
                gc = self._gate_c(original_code, patched, function_name, category, cases)
                attempt_gates.append(gc)
                if gc["status"] in ("fail", "error"):
                    stop = gc
            if stop is None:
                f_range = (applied["start"], applied["end"]) if applied.get("start") else None
                record("no_new_sast_findings", *gate_d_rescan_validation(
                    patched, finding.get("issue", "") or _issue_title(finding), scanner=self.scanner,
                    original_code=original_code, function_range=f_range,
                ))
                if attempt_gates[-1]["status"] in ("fail", "error"):
                    stop = attempt_gates[-1]

            for g in attempt_gates:
                g["attempt"] = attempt
            gate_log.extend(attempt_gates)

            by_name = {g["gate"]: g["status"] for g in attempt_gates}
            score = sum(1 for name in REQUIRED_GATES if by_name.get(name) == "pass")
            if best is None or score >= best["score"]:
                best = {"patched": patched, "applied": applied, "gates": attempt_gates, "score": score, "attempt": attempt}

            if all(by_name.get(name) == "pass" for name in REQUIRED_GATES):
                verified = True
                best = {"patched": patched, "applied": applied, "gates": attempt_gates, "score": score, "attempt": attempt}
                break
            if stop is not None:
                feedback = f"{GATE_LABELS.get(stop['gate'], stop['gate'])}: {stop['detail']}"
                continue
            break  # nothing failed, something could only be skipped: another attempt will not help

        if best and best["patched"] != original_code:
            best_patch = best["patched"]
            diff_str = "".join(difflib.unified_diff(
                original_code.splitlines(keepends=True), best_patch.splitlines(keepends=True),
                fromfile=f"a/{rel_path or 'original.py'}", tofile=f"b/{rel_path or 'patched.py'}",
            ))
            patch_status = "verified" if verified else "unverified_draft"
        else:
            best_patch, diff_str, patch_status = original_code, "", "failed"

        final_gates = best["gates"] if best else []
        failed_gate = None
        if patch_status != "verified":
            by_name = {g["gate"]: g for g in final_gates}
            for name in REQUIRED_GATES:
                g = by_name.get(name)
                if g is None or g["status"] != "pass":
                    failed_gate = (
                        {"gate": name, "label": GATE_LABELS[name], "status": g["status"] if g else "not_run",
                         "detail": g["detail"] if g else "not reached: an earlier gate failed"}
                    )
                    break
            if failed_gate is None and gate_log:
                last = gate_log[-1]
                failed_gate = {"gate": last["gate"], "label": GATE_LABELS.get(last["gate"], last["gate"]), "status": last["status"], "detail": last["detail"]}

        fmt_step = next((g for g in final_gates if g.get("gate") == "formatter"), None)
        applied = best["applied"] if best else {}
        return {
            "patch_status": patch_status,
            "patched_code": best_patch,
            "patched_function": applied.get("function_code") if best else None,
            "original_function": loc["code"] if loc else None,
            "function_name": function_name,
            "start_line": loc["start"] if loc else None,
            "end_line": loc["end"] if loc else None,
            "diff": diff_str,
            "gates": gate_log,
            "final_gates": final_gates,
            "failed_gate": failed_gate,
            "attempts": attempts_made,
            "finding": finding,
            "codebase_examples_used": codebase_examples,
            "project_helpers_used": helpers,
            "added_imports": applied.get("added_imports", []) if best else [],
            "formatter": fmt_step,
        }


def run_verified_fix(
    original_code: str,
    finding: Dict[str, Any],
    invoke_llm_fn: Callable[[str], str],
    test_dir: Optional[str] = None,
    project_root: Optional[str] = None,
    **kwargs: Any,
) -> Dict[str, Any]:
    """Convenience wrapper; same result as VerifiedFixer.fix()."""
    fixer = VerifiedFixer(invoke_llm_fn=invoke_llm_fn, test_dir=test_dir, project_root=project_root, **kwargs)
    return fixer.fix(original_code=original_code, finding=finding)
