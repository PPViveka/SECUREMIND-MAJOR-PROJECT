"""
Sandbox harness for the exploit gate.

The harness is a self-contained Python program that runs inside the isolated container.
It replaces every dangerous sink with a recorder ("fake sink"), loads the target code,
calls the target function with an attack payload, and prints what each sink received.

Nothing the attacker controls is ever executed for real: SQL is not run, shell commands are
not spawned, files are not opened, HTTP requests are not sent, and strings passed to
eval/exec/pickle/yaml are recorded instead of evaluated. The host then decides whether the
payload's unique canary reached a sink argument intact (see ``match_sink_evidence``).
"""

import os
import posixpath
import re
from typing import Any, Dict, Iterable, List, Optional, Tuple
from urllib.parse import urlparse

CANARY_PLACEHOLDER = "CANARY_TOKEN"

# Fixed attack strings, tried first because they are fast and need no model.
# "{C}" is replaced by the run's unique canary.
CATEGORY_SPECS: Dict[str, Dict[str, Any]] = {
    "sql_injection": {
        "vectors": ["{C}' OR '1'='1", "1 OR 1=1 -- {C}", "{C}\"; DROP TABLE users--"],
        "sink": "a SQL execute() call: the query text it receives is recorded (bound parameters are recorded separately)",
        "goal": "the payload must appear verbatim inside the SQL query text, so quotes or SQL syntax survive",
    },
    "command_injection": {
        "vectors": ["; echo {C}", "| echo {C}", "$(echo {C})"],
        "sink": "os.system / os.popen / subprocess with shell=True: the command string is recorded",
        "goal": "the payload must appear verbatim in a command a shell interprets, with a shell metacharacter (; | & $ `)",
    },
    "path_traversal": {
        "vectors": ["../../../../etc/{C}", "..\\..\\..\\..\\etc\\{C}", "/etc/{C}"],
        "sink": "open() / pathlib / send_file: the path is recorded; os.path.exists() reports True for paths containing the canary",
        "goal": "the opened path must contain the canary and escape the intended directory ('..' segments kept, or an absolute path under /etc)",
    },
    "code_evaluation": {
        "vectors": ["__import__('os').getenv('{C}')", "'{C}'.upper()", "{C}"],
        "sink": "eval() / exec() / compile() on a string: the source is recorded, never run",
        "goal": "the payload must reach eval/exec as source code",
    },
    "ssrf": {
        "vectors": ["http://{C}.attacker.example/", "http://169.254.169.254/latest/{C}", "{C}.attacker.example"],
        "sink": "requests / httpx / urllib.request.urlopen: the URL is recorded, no request is sent",
        "goal": "the canary must end up in the request's host name, or the payload must be the start of the URL",
    },
    "open_redirect": {
        "vectors": ["https://{C}.attacker.example/", "//{C}.attacker.example/", "{C}.attacker.example"],
        "sink": "flask/django redirect(): the target URL is recorded",
        "goal": "the canary must end up in the redirect's host name, or the payload must be the start of the URL",
    },
    "deserialization": {
        "vectors": ["{C}", "{B64C}", "!!python/object/apply:os.system ['{C}']"],
        "sink": "pickle/marshal/dill/jsonpickle loads and yaml.load without SafeLoader: the data is recorded, never deserialized",
        "goal": "the canary must reach an unsafe deserializer's input",
    },
    "template_injection": {
        "vectors": ["{{7*7}}{C}", "{% raw %}{C}{% endraw %}", "${7*7}{C}"],
        "sink": "jinja2 Template()/from_string() and flask render_template_string(): the template source is recorded",
        "goal": "the payload, including its {{ }} or {% %} syntax, must become part of the template source",
    },
    "xss": {
        "vectors": ["<script>{C}</script>", "\"><img src=x onerror={C}>", "<svg onload={C}>"],
        "sink": "the HTML the function returns, or the body given to Response/make_response/HttpResponse",
        "goal": "the payload's HTML tag must appear unescaped in an HTML response",
    },
}

SUPPORTED_CATEGORIES = set(CATEGORY_SPECS)


def infer_category(issue_title: str) -> str:
    """Map a finding title / CWE to the exploit class the harness can test, or 'generic'."""
    s = (issue_title or "").lower()
    if "sql" in s or "cwe-89" in s:
        return "sql_injection"
    if "template injection" in s or "ssti" in s or "cwe-1336" in s:
        return "template_injection"
    if "xss" in s or "cross-site scripting" in s or "cross site scripting" in s or "cwe-79" in s:
        return "xss"
    if "ssrf" in s or "server-side request" in s or "server side request" in s or "cwe-918" in s:
        return "ssrf"
    if "redirect" in s or "cwe-601" in s:
        return "open_redirect"
    if "deserial" in s or "pickle" in s or "unsafe yaml" in s or "yaml.load" in s or "marshal" in s or "cwe-502" in s:
        return "deserialization"
    if "path" in s or "traversal" in s or "directory" in s or "cwe-22" in s:
        return "path_traversal"
    if "command" in s or "shell" in s or "cwe-78" in s or "os.system" in s or "subprocess" in s:
        return "command_injection"
    if "eval" in s or "code execution" in s or "code injection" in s or "cwe-94" in s or "cwe-95" in s:
        return "code_evaluation"
    if "exec" in s:
        return "command_injection"
    return "generic"


def fixed_vectors(category: str, canary: str) -> List[str]:
    import base64
    b64 = base64.b64encode(canary.encode()).decode()
    return [
        v.replace("{B64C}", b64).replace("{C}", canary)
        for v in CATEGORY_SPECS.get(category, {}).get("vectors", [])
    ]


def _string_values(value: Any) -> Iterable[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for item in value.values():
            yield from _string_values(item)
    elif isinstance(value, (list, tuple)):
        for item in value:
            yield from _string_values(item)


def candidate_strings(payload: str, kwargs: Optional[Dict[str, Any]], canary: str) -> List[str]:
    """Attacker strings that carry the canary: the payload and any keyword value."""
    out = [payload] if canary in (payload or "") else []
    out.extend(s for s in _string_values(kwargs or {}) if canary in s and s not in out)
    return out


def _host_controlled(url: str, candidates: List[str], canary: str) -> bool:
    url = str(url or "")
    try:
        host = (urlparse(url if "//" in url else "//" + url).hostname or "").lower()
    except ValueError:
        host = ""
    if canary.lower() in host:
        return True
    # The payload is the start of the URL: the attacker picks scheme and host.
    return any(c.startswith(("http", "//")) and url.startswith(c.split(canary)[0]) and c in url for c in candidates)


def _sql_literal_mask(text: str) -> List[Optional[str]]:
    """For each character: the quote of the SQL string literal it belongs to, or None."""
    mask: List[Optional[str]] = [None] * len(text)
    quote = None
    i = 0
    while i < len(text):
        ch = text[i]
        if quote:
            mask[i] = quote
            if ch == quote:
                if i + 1 < len(text) and text[i + 1] == quote:  # '' is an escaped quote
                    mask[i + 1] = quote
                    i += 2
                    continue
                quote = None
        elif ch in ("'", '"'):
            quote = ch
            mask[i] = ch
        i += 1
    return mask


def _sql_injects(query: str, cand: str) -> bool:
    """
    The payload changes the SQL structure: part of it ends up outside any string literal,
    either because it was never quoted (numeric context) or because it closed its literal.
    A payload that stays inside a quoted literal is only data.
    """
    if not any(t in cand for t in (" ", ";", "--", "/*", "'", '"', "(", "=")):
        return False
    mask = _sql_literal_mask(query)
    start = query.find(cand)
    while start != -1:
        if any(mask[k] is None and not query[k].isspace() for k in range(start, start + len(cand))):
            return True
        start = query.find(cand, start + 1)
    return False


def _shell_injects(command: str, cand: str) -> bool:
    """
    The payload is interpreted by a POSIX shell: an unquoted, unescaped metacharacter
    (; | & ` $ newline), or $( / backtick inside double quotes. Inside single quotes nothing
    is special until the quote is closed.
    """
    state: List[Optional[str]] = [None] * len(command)
    escaped = [False] * len(command)
    quote = None
    i = 0
    while i < len(command):
        ch = command[i]
        state[i] = quote
        if quote == "'":
            if ch == "'":
                quote = None
        elif ch == "\\" and i + 1 < len(command):
            state[i + 1] = quote
            escaped[i + 1] = True
            i += 2
            continue
        elif quote == '"':
            if ch == '"':
                quote = None
        elif ch in ("'", '"'):
            quote = ch
        i += 1

    start = command.find(cand)
    while start != -1:
        for k in range(start, start + len(cand)):
            if escaped[k]:
                continue
            ch = command[k]
            if state[k] is None and ch in ";|&`$\n":
                return True
            if state[k] == '"' and (ch == "`" or command[k:k + 2] == "$("):
                return True
        start = command.find(cand, start + 1)
    return False


def _escapes_directory(path: str) -> bool:
    segments = re.split(r"[\\/]+", path)
    if ".." in segments:
        return True
    return posixpath.normpath(path.replace("\\", "/")).startswith("/etc/")


def match_sink_evidence(category: str, records: List[Dict[str, Any]], candidates: List[str], canary: str) -> Optional[int]:
    """
    Return the index of the first sink record that proves the exploit, or None.
    Proof means the attacker's canary arrived in the sink argument with its attack syntax
    intact, during the call to the target function.
    """
    for idx, rec in enumerate(records):
        if not isinstance(rec, dict) or not rec.get("during_call"):
            continue
        kind = rec.get("kind")
        if category == "sql_injection" and kind == "sql":
            query = str(rec.get("query", ""))
            if any(c in query and _sql_injects(query, c) for c in candidates):
                return idx
        elif category == "command_injection" and kind == "command" and rec.get("shell"):
            command = str(rec.get("command", ""))
            if any(c in command and _shell_injects(command, c) for c in candidates):
                return idx
        elif category == "path_traversal" and kind == "file" and not rec.get("safe"):
            path = str(rec.get("path", ""))
            if canary in path and _escapes_directory(path):
                return idx
        elif category == "code_evaluation" and kind in ("eval", "exec"):
            if any(c in str(rec.get("expr", "")) for c in candidates):
                return idx
        elif category == "ssrf" and kind == "http":
            if _host_controlled(rec.get("url", ""), candidates, canary):
                return idx
        elif category == "open_redirect" and kind == "redirect":
            if _host_controlled(rec.get("url", ""), candidates, canary):
                return idx
        elif category == "deserialization" and kind == "deserialize" and not rec.get("safe"):
            if canary in str(rec.get("data", "")):
                return idx
        elif category == "template_injection" and kind == "template":
            source = str(rec.get("source", ""))
            if any(c in source and any(t in c for t in ("{{", "{%", "${")) for c in candidates):
                return idx
        elif category == "xss" and kind in ("return", "response") and rec.get("html"):
            body = str(rec.get("body", ""))
            if any(c in body and "<" in c for c in candidates):
                return idx
    return None


SINK_KINDS = {"sql", "command", "file", "eval", "exec", "http", "redirect", "deserialize", "template", "response", "return"}


def sink_argument(rec: Dict[str, Any]) -> str:
    for key in ("query", "command", "path", "expr", "url", "data", "source", "body"):
        if key in rec:
            return str(rec[key])
    return ""


def build_case_invocation(function_name: str, cases: List[Tuple[str, Dict[str, Any]]], canary: str) -> str:
    """Harness lines that call the target once per (payload, kwargs) case, marking each case in the
    hook records. Used for behaviour tests on normal inputs. Values are repr() literals: never code."""
    literal = [(str(p), dict(k or {})) for p, k in cases]
    return (
        f"    for _sage_i, (_sage_p, _sage_k) in enumerate({literal!r}):\n"
        "        _rec('case', n=_sage_i)\n"
        "        try:\n"
        f"            _sage_invoke({function_name!r}, _sage_p, {canary!r}, _sage_k)\n"
        "        except BaseException as _sage_e:\n"
        "            _rec('case_error', n=_sage_i, error=type(_sage_e).__name__ + ': ' + str(_sage_e))\n"
    )


def build_invocation(function_name: str, payload: str, canary: str, kwargs: Optional[Dict[str, Any]] = None) -> str:
    """Harness call line. All values are Python literals built with repr(): never code."""
    return f"    _sage_invoke({function_name!r}, {payload!r}, {canary!r}, {dict(kwargs or {})!r})\n"


HARNESS_TEMPLATE = r'''
import sys
import os
import io
import re
import json
import types
import builtins
import subprocess
import html as _sage_html
import inspect
import base64

hook_records = []
_SAGE = {"payload": "", "canary": "", "kwargs": {}, "active": False}
_SAGE_MAX = 1500


def _sage_clip(value):
    if isinstance(value, str):
        text = value
    elif isinstance(value, (bytes, bytearray)):
        text = bytes(value).decode("utf-8", "replace")
    else:
        try:
            text = repr(value)
        except Exception:
            text = "<unrepresentable>"
    return text[:_SAGE_MAX]


_SAGE_MAIN = os.path.basename(getattr(sys.modules.get("__main__"), "__file__", "<stdin>") or "<stdin>")


def _from_target(depth=2):
    """True when the hooked call comes from the code under test, not from the standard library."""
    try:
        name = os.path.basename(sys._getframe(depth).f_code.co_filename)
    except ValueError:
        return False
    return name in ("<stdin>", _SAGE_MAIN)


def _rec(kind, **fields):
    entry = {"kind": kind, "during_call": bool(_SAGE["active"])}
    for key, value in fields.items():
        entry[key] = value if (value is None or isinstance(value, (bool, int, float))) else _sage_clip(value)
    hook_records.append(entry)


# ---- Unresolved third-party imports become recording stubs --------------------------------
class _StubModule:
    def __init__(self, name, is_module=False):
        self.__name__ = name
        self._is_module = is_module
    def __getattr__(self, item):
        if item.startswith("__") and item.endswith("__"):
            raise AttributeError(item)
        # `from x import y` binds a name off the module: that alone is not use.
        if not object.__getattribute__(self, "_is_module"):
            _rec("stub_access", module=self.__name__, attr=str(item))
        return _StubModule(self.__name__ + "." + str(item))
    def __call__(self, *args, **kwargs):
        _rec("stub_call", module=self.__name__)
        return _StubModule(self.__name__ + "()")


class _StubFinder:
    def find_spec(self, fullname, path, target=None):
        import importlib.util
        if fullname in sys.modules or fullname in sys.builtin_module_names:
            return None
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


def _stub_fallback(module_name):
    def __getattr__(item):
        if item.startswith("__"):
            raise AttributeError(item)
        return _StubModule(module_name + "." + item)
    return __getattr__


def _raise(exc):
    raise exc


def _fake_module(name, **attrs):
    """A modeled library: known names behave like the real API, unknown names fall back to stubs."""
    mod = types.ModuleType(name)
    mod.__dict__.update(attrs)
    mod.__getattr__ = _stub_fallback(name)
    sys.modules[name] = mod
    parent, _, child = name.rpartition(".")
    if parent:
        if parent not in sys.modules:
            _fake_module(parent)
        setattr(sys.modules[parent], child, mod)
    return mod


class _Ctx:
    def __enter__(self):
        return self
    def __exit__(self, *exc):
        return False


# ---- SQL -----------------------------------------------------------------------------------
class _MockCursor(_Ctx):
    rowcount = 0
    lastrowid = 1
    description = None
    def execute(self, query, params=None, *args, **kwargs):
        _rec("sql", query=query, bound_args="" if params is None else params)
        return self
    def executemany(self, query, seq=None, *args, **kwargs):
        _rec("sql", query=query, bound_args="" if seq is None else seq)
        return self
    def executescript(self, script):
        _rec("sql", query=script, bound_args="")
        return self
    def fetchall(self):
        return []
    def fetchone(self):
        return None
    def fetchmany(self, *args, **kwargs):
        return []
    def close(self):
        pass
    def __iter__(self):
        return iter([])


class _MockConnection(_Ctx):
    row_factory = None
    def cursor(self, *args, **kwargs):
        return _MockCursor()
    def execute(self, query, params=None, *args, **kwargs):
        return _MockCursor().execute(query, params)
    def executemany(self, query, seq=None, *args, **kwargs):
        return _MockCursor().executemany(query, seq)
    def executescript(self, script):
        return _MockCursor().executescript(script)
    def commit(self):
        pass
    def rollback(self):
        pass
    def close(self):
        pass


cursor = _MockCursor()
conn = _MockConnection()
connection = conn
db = conn

import sqlite3
sqlite3.connect = lambda *a, **kw: _MockConnection()
_sage_connect = lambda *a, **kw: _MockConnection()
_fake_module("psycopg2", connect=_sage_connect, Error=Exception, DatabaseError=Exception)
_fake_module("psycopg2.extras", RealDictCursor=object, DictCursor=object)
_fake_module("psycopg", connect=_sage_connect)
_fake_module("pymysql", connect=_sage_connect, Error=Exception)
_fake_module("pymysql.cursors", DictCursor=object)
_fake_module("MySQLdb", connect=_sage_connect)
_fake_module("mysql.connector", connect=_sage_connect, Error=Exception)


# ---- Shell commands ------------------------------------------------------------------------
def _cmd_text(cmd):
    if isinstance(cmd, (list, tuple)):
        return " ".join(str(c) for c in cmd)
    return cmd if isinstance(cmd, str) else str(cmd)


def _record_command(cmd, shell):
    is_list = isinstance(cmd, (list, tuple))
    if shell and is_list:
        text = str(cmd[0]) if cmd else ""
    elif is_list and len(cmd) >= 3 and os.path.basename(str(cmd[0])) in ("sh", "bash", "zsh", "dash", "cmd", "cmd.exe", "powershell") and str(cmd[1]) in ("-c", "/c", "-Command"):
        shell, text = True, str(cmd[2])
    else:
        text = _cmd_text(cmd)
    _rec("command", command=text, shell=bool(shell))


class _FakeProcess(_Ctx):
    returncode = 0
    pid = 4242
    def __init__(self):
        self.stdout = io.StringIO("")
        self.stderr = io.StringIO("")
        self.args = ""
    def communicate(self, *args, **kwargs):
        return ("", "")
    def wait(self, *args, **kwargs):
        return 0
    def poll(self):
        return 0
    def kill(self):
        pass
    def terminate(self):
        pass


class _FakeCompleted:
    returncode = 0
    stdout = ""
    stderr = ""
    args = ""
    def check_returncode(self):
        return None


def _mock_system(command):
    _record_command(command, True)
    return 0


def _sp_cmd(args, kwargs):
    return args[0] if args else kwargs.get("args", "")


os.system = _mock_system
os.popen = lambda cmd, *a, **kw: (_record_command(cmd, True), io.StringIO(""))[1]
subprocess.run = lambda *a, **kw: (_record_command(_sp_cmd(a, kw), kw.get("shell", False)), _FakeCompleted())[1]
subprocess.call = lambda *a, **kw: (_record_command(_sp_cmd(a, kw), kw.get("shell", False)), 0)[1]
subprocess.check_call = lambda *a, **kw: (_record_command(_sp_cmd(a, kw), kw.get("shell", False)), 0)[1]
subprocess.check_output = lambda *a, **kw: (_record_command(_sp_cmd(a, kw), kw.get("shell", False)), "" if (kw.get("text") or kw.get("universal_newlines") or kw.get("encoding")) else b"")[1]
subprocess.getoutput = lambda cmd: (_record_command(cmd, True), "")[1]
subprocess.getstatusoutput = lambda cmd: (_record_command(cmd, True), (0, ""))[1]
subprocess.Popen = lambda *a, **kw: (_record_command(_sp_cmd(a, kw), kw.get("shell", False)), _FakeProcess())[1]


# ---- Files ---------------------------------------------------------------------------------
def _mock_open(path, mode="r", *args, **kwargs):
    if isinstance(path, int):
        return io.StringIO("")
    try:
        p = os.fspath(path)
    except TypeError:
        p = str(path)
    _rec("file", path=p, mode=str(mode))
    return io.BytesIO(b"") if "b" in str(mode) else io.StringIO("")


builtins.open = _mock_open
io.open = _mock_open

_real_exists = os.path.exists
_real_isfile = os.path.isfile


def _canary_path(p):
    return bool(_SAGE["canary"]) and _SAGE["canary"] in str(p)


# The attacker aims at a file that exists (e.g. /etc/passwd); model that for canary paths.
os.path.exists = lambda p: True if _canary_path(p) else _real_exists(p)
os.path.isfile = lambda p: True if _canary_path(p) else _real_isfile(p)
os.remove = lambda p, *a, **kw: _rec("file", path=str(p), mode="delete")
os.unlink = os.remove

try:
    import pathlib
    pathlib.Path.open = lambda self, mode="r", *a, **kw: _mock_open(str(self), mode)
    pathlib.Path.read_text = lambda self, *a, **kw: (_mock_open(str(self)), "")[1]
    pathlib.Path.read_bytes = lambda self, *a, **kw: (_mock_open(str(self), "rb"), b"")[1]
    pathlib.Path.write_text = lambda self, data, *a, **kw: (_mock_open(str(self), "w"), len(data))[1]
    pathlib.Path.write_bytes = lambda self, data, *a, **kw: (_mock_open(str(self), "wb"), len(data))[1]
    _real_path_exists = pathlib.Path.exists
    _real_path_is_file = pathlib.Path.is_file
    pathlib.Path.exists = lambda self, *a, **kw: True if _canary_path(self) else _real_path_exists(self)
    pathlib.Path.is_file = lambda self, *a, **kw: True if _canary_path(self) else _real_path_is_file(self)
except Exception:
    pass


# ---- eval / exec: strings are recorded, never run -------------------------------------------
_real_eval = builtins.eval
_real_exec = builtins.exec
_real_compile = builtins.compile


def _mock_eval(source, *args, **kwargs):
    # Code objects, and strings evaluated by the standard library (e.g. namedtuple), run for real.
    if not isinstance(source, (str, bytes, bytearray)) or not _from_target():
        return _real_eval(source, *args, **kwargs)
    _rec("eval", expr=source)
    return None


def _mock_exec(source, *args, **kwargs):
    if not isinstance(source, (str, bytes, bytearray)) or not _from_target():
        return _real_exec(source, *args, **kwargs)
    _rec("exec", expr=source)
    return None


def _mock_compile(source, filename="<string>", mode="exec", *args, **kwargs):
    if isinstance(source, (str, bytes, bytearray)) and _SAGE["active"] and _from_target():
        _rec("eval", expr=source)
        return _real_compile("None", filename, "eval")
    return _real_compile(source, filename, mode, *args, **kwargs)


builtins.eval = _mock_eval
builtins.exec = _mock_exec
builtins.compile = _mock_compile
builtins.input = lambda *a, **kw: _SAGE["payload"]


# ---- Deserialization -----------------------------------------------------------------------
def _deser(library, data, safe=False):
    if hasattr(data, "read"):
        try:
            data = data.read()
        except Exception:
            data = ""
    _rec("deserialize", library=library, data=data, safe=bool(safe))
    return {}


import pickle
import marshal
pickle.loads = lambda data, *a, **kw: _deser("pickle", data)
pickle.load = lambda f, *a, **kw: _deser("pickle", f)
_real_marshal_loads = marshal.loads


def _mock_marshal_loads(data, *args, **kwargs):
    # The import system loads .pyc files through marshal.loads: those calls must stay real.
    if not _from_target():
        return _real_marshal_loads(data, *args, **kwargs)
    return _deser("marshal", data)


marshal.loads = _mock_marshal_loads
_fake_module("dill", loads=lambda d, *a, **kw: _deser("dill", d), load=lambda f, *a, **kw: _deser("dill", f))
_fake_module("jsonpickle", decode=lambda d, *a, **kw: _deser("jsonpickle", d), encode=lambda o, *a, **kw: "{}")


class _YamlLoader:
    pass


_yaml_loaders = {n: type(n, (_YamlLoader,), {}) for n in (
    "SafeLoader", "CSafeLoader", "BaseLoader", "CBaseLoader", "Loader", "CLoader",
    "UnsafeLoader", "FullLoader", "CFullLoader")}


def _yaml_load(stream, Loader=None, *args, **kwargs):
    loader = Loader or kwargs.get("Loader")
    safe = getattr(loader, "__name__", "") in ("SafeLoader", "CSafeLoader", "BaseLoader", "CBaseLoader")
    return _deser("yaml", stream, safe=safe)


_fake_module(
    "yaml", load=_yaml_load, load_all=lambda s, Loader=None, **kw: [_yaml_load(s, Loader)],
    safe_load=lambda s: _deser("yaml", s, safe=True), safe_load_all=lambda s: [_deser("yaml", s, safe=True)],
    full_load=lambda s: _deser("yaml", s), unsafe_load=lambda s: _deser("yaml", s),
    dump=lambda *a, **kw: "", safe_dump=lambda *a, **kw: "", YAMLError=Exception, **_yaml_loaders,
)


# ---- Outbound HTTP (SSRF) --------------------------------------------------------------------
class _FakeHttpResponse(_Ctx):
    status_code = 200
    status = 200
    code = 200
    ok = True
    text = ""
    content = b""
    reason = "OK"
    encoding = "utf-8"
    def __init__(self, url=""):
        self.url = url
        self.headers = {}
    def json(self, *args, **kwargs):
        return {}
    def raise_for_status(self):
        return None
    def read(self, *args):
        return b""
    def getcode(self):
        return 200
    def iter_content(self, *args, **kwargs):
        return iter([])
    def iter_lines(self, *args, **kwargs):
        return iter([])
    def close(self):
        pass


def _http(method, url):
    target = getattr(url, "full_url", None) or str(url)
    _rec("http", method=method, url=target)
    return _FakeHttpResponse(target)


def _http_api():
    api = {m: (lambda url, *a, _m=m.upper(), **kw: _http(_m, url)) for m in ("get", "post", "put", "patch", "delete", "head", "options")}
    api["request"] = lambda method, url, *a, **kw: _http(str(method).upper(), url)
    return api


class _HttpSession(_Ctx):
    def __init__(self, *args, **kwargs):
        self.headers = {}
        self.cookies = {}
    def close(self):
        pass


for _name, _fn in _http_api().items():
    setattr(_HttpSession, _name, (lambda f: (lambda self, *a, **kw: f(*a, **kw)))(_fn))


class _AsyncHttpClient(_HttpSession):
    async def __aenter__(self):
        return self
    async def __aexit__(self, *exc):
        return False


for _name, _fn in _http_api().items():
    async def _async_call(self, *a, _f=_fn, **kw):
        return _f(*a, **kw)
    setattr(_AsyncHttpClient, _name, _async_call)

_http_errors = dict(RequestException=Exception, Timeout=Exception, ConnectionError=Exception, HTTPError=Exception)
_fake_module("requests", Session=_HttpSession, session=_HttpSession, Response=_FakeHttpResponse, codes=types.SimpleNamespace(ok=200), **_http_api(), **_http_errors)
_fake_module("requests.exceptions", **_http_errors)
_fake_module("httpx", Client=_HttpSession, AsyncClient=_AsyncHttpClient, HTTPError=Exception, **_http_api())
try:
    import urllib.request
    urllib.request.urlopen = lambda url, *a, **kw: _http("GET", url)
    urllib.request.urlretrieve = lambda url, *a, **kw: (_http("GET", url), ("", {}))[1]
except Exception:
    pass


# ---- Templates / HTML responses ----------------------------------------------------------------
class _Template:
    def __init__(self, source="", *args, **kwargs):
        _rec("template", source=source)
        self.source = source
    def render(self, *args, **kwargs):
        return str(self.source)


class _FileTemplate:
    def __init__(self, name):
        _rec("template_file", name=name)
    def render(self, *args, **kwargs):
        return ""


class _Environment:
    def __init__(self, *args, **kwargs):
        self.globals = {}
        self.filters = {}
    def from_string(self, source, *args, **kwargs):
        return _Template(source)
    def get_template(self, name, *args, **kwargs):
        return _FileTemplate(name)


_noop_factory = lambda *a, **kw: None
_fake_module("jinja2", Template=_Template, Environment=_Environment, FileSystemLoader=_noop_factory,
             PackageLoader=_noop_factory, DictLoader=_noop_factory, BaseLoader=_noop_factory,
             select_autoescape=lambda *a, **kw: True, Markup=str, escape=lambda s: _sage_html.escape(str(s)))
_fake_module("markupsafe", Markup=str, escape=lambda s: _sage_html.escape(str(s)))


def _is_html_type(mimetype):
    mimetype = str(mimetype or "text/html").lower()
    return "html" in mimetype or mimetype.startswith("text/")


class _Response:
    def __init__(self, response=None, status=200, headers=None, mimetype=None, content_type=None, media_type=None, content=None, **kwargs):
        body = response if response is not None else (content if content is not None else "")
        if isinstance(body, (list, tuple)):
            body = "".join(str(b) for b in body)
        self.body = body
        self.data = body
        self.status_code = status if isinstance(status, int) else 200
        self.headers = dict(headers or {})
        kind = mimetype or content_type or media_type or self._default_type
        _rec("response", body=body, html=_is_html_type(kind) and isinstance(body, (str, bytes, bytearray)))
    _default_type = "text/html"
    def set_cookie(self, *args, **kwargs):
        pass
    def __getitem__(self, key):
        return self.headers.get(key)
    def __setitem__(self, key, value):
        self.headers[key] = value


class _JsonResponse(_Response):
    _default_type = "application/json"
    def __init__(self, data=None, *args, **kwargs):
        super().__init__(json.dumps(data, default=str) if not isinstance(data, str) else data, mimetype="application/json")


class _HTTPAbort(Exception):
    def __init__(self, code=400, *args, **kwargs):
        super().__init__(code)
        self.code = code


def _redirect(location, *args, **kwargs):
    _rec("redirect", url=location)
    resp = _Response("", 302)
    resp.headers["Location"] = location
    return resp


def _make_response(*args, **kwargs):
    body = args[0] if args else ""
    if isinstance(body, tuple):
        body = body[0] if body else ""
    return body if isinstance(body, _Response) else _Response(body)


def _render_template_string(source, **context):
    _rec("template", source=source)
    return str(source)


def _render_template(name, **context):
    _rec("template_file", name=name)
    return ""


def _send_file(path_or_file, *args, **kwargs):
    if isinstance(path_or_file, (str, bytes, os.PathLike)):
        _rec("file", path=os.fspath(path_or_file), mode="r")
    return _Response("")


def _send_from_directory(directory, path, *args, **kwargs):
    # Mirrors werkzeug.safe_join: traversal and absolute paths are rejected before opening.
    norm = str(path).replace("\\", "/")
    if ".." in norm.split("/") or norm.startswith("/") or re.match(r"^[A-Za-z]:", norm):
        raise _HTTPAbort(404)
    _rec("file", path=os.path.join(str(directory), str(path)), mode="r", safe=True)
    return _Response("")


def _secure_filename(filename):
    name = str(filename)
    for sep in ("/", "\\"):
        name = name.replace(sep, " ")
    name = re.sub(r"[^A-Za-z0-9_.-]", "", "_".join(name.split()))
    return name.strip("._")


class _AppLike:
    """Flask/FastAPI app or blueprint: every decorator returns the function unchanged."""
    def __init__(self, *args, **kwargs):
        self.config = {}
        self.secret_key = None
        self.name = "app"
        self.extensions = {}
    def __getattr__(self, item):
        if item.startswith("__"):
            raise AttributeError(item)
        def decorator_or_noop(*args, **kwargs):
            if len(args) == 1 and callable(args[0]) and not kwargs:
                return args[0]
            return lambda f: f
        return decorator_or_noop
    def run(self, *args, **kwargs):
        pass
    def app_context(self):
        return _Ctx()


def _sage_field(key):
    overrides = _SAGE["kwargs"]
    if isinstance(overrides, dict) and key in overrides:
        return overrides[key]
    return _SAGE["payload"]


class _PayloadMap(dict):
    """Request data where every field holds the attack payload, as if the attacker filled them all."""
    def get(self, key, default=None, type=None):
        value = _sage_field(key)
        if type is not None:
            try:
                return type(value)
            except Exception:
                return default
        return value
    def __getitem__(self, key):
        return _sage_field(key)
    def __contains__(self, key):
        return True
    def getlist(self, key, type=None):
        return [_sage_field(key)]
    def to_dict(self, *args, **kwargs):
        return {}


class _FakeRequest:
    method = "POST"
    path = "/"
    full_path = "/?"
    url = "http://localhost/"
    base_url = "http://localhost/"
    host = "localhost"
    remote_addr = "127.0.0.1"
    is_json = True
    content_type = "application/json"
    user = None
    def __init__(self):
        fields = _PayloadMap()
        self.args = self.form = self.values = self.cookies = self.headers = fields
        self.GET = self.POST = self.COOKIES = self.META = self.query_params = self.path_params = fields
        self.files = {}
        self.session = {}
    @property
    def json(self):
        return _PayloadMap()
    def get_json(self, *args, **kwargs):
        return _PayloadMap()
    @property
    def data(self):
        return str(_SAGE["payload"]).encode()
    @property
    def body(self):
        return str(_SAGE["payload"]).encode()
    def get_data(self, as_text=False, *args, **kwargs):
        return str(_SAGE["payload"]) if as_text else str(_SAGE["payload"]).encode()


_FAKE_REQUEST = _FakeRequest()

_fake_module(
    "flask", Flask=_AppLike, Blueprint=_AppLike, request=_FAKE_REQUEST, session={}, g=types.SimpleNamespace(),
    current_app=_AppLike(), jsonify=lambda *a, **kw: _JsonResponse(a[0] if len(a) == 1 else (list(a) or kw)),
    render_template=_render_template, render_template_string=_render_template_string,
    make_response=_make_response, Response=_Response, redirect=_redirect, abort=lambda code=400, *a, **kw: _raise(_HTTPAbort(code)),
    url_for=lambda endpoint, **kw: "/" + str(endpoint), send_file=_send_file, send_from_directory=_send_from_directory,
    escape=lambda s: _sage_html.escape(str(s)), flash=lambda *a, **kw: None, Markup=str,
)
_fake_module("werkzeug.utils", secure_filename=_secure_filename)
_fake_module("werkzeug.security", generate_password_hash=lambda p, *a, **kw: "pbkdf2:sha256$" + str(len(str(p))),
             check_password_hash=lambda h, p: False, safe_join=lambda d, *p: os.path.join(d, *p))
_fake_module("werkzeug.exceptions", HTTPException=_HTTPAbort, NotFound=_HTTPAbort, BadRequest=_HTTPAbort, Forbidden=_HTTPAbort)

_fastapi_param = lambda default=None, *a, **kw: default
_fake_module(
    "fastapi", FastAPI=_AppLike, APIRouter=_AppLike, Request=_FakeRequest, HTTPException=_HTTPAbort,
    Query=_fastapi_param, Body=_fastapi_param, Path=_fastapi_param, Form=_fastapi_param, Header=_fastapi_param,
    Cookie=_fastapi_param, Depends=lambda *a, **kw: None, Response=_Response, status=types.SimpleNamespace(),
)
_fake_module("fastapi.responses", HTMLResponse=_Response, PlainTextResponse=_Response, JSONResponse=_JsonResponse,
             RedirectResponse=lambda url, *a, **kw: _redirect(url), FileResponse=_send_file)
_fake_module("starlette.responses", HTMLResponse=_Response, JSONResponse=_JsonResponse,
             RedirectResponse=lambda url, *a, **kw: _redirect(url))

_fake_module("django.http", HttpResponse=_Response, JsonResponse=_JsonResponse, HttpResponseRedirect=_redirect,
             HttpResponseBadRequest=_Response, HttpResponseForbidden=_Response, HttpResponseNotFound=_Response,
             Http404=_HTTPAbort, FileResponse=_send_file)
_fake_module("django.shortcuts", render=lambda req, name, *a, **kw: (_render_template(name), _Response(""))[1],
             redirect=_redirect)
_fake_module("django.db", connection=_MockConnection(), connections={"default": _MockConnection()})
_fake_module("django.utils.html", escape=lambda s: _sage_html.escape(str(s)), mark_safe=lambda s: s, format_html=lambda f, *a, **kw: f.format(*[_sage_html.escape(str(x)) for x in a]))
_fake_module("django.utils.safestring", mark_safe=lambda s: s)


# ---- Target code -----------------------------------------------------------------------------
{TARGET_CODE}


# ---- Driver ------------------------------------------------------------------------------------
def _sage_shape(value, depth=0):
    """JSON-friendly summary of a return value, for comparing old and patched code."""
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, str):
        return value[:300]
    if isinstance(value, (bytes, bytearray)):
        return bytes(value[:300]).decode("utf-8", "replace")
    if isinstance(value, _Response):
        return {"<response>": _sage_shape(value.body, depth + 1), "status": value.status_code}
    if depth < 3 and isinstance(value, (list, tuple, set, frozenset)):
        return [_sage_shape(v, depth + 1) for v in list(value)[:20]]
    if depth < 3 and isinstance(value, dict):
        return {str(k)[:60]: _sage_shape(v, depth + 1) for k, v in list(value.items())[:20]}
    return "<" + type(value).__name__ + ">"


def _sage_record_return(value):
    try:
        _rec("returned", shape=json.dumps(_sage_shape(value), default=str, sort_keys=True))
    except Exception:
        pass
    if isinstance(value, tuple) and value:
        value = value[0]
    if isinstance(value, _Response):
        return  # recorded when the response was built
    if isinstance(value, (str, bytes, bytearray)):
        _rec("return", body=value, html=True)


def _sage_invoke(name, payload, canary, overrides):
    import inspect
    _SAGE.update(payload=payload, canary=canary, kwargs=overrides or {})
    fn = globals().get(name)
    if fn is None or not callable(fn):
        raise NameError("target function %r is not defined" % name)
    args, kwargs = [], {}
    try:
        params = list(inspect.signature(fn).parameters.values())
    except (TypeError, ValueError):
        params = []
    for p in params:
        if p.kind in (p.VAR_POSITIONAL, p.VAR_KEYWORD):
            continue
        if p.name in _SAGE["kwargs"]:
            value = _SAGE["kwargs"][p.name]
        elif p.name in ("request", "req", "http_request"):
            value = _FAKE_REQUEST
        elif p.default is p.empty or p.default is None or isinstance(p.default, str):
            value = payload
        else:
            continue  # keep the code's own non-string default (e.g. limit=10)
        if p.kind == p.POSITIONAL_ONLY:
            args.append(value)
        else:
            kwargs[p.name] = value
    _SAGE["active"] = True
    try:
        result = fn(*args, **kwargs)
        if inspect.iscoroutine(result):
            import asyncio
            result = asyncio.run(result)
        elif inspect.isgenerator(result):
            result = "".join(str(chunk) for _, chunk in zip(range(200), result))
        _sage_record_return(result)
    finally:
        _SAGE["active"] = False


executed_lines = []
_main_file = getattr(sys.modules.get("__main__"), "__file__", "<stdin>") or "<stdin>"
target_filenames = {"<stdin>", _main_file, os.path.abspath(_main_file)}


def trace_calls(frame, event, arg):
    if event == "line":
        code = frame.f_code
        if code.co_filename in target_filenames or os.path.basename(code.co_filename) in ("<stdin>", os.path.basename(_main_file)):
            executed_lines.append(frame.f_lineno)
    return trace_calls


sys.settrace(trace_calls)
error_msg = None
trace_success = False
try:
{TEST_INVOCATION}
    trace_success = True
except BaseException as e:
    error_msg = type(e).__name__ + ": " + str(e)
    trace_success = True
sys.settrace(None)

result = {
    "executed_lines": executed_lines,
    "unique_executed_lines": sorted(set(executed_lines)),
    "success": trace_success,
    "error": error_msg,
    "hook_records": hook_records,
}
sys.stdout.write("\n===SAGE_TRACE_RESULT_START===\n" + json.dumps(result, default=str) + "\n===SAGE_TRACE_RESULT_END===\n")
'''
