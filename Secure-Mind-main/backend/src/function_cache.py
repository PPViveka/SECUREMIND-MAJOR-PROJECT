"""
Function Slicer, Fingerprinting, and Result Cache Engine
Part of SageArmor / SecureMind Core Scanning Pipeline

Provides:
- AST-based function extraction for Python and heuristic extraction for other languages
- SHA-256 fingerprinting of normalized function bodies
- Persistent SQLite-backed caching of security review results per function
- Line-offset adjustment for cached findings when functions move within a file
- Cost and telemetry tracking (tokens saved, execution time saved, hit rates)
"""

import ast
import hashlib
import json
import os
import re
import sqlite3
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple


# Dangerous sink indicators that warrant deeper AI analysis
RISKY_SINKS = {
    "sql": ["execute", "raw", "cursor", "select", "insert", "update", "delete"],
    "file": ["open", "read", "write", "unlink", "remove", "path", "join"],
    "command": ["system", "popen", "subprocess", "spawn", "exec", "eval"],
    "crypto": ["md5", "sha1", "des", "rc4", "ecb"],
    "auth": ["password", "token", "secret", "jwt", "authorize", "authenticate", "session"],
    "deserialize": ["pickle", "yaml.load", "loads", "unserialize"],
}


def normalize_code_for_hash(code_str: str) -> str:
    """
    Normalizes code string before hashing so trivial whitespace variance
    does not cause unnecessary cache invalidation.
    """
    if not code_str:
        return ""
    # Strip leading/trailing whitespace
    lines = [line.rstrip() for line in code_str.strip().splitlines() if line.strip()]
    return "\n".join(lines)


def compute_function_hash(code_str: str) -> str:
    """
    Computes a deterministic SHA-256 fingerprint for a given code block.
    """
    normalized = normalize_code_for_hash(code_str)
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def _detect_risky_sinks(code_str: str) -> List[str]:
    """Detects if any dangerous sink categories appear in the function body."""
    found = []
    code_lower = code_str.lower()
    for category, terms in RISKY_SINKS.items():
        if any(term in code_lower for term in terms):
            found.append(category)
    return found


def extract_python_functions(source_code: str) -> List[Dict[str, Any]]:
    """
    Extracts all functions and methods from Python source code using AST.
    Falls back gracefully if the code has syntax errors.
    """
    functions = []
    lines = source_code.splitlines()

    try:
        tree = ast.parse(source_code)
    except SyntaxError:
        # If syntax error, return the whole source as a fallback single chunk
        return [{
            "name": "<snippet>",
            "start_line": 1,
            "end_line": len(lines) if lines else 1,
            "code": source_code,
            "hash": compute_function_hash(source_code),
            "risky_sinks": _detect_risky_sinks(source_code),
            "is_function": False,
        }]

    class FunctionVisitor(ast.NodeVisitor):
        def __init__(self):
            self.extracted = []

        def visit_FunctionDef(self, node):
            self._handle_func(node)
            self.generic_visit(node)

        def visit_AsyncFunctionDef(self, node):
            self._handle_func(node)
            self.generic_visit(node)

        def _handle_func(self, node):
            start = node.lineno
            # node.end_lineno is supported in Python 3.8+
            end = getattr(node, "end_lineno", None)
            if end is None:
                # Estimate end line
                end = start
                for child in ast.walk(node):
                    if hasattr(child, "lineno") and child.lineno > end:
                        end = child.lineno

            func_lines = lines[start - 1 : end]
            func_code = "\n".join(func_lines)

            self.extracted.append({
                "name": node.name,
                "start_line": start,
                "end_line": end,
                "code": func_code,
                "hash": compute_function_hash(func_code),
                "risky_sinks": _detect_risky_sinks(func_code),
                "is_function": True,
            })

    visitor = FunctionVisitor()
    visitor.visit(tree)
    functions = visitor.extracted

    # If no functions defined (e.g. flat script), wrap entire content
    if not functions and source_code.strip():
        functions.append({
            "name": "<module>",
            "start_line": 1,
            "end_line": len(lines) if lines else 1,
            "code": source_code,
            "hash": compute_function_hash(source_code),
            "risky_sinks": _detect_risky_sinks(source_code),
            "is_function": False,
        })

    return functions


def extract_generic_functions(source_code: str, language: str) -> List[Dict[str, Any]]:
    """
    Heuristic regex-based function boundary extractor for JavaScript, TypeScript,
    Go, Java, C/C++, PHP, etc.
    """
    functions = []
    lines = source_code.splitlines()

    # Pattern for typical C/JS/TS/Java function declarations
    pattern = re.compile(
        r'^\s*(?:(?:async|public|private|protected|static|export|default|function)\s+)*'
        r'(?:function\s+([a-zA-Z0-9_$]+)|([a-zA-Z0-9_$]+)\s*\([^)]*\)\s*(?::\s*[^=\n{]+)?\s*\{|const\s+([a-zA-Z0-9_$]+)\s*=\s*(?:async\s*)?\([^)]*\)\s*=>\s*\{)',
        re.MULTILINE
    )

    for match in pattern.finditer(source_code):
        start_char = match.start()
        start_line = source_code.count("\n", 0, start_char) + 1
        name = match.group(1) or match.group(2) or match.group(3) or "<anonymous>"

        # Find closing brace by brace matching
        brace_count = 0
        end_char = start_char
        found_open = False

        for i in range(start_char, len(source_code)):
            ch = source_code[i]
            if ch == '{':
                brace_count += 1
                found_open = True
            elif ch == '}':
                brace_count -= 1
                if found_open and brace_count == 0:
                    end_char = i + 1
                    break

        if found_open and brace_count == 0:
            func_code = source_code[start_char:end_char]
            end_line = source_code.count("\n", 0, end_char) + 1
            functions.append({
                "name": name,
                "start_line": start_line,
                "end_line": end_line,
                "code": func_code,
                "hash": compute_function_hash(func_code),
                "risky_sinks": _detect_risky_sinks(func_code),
                "is_function": True,
            })

    # Fallback to whole snippet if no functions matched
    if not functions and source_code.strip():
        functions.append({
            "name": "<snippet>",
            "start_line": 1,
            "end_line": len(lines) if lines else 1,
            "code": source_code,
            "hash": compute_function_hash(source_code),
            "risky_sinks": _detect_risky_sinks(source_code),
            "is_function": False,
        })

    return functions


def extract_functions(source_code: str, language: str = "python") -> List[Dict[str, Any]]:
    """
    Extracts function blocks with boundary metadata and hashes based on language.
    """
    if not source_code or not source_code.strip():
        return []

    lang = (language or "python").lower()
    if lang in ["python", "py"]:
        return extract_python_functions(source_code)
    else:
        return extract_generic_functions(source_code, lang)


class FunctionScanCache:
    """
    Persistent SQLite-backed cache for storing and retrieving security scan results
    by function SHA-256 fingerprint.
    """

    def __init__(self, db_path: Optional[str] = None):
        if db_path is None:
            base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            self.db_path = os.path.join(base_dir, ".sage_armor_cache.db")
        else:
            self.db_path = db_path

        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10.0)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        conn = self._get_connection()
        try:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS function_cache (
                    function_hash TEXT PRIMARY KEY,
                    function_name TEXT,
                    language TEXT,
                    file_path TEXT,
                    original_start_line INTEGER,
                    scan_result TEXT,
                    tokens_used INTEGER DEFAULT 0,
                    scan_duration_ms REAL DEFAULT 0.0,
                    provider TEXT,
                    created_at TEXT,
                    last_accessed TEXT,
                    hit_count INTEGER DEFAULT 0
                )
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_cache_hash ON function_cache(function_hash)
            """)
            conn.commit()
        finally:
            conn.close()

    def get(self, function_hash: str) -> Optional[Dict[str, Any]]:
        """
        Retrieves a cached scan result by function hash.
        Increments hit_count and updates last_accessed.
        """
        now = datetime.now(timezone.utc).isoformat()
        conn = self._get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT * FROM function_cache WHERE function_hash = ?",
                (function_hash,),
            )
            row = cursor.fetchone()
            if not row:
                return None

            cursor.execute(
                """
                UPDATE function_cache 
                SET hit_count = hit_count + 1, last_accessed = ? 
                WHERE function_hash = ?
                """,
                (now, function_hash),
            )
            conn.commit()

            return {
                "function_hash": row["function_hash"],
                "function_name": row["function_name"],
                "language": row["language"],
                "file_path": row["file_path"],
                "original_start_line": row["original_start_line"],
                "scan_result": json.loads(row["scan_result"]),
                "tokens_used": row["tokens_used"],
                "scan_duration_ms": row["scan_duration_ms"],
                "provider": row["provider"],
                "created_at": row["created_at"],
                "last_accessed": now,
                "hit_count": row["hit_count"] + 1,
            }
        finally:
            conn.close()

    def set(
        self,
        function_hash: str,
        function_name: str,
        language: str,
        scan_result: Dict[str, Any],
        original_start_line: int = 1,
        file_path: str = "",
        tokens_used: int = 0,
        scan_duration_ms: float = 0.0,
        provider: str = "rules_ai",
    ):
        """
        Saves or updates a function's scan result in the cache.
        """
        now = datetime.now(timezone.utc).isoformat()
        serialized_result = json.dumps(scan_result)

        conn = self._get_connection()
        try:
            conn.execute(
                """
                INSERT INTO function_cache (
                    function_hash, function_name, language, file_path,
                    original_start_line, scan_result, tokens_used,
                    scan_duration_ms, provider, created_at, last_accessed, hit_count
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0)
                ON CONFLICT(function_hash) DO UPDATE SET
                    function_name = excluded.function_name,
                    language = excluded.language,
                    file_path = excluded.file_path,
                    original_start_line = excluded.original_start_line,
                    scan_result = excluded.scan_result,
                    tokens_used = excluded.tokens_used,
                    scan_duration_ms = excluded.scan_duration_ms,
                    provider = excluded.provider,
                    last_accessed = excluded.last_accessed
                """,
                (
                    function_hash,
                    function_name,
                    language,
                    file_path,
                    original_start_line,
                    serialized_result,
                    tokens_used,
                    scan_duration_ms,
                    provider,
                    now,
                    now,
                ),
            )
            conn.commit()
        finally:
            conn.close()

    def get_metrics(self) -> Dict[str, Any]:
        """
        Calculates telemetry metrics: total cached functions, cumulative cache hits,
        estimated tokens saved, and processing time saved.
        """
        conn = self._get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT 
                    COUNT(*) as total_entries,
                    COALESCE(SUM(hit_count), 0) as total_hits,
                    COALESCE(SUM(hit_count * tokens_used), 0) as tokens_saved,
                    COALESCE(SUM(hit_count * scan_duration_ms), 0.0) as time_saved_ms
                FROM function_cache
            """)
            row = cursor.fetchone()
            return {
                "total_cached_functions": row["total_entries"],
                "total_cache_hits": row["total_hits"],
                "estimated_tokens_saved": row["tokens_saved"],
                "estimated_time_saved_ms": round(row["time_saved_ms"], 2),
            }
        finally:
            conn.close()

    def clear(self):
        """Clears all entries from the cache."""
        conn = self._get_connection()
        try:
            conn.execute("DELETE FROM function_cache")
            conn.commit()
        finally:
            conn.close()


def adjust_line_offsets(
    vulnerabilities: List[Dict[str, Any]],
    old_start_line: int,
    new_start_line: int,
) -> List[Dict[str, Any]]:
    """
    Adjusts line coordinates of cached vulnerabilities when a function has moved
    vertically within a file.
    """
    delta = new_start_line - old_start_line
    if delta == 0:
        return vulnerabilities

    adjusted = []
    for vuln in vulnerabilities:
        v_copy = dict(vuln)
        if "line" in v_copy and isinstance(v_copy["line"], int):
            v_copy["line"] = max(1, v_copy["line"] + delta)
        adjusted.append(v_copy)
    return adjusted


class SelectiveFunctionScanner:
    """
    Coordinates the function-level caching and slicing workflow:
    1. Extracts functions from submitted code
    2. Checks cache by function fingerprint
    3. Returns cached results for unchanged functions
    4. Identifies only the modified/new functions that require scanning
    """

    def __init__(self, cache: Optional[FunctionScanCache] = None):
        self.cache = cache or FunctionScanCache()

    def partition_functions(
        self,
        source_code: str,
        language: str = "python",
        file_path: str = "",
    ) -> Dict[str, Any]:
        """
        Splits code into functions and partitions them into cache hits vs cache misses.
        """
        start_time = time.time()
        functions = extract_functions(source_code, language)

        cached_vulns = []
        functions_to_scan = []
        tokens_saved = 0
        hits = 0
        misses = 0

        for func in functions:
            cached_entry = self.cache.get(func["hash"])
            if cached_entry is not None:
                # Cache hit!
                hits += 1
                tokens_saved += cached_entry.get("tokens_used", 0)
                raw_vulns = cached_entry.get("scan_result", {}).get("vulnerabilities", [])
                
                # Adjust line numbers if function start line shifted
                adjusted_vulns = adjust_line_offsets(
                    raw_vulns,
                    cached_entry.get("original_start_line", 1),
                    func["start_line"],
                )
                
                # Tag with cache metadata
                for v in adjusted_vulns:
                    v["cached"] = True
                    v["function_name"] = func["name"]
                    cached_vulns.append(v)
            else:
                # Cache miss - function changed or never scanned
                misses += 1
                func["file_path"] = file_path
                functions_to_scan.append(func)

        partition_time_ms = round((time.time() - start_time) * 1000, 2)

        return {
            "total_functions": len(functions),
            "cache_hits": hits,
            "cache_misses": misses,
            "tokens_saved": tokens_saved,
            "partition_time_ms": partition_time_ms,
            "cached_vulnerabilities": cached_vulns,
            "functions_to_scan": functions_to_scan,
        }
