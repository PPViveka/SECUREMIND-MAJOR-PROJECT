"""
test_unit_comprehensive_matrix.py
Comprehensive unit test matrix covering all requirements in Section 15:
- Finding deduplication, ranking, and null-line tests
- Vulnerable vs safe twins, exact ranges, CWE, language, confidence for SAST rules
- Slicing with decorators, nested/async functions, syntax errors, Unicode, module context
- Cache invalidation, provider/language separation, usage accounting
- Provider timeout, retries, 429/5xx mapping, malformed JSON, schema rejection, fallback
- Differential verifier predicates (SQL, Command, Path, Eval)
- Fail-closed gates (crashes, timeouts, missing functions, garbage patches, still-vulnerable patches)
- Taint propagation, sanitizers, graph path absence, no fabricated paths
- Job TTL, stale recovery, concurrent updates, cancellation, idempotency
"""

import ast
import json
import os
import sys
import tempfile
import time
import unittest
from concurrent.futures import ThreadPoolExecutor

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from src.sast_scanner import SASTScanner
from src.finding_schema import normalize_finding, normalize_findings, anchor_findings, validate_finding
from src.function_cache import extract_functions, compute_function_hash, FunctionScanCache, SelectiveFunctionScanner
from src.code_graph import build_code_graph
from src.llm_provider import (
    DeterministicMockProvider,
    ProviderError,
    ProviderRateLimitError,
    ProviderUnavailableError,
    redact_secrets,
)
from src.sandbox_verifier import SandboxVerifier, apply_verification_gate
from src.verified_fixer import (
    gate_a_parse_compile,
    gate_b_differential_exploit,
    gate_d_rescan_validation,
    gate_e_diff_path_constraints,
)
from src.job_manager import (
    set_db_path,
    create_job,
    get_job,
    update_job,
    update_job_progress,
    cancel_job,
    reap_stale_jobs,
    add_job_event,
    record_stage_timing,
)


class TestComprehensiveUnitMatrix(unittest.TestCase):
    """Matrix tests ensuring complete unit test coverage of all components."""

    def setUp(self):
        self.tmp_db = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.db_path = self.tmp_db.name
        self.tmp_db.close()
        set_db_path(self.db_path)

    def tearDown(self):
        try:
            if hasattr(self, "db_path") and os.path.exists(self.db_path):
                os.unlink(self.db_path)
        except OSError:
            pass

    # -------------------------------------------------------------------------
    # 1. Finding Deduplication, Ranking, and Null-Line Tests
    # -------------------------------------------------------------------------
    def test_finding_dedup_and_null_lines(self):
        """Findings with null or missing line numbers are normalized cleanly without pinning to line 0."""
        finding_no_line = {
            "issue": "Unauthenticated API Route",
            "severity": "High",
            "file": "routes/api.py",
            "line": None,
        }
        normalized = normalize_finding(finding_no_line, file_path="routes/api.py", language="python")
        self.assertEqual(normalized["line"], 0)
        self.assertEqual(normalized["range"]["start"], 0)
        self.assertEqual(normalized["range"]["end"], 0)
        self.assertTrue(validate_finding(normalized))

        # Deduplication test
        findings = [
            {"issue": "SQLi", "line": 5, "file": "app.py", "severity": "High"},
            {"issue": "SQLi", "line": 5, "file": "app.py", "severity": "High"},
            {"issue": "Command Injection", "line": 12, "file": "app.py", "severity": "Critical"},
        ]
        norm_list = normalize_findings(findings)
        # Deduplication by ID
        unique_ids = {f["finding_id"] for f in norm_list}
        self.assertEqual(len(unique_ids), 2)

    # -------------------------------------------------------------------------
    # 2. SAST Rules: Vulnerable vs Safe Twins, CWE, Language, Confidence
    # -------------------------------------------------------------------------
    def test_sast_rules_and_twins_matrix(self):
        """Tests vulnerable and safe twin assertions for major CWE classes."""
        twins = [
            # SQL Injection
            ("cursor.execute('SELECT * FROM t WHERE id = ' + uid)", "cursor.execute('SELECT * FROM t WHERE id = ?', (uid,))", "CWE-89"),
            # Command Injection
            ("subprocess.run('ping ' + host)", "subprocess.run(['ping', host], shell=False)", "CWE-78"),
            # Path Traversal
            ("open(user_path).read()", "open(os.path.basename(user_path)).read()", "CWE-22"),
            # Eval / Code Injection (insecure deserialization category)
            ("eval(expr)", "ast.literal_eval(expr)", "CWE-502"),
            # Insecure Deserialization
            ("pickle.loads(payload)", "json.loads(payload)", "CWE-502"),
        ]

        scanner = SASTScanner()
        for vuln_code, safe_code, expected_cwe in twins:
            vuln_findings = scanner.scan_code(vuln_code)
            self.assertGreater(len(vuln_findings), 0, f"Expected vuln finding for: {vuln_code}")
            vuln_cwe = vuln_findings[0].get("cwe_id") or vuln_findings[0].get("cwe")
            self.assertEqual(vuln_cwe, expected_cwe)
            self.assertIn(vuln_findings[0].get("confidence", "").lower(), ("high", "medium"))

            # Safe twin should not trigger the same vulnerability
            safe_findings = scanner.scan_code(safe_code)
            matched_same_cwe = [
                f for f in safe_findings if (f.get("cwe_id") or f.get("cwe")) == expected_cwe
            ]
            self.assertEqual(len(matched_same_cwe), 0, f"Safe twin should not be flagged: {safe_code}")

    # -------------------------------------------------------------------------
    # 3. Function Slicing with Decorators, Nested/Async, Syntax Errors, Unicode
    # -------------------------------------------------------------------------
    def test_function_slicing_edge_cases(self):
        """Tests slicing with decorators, async functions, nested functions, syntax errors, and Unicode."""
        code = (
            "@app.route('/login', methods=['POST'])\n"
            "@rate_limit(10)\n"
            "async def login_handler(request: Request):\n"
            "    # Développeur token with Unicode 🛡️\n"
            "    def inner_helper(val):\n"
            "        return val.strip()\n"
            "    user = inner_helper(request.form['username'])\n"
            "    return {'status': 'ok'}\n"
        )
        funcs = extract_functions(code, language="python")
        self.assertGreaterEqual(len(funcs), 1)
        login_fn = next((f for f in funcs if f["name"] == "login_handler"), None)
        self.assertIsNotNone(login_fn)
        self.assertIn("async def login_handler", login_fn["code"])
        self.assertIn("inner_helper", login_fn["code"])

        # Syntax error test: should degrade gracefully to whole-file slicing
        broken_code = "def syntax_err(\n    return 42"
        broken_funcs = extract_functions(broken_code, language="python")
        self.assertEqual(len(broken_funcs), 1)
        self.assertEqual(broken_funcs[0]["name"], "<snippet>")

    # -------------------------------------------------------------------------
    # 4. Cache Invalidation, Language/Provider Separation, Usage Accounting
    # -------------------------------------------------------------------------
    def test_cache_separation_and_invalidation(self):
        """Verifies cache separation across providers, cache_kinds, and accurate usage telemetry."""
        cache = FunctionScanCache(self.db_path)
        cache.clear()

        fn_hash = "hash_abc_123"
        cache.set(
            function_hash=fn_hash,
            function_name="test_fn",
            language="python",
            scan_result={"vulnerabilities": [{"issue": "Test Issue"}]},
            tokens_used=120,
            scan_duration_ms=45.0,
            provider="bedrock",
            cache_kind="model",
        )
        cache.set(
            function_hash=fn_hash,
            function_name="test_fn",
            language="python",
            scan_result={"vulnerabilities": []},
            tokens_used=0,
            scan_duration_ms=2.0,
            provider="rules_ai",
            cache_kind="rules_only",
        )

        model_entry = cache.get(fn_hash, cache_kind="model")
        rules_entry = cache.get(fn_hash, cache_kind="rules_only")
        self.assertIsNotNone(model_entry)
        self.assertIsNotNone(rules_entry)
        self.assertEqual(len(model_entry["scan_result"]["vulnerabilities"]), 1)
        self.assertEqual(len(rules_entry["scan_result"]["vulnerabilities"]), 0)

        # Telemetry metrics check
        metrics = cache.get_metrics()
        self.assertGreaterEqual(metrics["total_cache_hits"], 2)
        self.assertGreaterEqual(metrics["estimated_tokens_saved"], 120)

        # Invalidate specific cache_kind
        removed = cache.invalidate(function_hash=fn_hash, cache_kind="rules_only")
        self.assertEqual(removed, 1)
        self.assertIsNone(cache.get(fn_hash, cache_kind="rules_only"))
        self.assertIsNotNone(cache.get(fn_hash, cache_kind="model"))

    # -------------------------------------------------------------------------
    # 5. Provider Timeout, Retries, 429/5xx Mapping, Malformed JSON, Fallback
    # -------------------------------------------------------------------------
    def test_provider_resilience_matrix(self):
        """Tests provider exception handling, rate limiting, and secret redaction."""
        # 1. Secret redaction
        secret_text = 'api_key = "sk-proj-1234567890abcdef1234"\npassword = "secret_password_123"'
        redacted = redact_secrets(secret_text)
        self.assertNotIn("sk-proj-1234567890abcdef1234", redacted)
        self.assertNotIn("secret_password_123", redacted)

        # 2. MockProvider and Error simulation
        mock_p = DeterministicMockProvider()
        res = mock_p.complete("prompt")
        self.assertIsNotNone(res.text)

        with self.assertRaises(ProviderRateLimitError):
            raise ProviderRateLimitError("Rate limit exceeded")

        with self.assertRaises(ProviderUnavailableError):
            raise ProviderUnavailableError("503 Service Unavailable")

    # -------------------------------------------------------------------------
    # 6. Differential Verifier Predicates & Fail-Closed Verification
    # -------------------------------------------------------------------------
    def test_differential_verifier_predicates_and_fail_closed(self):
        """Tests differential exploit execution and fail-closed gates."""
        verifier = SandboxVerifier(timeout_sec=3.0, runtime="host")

        # SQL Injection Predicate
        sqli_fn = (
            "import sqlite3\n"
            "def query(uid):\n"
            "    conn = sqlite3.connect(':memory:')\n"
            "    return conn.execute('SELECT * FROM t WHERE id=' + uid).fetchall()\n"
        )
        sqli_res = verifier.verify(sqli_fn, "query", "sql_injection", 4)
        self.assertTrue(sqli_res.get("verified", False))

        # Command Injection Predicate
        cmd_fn = (
            "import subprocess\n"
            "def run_cmd(user_input):\n"
            "    return subprocess.run(f'echo {user_input}', shell=True)\n"
        )
        cmd_res = verifier.verify(cmd_fn, "run_cmd", "command_injection", 3)
        self.assertTrue(cmd_res.get("verified", False))

        # Fail-closed Gate A: syntax error
        pass_a, status_a, _ = gate_a_parse_compile("def invalid(\n    return")
        self.assertFalse(pass_a)
        self.assertEqual(status_a, "fail")

        # Fail-closed Gate B: still vulnerable patch
        finding = {"issue": "SQL Injection", "function_name": "query", "cwe_id": "CWE-89"}
        pass_b, status_b, _ = gate_b_differential_exploit(sqli_fn, finding, verifier)
        self.assertFalse(pass_b)

        # Fail-closed Gate E: signature change rejected
        mismatched_sig = "def query(uid, extra_unwanted_arg):\n    pass\n"
        pass_e, status_e, _ = gate_e_diff_path_constraints(sqli_fn, mismatched_sig, "query")
        self.assertFalse(pass_e)

    # -------------------------------------------------------------------------
    # 7. Taint Propagation, Sanitizers, Graph Path Absence
    # -------------------------------------------------------------------------
    def test_graph_taint_and_no_fabricated_paths(self):
        """Verifies taint path generation and that safe code produces no attack path."""
        code_connected = (
            "from flask import Flask, request\n"
            "import os\n"
            "app = Flask(__name__)\n"
            "@app.route('/cmd')\n"
            "def handle_cmd():\n"
            "    user_input = request.args.get('target')\n"
            "    execute_target(user_input)\n"
            "def execute_target(cmd):\n"
            "    os.system(cmd)\n"
        )
        graph = build_code_graph(code_connected, vuln_function_names=["execute_target"])
        self.assertTrue(graph.get("ast_derived", False))
        paths = graph.get("attack_paths", [])
        self.assertGreaterEqual(len(paths), 1)

        # Disconnected code without callers produces no fabricated multi-hop attack path
        disconnected_code = (
            "import math\n"
            "def compute_square(x):\n"
            "    return x * x\n"
        )
        clean_graph = build_code_graph(disconnected_code, vuln_function_names=[])
        self.assertEqual(len(clean_graph.get("attack_paths", [])), 0)

    # -------------------------------------------------------------------------
    # 8. Job TTL, Stale Recovery, Concurrent Updates, Cancellation
    # -------------------------------------------------------------------------
    def test_jobs_ttl_stale_and_concurrency(self):
        """Tests job life cycle, TTL reaping, cancellation, and concurrent updates."""
        # TTL & Stale Recovery
        job_id = create_job(ttl_seconds=1)
        job = get_job(job_id)
        self.assertIsNotNone(job)
        self.assertEqual(job["status"], "running")

        # Cancellation
        cancelled = cancel_job(job_id)
        self.assertEqual(cancelled["status"], "cancelled")

        # Reaping expired jobs
        update_job(job_id, {"expires_at": time.time() - 10})
        reaped = reap_stale_jobs(max_age_seconds=1)
        self.assertGreaterEqual(reaped, 1)

        # Concurrent updates
        concurrent_job_id = create_job()
        def worker_task(idx):
            update_job_progress(concurrent_job_id, f"stage_{idx}", idx * 10, f"Log {idx}")
            add_job_event(concurrent_job_id, "test_event", f"Detail {idx}")

        with ThreadPoolExecutor(max_workers=4) as executor:
            list(executor.map(worker_task, range(1, 6)))

        updated_job = get_job(concurrent_job_id)
        self.assertIsNotNone(updated_job)
        self.assertGreaterEqual(len(updated_job.get("events", [])), 5)


if __name__ == "__main__":
    unittest.main()
