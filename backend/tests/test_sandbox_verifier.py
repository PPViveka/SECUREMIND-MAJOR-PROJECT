import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from src.sandbox_verifier import SandboxVerifier, apply_verification_gate


class TestSandboxVerifier(unittest.TestCase):
    def setUp(self):
        # Unit tests exercise verdict logic; production defaults to Docker isolation.
        self.verifier = SandboxVerifier(timeout_sec=3.0, max_retries=2, runtime="host")

    def test_verified_sql_injection(self):
        # Vulnerable SQLi without sanitization
        code = (
            "def fetch_user(user_id):\n"
            "    query = 'SELECT * FROM users WHERE id = ' + user_id\n"
            "    cursor.execute(query)\n"
            "    return query\n"
        )
        # Line 3 is cursor.execute(query)
        result = self.verifier.verify_vulnerability(
            function_code=code,
            function_name="fetch_user",
            sink_line=3,
            issue_title="SQL Injection Vulnerability",
        )

        self.assertTrue(result.verified)
        self.assertEqual(result.status, "verified")
        self.assertTrue(result.reached_sink)
        self.assertGreaterEqual(len(result.executed_lines), 1)

    def test_unconfirmed_guarded_sql_injection(self):
        # Guarded SQL: input validation halts execution before sink
        code = (
            "def fetch_user(user_id):\n"
            "    if not str(user_id).isalnum():\n"
            "        return None\n"
            "    query = 'SELECT * FROM users WHERE id = ' + user_id\n"
            "    cursor.execute(query)\n"
            "    return query\n"
        )
        # Line 5 is cursor.execute(query)
        result = self.verifier.verify_vulnerability(
            function_code=code,
            function_name="fetch_user",
            sink_line=5,
            issue_title="SQL Injection Vulnerability",
        )

        # Attacker payload ("' OR '1'='1") fails isalnum(), stops at line 3, never hits sink
        self.assertFalse(result.verified)
        self.assertEqual(result.status, "unconfirmed")
        self.assertFalse(result.reached_sink)

    def test_verified_path_traversal(self):
        code = (
            "def read_user_file(file_path):\n"
            "    full_path = '/app/data/' + file_path\n"
            "    with open(full_path, 'r') as f:\n"
            "        return f.read()\n"
        )
        # Line 3 is with open(...)
        result = self.verifier.verify_vulnerability(
            function_code=code,
            function_name="read_user_file",
            sink_line=3,
            issue_title="Path Traversal / Directory Escape",
        )

        self.assertTrue(result.verified)
        self.assertEqual(result.status, "verified")
        self.assertTrue(result.reached_sink)

    def test_unconfirmed_guarded_path_traversal(self):
        code = (
            "def read_user_file(file_path):\n"
            "    if '..' in str(file_path) or '/' in str(file_path):\n"
            "        return 'Access Denied'\n"
            "    full_path = '/app/data/' + file_path\n"
            "    with open(full_path, 'r') as f:\n"
            "        return f.read()\n"
        )
        # Line 5 is with open(...)
        result = self.verifier.verify_vulnerability(
            function_code=code,
            function_name="read_user_file",
            sink_line=5,
            issue_title="Path Traversal / Directory Escape",
        )

        self.assertFalse(result.verified)
        self.assertEqual(result.status, "unconfirmed")
        self.assertFalse(result.reached_sink)

    def test_apply_verification_gate_enrichment(self):
        code = (
            "def fetch_user(user_id):\n"
            "    query = 'SELECT * FROM users WHERE id = ' + user_id\n"
            "    cursor.execute(query)\n"
            "    return query\n"
        )
        vulns = [
            {
                "issue": "SQL Injection Vulnerability",
                "severity": "High",
                "line": 3,
            }
        ]

        enriched = apply_verification_gate(
            vulnerabilities=vulns,
            function_code=code,
            function_name="fetch_user",
            verifier=self.verifier,
        )

        self.assertEqual(len(enriched), 1)
        self.assertEqual(enriched[0]["verification_status"], "verified")
        self.assertTrue(enriched[0]["verified"])
        self.assertIn("dynamic_trace", enriched[0])
        self.assertEqual(enriched[0]["effective_severity"], "High (Verified)")

    def test_sandbox_output_limit_is_enforced(self):
        verifier = SandboxVerifier(timeout_sec=3.0, max_retries=1, runtime="host", max_output_bytes=1024)
        lines, success, error = verifier._execute_harness("print('x' * 2048)")

        self.assertEqual(lines, [])
        self.assertFalse(success)
        self.assertIn("output exceeded", error)

    def test_non_python_language_is_not_applicable(self):
        enriched = apply_verification_gate(
            [{"issue": "SQL Injection", "severity": "High", "line": 2}],
            "function search() { return query; }",
            "search",
            language="javascript",
        )

        assert enriched[0]["verification_status"] == "not_applicable"
        assert enriched[0]["verified"] is False

    def test_context_bundle_excludes_unrelated_module_side_effects(self):
        source = (
            "import os\n"
            "CONSTANT = 'safe'\n"
            "open('/tmp/should-not-run', 'w').write('side effect')\n"
            "def helper(value):\n"
            "    return value + CONSTANT\n"
            "def target(value):\n"
            "    return helper(value)\n"
        )

        bundle = self.verifier.build_context_bundle(source, "target")

        assert "import os" in bundle
        assert "CONSTANT = 'safe'" in bundle
        assert "def helper" in bundle
        assert "should-not-run" not in bundle

    def test_sql_canary_distinguishes_bound_parameters(self):
        safe = (
            "def fetch_user(user_id):\n"
            "    cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))\n"
        )
        result = self.verifier.verify_vulnerability(safe, "fetch_user", 2, "SQL Injection Vulnerability")

        assert result.verified is False
        assert result.status == "unconfirmed"

    def test_command_canary_requires_shell_interpretation(self):
        safe = (
            "def run_command(user_input):\n"
            "    import subprocess\n"
            "    subprocess.run(['echo', user_input], shell=False)\n"
        )
        result = self.verifier.verify_vulnerability(safe, "run_command", 3, "Command Injection")

        assert result.verified is False
        assert result.status == "unconfirmed"

    def test_path_canary_requires_directory_escape(self):
        safe = (
            "def read_file(file_path):\n"
            "    if '..' in file_path:\n"
            "        return 'denied'\n"
            "    return open('/app/data/' + file_path).read()\n"
        )
        result = self.verifier.verify_vulnerability(safe, "read_file", 4, "Path Traversal")

        assert result.verified is False
        assert result.status == "unconfirmed"

    def test_evaluation_canary_confirms_eval(self):
        vuln = (
            "def calc(user_input):\n"
            "    return eval(user_input)\n"
        )
        result = self.verifier.verify_vulnerability(vuln, "calc", 2, "Code Evaluation")
        self.assertTrue(result.verified)
        self.assertEqual(result.status, "verified")

        safe = (
            "def calc(user_input):\n"
            "    if not user_input.isdigit():\n"
            "        return None\n"
            "    return eval(user_input)\n"
        )
        result_safe = self.verifier.verify_vulnerability(safe, "calc", 4, "Code Evaluation")
        self.assertFalse(result_safe.verified)

    def test_stub_influenced_marked_inconclusive(self):
        code_with_unresolved = (
            "import nonexistent_billing_module_xyz\n"
            "def process_charge(amount):\n"
            "    nonexistent_billing_module_xyz.charge(amount)\n"
            "    cursor.execute('SELECT * FROM charges WHERE amt = ' + str(amount))\n"
        )
        result = self.verifier.verify_vulnerability(code_with_unresolved, "process_charge", 4, "SQL Injection")
        self.assertEqual(result.status, "inconclusive")
        self.assertFalse(result.verified)

    def test_audit_record_structure_and_redaction(self):
        code = (
            "def run_secret(api_key):\n"
            "    query = 'SELECT * FROM users WHERE token = ' + api_key\n"
            "    cursor.execute(query)\n"
        )
        result = self.verifier.verify_vulnerability(code, "run_secret", 3, "SQL Injection")
        self.assertIsNotNone(result.audit_record)
        audit = result.audit_record
        self.assertIn("input_hash", audit)
        self.assertIn("context_hash", audit)
        self.assertIn("sandbox_image_digest", audit)
        self.assertIn("harness_hash", audit)
        self.assertIn("canary", audit)
        self.assertIn("hook_records", audit)
        self.assertIn("verdict", audit)
        self.assertIn("duration_ms", audit)
        self.assertIn("failure_reason", audit)

        # Ensure no secrets leak
        record_str = str(audit)
        self.assertNotIn("ghp_fakeToken1234567890", record_str)

    def test_docker_unavailable_fails_closed_without_leak(self):
        from unittest.mock import patch
        # Plant secret in env
        os.environ["SECRET_TEST_TOKEN"] = "SUPER_SECRET_LEAK_TARGET"
        try:
            with patch.object(SandboxVerifier, "_is_docker_live", return_value=False):
                with patch.dict(os.environ, {"SAGE_ARMOR_UNSAFE_LOCAL_SANDBOX": "0"}):
                    prod_verifier = SandboxVerifier(runtime="docker")
                    self.assertFalse(prod_verifier.isolation_available())
                    code = (
                        "def leak_check(val):\n"
                        "    import os\n"
                        "    token = os.environ.get('SECRET_TEST_TOKEN', '')\n"
                        "    cursor.execute('SELECT * FROM t WHERE val=' + token)\n"
                    )
                    res = prod_verifier.verify_vulnerability(code, "leak_check", 4, "SQL Injection")
                    self.assertEqual(res.status, "not_applicable")
                    self.assertFalse(res.verified)
        finally:
            os.environ.pop("SECRET_TEST_TOKEN", None)

    def test_reference_functions_available(self):
        self.assertTrue(hasattr(self.verifier, "REFERENCE_FUNCTIONS"))
        for category in ["sql_injection", "command_injection", "path_traversal", "code_evaluation"]:
            self.assertIn(category, self.verifier.REFERENCE_FUNCTIONS)
            self.assertIn("vulnerable", self.verifier.REFERENCE_FUNCTIONS[category])
            self.assertIn("safe", self.verifier.REFERENCE_FUNCTIONS[category])


if __name__ == "__main__":
    unittest.main()
