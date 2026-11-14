import unittest
from src.sandbox_verifier import SandboxVerifier, apply_verification_gate


class TestSandboxVerifier(unittest.TestCase):
    def setUp(self):
        self.verifier = SandboxVerifier(timeout_sec=3.0, max_retries=2)

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


if __name__ == "__main__":
    unittest.main()
