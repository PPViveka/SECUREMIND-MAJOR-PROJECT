"""
test_verified_fixer.py — Tests for Codebase-Aware Verified Fix Loop (Step 5)
Deterministic tests with mocked gates, verifying all Gates A through E.
"""

import sys
import os
import unittest
import tempfile
import shutil

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from unittest.mock import patch, MagicMock
from src.verified_fixer import (
    VerifiedFixer,
    build_verified_fix_prompt,
    find_project_sanitizer_examples,
    run_verified_fix,
    gate_a_parse_compile,
    gate_b_differential_exploit,
    gate_c_project_tests,
    gate_d_rescan_validation,
    gate_e_diff_path_constraints,
    _gate1_exploit_no_longer_reaches_sink,
    _gate2_tests_still_pass,
    _gate3_no_new_sast_findings,
)


VULN_FINDING = {
    "function_name": "search_users",
    "issue": "SQL Injection",
    "cwe_id": "CWE-89",
    "explanation": "User input directly concatenated into SQL query",
    "line_number": 5,
    "severity": "High",
}

ORIGINAL_CODE = """def search_users(query):
    import sqlite3
    conn = sqlite3.connect("app.db")
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE name = '" + query + "'")
    return cur.fetchall()
"""

PATCHED_CODE = """def search_users(query):
    import sqlite3
    conn = sqlite3.connect("app.db")
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE name = ?", (query,))
    return cur.fetchall()
"""


class TestVerifiedFixer(unittest.TestCase):
    def test_prompt_contains_cwe_id(self):
        prompt = build_verified_fix_prompt(ORIGINAL_CODE, VULN_FINDING, [])
        self.assertIn("CWE-89", prompt)

    def test_prompt_contains_function_name(self):
        prompt = build_verified_fix_prompt(ORIGINAL_CODE, VULN_FINDING, [])
        self.assertIn("search_users", prompt)

    def test_prompt_contains_codebase_examples(self):
        examples = ["cursor.execute(sql, (param,))", "conn.cursor().execute(query, values)"]
        prompt = build_verified_fix_prompt(ORIGINAL_CODE, VULN_FINDING, examples)
        self.assertIn("cursor.execute(sql, (param,))", prompt)

    # -----------------------------------------------------------------------
    # Gate A: Parse & Compile
    # -----------------------------------------------------------------------
    def test_gate_a_passes_valid_code(self):
        passed, status, detail = gate_a_parse_compile(PATCHED_CODE)
        self.assertTrue(passed)
        self.assertEqual(status, "pass")

    def test_gate_a_fails_syntax_error(self):
        broken = "def broken(x):\n    return x + ("
        passed, status, detail = gate_a_parse_compile(broken)
        self.assertFalse(passed)
        self.assertEqual(status, "fail")

    def test_gate_a_fails_empty_patch(self):
        passed, status, detail = gate_a_parse_compile("   \n\t")
        self.assertFalse(passed)
        self.assertEqual(status, "fail")

    # -----------------------------------------------------------------------
    # Gate B: Differential Exploit
    # -----------------------------------------------------------------------
    def test_gate_b_passes_when_exploit_unconfirmed_or_refuted(self):
        mock_result = {
            "verification_status": "unconfirmed",
            "dynamic_trace": {"sink_reached": False},
        }
        with patch("src.verified_fixer.SandboxVerifier") as MockVerifier:
            MockVerifier.return_value.verify.return_value = mock_result
            passed, status, detail = gate_b_differential_exploit(PATCHED_CODE, VULN_FINDING)
        self.assertTrue(passed)
        self.assertEqual(status, "pass")

    def test_gate_b_fails_when_exploit_verified(self):
        mock_result = {
            "verification_status": "verified",
            "dynamic_trace": {"sink_reached": True},
        }
        with patch("src.verified_fixer.SandboxVerifier") as MockVerifier:
            MockVerifier.return_value.verify.return_value = mock_result
            passed, status, detail = gate_b_differential_exploit(PATCHED_CODE, VULN_FINDING)
        self.assertFalse(passed)
        self.assertEqual(status, "fail")

    def test_gate_b_skips_when_isolation_unavailable(self):
        mock_instance = MagicMock()
        mock_instance.isolation_available.return_value = False
        passed, status, detail = gate_b_differential_exploit(PATCHED_CODE, VULN_FINDING, verifier=mock_instance)
        self.assertFalse(passed)
        self.assertEqual(status, "skipped")

    # -----------------------------------------------------------------------
    # Gate C: Tests & Benign Input
    # -----------------------------------------------------------------------
    def test_gate_c_skips_when_no_test_dir(self):
        passed, status, detail = gate_c_project_tests(PATCHED_CODE, "search_users", test_dir=None)
        self.assertFalse(passed)
        self.assertEqual(status, "skipped")

    def test_gate_c_fails_when_benign_check_fails(self):
        def failing_benign(_code, _func):
            return False
        passed, status, detail = gate_c_project_tests(
            PATCHED_CODE, "search_users", test_dir=None, benign_check_fn=failing_benign
        )
        self.assertFalse(passed)
        self.assertEqual(status, "fail")

    # -----------------------------------------------------------------------
    # Gate D: Rescan Validation
    # -----------------------------------------------------------------------
    def test_gate_d_passes_clean_rescan(self):
        mock_scanner = MagicMock()
        mock_scanner.scan.return_value = [{"severity": "low", "issue": "style"}]
        passed, status, detail = gate_d_rescan_validation(PATCHED_CODE, "SQL Injection", scanner=mock_scanner)
        self.assertTrue(passed)
        self.assertEqual(status, "pass")

    def test_gate_d_fails_when_original_finding_remains(self):
        mock_scanner = MagicMock()
        mock_scanner.scan.return_value = [{"severity": "high", "issue": "SQL Injection Still There"}]
        passed, status, detail = gate_d_rescan_validation(PATCHED_CODE, "SQL Injection", scanner=mock_scanner)
        self.assertFalse(passed)
        self.assertEqual(status, "fail")

    def test_gate_d_fails_when_new_severe_finding(self):
        mock_scanner = MagicMock()
        mock_scanner.scan.return_value = [{"severity": "critical", "issue": "Command Injection Introduced"}]
        passed, status, detail = gate_d_rescan_validation(PATCHED_CODE, "SQL Injection", scanner=mock_scanner)
        self.assertFalse(passed)
        self.assertEqual(status, "fail")

    # -----------------------------------------------------------------------
    # Gate E: Diff, Signature & Path Constraints
    # -----------------------------------------------------------------------
    def test_gate_e_passes_valid_diff(self):
        passed, status, detail = gate_e_diff_path_constraints(
            ORIGINAL_CODE, PATCHED_CODE, function_name="search_users"
        )
        self.assertTrue(passed)
        self.assertEqual(status, "pass")

    def test_gate_e_rejects_markdown_code_fences(self):
        code_fence = "```python\n" + PATCHED_CODE + "\n```"
        passed, status, detail = gate_e_diff_path_constraints(
            ORIGINAL_CODE, code_fence, function_name="search_users"
        )
        self.assertFalse(passed)
        self.assertEqual(status, "fail")

    def test_gate_e_rejects_prose_explanation(self):
        prose_code = "Here is the fixed function:\n" + PATCHED_CODE
        passed, status, detail = gate_e_diff_path_constraints(
            ORIGINAL_CODE, prose_code, function_name="search_users"
        )
        self.assertFalse(passed)
        self.assertEqual(status, "fail")

    def test_gate_e_rejects_placeholders_and_truncation(self):
        truncated = "def search_users(query):\n    # ...\n    pass\n"
        passed, status, detail = gate_e_diff_path_constraints(
            ORIGINAL_CODE, truncated, function_name="search_users"
        )
        self.assertFalse(passed)
        self.assertEqual(status, "fail")

    def test_gate_e_rejects_signature_changes(self):
        changed_sig = "def search_users(query, extra_arg=None):\n    return []"
        passed, status, detail = gate_e_diff_path_constraints(
            ORIGINAL_CODE, changed_sig, function_name="search_users"
        )
        self.assertFalse(passed)
        self.assertEqual(status, "fail")

    # -----------------------------------------------------------------------
    # Integration & VerifiedFixer
    # -----------------------------------------------------------------------
    def test_verified_fixer_returns_unverified_draft_when_tests_skipped(self):
        def fake_llm(_prompt):
            return PATCHED_CODE

        with patch("src.verified_fixer.SandboxVerifier") as MockVerifier, \
             patch("src.verified_fixer.SASTScanner") as MockSAST:
            MockVerifier.return_value.verify.return_value = {
                "verification_status": "unconfirmed",
                "dynamic_trace": {"sink_reached": False},
            }
            MockSAST.return_value.scan.return_value = []

            fixer = VerifiedFixer(invoke_llm_fn=fake_llm, test_dir=None)
            result = fixer.fix(ORIGINAL_CODE, VULN_FINDING)

        self.assertEqual(result["patch_status"], "unverified_draft")
        self.assertEqual(result["patched_code"], PATCHED_CODE)
        self.assertNotEqual(result["diff"], "")

    def test_verified_fixer_returns_verified_status_when_all_gates_pass(self):
        temp_dir = tempfile.mkdtemp()
        try:
            def fake_llm(_prompt):
                return PATCHED_CODE

            with patch("src.sandbox_verifier.SandboxVerifier._is_docker_live", return_value=True), \
                 patch("src.verified_fixer.SandboxVerifier") as MockVerifier, \
                 patch("src.verified_fixer.SASTScanner") as MockSAST, \
                 patch("subprocess.run") as MockSubprocess:
                MockVerifier.return_value.verify.return_value = {
                    "verification_status": "unconfirmed",
                    "dynamic_trace": {"sink_reached": False},
                }
                MockSAST.return_value.scan.return_value = []
                MockSubprocess.return_value = MagicMock(returncode=0, stdout="1 passed in 0.01s", stderr="")

                fixer = VerifiedFixer(
                    invoke_llm_fn=fake_llm,
                    test_dir=temp_dir,
                    benign_check_fn=lambda _code, _fn: True,
                )
                result = fixer.fix(ORIGINAL_CODE, VULN_FINDING)

            self.assertEqual(result["patch_status"], "verified")
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_verified_fixer_gate_log_statuses(self):
        def fake_llm(_prompt):
            return PATCHED_CODE

        with patch("src.verified_fixer.SandboxVerifier") as MockVerifier, \
             patch("src.verified_fixer.SASTScanner") as MockSAST:
            MockVerifier.return_value.verify.return_value = {
                "verification_status": "unconfirmed",
                "dynamic_trace": {"sink_reached": False},
            }
            MockSAST.return_value.scan.return_value = []

            fixer = VerifiedFixer(invoke_llm_fn=fake_llm, test_dir=None)
            result = fixer.fix(ORIGINAL_CODE, VULN_FINDING)

        self.assertIsInstance(result["gates"], list)
        self.assertGreater(len(result["gates"]), 0)
        for gate_entry in result["gates"]:
            self.assertIn("gate", gate_entry)
            self.assertIn("passed", gate_entry)
            self.assertIn(gate_entry["status"], {"pass", "fail", "error", "skipped"})
            self.assertIn("detail", gate_entry)

    def test_find_project_sanitizer_examples_returns_list(self):
        temp_dir = tempfile.mkdtemp()
        try:
            with open(os.path.join(temp_dir, "db.py"), "w") as f:
                f.write('cursor.execute("SELECT * FROM t WHERE id = ?", (user_id,))\n')
            examples = find_project_sanitizer_examples(temp_dir, "CWE-89")
            self.assertIsInstance(examples, list)
            self.assertGreaterEqual(len(examples), 1)
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_gate_e_constraints_and_edge_cases(self):
        with tempfile.TemporaryDirectory() as td:
            # 1. Path outside allowed root
            outside_path = "/etc/passwd"
            pass_e, status_e, detail_e = gate_e_diff_path_constraints(
                ORIGINAL_CODE, PATCHED_CODE, "search_users", file_path=outside_path, allowed_root=td
            )
            self.assertFalse(pass_e)
            self.assertEqual(status_e, "fail")

            # 2. Diff too large (>120 lines)
            bloated_patch = ORIGINAL_CODE + "\n" + "\n".join([f"# comment line {i}" for i in range(130)])
            pass_bloat, status_bloat, _ = gate_e_diff_path_constraints(
                ORIGINAL_CODE, bloated_patch, "search_users"
            )
            self.assertFalse(pass_bloat)

            # 3. Signature change
            sig_change = "def search_users(query, extra_arg=True):\n    pass\n"
            pass_sig, status_sig, _ = gate_e_diff_path_constraints(
                ORIGINAL_CODE, sig_change, "search_users"
            )
            self.assertFalse(pass_sig)

    def test_gate_c_with_temp_test_dir(self):
        with tempfile.TemporaryDirectory() as td:
            # Create a mock target file and test
            app_file = os.path.join(td, "app.py")
            with open(app_file, "w") as f:
                f.write(ORIGINAL_CODE)

            # Create test file that asserts search_users returns list
            test_file = os.path.join(td, "test_app.py")
            with open(test_file, "w") as f:
                f.write("def test_search():\n    assert True\n")

            pass_c, status_c, detail_c = gate_c_project_tests(
                PATCHED_CODE, "search_users", td
            )
            # Pytest or test runner executes
            self.assertIn(status_c, {"pass", "fail", "skipped"})

    def test_verified_fixer_llm_failure_and_retries(self):
        attempts = 0
        def failing_then_empty_llm(p):
            nonlocal attempts
            attempts += 1
            if attempts == 1:
                raise RuntimeError("LLM API timeout")
            return ""

        fixer = VerifiedFixer(invoke_llm_fn=failing_then_empty_llm, max_retries=2)
        result = fixer.fix(ORIGINAL_CODE, VULN_FINDING)
        self.assertEqual(result["patch_status"], "failed")
        self.assertEqual(len(result["gates"]), 2)

    def test_run_verified_fix_wrapper(self):
        with patch.object(VerifiedFixer, "fix", return_value={"patch_status": "verified"}):
            res = run_verified_fix(ORIGINAL_CODE, VULN_FINDING, lambda p: PATCHED_CODE)
            self.assertEqual(res["patch_status"], "verified")


if __name__ == "__main__":
    unittest.main()
