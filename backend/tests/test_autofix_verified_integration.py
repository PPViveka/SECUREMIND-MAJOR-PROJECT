"""
test_autofix_verified_integration.py
Integration tests for the Step 5 Verified Fix Loop wired into autofix_engine.py

Tests confirm:
  - snippet autofix tags result 'verified' when all 3 gates pass
  - snippet autofix tags result 'unverified_draft' when any gate fails
  - verification_gates list is always present in the result
  - non-python snippets skip verification (gate functions not called)
"""

import sys
import os
import unittest
from unittest.mock import patch, call

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from src.autofix_engine import _run_snippet_autofix


VULN_SNIPPET = (
    "def fetch(user_id):\n"
    "    return cursor.execute('SELECT * FROM t WHERE id=' + user_id)\n"
)

PATCHED_SNIPPET = (
    "def fetch(user_id):\n"
    "    return cursor.execute('SELECT * FROM t WHERE id=?', (user_id,))\n"
)

VULNERABILITIES = [
    {"issue": "SQL Injection", "function_name": "fetch", "cwe_id": "CWE-89"}
]


def _make_llm_fix(patched_code):
    """Return an autofix_fn that always returns a fixed version."""
    def autofix_fn(snip, vulns, path):
        return {
            "fixes": [{"issue": "SQL Injection", "explanation": "Used parameterized query"}],
            "modified_content": patched_code,
        }
    return autofix_fn


class TestSnippetAutofixVerifiedIntegration(unittest.TestCase):

    @patch("src.autofix_engine.mark_completed")
    @patch("src.autofix_engine.update_job_progress")
    @patch("src.autofix_engine.append_partial_result")
    @patch("src.autofix_engine._gate3_no_new_sast_findings", return_value=(True, "Gate 3 PASS"))
    @patch("src.autofix_engine._gate2_tests_still_pass", return_value=(True, "Gate 2 PASS"))
    @patch("src.autofix_engine._gate1_exploit_no_longer_reaches_sink", return_value=(True, "Gate 1 PASS"))
    def test_verified_when_all_gates_pass(self, mock_g1, mock_g2, mock_g3, mock_append, mock_prog, mock_done):
        _run_snippet_autofix(
            "job-001", VULN_SNIPPET, VULNERABILITIES,
            "python", "suggest", _make_llm_fix(PATCHED_SNIPPET)
        )

        self.assertTrue(mock_append.called)
        result = mock_append.call_args[0][1]
        self.assertEqual(result["patch_status"], "verified")
        self.assertEqual(result["confidence"], "Verified Patch")
        self.assertEqual(len(result["verification_gates"]), 3)
        self.assertTrue(all(g["passed"] for g in result["verification_gates"]))

    @patch("src.autofix_engine.mark_completed")
    @patch("src.autofix_engine.update_job_progress")
    @patch("src.autofix_engine.append_partial_result")
    @patch("src.autofix_engine._gate3_no_new_sast_findings", return_value=(True, "Gate 3 PASS"))
    @patch("src.autofix_engine._gate2_tests_still_pass", return_value=(True, "Gate 2 PASS"))
    @patch("src.autofix_engine._gate1_exploit_no_longer_reaches_sink", return_value=(False, "Gate 1 FAIL: exploit still reaches sink"))
    def test_unverified_draft_when_gate1_fails(self, mock_g1, mock_g2, mock_g3, mock_append, mock_prog, mock_done):
        _run_snippet_autofix(
            "job-002", VULN_SNIPPET, VULNERABILITIES,
            "python", "suggest", _make_llm_fix(PATCHED_SNIPPET)
        )

        self.assertTrue(mock_append.called)
        result = mock_append.call_args[0][1]
        self.assertEqual(result["patch_status"], "unverified_draft")
        self.assertEqual(result["confidence"], "Unverified Draft")
        self.assertFalse(result["verification_gates"][0]["passed"])

    @patch("src.autofix_engine.mark_completed")
    @patch("src.autofix_engine.update_job_progress")
    @patch("src.autofix_engine.append_partial_result")
    @patch("src.autofix_engine._gate3_no_new_sast_findings", return_value=(False, "Gate 3 FAIL: new findings"))
    @patch("src.autofix_engine._gate2_tests_still_pass", return_value=(True, "Gate 2 PASS"))
    @patch("src.autofix_engine._gate1_exploit_no_longer_reaches_sink", return_value=(True, "Gate 1 PASS"))
    def test_unverified_draft_when_gate3_fails(self, mock_g1, mock_g2, mock_g3, mock_append, mock_prog, mock_done):
        _run_snippet_autofix(
            "job-003", VULN_SNIPPET, VULNERABILITIES,
            "python", "suggest", _make_llm_fix(PATCHED_SNIPPET)
        )

        result = mock_append.call_args[0][1]
        self.assertEqual(result["patch_status"], "unverified_draft")
        # Gate 3 is the failing one
        gate3 = next(g for g in result["verification_gates"] if g["gate"] == "no_new_sast_findings")
        self.assertFalse(gate3["passed"])

    @patch("src.autofix_engine.mark_completed")
    @patch("src.autofix_engine.update_job_progress")
    @patch("src.autofix_engine.append_partial_result")
    @patch("src.autofix_engine._gate1_exploit_no_longer_reaches_sink")
    def test_non_python_skips_verification_gates(self, mock_g1, mock_append, mock_prog, mock_done):
        """JavaScript snippets should skip gate verification (python-only)."""
        js_snippet = "function fetch(id) { db.query('SELECT * FROM t WHERE id=' + id); }"
        js_vulns = [{"issue": "SQL Injection", "function_name": "fetch", "cwe_id": "CWE-89"}]

        def js_llm_fix(snip, vulns, path):
            return {
                "fixes": [{"issue": "SQL Injection", "explanation": "Parameterized"}],
                "modified_content": "function fetch(id) { db.query('SELECT * FROM t WHERE id=?', [id]); }",
            }

        _run_snippet_autofix("job-004", js_snippet, js_vulns, "javascript", "suggest", js_llm_fix)

        # Gate 1 must NOT be called for non-python
        mock_g1.assert_not_called()

    @patch("src.autofix_engine.mark_completed")
    @patch("src.autofix_engine.update_job_progress")
    @patch("src.autofix_engine.append_partial_result")
    @patch("src.autofix_engine._gate3_no_new_sast_findings", return_value=(True, "Gate 3 PASS"))
    @patch("src.autofix_engine._gate2_tests_still_pass", return_value=(True, "Gate 2 PASS"))
    @patch("src.autofix_engine._gate1_exploit_no_longer_reaches_sink", return_value=(True, "Gate 1 PASS"))
    def test_result_always_has_diff(self, mock_g1, mock_g2, mock_g3, mock_append, mock_prog, mock_done):
        """The result dict must include a non-empty diff when code changed."""
        _run_snippet_autofix(
            "job-005", VULN_SNIPPET, VULNERABILITIES,
            "python", "suggest", _make_llm_fix(PATCHED_SNIPPET)
        )

        result = mock_append.call_args[0][1]
        self.assertIn("diff", result)
        self.assertGreater(len(result["diff"]), 0)

    @patch("src.autofix_engine.mark_completed")
    @patch("src.autofix_engine.update_job_progress")
    @patch("src.autofix_engine.append_partial_result")
    @patch("src.autofix_engine._gate3_no_new_sast_findings", return_value=(True, "Gate 3 PASS"))
    @patch("src.autofix_engine._gate2_tests_still_pass", return_value=(True, "Gate 2 PASS"))
    @patch("src.autofix_engine._gate1_exploit_no_longer_reaches_sink", return_value=(True, "Gate 1 PASS"))
    def test_result_includes_original_and_fixed_code(self, mock_g1, mock_g2, mock_g3, mock_append, mock_prog, mock_done):
        """Result must carry original_code and fixed_code for the frontend."""
        _run_snippet_autofix(
            "job-006", VULN_SNIPPET, VULNERABILITIES,
            "python", "suggest", _make_llm_fix(PATCHED_SNIPPET)
        )

        result = mock_append.call_args[0][1]
        self.assertEqual(result["original_code"], VULN_SNIPPET)
        self.assertEqual(result["fixed_code"], PATCHED_SNIPPET)


if __name__ == "__main__":
    unittest.main()
