"""
test_autofix_verified_integration.py
The autofix engine runs every Python fix through VerifiedFixer (gates A, E, B, C, D).

  - a snippet fix is 'verified' only when all five gates pass
  - a failed gate is fed back to the model and the result stays an unverified draft
  - non-Python snippets never claim verification
  - repository fixes are written only when verified (unless drafts are allowed)
"""

import os
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from src.autofix_engine import _run_snippet_autofix, _run_repo_autofix


VULN_SNIPPET = (
    "def fetch(user_id):\n"
    "    return cursor.execute('SELECT * FROM t WHERE id=' + user_id)\n"
)

PATCHED_FUNCTION = (
    "def fetch(user_id):\n"
    "    return cursor.execute('SELECT * FROM t WHERE id=?', (user_id,))\n"
)

VULNERABILITIES = [{"issue": "SQL Injection", "function_name": "fetch", "cwe_id": "CWE-89", "line_number": 2}]

GATE_B_PASS = {"gate": "exploit_blocked", "passed": True, "status": "pass", "detail": "Gate B PASS: none reached the sink"}
GATE_B_FAIL = {"gate": "exploit_blocked", "passed": False, "status": "fail",
               "detail": "Gate B FAIL: the recorded attack `x' OR 1=1` still reached the sql call"}
BEHAVIOUR_PASS = {"status": "pass", "detail": "behaviour preserved on 2/2 normal inputs", "cases": []}


def _result(mock_append):
    return mock_append.call_args[0][1]


@patch("src.autofix_engine.mark_completed")
@patch("src.autofix_engine.update_job_progress")
@patch("src.autofix_engine.append_partial_result")
class TestSnippetAutofixVerifiedIntegration(unittest.TestCase):

    def _run(self, llm, sast=None, gate_b=GATE_B_PASS, behaviour=BEHAVIOUR_PASS, language="python"):
        with patch("src.verified_fixer.run_gate_b", return_value=gate_b) as gb, \
             patch("src.verified_fixer.run_behaviour_check", return_value=behaviour), \
             patch("src.verified_fixer.SASTScanner") as MockSAST:
            MockSAST.return_value.scan.return_value = sast or []
            _run_snippet_autofix("job", VULN_SNIPPET, VULNERABILITIES, language, "fix",
                                 autofix_fn=lambda *a: {}, fix_llm_fn=llm)
            return gb

    def test_verified_when_all_gates_pass(self, mock_append, _prog, mock_done):
        self._run(lambda prompt: PATCHED_FUNCTION)
        result = _result(mock_append)
        self.assertEqual(result["patch_status"], "verified")
        self.assertEqual(result["confidence"], "Verified Patch")
        self.assertEqual(result["fixed_code"], PATCHED_FUNCTION)
        names = [g["gate"] for g in result["verification_gates"]]
        for gate in ("gate_a_parse_compile", "gate_e_diff_constraints", "exploit_blocked", "tests_pass", "no_new_sast_findings"):
            self.assertIn(gate, names)
        self.assertTrue(all(g["status"] == "pass" for g in result["verification_gates"]))
        self.assertEqual(result["fixes"][0]["patch_status"], "verified")
        # mode 'fix' hands the patched snippet back to the editor
        self.assertEqual(mock_done.call_args[0][3], PATCHED_FUNCTION)

    def test_unverified_draft_when_exploit_still_works_and_feedback_reaches_model(self, mock_append, _prog, _done):
        prompts = []

        def llm(prompt):
            prompts.append(prompt)
            return PATCHED_FUNCTION

        self._run(llm, gate_b=GATE_B_FAIL)
        result = _result(mock_append)
        self.assertEqual(result["patch_status"], "unverified_draft")
        self.assertEqual(len(prompts), 3)  # retried with feedback
        self.assertIn("still reached the sql call", prompts[1])
        self.assertEqual(result["fixes"][0]["failed_gate"]["gate"], "exploit_blocked")

    def test_unverified_draft_when_rescan_fails(self, mock_append, _prog, _done):
        self._run(lambda p: PATCHED_FUNCTION, sast=[{"severity": "high", "issue": "SQL Injection", "line": 2}])
        result = _result(mock_append)
        self.assertEqual(result["patch_status"], "unverified_draft")
        self.assertEqual(result["fixes"][0]["failed_gate"]["gate"], "no_new_sast_findings")

    def test_unverified_draft_when_behaviour_changes(self, mock_append, _prog, _done):
        self._run(lambda p: PATCHED_FUNCTION,
                  behaviour={"status": "fail", "detail": "on normal input `alice` the patched code no longer makes the sql call", "cases": []})
        result = _result(mock_append)
        self.assertEqual(result["patch_status"], "unverified_draft")
        self.assertEqual(result["fixes"][0]["failed_gate"]["gate"], "tests_pass")

    def test_non_python_never_claims_verification(self, mock_append, _prog, _done):
        def autofix_fn(snip, vulns, path):
            return {"fixes": [{"issue": "XSS", "explanation": "escape"}], "modified_content": "const x = escape(y);\n"}

        with patch("src.verified_fixer.VerifiedFixer.fix") as fix:
            _run_snippet_autofix("job", "const x = y;\n", [{"issue": "XSS"}], "javascript", "fix", autofix_fn)
            fix.assert_not_called()
        result = _result(mock_append)
        self.assertEqual(result["patch_status"], "unverified_draft")
        self.assertEqual(result["verification_gates"], [])

    def test_result_has_diff_and_both_versions(self, mock_append, _prog, _done):
        self._run(lambda p: PATCHED_FUNCTION)
        result = _result(mock_append)
        self.assertIn("---", result["diff"])
        self.assertEqual(result["original_code"], VULN_SNIPPET)
        self.assertIn("id=?", result["fixed_code"])

    def test_json_autofix_callback_still_goes_through_the_gates(self, mock_append, _prog, _done):
        def autofix_fn(snip, vulns, path):
            return {"fixes": [{"issue": "SQL Injection"}], "modified_content": PATCHED_FUNCTION}

        with patch("src.verified_fixer.run_gate_b", return_value=GATE_B_PASS), \
             patch("src.verified_fixer.run_behaviour_check", return_value=BEHAVIOUR_PASS), \
             patch("src.verified_fixer.SASTScanner") as MockSAST:
            MockSAST.return_value.scan.return_value = []
            _run_snippet_autofix("job", VULN_SNIPPET, VULNERABILITIES, "python", "preview", autofix_fn)
        result = _result(mock_append)
        self.assertEqual(result["patch_status"], "verified")


class TestRepoAutofixWritesOnlyVerifiedPatches(unittest.TestCase):
    SOURCE = (
        "import os\n\n\n"
        "def run(host):\n"
        "    os.system('ping -c 1 ' + host)\n"
    )
    FIXED = (
        "def run(host):\n"
        "    subprocess.run(['ping', '-c', '1', host], shell=False)\n"
    )

    def _repo(self, gate_b, include_drafts=None, mode="fix"):
        from src.job_manager import create_job, get_job

        def fake_clone(repo_url, target_dir, token=None, branch=None):
            with open(os.path.join(target_dir, "app.py"), "w", encoding="utf-8") as f:
                f.write(self.SOURCE)

        captured = {}

        def fake_mark_completed(job_id, summary, pr_url=None, modified=None):
            captured["modified"] = modified
            captured["summary"] = summary

        job_id = create_job()
        with patch("src.autofix_engine._clone_repository", side_effect=fake_clone), \
             patch("src.autofix_engine.mark_completed", side_effect=fake_mark_completed), \
             patch("src.verified_fixer.run_gate_b", return_value=gate_b), \
             patch("src.verified_fixer.run_behaviour_check", return_value=BEHAVIOUR_PASS), \
             patch("src.verified_fixer.SASTScanner") as MockSAST:
            MockSAST.return_value.scan.return_value = []
            vulns = [{"file_path": "app.py", "issue": "Command Injection", "function_name": "run", "line_number": 5}]
            _run_repo_autofix(job_id, "https://github.com/org/repo", vulns, "tok", "main", mode,
                              autofix_fn=lambda *a: {}, fix_llm_fn=lambda p: "import subprocess\n" + self.FIXED,
                              include_drafts=include_drafts)
        return captured, get_job(job_id)

    def test_verified_patch_is_written(self):
        captured, job = self._repo(GATE_B_PASS)
        self.assertEqual(captured["modified"], ["app.py"])
        item = job["results"][0]
        self.assertEqual(item["patch_status"], "verified")
        self.assertTrue(item["applied"])
        self.assertIn("import subprocess", item["diff"])
        self.assertIn("1 of 1 fixes passed every gate", captured["summary"])

    def test_draft_is_not_written_by_default(self):
        captured, job = self._repo(GATE_B_FAIL)
        self.assertEqual(captured["modified"], [])
        self.assertEqual(job["results"][0]["patch_status"], "unverified_draft")
        self.assertFalse(job["results"][0]["applied"])

    def test_draft_is_written_when_allowed(self):
        captured, _job = self._repo(GATE_B_FAIL, include_drafts=True)
        self.assertEqual(captured["modified"], ["app.py"])


if __name__ == "__main__":
    unittest.main()
