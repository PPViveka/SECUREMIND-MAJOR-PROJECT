"""
Unit tests for backend/src/github_commenter.py

Validates:
- Clean pass message when no vulnerabilities are found
- Correct severity emoji mapping for High findings
- post_pr_review returns False when GITHUB_TOKEN is not set
- Avoid duplicate comments on PRs
- Show actual provider/model in review output
- Filter findings to changed files only
"""
import sys
import os
import unittest
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from src.github_commenter import _build_review_body, post_pr_review
from src.repo_selective_scan import _is_allowed_repo_url, parse_github_url


SAMPLE_VULN_HIGH = {
    "severity": "High",
    "issue": "SQL Injection",
    "explanation": "Unsanitized user input is concatenated directly into a SQL query.",
    "poc_exploit_scenario": "1. Attacker sends user_id=1 OR 1=1.\n2. Query returns all rows.",
    "file": "app/db.py",
    "line": 42,
    "remediation": {
        "patch": "cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))",
        "explanation": "Parameterized queries prevent injection by separating data from code.",
    }
}

SAMPLE_VULN_MEDIUM = {
    "severity": "Medium",
    "issue": "Hardcoded Secret",
    "explanation": "API key exposed in source code.",
    "poc_exploit_scenario": "Attacker clones repo and extracts API_KEY from source.",
    "file": "config/settings.py",
    "line": 10,
    "suggested_fix": "Use environment variables instead."
}


class TestBuildReviewBody(unittest.TestCase):

    def test_empty_vulnerabilities_returns_pass_message(self):
        body = _build_review_body([])
        self.assertTrue("Passed" in body or "passed" in body)
        self.assertIn("SageArmor", body)

    def test_high_severity_maps_to_orange_emoji(self):
        body = _build_review_body([SAMPLE_VULN_HIGH])
        self.assertIn("🟠", body)

    def test_medium_severity_maps_to_yellow_emoji(self):
        body = _build_review_body([SAMPLE_VULN_MEDIUM])
        self.assertIn("🟡", body)

    def test_finding_issue_title_appears_in_body(self):
        body = _build_review_body([SAMPLE_VULN_HIGH])
        self.assertIn("SQL Injection", body)

    def test_poc_scenario_appears_in_body(self):
        body = _build_review_body([SAMPLE_VULN_HIGH])
        self.assertIn("Attacker", body)

    def test_remediation_patch_appears_in_body(self):
        body = _build_review_body([SAMPLE_VULN_HIGH])
        self.assertIn("cursor.execute", body)

    def test_fallback_to_suggested_fix_for_old_schema(self):
        body = _build_review_body([SAMPLE_VULN_MEDIUM])
        self.assertIn("environment variables", body)

    def test_multiple_findings_numbered(self):
        body = _build_review_body([SAMPLE_VULN_HIGH, SAMPLE_VULN_MEDIUM])
        self.assertIn("Finding #1", body)
        self.assertIn("Finding #2", body)

    def test_shows_actual_provider_and_model(self):
        body = _build_review_body([SAMPLE_VULN_HIGH], provider="Anthropic", model="claude-3-opus")
        self.assertIn("Anthropic", body)
        self.assertIn("claude-3-opus", body)


class TestPostPrReview(unittest.TestCase):

    def test_repo_url_requires_exact_github_host(self):
        self.assertTrue(_is_allowed_repo_url('https://github.com/owner/repo'))
        self.assertFalse(_is_allowed_repo_url('https://evilgithub.com/owner/repo'))
        self.assertFalse(_is_allowed_repo_url('https://user:pass@github.com/owner/repo'))
        self.assertFalse(_is_allowed_repo_url('http://github.com/owner/repo'))
        self.assertFalse(_is_allowed_repo_url('https://github.com:8443/owner/repo'))

    def test_parse_github_url_rejects_unapproved_host(self):
        with self.assertRaises(ValueError):
            parse_github_url('https://evilgithub.com/owner/repo')

    def test_returns_false_when_token_not_set(self):
        with patch.dict(os.environ, {}, clear=True):
            os.environ.pop('GITHUB_TOKEN', None)
            result = post_pr_review("owner/repo", 42, [SAMPLE_VULN_HIGH])
        self.assertFalse(result)

    def test_returns_true_on_201_response(self):
        mock_response = MagicMock()
        mock_response.status_code = 201

        with patch.dict(os.environ, {'GITHUB_TOKEN': 'fake-token'}):
            with patch('src.github_commenter.requests.get', return_value=MagicMock(status_code=200, json=lambda: [])):
                with patch('src.github_commenter.requests.post', return_value=mock_response):
                    result = post_pr_review("owner/repo", 1, [SAMPLE_VULN_HIGH])
        self.assertTrue(result)

    def test_returns_false_on_401_response(self):
        mock_response = MagicMock()
        mock_response.status_code = 401
        mock_response.text = "Unauthorized"

        with patch.dict(os.environ, {'GITHUB_TOKEN': 'bad-token'}):
            with patch('src.github_commenter.requests.get', return_value=MagicMock(status_code=200, json=lambda: [])):
                with patch('src.github_commenter.requests.post', return_value=mock_response):
                    result = post_pr_review("owner/repo", 1, [])
        self.assertFalse(result)

    def test_rejects_invalid_repository_identifier(self):
        with patch.dict(os.environ, {'GITHUB_TOKEN': 'fake-token'}):
            self.assertFalse(post_pr_review('evil.example/owner/repo', 1, []))

    def test_skips_duplicate_review_comment(self):
        from src.github_commenter import _compute_findings_fingerprint
        fp = _compute_findings_fingerprint([SAMPLE_VULN_HIGH])
        existing_review = {
            "body": f"SageArmor AI — Security Review\n<!-- sagearmor-fingerprint:{fp} -->"
        }
        mock_get = MagicMock(status_code=200, json=lambda: [existing_review])

        with patch.dict(os.environ, {'GITHUB_TOKEN': 'fake-token'}):
            with patch('src.github_commenter.requests.get', return_value=mock_get):
                with patch('src.github_commenter.requests.post') as mock_post:
                    result = post_pr_review("owner/repo", 1, [SAMPLE_VULN_HIGH])
                    self.assertTrue(result)
                    mock_post.assert_not_called()

    def test_filters_findings_to_changed_files_only(self):
        mock_post = MagicMock(status_code=201)
        with patch.dict(os.environ, {'GITHUB_TOKEN': 'fake-token'}):
            with patch('src.github_commenter.requests.get', return_value=MagicMock(status_code=200, json=lambda: [])):
                with patch('src.github_commenter.requests.post', return_value=mock_post) as post_call:
                    post_pr_review(
                        "owner/repo",
                        1,
                        [SAMPLE_VULN_HIGH, SAMPLE_VULN_MEDIUM],
                        changed_files=["app/db.py"]
                    )
                    payload = post_call.call_args[1]["json"]
                    self.assertIn("SQL Injection", payload["body"])
                    self.assertNotIn("Hardcoded Secret", payload["body"])


if __name__ == '__main__':
    unittest.main()
