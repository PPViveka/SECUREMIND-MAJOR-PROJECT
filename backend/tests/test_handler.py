"""
Unit tests for backend/src/handler.py

Validates:
- Returns 400 when no code is provided in non-webhook requests
- Returns 401 when GitHub webhook signature is invalid
- Skips non-actionable webhook actions (e.g. 'closed')

All model-provider and GitHub API calls are mocked — zero real network traffic.
"""
import sys
import os
import json
import unittest
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))


def _make_event(body: dict, headers: dict = None) -> dict:
    """Helper that builds a mock Lambda API Gateway event."""
    return {
        "body": json.dumps(body),
        "headers": headers or {},
    }


class TestReviewCodeInputValidation(unittest.TestCase):

    def test_provider_selection_does_not_switch_from_available_keys(self):
        handler, _ = self._patched_import()
        with patch.dict(os.environ, {'LLM_PROVIDER': '', 'MODEL_PROVIDER': '', 'NVIDIA_API_KEY': 'present'}):
            self.assertEqual(handler._get_model_provider(), 'bedrock')

        with patch.dict(os.environ, {'LLM_PROVIDER': '', 'MODEL_PROVIDER': 'unsupported', 'NVIDIA_API_KEY': ''}):
            with self.assertRaises(ValueError):
                handler._get_model_provider()

    def _patched_import(self):
        """Returns handler module with boto3 mocked to prevent init-time AWS calls."""
        mock_bedrock = MagicMock()
        with patch('boto3.client', return_value=mock_bedrock):
            import importlib
            from src import handler
            importlib.reload(handler)
            return handler, mock_bedrock

    def test_returns_400_when_code_is_missing(self):
        handler, _ = self._patched_import()
        event = _make_event({"language": "python"})  # no 'code' key

        with patch.dict(os.environ, {'GITHUB_WEBHOOK_SECRET': ''}):
            response = handler.review_code(event, {})

        self.assertEqual(response["statusCode"], 400)
        body = json.loads(response["body"])
        self.assertIn("error", body)

    def test_returns_400_when_code_is_empty_string(self):
        handler, _ = self._patched_import()
        event = _make_event({"code": "", "language": "python"})

        with patch.dict(os.environ, {'GITHUB_WEBHOOK_SECRET': ''}):
            response = handler.review_code(event, {})

        self.assertEqual(response["statusCode"], 400)

    def test_skips_non_opened_webhook_action(self):
        handler, _ = self._patched_import()
        # 'closed' PR events should be skipped gracefully
        event = _make_event({
            "action": "closed",
            "pull_request": {"diff_url": "https://example.com/diff"},
            "repository": {"full_name": "owner/repo"}
        })

        with patch.dict(os.environ, {'GITHUB_WEBHOOK_SECRET': ''}):
            response = handler.review_code(event, {})

        self.assertEqual(response["statusCode"], 200)
        body = json.loads(response["body"])
        self.assertIn("msg", body)
        self.assertIn("Skipping", body["msg"])

    def test_review_uses_local_fallback_when_model_unavailable(self):
        handler, _ = self._patched_import()
        event = _make_event({
            "code": "query = \"SELECT * FROM users WHERE id = \" + user_id",
            "language": "python",
        })

        with patch.object(handler, '_invoke_model_json', side_effect=Exception("Model unavailable")):
            response = handler.review_code(event, {})

        self.assertEqual(response["statusCode"], 200)
        body = json.loads(response["body"])
        self.assertIn("vulnerabilities", body)
        self.assertGreaterEqual(len(body["vulnerabilities"]), 1)
        self.assertIn("analysis_mode", body)
        self.assertIn("job_id", body)

    def test_envelopes_include_analysis_mode_and_optional_job_id(self):
        handler, _ = self._patched_import()
        # With job_id
        event_with_job = _make_event({
            "code": "query = \"SELECT * FROM users WHERE id = \" + user_id",
            "language": "python",
            "router_mode": "rules-only",
            "job_id": "custom-job-42",
        })
        res = handler.review_code(event_with_job, {})
        body = json.loads(res["body"])
        self.assertEqual(body["job_id"], "custom-job-42")
        self.assertEqual(body["analysis_mode"], "rules-only")

        # Without job_id
        event_no_job = _make_event({
            "code": "query = \"SELECT * FROM users WHERE id = \" + user_id",
            "language": "python",
            "router_mode": "rules-only",
        })
        res_no_job = handler.review_code(event_no_job, {})
        body_no_job = json.loads(res_no_job["body"])
        self.assertIsNone(body_no_job["job_id"])
        self.assertEqual(body_no_job["analysis_mode"], "rules-only")

    def test_healthz_exposes_non_sensitive_service_state(self):
        handler, _ = self._patched_import()

        response = handler.healthz({}, {})

        self.assertEqual(response["statusCode"], 200)
        body = json.loads(response["body"])
        self.assertEqual(body["status"], "ok")
        self.assertIn("schema_version", body)
        self.assertEqual(response["headers"]["X-Request-ID"], body["request_id"])
        self.assertIn("degraded", body)
        self.assertIn("telemetry", body)
        self.assertIn("usage", body)
        self.assertIn("analysis_mode", body)
        self.assertNotIn("NVIDIA_API_KEY", response["body"])

    def test_rejects_oversized_code_snippet(self):
        handler, _ = self._patched_import()
        event = _make_event({"code": "x" * 32, "language": "python"})

        with patch.dict(os.environ, {
            'GITHUB_WEBHOOK_SECRET': '',
            'MAX_CODE_SIZE_BYTES': '16',
        }):
            response = handler.review_code(event, {})

        self.assertEqual(response["statusCode"], 413)

    def test_rejects_unsupported_language(self):
        handler, _ = self._patched_import()
        event = _make_event({"code": "x = 1", "language": "made-up-language"})

        with patch.dict(os.environ, {'GITHUB_WEBHOOK_SECRET': ''}):
            response = handler.review_code(event, {})

        self.assertEqual(response["statusCode"], 400)
        self.assertIn("schema_version", json.loads(response["body"]))

    def test_rules_only_mode_skips_model_pipeline(self):
        handler, _ = self._patched_import()
        event = _make_event({
            "code": "query = \"SELECT * FROM users WHERE id = \" + user_id",
            "language": "python",
            "router_mode": "rules-only",
        })

        with patch.object(handler, '_invoke_model_json', side_effect=AssertionError("model called")):
            response = handler.review_code(event, {})

        self.assertEqual(response["statusCode"], 200)
        self.assertEqual(json.loads(response["body"])["analysis_mode"], "rules-only")

    def test_zero_budget_returns_degraded_local_results(self):
        handler, _ = self._patched_import()
        event = _make_event({"code": "eval(user_input)", "language": "python", "budget": 0})

        with patch.object(handler, '_invoke_model_json', side_effect=AssertionError("model called")):
            response = handler.review_code(event, {})

        body = json.loads(response["body"])
        self.assertEqual(response["statusCode"], 200)
        self.assertEqual(body["analysis_mode"], "budget-exhausted")
        self.assertTrue(body["degraded"])


class TestReviewCodeSignatureValidation(unittest.TestCase):

    def test_returns_401_on_invalid_signature(self):
        mock_bedrock = MagicMock()
        with patch('boto3.client', return_value=mock_bedrock):
            import importlib
            from src import handler
            importlib.reload(handler)

        body_str = json.dumps({"code": "x = 1", "language": "python"})
        event = {
            "body": body_str,
            "headers": {
                "x-hub-signature-256": "sha256=invalidsignature",
            }
        }

        with patch.dict(os.environ, {'GITHUB_WEBHOOK_SECRET': 'real-secret'}):
            response = handler.review_code(event, {})

        self.assertEqual(response["statusCode"], 401)
        body = json.loads(response["body"])
        self.assertIn("error", body)

    def test_returns_401_when_configured_signature_is_missing(self):
        mock_bedrock = MagicMock()
        with patch('boto3.client', return_value=mock_bedrock):
            import importlib
            from src import handler
            importlib.reload(handler)

        event = _make_event({"code": "x = 1", "language": "python"})
        with patch.dict(os.environ, {'GITHUB_WEBHOOK_SECRET': 'real-secret'}):
            response = handler.review_code(event, {})

        self.assertEqual(response["statusCode"], 401)


class TestAdvancedEndpoints(unittest.TestCase):

    def _patched_import(self):
        mock_bedrock = MagicMock()
        with patch('boto3.client', return_value=mock_bedrock):
            import importlib
            from src import handler
            importlib.reload(handler)
            return handler

    def test_attack_path_accepts_vulnerabilities_payload(self):
        handler = self._patched_import()
        event = _make_event({
            "vulnerabilities": [
                {
                    "severity": "High",
                    "issue": "Weak Auth",
                    "explanation": "Token validation is bypassable",
                    "poc_exploit_scenario": "Attacker replays unsigned token",
                }
            ]
        })

        response = handler.attack_path(event, {})
        self.assertEqual(response["statusCode"], 200)
        payload = json.loads(response["body"])
        self.assertIn("attack_graph", payload)
        self.assertIn("attack_paths", payload)

    def test_attack_path_reports_no_proven_path_for_code_only_payload(self):
        handler = self._patched_import()
        event = _make_event({
            "code": "query = \"SELECT * FROM users WHERE id = \" + user_id",
            "language": "python",
        })

        with patch.object(handler, '_invoke_model_json', side_effect=Exception("Model unavailable")):
            response = handler.attack_path(event, {})

        self.assertEqual(response["statusCode"], 200)
        payload = json.loads(response["body"])
        self.assertIn("attack_graph", payload)
        self.assertEqual(payload["attack_paths"], [])
        self.assertIn("path_reason", payload["attack_graph"])

    def test_risk_score_returns_ranked_items(self):
        handler = self._patched_import()
        event = _make_event({
            "vulnerabilities": [
                {
                    "severity": "High",
                    "issue": "SQL Injection",
                    "explanation": "Dynamic SQL in API handler",
                    "poc_exploit_scenario": "Inject OR 1=1",
                }
            ]
        })

        response = handler.risk_score(event, {})
        self.assertEqual(response["statusCode"], 200)
        payload = json.loads(response["body"])
        self.assertIn("risk_ranking", payload)
        self.assertGreaterEqual(len(payload["risk_ranking"]), 1)

    def test_simulate_returns_accessible_data(self):
        handler = self._patched_import()
        event = _make_event({
            "vulnerabilities": [
                {
                    "severity": "Medium",
                    "issue": "Hardcoded Secret",
                    "explanation": "Credential present in source",
                    "poc_exploit_scenario": "Attacker reads key from repo",
                }
            ]
        })

        response = handler.simulate(event, {})
        self.assertEqual(response["statusCode"], 200)
        payload = json.loads(response["body"])
        self.assertIn("breach_simulation", payload)
        self.assertIn("accessible_data", payload["breach_simulation"])

    def test_copilot_requires_question(self):
        handler = self._patched_import()
        event = _make_event({"vulnerabilities": []})

        response = handler.copilot_chat(event, {})
        self.assertEqual(response["statusCode"], 400)

    def test_copilot_returns_answer(self):
        handler = self._patched_import()
        event = _make_event({
            "question": "What should I fix first?",
            "vulnerabilities": [
                {
                    "severity": "High",
                    "issue": "Weak IAM policy",
                    "explanation": "Wildcard permissions",
                    "poc_exploit_scenario": "Privilege escalation",
                }
            ]
        })

        with patch.object(handler, '_invoke_model_text', return_value="Fix IAM wildcard policy first."):
            response = handler.copilot_chat(event, {})

        self.assertEqual(response["statusCode"], 200)
        payload = json.loads(response["body"])
        self.assertIn("answer", payload)

    def test_copilot_falls_back_when_model_unavailable(self):
        handler = self._patched_import()
        event = _make_event({
            "question": "What should I fix first?",
            "code": "password = 'hardcoded123'",
            "language": "python",
        })

        with patch.object(handler, '_invoke_model_text', side_effect=Exception("ModelUnavailable")):
            response = handler.copilot_chat(event, {})

        self.assertEqual(response["statusCode"], 200)
        payload = json.loads(response["body"])
        self.assertIn("answer", payload)
        self.assertEqual(payload.get("analysis_mode"), "local-fallback")

    def test_repo_scan_requires_repo_url(self):
        handler = self._patched_import()
        event = _make_event({"query": "sql injection auth token"})

        response = handler.repo_scan(event, {})
        self.assertEqual(response["statusCode"], 400)
        payload = json.loads(response["body"])
        self.assertIn("error", payload)

    def test_repo_scan_returns_analysis(self):
        handler = self._patched_import()
        event = _make_event({
            "repo_url": "https://github.com/example/repo",
            "query": "sql injection auth token",
            "top_k": 3,
        })

        fake_scan = {
            "repo_stats": {
                "total_seen": 120,
                "text_candidates": 88,
                "matched_files": 6,
                "selected_files": 3,
                "truncated_repo_map": False,
            },
            "keywords": ["sql", "auth", "token"],
            "selected_files": [
                {
                    "path": "src/auth.py",
                    "hit_count": 8,
                    "excerpt": "query = 'SELECT * FROM users WHERE id = ' + user_id",
                }
            ],
        }

        with patch.object(handler, 'selective_repo_scan', return_value=fake_scan), patch.object(handler, '_invoke_model_json', side_effect=Exception('model unavailable')):
            response = handler.repo_scan(event, {})

        self.assertEqual(response["statusCode"], 200)
        payload = json.loads(response["body"])
        self.assertIn("repo_stats", payload)
        self.assertIn("vulnerabilities", payload)
        self.assertIn("risk_ranking", payload)
        self.assertIn("attack_graph", payload)
        self.assertIn("analysis_mode", payload)

    def test_review_rejects_fallback_when_require_model_is_true(self):
        handler = self._patched_import()
        event = _make_event({
            "code": "query = 'SELECT * FROM users WHERE id = ' + user_id\ncursor.execute(query)",
            "language": "python",
            "require_model": True,
        })

        with patch.object(handler, '_invoke_model_json', side_effect=Exception("Model connection refused")):
            response = handler.review_code(event, {})

        self.assertEqual(response["statusCode"], 503)
        payload = json.loads(response["body"])
        self.assertIn("error", payload)
        self.assertTrue(payload.get("degraded"))
        self.assertEqual(payload.get("analysis_mode"), "model-unavailable")


if __name__ == "__main__":
    unittest.main()
