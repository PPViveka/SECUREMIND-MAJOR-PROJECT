import hashlib
import json
import os
import sys
import unittest
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from src.llm_provider import (
    DeterministicMockProvider,
    RecordedProvider,
    NvidiaProvider,
    BedrockProvider,
    BalancedRouterProvider,
    parse_json_response,
    redact_secrets,
    validate_json_schema,
    create_provider,
    ProviderError,
    ProviderTimeoutError,
    ProviderRateLimitError,
    ProviderAuthError,
    ProviderUnavailableError,
)


class TestLLMProvider(unittest.TestCase):
    def test_json_parser_handles_markdown_and_prefix_text(self):
        self.assertEqual(
            parse_json_response('result: ```json {"vulnerabilities": []} ```'),
            {"vulnerabilities": []},
        )

    def test_mock_provider_is_deterministic_and_reports_estimated_usage(self):
        result = DeterministicMockProvider().complete("scan", as_json=True)
        self.assertEqual(json.loads(result.text), {"vulnerabilities": []})
        self.assertTrue(result.usage["estimated"])

    def test_recorded_provider_uses_prompt_hash(self):
        prompt = "recorded prompt"
        key = hashlib.sha256(prompt.encode("utf-8")).hexdigest()
        result = RecordedProvider({key: {"response": {"vulnerabilities": []}, "usage": {"total_tokens": 3}}}).complete(prompt)
        self.assertEqual(json.loads(result.text), {"vulnerabilities": []})
        self.assertEqual(result.usage, {"total_tokens": 3})

    def test_redact_secrets_removes_credentials_and_private_keys(self):
        text = 'API_KEY="secret-value-123"\n-----BEGIN PRIVATE KEY-----abc-----END PRIVATE KEY-----'
        redacted = redact_secrets(text)
        self.assertNotIn("secret-value-123", redacted)
        self.assertNotIn("BEGIN PRIVATE KEY", redacted)

    def test_nvidia_provider_redacts_prompt_before_request(self):
        provider = NvidiaProvider()
        provider.api_key = "provider-key"
        response = type("Response", (), {
            "status_code": 200,
            "json": lambda self: {"choices": [{"message": {"content": "{}"}}]},
        })()

        captured = {}
        def fake_post(url, headers, json, timeout):
            captured["prompt"] = json["messages"][0]["content"]
            return response

        with patch("src.llm_provider.requests.post", side_effect=fake_post):
            provider.complete('token="secret-value-123"', as_json=True)

        self.assertNotIn("secret-value-123", captured["prompt"])

    def test_json_schema_validation(self):
        schema = {
            "type": "object",
            "required": ["vulnerabilities"],
            "properties": {
                "vulnerabilities": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "required": ["issue", "severity"],
                        "properties": {
                            "issue": {"type": "string"},
                            "severity": {"type": "string"},
                        },
                    },
                },
            },
        }

        valid_data = {"vulnerabilities": [{"issue": "SQLi", "severity": "High"}]}
        valid, err = validate_json_schema(valid_data, schema)
        self.assertTrue(valid)
        self.assertIsNone(err)

        invalid_data = {"vulnerabilities": [{"issue": "SQLi"}]}  # missing severity
        valid, err = validate_json_schema(invalid_data, schema)
        self.assertFalse(valid)
        self.assertIn("severity", str(err))

    def test_balanced_router_provider(self):
        p1 = DeterministicMockProvider()
        p2 = DeterministicMockProvider()
        router = BalancedRouterProvider(providers=[p1, p2])
        res1 = router.complete("test 1", as_json=True)
        self.assertIn("vulnerabilities", res1.text)
        res2 = router.complete("test 2", as_json=True)
        self.assertIn("vulnerabilities", res2.text)

    def test_provider_error_mapping(self):
        provider = NvidiaProvider()
        provider.api_key = "key"

        # 429 Rate limit
        resp_429 = type("Resp", (), {"status_code": 429, "text": "Too many requests"})()
        with patch("src.llm_provider.requests.post", return_value=resp_429):
            with self.assertRaises(ProviderRateLimitError):
                provider.complete("hi")

        # 401 Auth error
        resp_401 = type("Resp", (), {"status_code": 401, "text": "Unauthorized"})()
        with patch("src.llm_provider.requests.post", return_value=resp_401):
            with self.assertRaises(ProviderAuthError):
                provider.complete("hi")

    def test_task_router_per_task_routing(self):
        from src.llm_provider import TaskRouter, ModelProfile
        router = TaskRouter({
            "triage": ModelProfile("triage", "mock", "mock-triage", max_tokens=250),
            "patch": ModelProfile("patch", "mock", "mock-patch", max_tokens=700),
        })

        prov, prof = router.get_provider_for_task("patch")
        self.assertEqual(prof.name, "patch")
        self.assertEqual(prof.max_tokens, 700)

        res = router.route_and_execute("patch", "patch prompt", as_json=True)
        self.assertIsNotNone(res.text)


if __name__ == "__main__":
    unittest.main()