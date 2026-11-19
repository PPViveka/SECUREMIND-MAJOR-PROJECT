import importlib
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))


class TestDevServerSecurity(unittest.TestCase):

    def test_non_loopback_requires_authentication(self):
        old_host = os.environ.get('HOST')
        old_token = os.environ.get('SAGEARMOR_AUTH_TOKEN')
        try:
            os.environ['HOST'] = '0.0.0.0'
            os.environ['SAGEARMOR_AUTH_TOKEN'] = 'test-token'
            import dev_server
            server = importlib.reload(dev_server)
            client = server.app.test_client()

            unauthenticated = client.get('/healthz')
            authenticated = client.get('/healthz', headers={'X-SageArmor-Token': 'test-token'})

            self.assertEqual(unauthenticated.status_code, 401)
            self.assertEqual(authenticated.status_code, 200)
        finally:
            if old_host is None:
                os.environ.pop('HOST', None)
            else:
                os.environ['HOST'] = old_host
            if old_token is None:
                os.environ.pop('SAGEARMOR_AUTH_TOKEN', None)
            else:
                os.environ['SAGEARMOR_AUTH_TOKEN'] = old_token

    def test_production_rate_limiting_enforcement(self):
        old_limit = os.environ.get('RATE_LIMIT_PER_MINUTE')
        old_host = os.environ.get('HOST')
        try:
            os.environ['RATE_LIMIT_PER_MINUTE'] = '2'
            os.environ['HOST'] = '127.0.0.1'
            import dev_server
            server = importlib.reload(dev_server)
            client = server.app.test_client()

            r1 = client.get('/healthz')
            self.assertEqual(r1.status_code, 200)
            self.assertIn('X-RateLimit-Limit', r1.headers)
            self.assertEqual(r1.headers['X-RateLimit-Limit'], '2')

            r2 = client.get('/healthz')
            self.assertEqual(r2.status_code, 200)

            r3 = client.get('/healthz')
            self.assertEqual(r3.status_code, 429)
            data = json.loads(r3.data)
            self.assertIn('error', data)
            self.assertIn('retry_after_seconds', data)
            self.assertIn('Retry-After', r3.headers)
        finally:
            if old_limit is None:
                os.environ.pop('RATE_LIMIT_PER_MINUTE', None)
            else:
                os.environ['RATE_LIMIT_PER_MINUTE'] = old_limit
            if old_host is None:
                os.environ.pop('HOST', None)
            else:
                os.environ['HOST'] = old_host
            import dev_server
            importlib.reload(dev_server)
            if old_host is None:
                os.environ.pop('HOST', None)
            else:
                os.environ['HOST'] = old_host

    def test_error_envelope_scrubs_secrets(self):
        from src.handler import _json_response
        res = _json_response(400, {"error": "Failed with api_key=secret-value-12345"})
        body = json.loads(res["body"])
        self.assertNotIn("secret-value-12345", body["error"])
        self.assertIn("<REDACTED>", body["error"])

    def test_v2_security_score_endpoint(self):
        import dev_server
        client = dev_server.app.test_client()
        findings = [
            {"issue": "SQLi", "severity": "Critical", "verified": True},
            {"issue": "XSS", "severity": "High", "verified": False}, # Unconfirmed does not deduct
        ]
        res = client.post("/v2/security-score", json={"findings": findings})
        self.assertEqual(res.status_code, 200)
        data = json.loads(res.data)
        self.assertIn("security_score", data)
        self.assertEqual(data["verified_count"], 1)
        self.assertEqual(data["unconfirmed_count"], 1)
        self.assertEqual(data["security_score"], 70) # 100 - 30

    def test_v2_jobs_stream_endpoint(self):
        import dev_server
        from src.job_manager import create_job, update_job_progress
        client = dev_server.app.test_client()
        jid = create_job()
        update_job_progress(jid, "completed", 100, "Done")

        res = client.get(f"/v2/jobs/{jid}/stream")
        self.assertEqual(res.status_code, 200)
        self.assertIn("text/event-stream", res.content_type)

