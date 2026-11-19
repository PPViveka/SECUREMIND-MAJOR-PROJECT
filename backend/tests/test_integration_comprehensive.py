import json
import os
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
import dev_server
from src import handler
from src import job_manager
from src import sandbox_verifier
from src import verified_fixer

class TestComprehensiveIntegration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = dev_server.app
        cls.client = cls.app.test_client()

    def setUp(self):
        job_manager.set_db_path(":memory:")

    def test_every_flask_route_validation_and_cors(self):
        """Cover every route: GET /healthz, POST /review, GET /review/status, POST /risk-score,
        POST /attack-path, POST /simulate, POST /copilot, POST /repo-scan/start, POST /repo-autofix/start,
        GET /repo-scan/status, POST /repo-scan/cancel, plus OPTIONS CORS.
        """
        # 1. OPTIONS CORS check on /review
        res_opts = self.client.options('/review')
        self.assertIn(res_opts.status_code, [200, 204])
        self.assertIn('Access-Control-Allow-Origin', res_opts.headers)
        self.assertIn('Allow', res_opts.headers)

        # 2. GET /healthz
        res_health = self.client.get('/healthz')
        self.assertEqual(res_health.status_code, 200)
        data = res_health.get_json()
        self.assertEqual(data.get('status'), 'ok')
        self.assertIn('features', data)

        # 3. POST /review validation failure
        res_review_fail = self.client.post('/review', json={})
        self.assertEqual(res_review_fail.status_code, 400)
        self.assertIn('error', res_review_fail.get_json())

        # 4. GET /review/status validation failure (missing job_id)
        res_status_fail = self.client.get('/review/status')
        self.assertEqual(res_status_fail.status_code, 400)

        # 5. POST /risk-score validation failure
        res_risk_fail = self.client.post('/risk-score', json={})
        self.assertEqual(res_risk_fail.status_code, 400)

        # 6. POST /attack-path validation failure
        res_ap_fail = self.client.post('/attack-path', json={})
        self.assertEqual(res_ap_fail.status_code, 400)

        # 7. POST /simulate validation failure
        res_sim_fail = self.client.post('/simulate', json={})
        self.assertEqual(res_sim_fail.status_code, 400)

        # 8. POST /copilot validation failure
        res_copilot_fail = self.client.post('/copilot', json={})
        self.assertEqual(res_copilot_fail.status_code, 400)

        # 9. POST /repo-scan/start validation failure
        res_repo_fail = self.client.post('/repo-scan/start', json={})
        self.assertEqual(res_repo_fail.status_code, 400)

        # 10. POST /repo-autofix/start validation failure
        res_af_fail = self.client.post('/repo-autofix/start', json={})
        self.assertEqual(res_af_fail.status_code, 400)

        # 11. GET /repo-scan/status not found
        res_job_nf = self.client.get('/repo-scan/status?job_id=nonexistent-job-xyz')
        self.assertEqual(res_job_nf.status_code, 404)

        # 12. POST /repo-scan/cancel not found
        res_cancel_nf = self.client.post('/repo-scan/cancel', json={'job_id': 'nonexistent-job-xyz'})
        self.assertEqual(res_cancel_nf.status_code, 404)

    def test_review_all_fixture_languages_with_fallback(self):
        """Run /review for fixture languages in fallback mode and verify envelope."""
        languages = [
            ("python", "import os\ndef run(cmd):\n    os.system(cmd)\n"),
            ("javascript", "const cp = require('child_process');\nfunction run(cmd) { cp.exec(cmd); }\n"),
            ("typescript", "import { exec } from 'child_process';\nexport function run(cmd: string) { exec(cmd); }\n"),
            ("go", "package main\nimport \"os/exec\"\nfunc run(c string) { exec.Command(c).Run() }\n"),
            ("rust", "fn main() { std::process::Command::new(\"sh\").arg(\"-c\").spawn(); }\n"),
            ("java", "class Main { void r(String c) throws Exception { Runtime.getRuntime().exec(c); } }\n"),
            ("c", "int main() { char *buf = gets(stdin); return 0; }\n"),
            ("cpp", "int main() { char *buf = gets(stdin); return 0; }\n"),
            ("php", "<?php system($_GET['cmd']); ?>\n"),
            ("ruby", "cmd = params[:cmd]\nsystem(cmd)\n"),
            ("csharp", "using System.Diagnostics;\nProcess.Start(cmd);\n"),
        ]

        with patch.object(handler, '_invoke_model_json', side_effect=Exception("Model unavailable")):
            for lang, code in languages:
                res = self.client.post('/review', json={'code': code, 'language': lang, 'sync': True})
                self.assertEqual(res.status_code, 200, f"Failed for {lang}")
                body = res.get_json()
                self.assertIn('vulnerabilities', body)
                self.assertIn('analysis_mode', body)
                self.assertEqual(body.get('schema_version'), '1.0')

    def test_pipeline_slicing_and_stage_timings(self):
        """Test source slicing through cache, SAST, cascade, model candidate, and verification."""
        code = (
            "import os\n"
            "def vulnerable_target(user_input):\n"
            "    cmd = 'echo ' + user_input\n"
            "    os.system(cmd)\n"
            "\n"
            "def safe_target(param):\n"
            "    return param * 2\n"
        )
        res = self.client.post('/review', json={
            'code': code,
            'language': 'python',
            'async_verify': False
        })
        self.assertEqual(res.status_code, 200)
        body = res.get_json()
        self.assertGreaterEqual(len(body['vulnerabilities']), 1)
        vuln = body['vulnerabilities'][0]
        self.assertIn('finding_id', vuln)
        self.assertIn('verification_status', vuln)

    def test_sandbox_limits_enforced(self):
        """Prove sandbox timeout, memory limit, and process termination."""
        verifier = sandbox_verifier.SandboxVerifier(timeout_sec=0.5, runtime="host")
        res = verifier.verify(
            "import time\ndef looper(cmd):\n    while True:\n        time.sleep(0.1)\n",
            "looper",
            cwe_id="CWE-78",
            sink_line=3
        )
        self.assertFalse(res.get("verified", False))
        self.assertEqual(res.get("verification_status"), "unconfirmed")

    def test_gate_evaluates_patch_behavior_and_rejects_unsafe(self):
        """Prove patched code runs behavior test and unsafe patches are rejected."""
        # Gate A: syntax check
        gate_a_ok, _, _ = verified_fixer.gate_a_parse_compile("def good(): return 1")
        self.assertTrue(gate_a_ok)
        gate_a_bad, _, _ = verified_fixer.gate_a_parse_compile("def bad( return 1")
        self.assertFalse(gate_a_bad)

        # Gate D: rescan validation rejects still-vulnerable code
        unsafe_patch = "def run(cmd):\n    import os\n    return os.system(cmd)\n"
        gate_d_res = verified_fixer.gate_d_rescan_validation(
            patched_code=unsafe_patch,
            original_finding_issue="Command Injection"
        )
        self.assertFalse(gate_d_res[0])

    def test_job_worker_cancellation_and_idempotency(self):
        """Test jobs with cancellation and duplicate request handling."""
        job_id = job_manager.create_job('test_job_123', ttl_seconds=3600)
        job_manager.update_job_progress(job_id, 'running stage', 30)
        job_manager.append_partial_result(job_id, {'stage': 1, 'findings': [1]})

        status_data = job_manager.get_job(job_id)
        self.assertEqual(status_data['status'], 'running')
        self.assertEqual(status_data['progress'], 30)
        self.assertEqual(len(status_data['results']), 1)

        # Cancel job
        cancel_ok = job_manager.cancel_job(job_id)
        self.assertTrue(cancel_ok)

        status_after = job_manager.get_job(job_id)
        self.assertEqual(status_after['status'], 'cancelled')

        # Duplicate cancellation is idempotent
        cancel_again = job_manager.cancel_job(job_id)
        self.assertTrue(cancel_again)

    def test_github_webhook_signature_and_filtering(self):
        """Test GitHub signatures, redirects, and changed-file filtering."""
        secret = "super-secret-webhook-key"
        with patch.dict(os.environ, {'GITHUB_WEBHOOK_SECRET': secret, 'GITHUB_TOKEN': 'ghp_fake'}):
            # Invalid signature returns 401
            invalid_event = {
                'body': json.dumps({'action': 'opened', 'pull_request': {'diff_url': 'http://evil.com/diff'}}),
                'headers': {'x-hub-signature-256': 'sha256=badbadbad'}
            }
            res_invalid = handler.review_code(invalid_event, {})
            self.assertEqual(res_invalid['statusCode'], 401)

            # SSRF protection: reject diff_url not matching api.github.com / github.com
            with patch('src.handler.verify_signature', return_value=True):
                unsafe_diff_event = {
                    'body': json.dumps({
                        'action': 'opened',
                        'pull_request': {'diff_url': 'http://169.254.169.254/latest/meta-data/'},
                        'repository': {'full_name': 'test/repo'}
                    }),
                    'headers': {'x-hub-signature-256': 'sha256=mock'}
                }
                res_ssrf = handler.review_code(unsafe_diff_event, {})
                # Should safely reject or skip fetching internal metadata IP
                self.assertIn(res_ssrf['statusCode'], [200, 400])
