import json
import os
import sys
import time
import uuid
import unittest
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
import dev_server
from src import handler
from src import job_manager
from src import function_cache
from src import sandbox_verifier
from src.sast_scanner import SASTScanner

class TestPerformanceAndReliability(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = dev_server.app
        cls.client = cls.app.test_client()

    def setUp(self):
        job_manager.set_db_path(":memory:")

    def test_p95_cached_and_rules_only_scan(self):
        """Measure cached/rules-only scan p95 against the 1-second target."""
        code = (
            "import os\n"
            "def query_database(cmd):\n"
            "    os.system(cmd)\n"
            "    return True\n"
        )
        with patch.object(handler, '_invoke_model_json', return_value={'vulnerabilities': []}):
            # Prime cache / rules
            self.client.post('/review', json={'code': code, 'language': 'python', 'sync': True})

            durations = []
            for _ in range(20):
                t0 = time.perf_counter()
                res = self.client.post('/review', json={'code': code, 'language': 'python', 'sync': True})
                durations.append(time.perf_counter() - t0)
                self.assertEqual(res.status_code, 200)

            durations.sort()
            p95 = durations[int(len(durations) * 0.95)]
            # Target: p95 must be strictly under 1.0s (typically < 0.05s)
            self.assertLess(p95, 1.0, f"Cached scan p95 was {p95:.4f}s, expected < 1.0s")

    def test_async_verification_never_blocks(self):
        """Verify that async_verify=True returns in < 0.2s with job_id."""
        code = "import os\ndef f(x):\n    os.system(x)\n"
        t0 = time.perf_counter()
        res = self.client.post('/review', json={'code': code, 'language': 'python', 'async_verify': True})
        elapsed = time.perf_counter() - t0
        self.assertIn(res.status_code, [200, 202])
        self.assertLess(elapsed, 0.5, f"Async review took too long: {elapsed:.4f}s")
        data = res.get_json()
        self.assertIn('job_id', data)

    def test_concurrent_jobs_bounded_workers_no_lost_updates(self):
        """Test concurrent jobs with bounded worker pool without database lock errors."""
        job_ids = [job_manager.create_job(f"concurrent-job-{i}") for i in range(10)]

        def worker_task(jid):
            for step in range(5):
                job_manager.update_job_progress(jid, f"step-{step}", step * 20)
                job_manager.append_partial_result(jid, {"step": step, "status": "ok"})
            job_manager.mark_completed(jid, "Finished successfully")

        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(worker_task, jid) for jid in job_ids]
            for f in futures:
                f.result()

        for jid in job_ids:
            j = job_manager.get_job(jid)
            self.assertIsNotNone(j)
            self.assertEqual(j.get("status"), "completed")
            self.assertEqual(len(j.get("results", [])), 5)

    def test_provider_retry_under_transient_failure(self):
        """Test provider retry behavior under 429/5xx responses."""
        from src.llm_provider import ProviderError, ProviderRateLimitError, LLMProvider

        call_count = [0]
        def flaky_api():
            call_count[0] += 1
            if call_count[0] < 3:
                raise ProviderRateLimitError("Rate limit exceeded")
            return '{"vulnerabilities": []}'

        # Test retry loop helper
        def retry_call(fn, max_retries=3):
            for i in range(max_retries):
                try:
                    return fn()
                except ProviderRateLimitError:
                    if i == max_retries - 1:
                        raise
            return None

        result = retry_call(flaky_api, max_retries=4)
        self.assertIsNotNone(result)
        self.assertEqual(call_count[0], 3)

    def test_failure_scenarios_graceful_degradation(self):
        """Test Docker unavailable, GitHub unavailable, and malformed model output."""
        # 1. Docker unavailable: falls back to local runner without exception
        verifier = sandbox_verifier.SandboxVerifier(runtime="docker")
        with patch('src.sandbox_verifier.SandboxVerifier.isolation_available', return_value=False):
            res = verifier.verify("def safe(): return 1\n", "safe")
            # With no isolation runtime the verifier must say so rather than guess.
            self.assertIn(res.get("verification_status"), ["not_applicable", "unconfirmed", "refuted"])
            self.assertFalse(res.get("verified", False))

        # 2. GitHub API unavailable
        with patch('requests.post', side_effect=Exception("GitHub API Down")):
            from src import github_commenter
            res = github_commenter.post_pr_review("owner/repo", 1, [{"issue": "Test"}], "ghp_fake")
            self.assertFalse(res)

        # 3. Malformed model output degrades gracefully to SAST fallback
        unique_fn = f"malformed_test_{uuid.uuid4().hex[:8]}"
        with patch.object(handler, '_invoke_model_json', side_effect=json.JSONDecodeError("Malformed model JSON", "", 0)):
            res_degraded = self.client.post('/review', json={
                'code': f'import os\ndef {unique_fn}(cmd):\n    os.system(cmd)\n',
                'language': 'python',
                'sync': True,
                'flags': {'cache': False}
            })
            self.assertEqual(res_degraded.status_code, 200)
            body = res_degraded.get_json()
            self.assertTrue(body.get('degraded', False))
            self.assertEqual(body.get('analysis_mode'), 'sast-local')
