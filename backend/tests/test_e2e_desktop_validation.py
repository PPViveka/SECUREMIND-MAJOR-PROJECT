import json
import os
import sys
import unittest
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
import dev_server
from src import handler
from src import job_manager
from src import verified_fixer
from src import github_commenter

class TestEndToEndDesktopValidation(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = dev_server.app
        cls.client = cls.app.test_client()

    def setUp(self):
        job_manager.set_db_path(":memory:")

    def test_e2e_desktop_full_flow(self):
        """End-to-End verification across all core flows."""
        # 1. Health check
        res_health = self.client.get('/healthz')
        self.assertEqual(res_health.status_code, 200)

        # 2. File scan with diagnostic ranges & badges
        py_fixture = (
            "import os\n"
            "def handle_request(user_cmd):\n"
            "    # Line 3 sink\n"
            "    os.system(user_cmd)\n"
            "    return 'ok'\n"
        )
        res_review = self.client.post('/review', json={
            'code': py_fixture,
            'language': 'python',
            'sync': True
        })
        self.assertEqual(res_review.status_code, 200)
        review_data = res_review.get_json()
        self.assertTrue(len(review_data['vulnerabilities']) >= 1)
        vuln = review_data['vulnerabilities'][0]
        self.assertIn('line', vuln)
        self.assertEqual(vuln['line'], 4)
        self.assertIn('verification_status', vuln)
        self.assertIn(vuln['verification_status'], ['unconfirmed', 'verified', 'refuted', 'not_applicable', 'not_run', 'inconclusive'])

        # 3. Patch validation & rejection of malformed patches
        bad_syntax_patch = "def handle_request(user_cmd): os.system( return"
        gate_a_ok, _, _ = verified_fixer.gate_a_parse_compile(bad_syntax_patch)
        self.assertFalse(gate_a_ok)

        # Safe patch compilation
        good_patch = "import shlex, subprocess\ndef handle_request(user_cmd):\n    subprocess.run(shlex.split(user_cmd))\n    return 'ok'\n"
        gate_a_good, _, _ = verified_fixer.gate_a_parse_compile(good_patch)
        self.assertTrue(gate_a_good)

        # 4. Dashboard endpoints: risk score, attack path, simulation, copilot
        with patch.object(handler, '_invoke_model_json', side_effect=Exception("Model offline")):
            # Risk score
            res_risk = self.client.post('/risk-score', json={'vulnerabilities': review_data['vulnerabilities']})
            self.assertEqual(res_risk.status_code, 200)
            self.assertIn('risk_ranking', res_risk.get_json())

            # Attack path
            res_ap = self.client.post('/attack-path', json={'vulnerabilities': review_data['vulnerabilities']})
            self.assertEqual(res_ap.status_code, 200)
            self.assertIn('attack_paths', res_ap.get_json())

            # Simulation
            res_sim = self.client.post('/simulate', json={'vulnerabilities': review_data['vulnerabilities']})
            self.assertEqual(res_sim.status_code, 200)
            self.assertIn('breach_simulation', res_sim.get_json())

            # Copilot
            res_copilot = self.client.post('/copilot', json={'question': 'How do I remediate command injection?'})
            self.assertEqual(res_copilot.status_code, 200)
            self.assertIn('answer', res_copilot.get_json())

        # 5. Repo scan job flow
        with patch('src.repo_scan_engine.start_progressive_scan'):
            res_job = self.client.post('/repo-scan/start', json={'repo_url': 'https://github.com/owner/repo'})
            self.assertEqual(res_job.status_code, 200)
            job_info = res_job.get_json()
            job_id = job_info['job_id']

            # Check job status
            res_status = self.client.get(f'/repo-scan/status?job_id={job_id}')
            self.assertEqual(res_status.status_code, 200)

        # 6. Signed webhook review
        event = {
            'body': json.dumps({
                'action': 'opened',
                'pull_request': {'diff_url': 'https://github.com/owner/repo/pull/1.diff', 'number': 1},
                'repository': {'full_name': 'owner/repo'}
            }),
            'headers': {'x-hub-signature-256': 'sha256=mock'}
        }
        with patch('src.handler.verify_signature', return_value=True), \
             patch('src.handler.requests.get') as mock_diff_get, \
             patch('src.github_commenter.post_pr_review', return_value=True):
            mock_diff_get.return_value.status_code = 200
            mock_diff_get.return_value.text = "diff --git a/test.py b/test.py\n+os.system(cmd)"
            hook_res = handler.review_code(event, {})
            self.assertEqual(hook_res['statusCode'], 200)

        # 7. Gate calibration run
        from scripts import calibrate_gates
        exit_code = calibrate_gates.calibrate_all_gates()
        self.assertEqual(exit_code, 0)
        report_path = os.path.join(os.path.dirname(__file__), '..', 'benchmarks', 'calibration_report.json')
        self.assertTrue(os.path.exists(report_path))
        with open(report_path) as f:
            report_data = json.load(f)
        self.assertEqual(report_data.get('overall_status').lower(), 'pass')
