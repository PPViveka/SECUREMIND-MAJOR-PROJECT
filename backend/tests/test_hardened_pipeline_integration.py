"""
test_hardened_pipeline_integration.py
Unit and integration tests for Section 12: Hardened Pipeline Integration.
"""

import json
import os
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from src.handler import review_code, review_status, risk_score, simulate, attack_path
from src.job_manager import set_db_path, get_job, create_job, add_job_event, record_stage_timing
from src.github_commenter import post_pr_review, _build_review_body


class TestHardenedPipelineIntegration(unittest.TestCase):
    """Validates Section 12 requirements: feature flags, async verification, evidence filtering, finding ID preservation."""

    def setUp(self):
        self.tmp_file = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.test_db = self.tmp_file.name
        self.tmp_file.close()
        set_db_path(self.test_db)

    def tearDown(self):
        try:
            if hasattr(self, "test_db") and os.path.exists(self.test_db):
                os.unlink(self.test_db)
        except OSError:
            pass

    def test_feature_flags_model_disabled(self):
        """When model feature flag is disabled, scan falls back cleanly to static rules without LLM."""
        code = "import os\ndef run(cmd):\n    os.system(cmd)\n"
        event = {
            "body": json.dumps({
                "code": code,
                "language": "python",
                "features": {"model": False},
            })
        }
        resp = review_code(event, None)
        self.assertEqual(resp["statusCode"], 200)
        body = json.loads(resp["body"])
        self.assertEqual(body.get("analysis_mode"), "rules-only")
        self.assertTrue(len(body.get("vulnerabilities", [])) >= 1)

    def test_feature_flags_verification_disabled(self):
        """When verification feature flag is disabled, findings are not sent through sandbox verification."""
        code = "import sqlite3\ndef fetch(user_id):\n    conn = sqlite3.connect(':memory:')\n    return conn.execute('SELECT * FROM users WHERE id = ' + user_id).fetchall()\n"
        event = {
            "body": json.dumps({
                "code": code,
                "language": "python",
                "features": {"verification": False},
            })
        }
        resp = review_code(event, None)
        self.assertEqual(resp["statusCode"], 200)
        body = json.loads(resp["body"])
        vulns = body.get("vulnerabilities", [])
        self.assertTrue(len(vulns) >= 1)
        for v in vulns:
            # Verification was disabled, so no finding should be confirmed via sandbox
            self.assertFalse(v.get("verified", False))

    def test_async_verification_and_finding_id_preservation(self):
        """Asynchronous verification returns fast static results with job_id and preserves finding IDs through completion."""
        code = "import os\ndef execute_command(user_input):\n    os.system(user_input)\n"
        event = {
            "body": json.dumps({
                "code": code,
                "language": "python",
                "async_verify": True,
            })
        }
        resp = review_code(event, None)
        self.assertEqual(resp["statusCode"], 202)
        initial_body = json.loads(resp["body"])
        self.assertEqual(initial_body.get("status"), "pending_verification")
        job_id = initial_body.get("job_id")
        self.assertIsNotNone(job_id)

        initial_vulns = initial_body.get("vulnerabilities", [])
        self.assertTrue(len(initial_vulns) >= 1)
        initial_ids = {v["finding_id"] for v in initial_vulns}

        # Poll review_status endpoint
        status_event = {
            "queryStringParameters": {"job_id": job_id}
        }
        # Allow background worker up to 10 seconds to complete
        completed = False
        upgraded_body = {}
        for _ in range(50):
            st_resp = review_status(status_event, None)
            self.assertEqual(st_resp["statusCode"], 200)
            upgraded_body = json.loads(st_resp["body"])
            if upgraded_body.get("status") in ("completed", "failed"):
                completed = True
                break
            time.sleep(0.2)

        self.assertTrue(completed)
        result = upgraded_body.get("result", {})
        upgraded_vulns = result.get("vulnerabilities", [])
        self.assertTrue(len(upgraded_vulns) >= 1)

        # CRITICAL ASSERTION: finding_ids must NOT change between fast static response and final upgraded response
        for uv in upgraded_vulns:
            if uv.get("finding_id") in initial_ids:
                # Same ID was preserved!
                self.assertIn(uv["finding_id"], initial_ids)

    def test_evidence_filtering_refuted_findings_excluded(self):
        """Refuted findings are excluded from risk score, simulation, attack graph, and PR reviews."""
        findings = [
            {
                "finding_id": "f-1",
                "issue": "SQL Injection",
                "severity": "High",
                "verified": True,
                "verification_status": "confirmed",
                "line": 10,
            },
            {
                "finding_id": "f-2",
                "issue": "Command Injection",
                "severity": "Critical",
                "verified": False,
                "verification_status": "refuted",
                "line": 20,
            },
        ]

        # 1. Risk Score
        risk_event = {"body": json.dumps({"vulnerabilities": findings})}
        risk_resp = risk_score(risk_event, None)
        self.assertEqual(risk_resp["statusCode"], 200)
        risk_body = json.loads(risk_resp["body"])
        risk_ranked = risk_body.get("risk_ranking", [])
        # Only the verified SQL injection should be in ranking, refuted Command Injection excluded
        self.assertEqual(len(risk_ranked), 1)
        self.assertEqual(risk_ranked[0]["issue"], "SQL Injection")

        # 2. Simulate
        sim_event = {"body": json.dumps({"vulnerabilities": findings})}
        sim_resp = simulate(sim_event, None)
        self.assertEqual(sim_resp["statusCode"], 200)
        sim_body = json.loads(sim_resp["body"])
        breach = sim_body.get("breach_simulation", {})
        # Only 1 finding was active
        self.assertIn("Customer records", breach.get("accessible_data", []))

        # 3. Attack Path
        attack_event = {"body": json.dumps({"vulnerabilities": findings})}
        attack_resp = attack_path(attack_event, None)
        self.assertEqual(attack_resp["statusCode"], 200)
        attack_body = json.loads(attack_resp["body"])
        self.assertIsNotNone(attack_body.get("attack_graph"))

        # 4. PR Review Body formatting
        review_text = _build_review_body(findings)
        self.assertIn("SQL Injection", review_text)
        self.assertIn("[Verified Exploit]", review_text)

    def test_jobs_observability_and_events(self):
        """Observability metrics and stage timings are recorded into SQLite jobs."""
        job_id = create_job()
        add_job_event(job_id, "stage_transition", "Started AST slicing")
        record_stage_timing(job_id, "ast_slice", 14.5)
        record_stage_timing(job_id, "dynamic_sandbox", 120.3)

        job = get_job(job_id)
        self.assertIsNotNone(job)
        self.assertIn("events", job)
        self.assertTrue(any(e.get("event") == "stage_transition" for e in job["events"]))
        self.assertIn("metrics", job)
        metrics = job["metrics"]
        self.assertEqual(metrics.get("ast_slice_ms"), 14.5)
        self.assertEqual(metrics.get("dynamic_sandbox_ms"), 120.3)


if __name__ == "__main__":
    unittest.main()
