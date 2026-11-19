import os
import sys
import tempfile
import threading
import time
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import src.job_manager as manager


class TestJobManagerSQLite(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.temp_dir.name, "test_jobs.db")
        os.environ["SAGEARMOR_JOBS_DB"] = self.db_path
        manager.set_db_path(self.db_path)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_job_lifecycle_persists_in_sqlite(self):
        job_id = manager.create_job("job-1")
        manager.update_job_progress(job_id, "scanning", 40, "Scanning")
        manager.append_partial_result(job_id, {"finding_id": "f-1"})
        manager.mark_completed(job_id, "Done")

        job = manager.get_job(job_id)
        self.assertEqual(job["status"], "completed")
        self.assertEqual(job["results"], [{"finding_id": "f-1"}])
        self.assertEqual(job["progress"], 100)
        self.assertTrue(os.path.exists(self.db_path))

    def test_concurrent_updates_are_not_lost(self):
        job_id = manager.create_job("job-2")
        errors = []

        def append(index):
            try:
                manager.append_partial_result(job_id, {"index": index})
            except Exception as exc:
                errors.append(exc)

        threads = [threading.Thread(target=append, args=(i,)) for i in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(errors, [])
        job = manager.get_job(job_id)
        self.assertEqual(len(job["results"]), 10)

    def test_duplicate_start_is_idempotent_and_cancel_is_terminal(self):
        job_id = manager.create_job("job-3")
        manager.update_job_progress(job_id, "scanning", 40)
        self.assertEqual(manager.create_job(job_id), job_id)
        self.assertEqual(manager.get_job(job_id)["progress"], 40)

        cancelled = manager.cancel_job(job_id)
        self.assertEqual(cancelled["status"], "cancelled")
        self.assertEqual(manager.cancel_job(job_id)["status"], "cancelled")

    def test_events_and_observability_tracking(self):
        job_id = manager.create_job("job-obs")
        manager.add_job_event(job_id, "phase_start", {"stage": "sast"})
        manager.record_stage_timing(job_id, "sast_scan", 1.25)
        manager.record_observability(
            job_id,
            provider_calls=2,
            token_usage={"prompt_tokens": 100, "completion_tokens": 50, "total_tokens": 150},
            cache_hits=1,
            verdicts={"confirmed": 1, "refuted": 0},
            gate_health={"gate_a": "pass", "gate_b": "pass"},
        )
        manager.mark_completed(job_id, "Done")

        job = manager.get_job(job_id)
        event_types = [e["type"] for e in job["events"]]
        self.assertIn("job_created", event_types)
        self.assertIn("phase_start", event_types)
        self.assertIn("job_completed", event_types)

        obs = job["observability"]
        self.assertEqual(obs["stage_timings"]["sast_scan"], 1.25)
        self.assertEqual(obs["provider_calls"], 2)
        self.assertEqual(obs["token_usage"]["total_tokens"], 150)
        self.assertEqual(obs["cache_hits"], 1)
        self.assertEqual(obs["verdict_counts"]["confirmed"], 1)
        self.assertEqual(obs["gate_health"]["gate_a"], "pass")

    def test_stale_job_reaping(self):
        job_id = manager.create_job("job-stale", ttl_seconds=1)
        # Manually alter expires_at to be in the past
        conn = manager._connect()
        try:
            conn.execute(
                "UPDATE jobs SET expires_at = ? WHERE job_id = ?",
                (time.time() - 100, job_id),
            )
            conn.commit()
        finally:
            conn.close()

        reaped = manager.reap_stale_jobs()
        self.assertGreater(reaped, 0)
        self.assertIsNone(manager.get_job(job_id))

    def test_safe_restart_orphaned_jobs(self):
        # Create a job and leave it running
        job_id = manager.create_job("job-running")
        manager.update_job_progress(job_id, "running", 50)
        # Re-initialize DB as if app restarted
        restarted = manager.recover_interrupted_jobs()
        self.assertIn(job_id, restarted)
        job = manager.get_job(job_id)
        self.assertEqual(job["status"], "interrupted")

    def test_submit_job_async_execution(self):
        job_id = manager.create_job("job-async")

        def worker(jid):
            manager.update_job_progress(jid, "processing", 50)
            manager.append_partial_result(jid, {"done": True})
            manager.mark_completed(jid, "Finished")

        future = manager.submit_job(worker, job_id)
        future.result(timeout=5)

        job = manager.get_job(job_id)
        self.assertEqual(job["status"], "completed")
        self.assertEqual(job["results"], [{"done": True}])


if __name__ == "__main__":
    unittest.main()
