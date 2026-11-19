import os
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from src.repo_selective_scan import (
    _is_allowed_repo_url,
    parse_github_url,
    extract_keywords,
    _is_text_candidate,
    build_repo_map,
    _score_and_select,
    selective_repo_scan,
)
from src.repo_scan_engine import RateLimitedEngine
from src.job_manager import create_job, get_job


class TestRepoScanComprehensive(unittest.TestCase):
    def test_allowed_repo_url_validation(self):
        # Valid GitHub URLs
        self.assertTrue(_is_allowed_repo_url("https://github.com/org/repo"))
        self.assertTrue(_is_allowed_repo_url("https://www.github.com/user/project"))

        # Invalid schemes, hosts, ports, credentials
        self.assertFalse(_is_allowed_repo_url("http://github.com/org/repo"))
        self.assertFalse(_is_allowed_repo_url("https://gitlab.com/org/repo"))
        self.assertFalse(_is_allowed_repo_url("https://evilgithub.com/org/repo"))
        self.assertFalse(_is_allowed_repo_url("https://user:pass@github.com/org/repo"))
        self.assertFalse(_is_allowed_repo_url("https://github.com:8080/org/repo"))
        self.assertFalse(_is_allowed_repo_url(""))

    def test_parse_github_url(self):
        owner, repo = parse_github_url("https://github.com/microsoft/vscode")
        self.assertEqual(owner, "microsoft")
        self.assertEqual(repo, "vscode")

        with self.assertRaises(ValueError):
            parse_github_url("https://gitlab.com/microsoft/vscode")

    def test_extract_keywords(self):
        kws = extract_keywords("Find SQL injection in auth login tokens", max_keywords=10)
        self.assertIn("sql", kws)
        self.assertIn("auth", kws)
        self.assertIn("token", kws)

    def test_text_candidate_detection(self):
        self.assertTrue(_is_text_candidate("app.py", 1024))
        self.assertTrue(_is_text_candidate("package.json", 2048))
        self.assertFalse(_is_text_candidate("image.png", 1024))
        self.assertFalse(_is_text_candidate("large_file.py", 10 * 1024 * 1024))

    def test_build_repo_map_and_score(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            os.makedirs(os.path.join(tmp_dir, "auth"), exist_ok=True)
            login_file = os.path.join(tmp_dir, "auth", "login.py")
            with open(login_file, "w") as f:
                f.write("def login(user, password):\n    token = create_token()\n    return token\n")

            repo_map = build_repo_map(tmp_dir)
            paths = [f["path"] for f in repo_map["files"]]
            self.assertIn("auth/login.py", paths)

            selected = _score_and_select(tmp_dir, ["auth/login.py"], ["auth", "token", "login"], top_k=1)
            self.assertEqual(len(selected), 1)
            self.assertEqual(selected[0]["path"], "auth/login.py")
            self.assertGreater(selected[0]["hit_count"], 0)

    def test_rate_limited_engine_backoff_and_sync(self):
        job_id = create_job()
        
        mock_invoker = MagicMock()
        mock_invoker.side_effect = [
            Exception("Rate limit 429 quota exceeded"),
            {"vulnerabilities": []}
        ]

        engine = RateLimitedEngine(job_id=job_id, token="test_token", invoke_fn=mock_invoker, top_k=2)
        engine.max_retries = 2

        with patch("time.sleep", return_value=None):
            res = engine._invoke_with_backoff("test prompt", max_tokens=200)
            self.assertEqual(res, {"vulnerabilities": []})

        job = get_job(job_id)
        self.assertIsNotNone(job)
        self.assertTrue(any("Rate limited" in log for log in job.get("logs", [])))

    def test_rate_limited_engine_run_scan_complete_flow(self):
        from src.repo_scan_engine import start_progressive_scan
        import time

        job_id = create_job()

        mock_scan_bundle = {
            "selected_files": [
                {"path": "src/auth.py", "excerpt": "def login(): pass"},
                {"path": "src/api.py", "excerpt": "def route(): pass"},
            ],
            "repo_stats": {"total_files": 2, "total_lines": 50},
        }

        # Invoker returns fast scan findings then deep enrichment results
        def fake_invoker(prompt, max_tokens=2048):
            if "Fast scan" in prompt or "Scan the following" in prompt or "FILE:" in prompt:
                return {
                    "vulnerabilities": [
                        {"issue": "SQL Injection", "file_path": "src/auth.py", "line": 5, "matched_code": "execute()"},
                    ]
                }
            # Deep enrichment
            return {
                "severity": "High",
                "explanation": "Unsanitized input reaches SQL sink",
                "poc_exploit_scenario": "Pass ' OR 1=1",
                "attack_vector": "HTTP parameter",
                "remediation": {"patch": "use params", "explanation": "param query"},
            }

        with patch("src.repo_scan_engine.selective_repo_scan", return_value=mock_scan_bundle), \
             patch("src.repo_scan_engine.build_attack_intelligence", return_value={"risk_ranking": ["src/auth.py"], "attack_graph": {"nodes": []}}):
            engine = RateLimitedEngine(job_id=job_id, token="test_token", invoke_fn=fake_invoker, top_k=2)
            engine.run_scan("https://github.com/org/repo", "find sql")

        job = get_job(job_id)
        self.assertEqual(job["status"], "completed")
        self.assertEqual(job["progress"], 100)
        self.assertTrue(len(job.get("vulnerabilities_full", [])) > 0)
        self.assertEqual(job["risk_ranking"], ["src/auth.py"])

    def test_rate_limited_engine_edge_cases(self):
        from src.repo_scan_engine import start_progressive_scan
        import time

        # 1. Non-existent job
        engine_none = RateLimitedEngine(job_id="non-existent-job-999", token="t", invoke_fn=lambda p: {})
        engine_none.run_scan("https://github.com/org/repo", "q")

        # 2. No selected files found
        job_id_empty = create_job()
        with patch("src.repo_scan_engine.selective_repo_scan", return_value={"selected_files": []}):
            engine_empty = RateLimitedEngine(job_id=job_id_empty, token="t", invoke_fn=lambda p: {})
            engine_empty.run_scan("https://github.com/org/repo", "q")
        job_empty = get_job(job_id_empty)
        self.assertEqual(job_empty["status"], "completed")

        # 3. Unrecoverable fatal error
        job_id_err = create_job()
        with patch("src.repo_scan_engine.selective_repo_scan", side_effect=RuntimeError("Git clone failure")):
            engine_err = RateLimitedEngine(job_id=job_id_err, token="t", invoke_fn=lambda p: {})
            engine_err.run_scan("https://github.com/org/repo", "q")
        job_err = get_job(job_id_err)
        self.assertEqual(job_err["status"], "failed")

        # 4. start_progressive_scan
        job_id_prog = create_job()
        with patch("src.repo_scan_engine.selective_repo_scan", return_value={"selected_files": []}):
            start_progressive_scan(job_id_prog, "https://github.com/org/repo", "q", "tok", "main", 5, lambda p: {})
            for _ in range(20):
                job_prog = get_job(job_id_prog)
                if job_prog.get("status") == "completed":
                    break
                time.sleep(0.05)
        self.assertEqual(job_prog["status"], "completed")

    def test_selective_repo_scan_clone_and_filtering(self):
        with tempfile.TemporaryDirectory() as td:
            with open(os.path.join(td, "main.py"), "w") as f:
                f.write("import os\nprint('hello world')\n")
            with open(os.path.join(td, "secret.key"), "w") as f:
                f.write("dummy key\n")

            with patch("src.repo_selective_scan._clone_repository") as mock_clone, \
                 patch("src.repo_selective_scan.fetch_repo_tree", return_value=[{"path": "test.py", "type": "blob", "size": 100, "sha": "abc123"}]):
                def fake_clone(repo_url, target_dir, token=None, branch=None):
                    with open(os.path.join(target_dir, "test.py"), "w") as f:
                        f.write("def test():\n    pass\n")

                mock_clone.side_effect = fake_clone
                res = selective_repo_scan(
                    repo_url="https://github.com/org/repo",
                    query="security scan",
                    token=None,
                    branch="dev",
                    top_k=2,
                )
                self.assertIn("selected_files", res)
                self.assertIn("repo_stats", res)

    def test_clone_repository_git_commands(self):
        from src.repo_selective_scan import _clone_repository
        import subprocess

        with tempfile.TemporaryDirectory() as target_dir:
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr="")
                _clone_repository("https://github.com/org/repo", target_dir, token="secret-token", branch="feature")
                calls = mock_run.call_args_list
                # Verify git clone and branch were invoked
                self.assertTrue(any("clone" in str(c) for c in calls))
                self.assertTrue(any("feature" in str(c) for c in calls))

                # Test error path
                mock_run.return_value = subprocess.CompletedProcess(args=[], returncode=1, stdout="", stderr="Fatal error")
                with self.assertRaises(RuntimeError):
                    _clone_repository("https://github.com/org/repo", target_dir)

    def test_search_file_paths_and_tree(self):
        from src.repo_selective_scan import _search_file_paths, fetch_repo_tree

        with tempfile.TemporaryDirectory() as td:
            f1 = os.path.join(td, "login.py")
            with open(f1, "w") as f:
                f.write("def login(token): pass\n")
            f2 = os.path.join(td, "README.md")
            with open(f2, "w") as f:
                f.write("Welcome\n")

            matches = _search_file_paths(td, ["token"])
            self.assertIn("login.py", matches)
            self.assertEqual(_search_file_paths(td, []), [])

        # fetch_repo_tree test
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"tree": [{"path": "app.py", "sha": "123"}]}
        with patch("src.repo_selective_scan.requests.get", return_value=mock_resp):
            tree = fetch_repo_tree("owner", "repo", token="mytoken")
            self.assertEqual(len(tree), 1)
            self.assertEqual(tree[0]["path"], "app.py")

        # fetch_repo_tree failure
        mock_resp.status_code = 404
        mock_resp.text = "Not found"
        with patch("src.repo_selective_scan.requests.get", return_value=mock_resp):
            with self.assertRaises(Exception):
                fetch_repo_tree("owner", "repo", branch="custom")


if __name__ == "__main__":
    unittest.main()
