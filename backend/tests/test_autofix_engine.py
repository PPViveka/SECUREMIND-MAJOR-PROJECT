import os
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.autofix_engine import _create_github_pr, _resolve_fix_path, apply_multi_file_patch


class TestAutofixEngine(unittest.TestCase):
    def test_create_github_pr_rejects_unapproved_repository_url(self):
        with tempfile.TemporaryDirectory() as repo_dir:
            with patch.dict(os.environ, {}, clear=True):
                with self.assertRaises(ValueError) as ctx:
                    _create_github_pr(repo_dir, "https://evilgithub.com/owner/repo", "secret-token", [], [])
                self.assertIn("github.com", str(ctx.exception))

    def test_create_github_pr_does_not_store_token_in_remote_url(self):
        commands = []

        class Response:
            status_code = 201

            def json(self):
                return {"html_url": "https://github.com/owner/repo/pull/1"}

        def fake_git(args, cwd):
            commands.append(args)
            return type("Result", (), {"returncode": 0, "stderr": "", "stdout": ""})()

        with tempfile.TemporaryDirectory() as repo_dir:
            with patch("src.autofix_engine._run_git_command", side_effect=fake_git), \
                 patch("src.autofix_engine.requests.post", return_value=Response()):
                _create_github_pr(repo_dir, "https://github.com/owner/repo", "secret-token", [], [])

        remote_commands = [command for command in commands if "remote" in command]
        self.assertTrue(remote_commands)
        self.assertTrue(all("secret-token" not in " ".join(command) for command in remote_commands))

    def test_resolve_fix_path_rejects_escape_and_unsupported_files(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            source = os.path.join(temp_dir, "app.py")
            with open(source, "w", encoding="utf-8") as f:
                f.write("print('ok')")

            self.assertEqual(_resolve_fix_path(temp_dir, "app.py"), os.path.realpath(source))
            for path in ("../outside.py", "/tmp/outside.py", "notes.exe"):
                with self.assertRaises(ValueError):
                    _resolve_fix_path(temp_dir, path)

    def test_apply_multi_file_patch(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            f1 = os.path.join(temp_dir, "caller.py")
            with open(f1, "w", encoding="utf-8") as f:
                f.write("def call(): pass\n")
            f2 = os.path.join(temp_dir, "callee.py")
            with open(f2, "w", encoding="utf-8") as f:
                f.write("def func(): pass\n")

            patches = [
                {"file_path": "caller.py", "original_code": "def call(): pass\n", "fixed_code": "def call(): return True\n"},
                {"file_path": "callee.py", "original_code": "def func(): pass\n", "fixed_code": "def func(): return 42\n"},
            ]

            res = apply_multi_file_patch(temp_dir, patches)
            self.assertTrue(res["success"])
            self.assertEqual(res["files_patched"], 2)
            with open(f1, "r", encoding="utf-8") as f:
                self.assertIn("return True", f.read())
            with open(f2, "r", encoding="utf-8") as f:
                self.assertIn("return 42", f.read())

    def test_snippet_autofix_full_flow(self):
        from src.job_manager import create_job, get_job
        from src.autofix_engine import _run_snippet_autofix

        job_id = create_job()
        snippet = "def query(val):\n    return cursor.execute('SELECT * FROM t WHERE id=' + val)\n"
        vulns = [{"issue": "SQL Injection", "file_path": "snippet.py", "function_name": "query"}]

        def fake_autofix(code, v_list, fpath):
            return {
                "fixes": [{"issue": "SQL Injection", "explanation": "Use parameterized query"}],
                "modified_content": "def query(val):\n    return cursor.execute('SELECT * FROM t WHERE id=?', (val,))\n"
            }

        _run_snippet_autofix(job_id, snippet, vulns, "python", "fix", fake_autofix)

        job = get_job(job_id)
        self.assertEqual(job["status"], "completed")
        self.assertTrue(len(job.get("results", [])) > 0)
        self.assertEqual(job.get("progress"), 100)

    def test_snippet_autofix_no_fixes(self):
        from src.job_manager import create_job, get_job
        from src.autofix_engine import _run_snippet_autofix

        job_id = create_job()
        _run_snippet_autofix(job_id, "safe_code()", [], "python", "preview", lambda c, v, p: {})
        job = get_job(job_id)
        self.assertEqual(job["status"], "completed")
        self.assertIn("No safe fixes", job.get("summary", ""))

    def test_snippet_autofix_invalid_modified_content(self):
        from src.job_manager import create_job, get_job
        from src.autofix_engine import _run_snippet_autofix

        job_id = create_job()
        snippet = "def test():\n    pass\n"
        vulns = [{"issue": "Test Issue"}]

        def bad_fix(c, v, p):
            return {"fixes": [{"issue": "Test"}], "modified_content": "bad"}

        _run_snippet_autofix(job_id, snippet, vulns, "python", "preview", bad_fix)
        job = get_job(job_id)
        self.assertEqual(job["status"], "completed")

    def test_repo_autofix_and_start_autofix_job(self):
        from src.job_manager import create_job, get_job
        from src.autofix_engine import _run_repo_autofix, start_autofix_job
        import time

        job_id = create_job()
        vulns = [{"file_path": "app.py", "issue": "Command Injection", "function_name": "run"}]

        def fake_clone(repo_url, target_dir, token=None, branch=None):
            with open(os.path.join(target_dir, "app.py"), "w") as f:
                f.write("def run(cmd):\n    import os\n    os.system(cmd)\n")

        def fake_fix(code, v_list, fpath):
            return {
                "fixes": [{"issue": "Command Injection", "explanation": "Use shlex"}],
                "modified_content": "def run(cmd):\n    import subprocess\n    subprocess.run([cmd], shell=False)\n"
            }

        with patch("src.autofix_engine._clone_repository", side_effect=fake_clone):
            _run_repo_autofix(job_id, "https://github.com/org/repo", vulns, "tok", "main", "fix", fake_fix)

        job = get_job(job_id)
        self.assertEqual(job["status"], "completed")
        self.assertIn("app.py", job.get("modified_files", []))

        # Test start_autofix_job validation
        job_err_id = create_job()
        start_autofix_job(job_err_id, None, None, [], None, None, "preview", "python", lambda c, v, p: {})
        time.sleep(0.05)
        job_err = get_job(job_err_id)
        self.assertEqual(job_err["status"], "failed")

    def test_create_github_pr_validation(self):
        with tempfile.TemporaryDirectory() as td:
            with self.assertRaises(ValueError):
                _create_github_pr(td, "https://github.com/org/repo", "", [], [])
            with self.assertRaises(ValueError):
                _create_github_pr(td, "https://github.com/org", "token", [], [])


if __name__ == "__main__":
    unittest.main()
