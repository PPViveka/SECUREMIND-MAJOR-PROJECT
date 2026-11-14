import os
import tempfile
import unittest
from src.cascade_engine import CascadeEngine
from src.function_cache import extract_python_functions, FunctionScanCache


class TestCascadeEngine(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.temp_db_path = os.path.join(self.temp_dir, "test_cascade_cache.db")
        self.cache = FunctionScanCache(db_path=self.temp_db_path)
        self.engine = CascadeEngine(cache=self.cache)

    def tearDown(self):
        try:
            if os.path.exists(self.temp_db_path):
                os.remove(self.temp_db_path)
            if os.path.exists(self.temp_dir):
                os.rmdir(self.temp_dir)
        except OSError:
            pass

    def test_clean_function_triage(self):
        # Benign function: no regex match, no dangerous sinks
        code = (
            "def calculate_tax(amount, rate):\n"
            "    if amount < 0 or rate < 0:\n"
            "        return 0\n"
            "    return amount * rate\n"
        )
        funcs = extract_python_functions(code)
        triage = self.engine.filter_and_triage(funcs)

        self.assertEqual(triage["clean_count"], 1)
        self.assertEqual(triage["flagged_count"], 0)
        self.assertEqual(triage["clean_functions"][0]["name"], "calculate_tax")

        # Verify it was cached immediately as clean
        cached = self.cache.get(funcs[0]["hash"])
        self.assertIsNotNone(cached)
        self.assertEqual(cached["provider"], "sast-cascade-clean")
        self.assertEqual(cached["tokens_used"], 0)

    def test_flagged_function_by_sast(self):
        # Vulnerable to SQL injection (SAST regex match)
        code = (
            "def get_user(user_id):\n"
            "    query = 'SELECT * FROM users WHERE id = ' + user_id\n"
            "    cursor.execute(query)\n"
            "    return query\n"
        )
        funcs = extract_python_functions(code)
        triage = self.engine.filter_and_triage(funcs)

        self.assertEqual(triage["clean_count"], 0)
        self.assertEqual(triage["flagged_count"], 1)
        self.assertGreaterEqual(len(triage["flagged_functions"][0]["sast_findings"]), 1)

    def test_flagged_function_by_dangerous_sink(self):
        # Calls subprocess (risky sink even if pattern isn't a simple concatenation)
        code = (
            "def run_command(cmd_arg):\n"
            "    import subprocess\n"
            "    return subprocess.run([cmd_arg])\n"
        )
        funcs = extract_python_functions(code)
        triage = self.engine.filter_and_triage(funcs)

        self.assertEqual(triage["clean_count"], 0)
        self.assertEqual(triage["flagged_count"], 1)

    def test_mixed_functions_filtering(self):
        code = (
            "def safe_format(name):\n"
            "    return f'Hello {name}'\n"
            "\n"
            "def unsafe_read(filepath):\n"
            "    return open(filepath).read()\n"
        )
        funcs = extract_python_functions(code)
        triage = self.engine.filter_and_triage(funcs)

        self.assertEqual(triage["clean_count"], 1)
        self.assertEqual(triage["flagged_count"], 1)
        self.assertEqual(triage["clean_functions"][0]["name"], "safe_format")
        self.assertEqual(triage["flagged_functions"][0]["name"], "unsafe_read")

    def test_build_targeted_prompt_context(self):
        flagged = [{
            "name": "unsafe_read",
            "start_line": 4,
            "end_line": 5,
            "code": "def unsafe_read(filepath):\n    return open(filepath).read()",
            "sast_findings": [{"issue": "Path Traversal"}],
        }]
        prompt_context = CascadeEngine.build_targeted_prompt_context(flagged)
        self.assertIn("Lines 4-5", prompt_context)
        self.assertIn("Path Traversal", prompt_context)
        self.assertIn("def unsafe_read", prompt_context)


if __name__ == "__main__":
    unittest.main()
