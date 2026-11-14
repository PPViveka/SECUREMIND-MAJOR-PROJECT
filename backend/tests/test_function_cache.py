import os
import tempfile
import unittest
from src.function_cache import (
    normalize_code_for_hash,
    compute_function_hash,
    extract_python_functions,
    extract_generic_functions,
    extract_functions,
    FunctionScanCache,
    adjust_line_offsets,
    SelectiveFunctionScanner,
)


class TestFunctionCache(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.temp_db_path = os.path.join(self.temp_dir, "test_cache.db")
        self.cache = FunctionScanCache(db_path=self.temp_db_path)

    def tearDown(self):
        try:
            if os.path.exists(self.temp_db_path):
                os.remove(self.temp_db_path)
            if os.path.exists(self.temp_dir):
                os.rmdir(self.temp_dir)
        except OSError:
            pass

    def test_hash_normalization(self):
        code1 = "def login(user):\n    return user\n"
        code2 = "def login(user):\n    return user   \n\n"
        self.assertEqual(compute_function_hash(code1), compute_function_hash(code2))

        code3 = "def login(user):\n    return None"
        self.assertNotEqual(compute_function_hash(code1), compute_function_hash(code3))

    def test_extract_python_functions(self):
        source = (
            "import os\n"
            "\n"
            "def handle_request(req):\n"
            "    user_id = req.get('id')\n"
            "    query = 'SELECT * FROM users WHERE id = ' + user_id\n"
            "    cursor.execute(query)\n"
            "    return query\n"
            "\n"
            "async def safe_helper(val):\n"
            "    return val * 2\n"
        )
        funcs = extract_python_functions(source)
        self.assertEqual(len(funcs), 2)

        f1 = funcs[0]
        self.assertEqual(f1["name"], "handle_request")
        self.assertEqual(f1["start_line"], 3)
        self.assertEqual(f1["end_line"], 7)
        self.assertIn("sql", f1["risky_sinks"])

        f2 = funcs[1]
        self.assertEqual(f2["name"], "safe_helper")
        self.assertEqual(f2["start_line"], 9)
        self.assertEqual(f2["end_line"], 10)
        self.assertEqual(f2["risky_sinks"], [])

    def test_extract_python_fallback_on_flat_script(self):
        source = "import os\nprint('hello')\nos.system('dir')\n"
        funcs = extract_python_functions(source)
        self.assertEqual(len(funcs), 1)
        self.assertEqual(funcs[0]["name"], "<module>")
        self.assertIn("command", funcs[0]["risky_sinks"])

    def test_extract_generic_js_functions(self):
        js_code = (
            "function loginUser(req, res) {\n"
            "    const path = req.query.path;\n"
            "    fs.open(path);\n"
            "}\n"
            "\n"
            "const verifyToken = async (token) => {\n"
            "    return token === 'secret';\n"
            "}\n"
        )
        funcs = extract_generic_functions(js_code, "javascript")
        self.assertEqual(len(funcs), 2)
        self.assertEqual(funcs[0]["name"], "loginUser")
        self.assertIn("file", funcs[0]["risky_sinks"])

    def test_cache_set_and_get(self):
        h = compute_function_hash("def foo(): pass")
        result = {"vulnerabilities": [{"issue": "Test Vulnerability", "line": 1}]}

        self.assertIsNone(self.cache.get(h))

        self.cache.set(
            function_hash=h,
            function_name="foo",
            language="python",
            scan_result=result,
            original_start_line=1,
            tokens_used=120,
            scan_duration_ms=45.5,
            provider="gemini",
        )

        cached = self.cache.get(h)
        self.assertIsNotNone(cached)
        self.assertEqual(cached["function_name"], "foo")
        self.assertEqual(cached["tokens_used"], 120)
        self.assertEqual(cached["hit_count"], 1)

        # Hit count increments on second fetch
        cached2 = self.cache.get(h)
        self.assertEqual(cached2["hit_count"], 2)

    def test_cache_metrics(self):
        h1 = compute_function_hash("def f1(): pass")
        self.cache.set(h1, "f1", "python", {"vulnerabilities": []}, tokens_used=100, scan_duration_ms=50.0)

        # 2 hits on h1
        self.cache.get(h1)
        self.cache.get(h1)

        metrics = self.cache.get_metrics()
        self.assertEqual(metrics["total_cached_functions"], 1)
        self.assertEqual(metrics["total_cache_hits"], 2)
        self.assertEqual(metrics["estimated_tokens_saved"], 200)
        self.assertEqual(metrics["estimated_time_saved_ms"], 100.0)

    def test_adjust_line_offsets(self):
        vulns = [
            {"issue": "SQLi", "line": 5},
            {"issue": "Command Injection", "line": 8},
        ]
        # Moved from line 1 to line 21 (delta = +20)
        adjusted = adjust_line_offsets(vulns, old_start_line=1, new_start_line=21)
        self.assertEqual(adjusted[0]["line"], 25)
        self.assertEqual(adjusted[1]["line"], 28)

    def test_selective_function_scanner_partitioning(self):
        source = (
            "def func_a():\n"
            "    cursor.execute('select 1')\n"
            "\n"
            "def func_b():\n"
            "    return 42\n"
        )
        scanner = SelectiveFunctionScanner(cache=self.cache)

        # Pass 1: empty cache -> 2 misses
        p1 = scanner.partition_functions(source, language="python")
        self.assertEqual(p1["total_functions"], 2)
        self.assertEqual(p1["cache_hits"], 0)
        self.assertEqual(p1["cache_misses"], 2)
        self.assertEqual(len(p1["functions_to_scan"]), 2)

        # Simulate scanning func_b and storing in cache
        func_b = p1["functions_to_scan"][1]
        self.cache.set(
            function_hash=func_b["hash"],
            function_name=func_b["name"],
            language="python",
            scan_result={"vulnerabilities": []},
            original_start_line=func_b["start_line"],
            tokens_used=80,
            scan_duration_ms=30.0,
        )

        # Pass 2: func_b is now cached -> 1 hit, 1 miss
        p2 = scanner.partition_functions(source, language="python")
        self.assertEqual(p2["cache_hits"], 1)
        self.assertEqual(p2["cache_misses"], 1)
        self.assertEqual(p2["tokens_saved"], 80)
        self.assertEqual(p2["functions_to_scan"][0]["name"], "func_a")


if __name__ == "__main__":
    unittest.main()
