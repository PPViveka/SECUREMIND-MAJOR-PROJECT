"""
Feature 2: verified, codebase-aware fixes.

Unit tests for splicing, project helpers, formatter detection and behaviour comparison, and
(when Docker is available) end-to-end runs of the real gates: the recorded exploit is replayed
against the patch, normal inputs are compared, and the project's tests run before and after.
"""

import os
import shutil
import sys
import tempfile
import textwrap
import unittest
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from src.sandbox_verifier import SandboxVerifier
from src.verified_fixer import (
    VerifiedFixer,
    _compare_case,
    apply_model_output,
    benign_cases,
    build_verified_fix_prompt,
    detect_formatter,
    find_project_helpers,
    find_test_dir,
    format_patched_region,
    gate_c_project_tests,
    gate_d_rescan_validation,
    gate_e_diff_path_constraints,
    locate_function,
    replay_inputs,
    run_behaviour_check,
    run_gate_b,
)

DOCKER = SandboxVerifier._is_docker_live()

FILE = textwrap.dedent('''\
    """Users module."""
    import sqlite3

    DB = "app.db"


    class Repo:
        def find(self, name):
            conn = sqlite3.connect(DB)
            cur = conn.cursor()
            cur.execute("SELECT * FROM users WHERE name = '" + name + "'")
            return cur.fetchall()


    def lookup(name):
        conn = sqlite3.connect(DB)
        cur = conn.cursor()
        cur.execute("SELECT * FROM users WHERE name = '" + name + "'")
        return cur.fetchall()
''')

GOOD_LOOKUP = textwrap.dedent('''\
    def lookup(name):
        conn = sqlite3.connect(DB)
        cur = conn.cursor()
        cur.execute("SELECT * FROM users WHERE name = ?", (name,))
        return cur.fetchall()
''')

# Looks like a fix, still injectable: strips quotes only from the end.
WEAK_LOOKUP = textwrap.dedent('''\
    def lookup(name):
        conn = sqlite3.connect(DB)
        cur = conn.cursor()
        cleaned = name.rstrip("'")
        cur.execute("SELECT * FROM users WHERE name = '" + cleaned + "'")
        return cur.fetchall()
''')

# Blocks the exploit by not querying at all: breaks behaviour.
BROKEN_LOOKUP = textwrap.dedent('''\
    def lookup(name):
        return []
''')


class TestSplicing(unittest.TestCase):
    def test_locate_function_by_line_prefers_innermost(self):
        loc = locate_function(FILE, "", 11)
        self.assertEqual(loc["name"], "find")
        self.assertEqual(loc["indent"], "    ")
        self.assertEqual(loc["params"], ["self", "name"])
        self.assertEqual(locate_function(FILE, "lookup")["start"], 15)

    def test_splices_function_and_adds_new_import(self):
        loc = locate_function(FILE, "lookup")
        reply = "import re\n\n" + GOOD_LOOKUP
        out = apply_model_output(FILE, loc, reply)
        patched = out["patched"]
        self.assertIn("import re\n", patched)
        self.assertEqual(out["added_imports"], ["import re"])
        self.assertIn('WHERE name = ?", (name,))', patched)
        # the class method is untouched
        self.assertIn("\"SELECT * FROM users WHERE name = '\" + name + \"'\")\n        return", patched)
        relocated = locate_function(patched, "lookup")
        self.assertEqual((out["start"], out["end"]), (relocated["start"], relocated["end"]))

    def test_splices_method_with_indentation_and_fences(self):
        loc = locate_function(FILE, "find")
        reply = "```python\ndef find(self, name):\n    return []\n```"
        patched = apply_model_output(FILE, loc, reply)["patched"]
        self.assertIn("    def find(self, name):\n        return []\n", patched)
        compile(patched, "x", "exec")

    def test_whole_file_reply_is_reduced_to_the_target_function(self):
        loc = locate_function(FILE, "lookup")
        reply = FILE.replace("WHERE name = '\" + name + \"'\")\n    return", "WHERE name = ?\", (name,))\n    return")
        out = apply_model_output(FILE, loc, reply)
        self.assertNotIn("error", out)
        self.assertEqual(out["patched"].count("class Repo"), 1)

    def test_reply_without_the_function_is_rejected(self):
        out = apply_model_output(FILE, locate_function(FILE, "lookup"), "def other():\n    pass\n")
        self.assertIn("did not contain", out["error"])


class TestCodebaseAwareness(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp()
        os.makedirs(os.path.join(self.root, "utils"))
        os.makedirs(os.path.join(self.root, "tests"))
        with open(os.path.join(self.root, "utils", "paths.py"), "w") as f:
            f.write('def safe_join_path(base, name):\n    """Join and refuse paths outside base."""\n    return base\n\n'
                    'def unrelated():\n    pass\n')
        with open(os.path.join(self.root, "tests", "test_paths.py"), "w") as f:
            f.write("def is_valid_test_helper():\n    pass\n")

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def test_finds_project_helpers_and_skips_tests(self):
        helpers = find_project_helpers(self.root, "path_traversal")
        self.assertEqual(helpers[0]["name"], "safe_join_path")
        self.assertEqual(helpers[0]["path"], "utils/paths.py")
        self.assertIn("refuse paths", helpers[0]["doc"])
        self.assertFalse(any(h["name"] == "is_valid_test_helper" for h in helpers))
        self.assertEqual(find_test_dir(self.root), os.path.join(self.root, "tests"))

    def test_prompt_carries_proof_helpers_and_feedback(self):
        finding = {
            "issue": "SQL Injection", "cwe_id": "CWE-89", "function_name": "lookup", "line_number": 18,
            "evidence": {"payload": "x' OR '1'='1' -- SAGE_ab12cd34", "sink": {"kind": "sql", "argument": "SELECT ... 'x' OR '1'='1'"}},
        }
        helpers = [{"name": "quote_ident", "signature": "quote_ident(name)", "path": "db/util.py", "doc": ""}]
        prompt = build_verified_fix_prompt(FILE, finding, ["cur.execute(q, (a,))"], project_helpers=helpers,
                                           function_code=locate_function(FILE, "lookup")["code"],
                                           feedback="Exploit blocked: still reached the sql call", file_path="app/users.py")
        for needle in ("SANDBOX PROOF", "SAGE_ab12cd34", "quote_ident(name)  (db/util.py)", "cur.execute(q, (a,))",
                       "REJECTED", "still reached the sql call", "FUNCTION TO FIX", "app/users.py"):
            self.assertIn(needle, prompt)

    def test_formatter_detection_and_missing_tool(self):
        self.assertIsNone(detect_formatter(self.root))
        with open(os.path.join(self.root, "pyproject.toml"), "w") as f:
            f.write("[tool.black]\nline-length = 100\n")
        self.assertEqual(detect_formatter(self.root), "black")
        with patch("src.verified_fixer._formatter_command", return_value=None):
            code, step = format_patched_region("x=1\n", 1, 1, self.root)
        self.assertEqual(code, "x=1\n")
        self.assertEqual(step["status"], "skipped")
        self.assertIn("not installed", step["detail"])

    def test_formatter_runs_on_the_patched_range_only(self):
        with open(os.path.join(self.root, "pyproject.toml"), "w") as f:
            f.write("[tool.ruff]\nline-length = 100\n")
        proc = MagicMock(returncode=0, stdout="x = 1\n", stderr="")
        with patch("src.verified_fixer._formatter_command", return_value=["ruff"]), \
             patch("src.verified_fixer.subprocess.run", return_value=proc) as run:
            code, step = format_patched_region("x=1\n", 3, 9, self.root, "app.py")
        self.assertEqual(code, "x = 1\n")
        self.assertEqual(step["status"], "pass")
        cmd = run.call_args[0][0]
        self.assertIn("--range=3-9", cmd)
        self.assertIn("app.py", cmd)


class TestGateLogic(unittest.TestCase):
    def test_replay_inputs_put_the_proving_input_first(self):
        finding = {"evidence": {
            "canary": "SAGE_1234abcd", "payload": "p2", "kwargs": {"a": 1}, "sink": {"kind": "sql", "argument": "..."},
            "attempts": [{"payload": "p1", "status": "failed"}, {"payload": "p2", "kwargs": {"a": 1}, "status": "proved"}],
        }}
        inputs, canary = replay_inputs(finding)
        self.assertEqual(canary, "SAGE_1234abcd")
        self.assertEqual([i["payload"] for i in inputs], ["p2", "p1"])

    def test_gate_b_sends_recorded_inputs_and_reports_the_sink(self):
        v = MagicMock()
        v.isolation_available.return_value = True
        v.verify.return_value = {
            "verification_status": "verified", "dynamic_trace": {"sink_reached": True},
            "evidence": {"payload": "p2", "payload_source": "replay", "sink": {"kind": "sql", "argument": "SELECT p2"},
                         "attempts": [{"source": "replay"}]},
        }
        finding = {"function_name": "lookup", "issue": "SQL Injection",
                   "evidence": {"canary": "SAGE_1234abcd", "payload": "p2", "sink": {"kind": "sql"}, "attempts": []}}
        r = run_gate_b("code", finding, verifier=v, sink_line=4)
        kwargs = v.verify.call_args.kwargs
        self.assertEqual(kwargs["replay"], [{"payload": "p2", "kwargs": {}}])
        self.assertEqual(kwargs["canary"], "SAGE_1234abcd")
        self.assertEqual(kwargs["sink_line"], 4)
        self.assertEqual(r["status"], "fail")
        self.assertIn("the recorded attack `p2` still reached the sql call", r["detail"])

    def test_inconclusive_retest_never_counts_as_blocked(self):
        v = MagicMock()
        v.isolation_available.return_value = True
        v.verify.return_value = {"verification_status": "inconclusive", "dynamic_trace": {}}
        r = run_gate_b("code", {"function_name": "f", "issue": "SQL Injection"}, verifier=v)
        self.assertEqual(r["status"], "skipped")
        self.assertFalse(r["passed"])

    def test_compare_case_rules(self):
        old = {"sinks": [{"kind": "sql", "argument": "SELECT 'alice'", "bound": ""}], "returned": "[]", "returned_set": True}
        param = {"sinks": [{"kind": "sql", "argument": "SELECT ?", "bound": "('alice',)"}], "returned": "[]", "returned_set": True}
        self.assertEqual(_compare_case("sql_injection", "alice", {}, old, param), [])
        gone = {"sinks": [], "returned": "[]", "returned_set": True}
        self.assertIn("no longer makes the sql call", _compare_case("sql_injection", "alice", {}, old, gone)[0])
        raised = {"error": "ValueError: bad", "sinks": []}
        self.assertIn("raises ValueError", _compare_case("sql_injection", "alice", {}, old, raised)[0])
        changed = {"sinks": param["sinks"], "returned": "[1]", "returned_set": True}
        self.assertIn("returns", _compare_case("sql_injection", "alice", {}, old, changed)[0])

    def test_benign_cases_use_code_urls_and_numeric_params(self):
        cases = benign_cases("ssrf", ["url", "user_id"], "ALLOWED = 'https://api.internal.test/v1'")
        self.assertEqual(cases[0][0], "https://api.internal.test/v1")
        self.assertEqual(cases[0][1], {"user_id": "7"})

    def test_gate_d_is_differential_and_scoped_to_the_function(self):
        scanner = MagicMock()
        original = "a = 1\nb = run(x)\n"
        patched = "a = 1\nb = run(x)\n"
        scanner.scan.return_value = [{"issue": "Command Injection", "severity": "high", "line": 2}]
        passed, status, _ = gate_d_rescan_validation(patched, "SQL Injection", scanner=scanner,
                                                     original_code=original, function_range=(5, 9))
        self.assertTrue(passed)  # pre-existing high finding elsewhere is not "new"
        scanner.scan.side_effect = [[{"issue": "SQL Injection", "severity": "high", "line": 6}], []]
        passed, _, detail = gate_d_rescan_validation("\n" * 9, "SQL Injection", scanner=scanner,
                                                     original_code="x", function_range=(5, 9))
        self.assertFalse(passed)
        self.assertIn("still reported", detail)

    def test_gate_e_ignores_ellipsis_in_untouched_code(self):
        original = 'MSG = "Loading..."\n\ndef f(x):\n    return x\n'
        patched = 'MSG = "Loading..."\n\ndef f(x):\n    return int(x)\n'
        self.assertTrue(gate_e_diff_path_constraints(original, patched, "f")[0])


@unittest.skipUnless(DOCKER, "Docker is not available")
class TestGatesInDocker(unittest.TestCase):
    """Real sandbox runs: the exploit gate's own evidence drives the fix gates."""

    @classmethod
    def setUpClass(cls):
        cls.verifier = SandboxVerifier(timeout_sec=20, llm_attempts=0)
        found = cls.verifier.verify(FILE, "lookup", cwe_id="SQL Injection", sink_line=4)
        cls.finding = {
            "issue": "SQL Injection", "cwe_id": "CWE-89", "function_name": "lookup", "line_number": 18,
            "evidence": found["evidence"],
        }
        cls.proved = found["verification_status"]

    def _fix(self, function_code, **kw):
        fixer = VerifiedFixer(lambda prompt: function_code, verifier=self.verifier, max_retries=1, **kw)
        return fixer.fix(FILE, self.finding)

    def test_exploit_gate_proved_the_original(self):
        self.assertEqual(self.proved, "verified")

    def test_parameterized_fix_is_verified(self):
        r = self._fix(GOOD_LOOKUP)
        gates = {g["gate"]: g for g in r["final_gates"]}
        self.assertEqual(r["patch_status"], "verified", [g["detail"] for g in r["final_gates"]])
        self.assertIn("recorded attack", gates["exploit_blocked"]["detail"])
        self.assertIn("including the input that proved the finding", gates["exploit_blocked"]["detail"])
        self.assertIn("behaviour preserved on 2/2", gates["tests_pass"]["detail"])
        self.assertEqual(gates["tests_pass"]["behaviour"][0]["verdict"], "same")

    def test_cosmetic_fix_is_caught_by_the_exploit_replay(self):
        r = self._fix(WEAK_LOOKUP)
        self.assertEqual(r["patch_status"], "unverified_draft")
        self.assertEqual(r["failed_gate"]["gate"], "exploit_blocked")
        self.assertIn("still reached the sql call", r["failed_gate"]["detail"])

    def test_fix_that_removes_the_query_is_caught_by_behaviour_tests(self):
        r = self._fix(BROKEN_LOOKUP)
        self.assertEqual(r["patch_status"], "unverified_draft")
        self.assertEqual(r["failed_gate"]["gate"], "tests_pass")
        self.assertIn("no longer makes the sql call", r["failed_gate"]["detail"])

    def test_behaviour_check_direct(self):
        patched = apply_model_output(FILE, locate_function(FILE, "lookup"), GOOD_LOOKUP)["patched"]
        r = run_behaviour_check(FILE, patched, "lookup", "sql_injection", self.verifier)
        self.assertEqual(r["status"], "pass")
        self.assertIn("('alice_sageok1',)", r["cases"][0]["patched"]["sinks"][0]["bound"])


@unittest.skipUnless(DOCKER, "Docker is not available")
class TestProjectTestsInDocker(unittest.TestCase):
    """Gate C mounts the clone read-only in the hardened container, overlays the patched file
    and compares test results before and after."""

    def setUp(self):
        self.root = tempfile.mkdtemp()
        os.makedirs(os.path.join(self.root, "tests"))
        with open(os.path.join(self.root, "calc.py"), "w") as f:
            f.write("def add(a, b):\n    return a + b\n")
        with open(os.path.join(self.root, "tests", "test_calc.py"), "w") as f:
            f.write("from calc import add\n\ndef test_add():\n    assert add(2, 3) == 5\n\ndef test_zero():\n    assert add(0, 0) == 0\n")

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def test_regression_fails_and_good_patch_passes(self):
        tests = os.path.join(self.root, "tests")
        ok = gate_c_project_tests("def add(a, b):\n    return int(a) + int(b)\n", "add", tests,
                                  target_file_path="calc.py", project_root=self.root)
        self.assertEqual(ok[1], "pass", ok[2])
        self.assertIn("all 2 project tests", ok[2])
        bad = gate_c_project_tests("def add(a, b):\n    return a - b\n", "add", tests,
                                   target_file_path="calc.py", project_root=self.root)
        self.assertEqual(bad[1], "fail", bad[2])
        self.assertIn("test_add", bad[2])
        # the clone itself is never modified
        with open(os.path.join(self.root, "calc.py")) as f:
            self.assertIn("a + b", f.read())


if __name__ == "__main__":
    unittest.main()
