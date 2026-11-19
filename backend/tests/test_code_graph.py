import sys
import os
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from src.code_graph import build_code_graph, CodeGraph, merge_with_heuristic_graph


# ---------------------------------------------------------------------------
# Fixture sources
# ---------------------------------------------------------------------------

FLASK_SQL_SOURCE = """
from flask import Flask, request
import sqlite3

app = Flask(__name__)

@app.route("/search")
def search():
    query = request.args.get("q", "")
    conn = sqlite3.connect("app.db")
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE name = '" + query + "'")
    return str(cur.fetchall())
"""

FLASK_CMD_SOURCE = """
from flask import Flask, request
import os

app = Flask(__name__)

@app.route("/ping")
def ping():
    host = request.args.get("host", "localhost")
    result = os.system("ping -c 1 " + host)
    return str(result)
"""

CHAINED_SOURCE = """
from flask import Flask, request
import subprocess

app = Flask(__name__)

@app.route("/run")
def run_job():
    cmd = build_command(request.args.get("name", ""))
    return execute(cmd)

def build_command(name):
    return f"job_runner --task={name}"

def execute(cmd):
    return subprocess.run(cmd, shell=True, capture_output=True).stdout
"""

CLEAN_SOURCE = """
def add(a, b):
    return a + b

def multiply(a, b):
    return a * b
"""

EVAL_SOURCE = """
from flask import Flask, request
app = Flask(__name__)

@app.route("/calc")
def calc():
    expr = request.args.get("expr", "0")
    return str(eval(expr))
"""

# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestCodeGraph(unittest.TestCase):
    def test_sql_injection_path_detected(self):
        """Flask route → cursor.execute — CWE-89 must appear in the graph."""
        graph = build_code_graph(FLASK_SQL_SOURCE, vuln_function_names=["search"])

        self.assertTrue(graph["ast_derived"])
        self.assertGreaterEqual(len(graph["nodes"]), 2)
        self.assertGreaterEqual(len(graph["attack_paths"]), 1)

        cwe_ids = [e["cwe"] for e in graph["edges"]]
        self.assertIn("CWE-89", cwe_ids)

    def test_os_command_injection_path_detected(self):
        """Flask route → os.system — CWE-78 must appear."""
        graph = build_code_graph(FLASK_CMD_SOURCE, vuln_function_names=["ping"])

        self.assertGreaterEqual(len(graph["attack_paths"]), 1)
        cwe_ids = [e["cwe"] for e in graph["edges"]]
        self.assertIn("CWE-78", cwe_ids)

    def test_chained_path_includes_intermediate_function(self):
        """run_job → build_command → execute → subprocess — path depth ≥ 2 hops."""
        graph = build_code_graph(CHAINED_SOURCE, vuln_function_names=["run_job", "execute"])

        self.assertGreaterEqual(len(graph["nodes"]), 2)
        max_steps = max((len(p["steps"]) for p in graph["attack_paths"]), default=0)
        self.assertGreaterEqual(max_steps, 1)

    def test_clean_code_returns_empty_paths(self):
        """Pure arithmetic functions — no sinks, so attack_paths must be empty."""
        graph = build_code_graph(CLEAN_SOURCE)
        self.assertEqual(graph["attack_paths"], [])
        self.assertEqual(graph["edges"], [])

    def test_eval_cwe_94_detected(self):
        """Eval call in Flask route — CWE-94 must be flagged."""
        graph = build_code_graph(EVAL_SOURCE, vuln_function_names=["calc"])

        cwe_ids = [e["cwe"] for e in graph["edges"]]
        self.assertIn("CWE-94", cwe_ids)

    def test_graph_node_structure(self):
        """Every node must have required keys: id, label, kind, criticality."""
        graph = build_code_graph(FLASK_SQL_SOURCE, vuln_function_names=["search"])

        for node in graph["nodes"]:
            self.assertIn("id", node)
            self.assertIn("label", node)
            self.assertIn("kind", node)
            self.assertIn("criticality", node)

    def test_graph_edge_structure(self):
        """Every edge must have: id, source, target, cwe, mitre_technique."""
        graph = build_code_graph(FLASK_SQL_SOURCE, vuln_function_names=["search"])

        for edge in graph["edges"]:
            self.assertIn("id", edge)
            self.assertIn("source", edge)
            self.assertIn("target", edge)
            self.assertIn("cwe", edge)
            self.assertIn("mitre_technique", edge)

    def test_entry_points_reported(self):
        """Entry points list must include the Flask route function name."""
        graph = build_code_graph(FLASK_SQL_SOURCE, vuln_function_names=["search"])
        self.assertIn("search", graph["entry_points_found"])

    def test_functions_analyzed_count(self):
        """functions_analyzed must equal the number of def statements in the source."""
        graph = build_code_graph(CHAINED_SOURCE)
        self.assertEqual(graph["functions_analyzed"], 3)

    def test_merge_prefers_ast_graph(self):
        """merge_with_heuristic_graph should return AST graph when it has nodes."""
        ast_g = {"nodes": [{"id": "a"}], "edges": [], "attack_paths": [], "ast_derived": True}
        heur_g = {"nodes": [{"id": "b"}], "edges": [], "attack_paths": []}
        merged = merge_with_heuristic_graph(ast_g, heur_g)
        self.assertEqual(merged["nodes"][0]["id"], "a")
        self.assertTrue(merged["ast_derived"])

    def test_merge_preserves_empty_ast_graph_when_no_path_is_proven(self):
        """An analyzed empty AST graph must not be replaced with fabricated heuristics."""
        ast_g = {"nodes": [], "edges": [], "attack_paths": [], "ast_derived": True}
        heur_g = {"nodes": [{"id": "b"}], "edges": [], "attack_paths": []}
        merged = merge_with_heuristic_graph(ast_g, heur_g)
        self.assertEqual(merged["nodes"], [])
        self.assertTrue(merged.get("ast_derived"))

    def test_invalid_syntax_does_not_crash_and_not_ast_derived(self):
        """Malformed source must return an empty-but-valid graph with ast_derived False."""
        graph = build_code_graph("def broken(: pass")
        self.assertIn("nodes", graph)
        self.assertIn("edges", graph)
        self.assertIn("attack_paths", graph)
        self.assertFalse(graph["ast_derived"])

    def test_vuln_function_not_in_source_returns_no_fabricated_path(self):
        """A finding without a matching source function cannot prove an attack path."""
        graph = build_code_graph(CLEAN_SOURCE, vuln_function_names=["missing_func"])
        self.assertEqual(graph["attack_paths"], [])
        self.assertIn("No source-backed", graph["path_reason"])

    def test_taint_propagation_and_metadata_linking(self):
        findings = [
            {
                "function_name": "search",
                "finding_id": "FIND-SQL-001",
                "cwe_id": "CWE-89",
                "file": "app.py",
                "line": 30,
                "verified": True,
                "verification_status": "verified",
            }
        ]
        graph = build_code_graph(FLASK_SQL_SOURCE, vuln_function_names=["search"], findings=findings)
        self.assertGreaterEqual(len(graph["attack_paths"]), 1)
        path = graph["attack_paths"][0]
        self.assertEqual(path["evidence_strength"], "proven_taint")
        self.assertEqual(path["verification_state"], "verified")

        node_search = next(n for n in graph["nodes"] if n["label"] == "search")
        self.assertEqual(node_search.get("finding_id"), "FIND-SQL-001")
        self.assertEqual(node_search.get("evidence_strength"), "verified")

    def test_cross_file_attack_path_resolution(self):
        from src.code_graph import build_multi_file_code_graph
        files = {
            "app.py": (
                "from db import execute_query\n"
                "def handler(user_id):\n"
                "    return execute_query(user_id)\n"
            ),
            "db.py": (
                "def execute_query(uid):\n"
                "    cursor.execute('SELECT * FROM t WHERE id=' + uid)\n"
            ),
        }
        res = build_multi_file_code_graph(files)
        self.assertTrue(res["cross_file_enabled"])
        self.assertEqual(len(res["files_analyzed"]), 2)
        # Check cross-file edges
        cross_edges = [e for e in res["edges"] if e.get("cross_file")]
        self.assertGreaterEqual(len(cross_edges), 1)


if __name__ == "__main__":
    unittest.main()
