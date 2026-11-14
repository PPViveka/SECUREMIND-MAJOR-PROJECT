"""
test_code_graph.py — Tests for AST-Grounded Attack Path Generator (Step 4)

All tests are deterministic (no LLM calls, no network, no filesystem writes).
"""

import sys
import os

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


def test_sql_injection_path_detected():
    """Flask route → cursor.execute — CWE-89 must appear in the graph."""
    graph = build_code_graph(FLASK_SQL_SOURCE, vuln_function_names=["search"])

    assert graph["ast_derived"] is True
    assert len(graph["nodes"]) >= 2
    assert len(graph["attack_paths"]) >= 1

    # At least one edge must reference CWE-89
    cwe_ids = [e["cwe"] for e in graph["edges"]]
    assert "CWE-89" in cwe_ids, f"Expected CWE-89 in edges, got: {cwe_ids}"


def test_os_command_injection_path_detected():
    """Flask route → os.system — CWE-78 must appear."""
    graph = build_code_graph(FLASK_CMD_SOURCE, vuln_function_names=["ping"])

    assert len(graph["attack_paths"]) >= 1
    cwe_ids = [e["cwe"] for e in graph["edges"]]
    assert "CWE-78" in cwe_ids, f"Expected CWE-78, got: {cwe_ids}"


def test_chained_path_includes_intermediate_function():
    """run_job → build_command → execute → subprocess — path depth ≥ 2 hops."""
    graph = build_code_graph(CHAINED_SOURCE, vuln_function_names=["run_job", "execute"])

    assert len(graph["nodes"]) >= 2
    # At least one attack path must have more than 1 step
    max_steps = max((len(p["steps"]) for p in graph["attack_paths"]), default=0)
    assert max_steps >= 1, "Expected at least a 1-hop path in chained source"


def test_clean_code_returns_empty_paths():
    """Pure arithmetic functions — no sinks, so attack_paths must be empty."""
    graph = build_code_graph(CLEAN_SOURCE)
    assert graph["attack_paths"] == []
    assert graph["edges"] == []


def test_eval_cwe_94_detected():
    """Eval call in Flask route — CWE-94 must be flagged."""
    graph = build_code_graph(EVAL_SOURCE, vuln_function_names=["calc"])

    cwe_ids = [e["cwe"] for e in graph["edges"]]
    assert "CWE-94" in cwe_ids, f"Expected CWE-94, got: {cwe_ids}"


def test_graph_node_structure():
    """Every node must have required keys: id, label, kind, criticality."""
    graph = build_code_graph(FLASK_SQL_SOURCE, vuln_function_names=["search"])

    for node in graph["nodes"]:
        assert "id" in node
        assert "label" in node
        assert "kind" in node
        assert "criticality" in node


def test_graph_edge_structure():
    """Every edge must have: id, source, target, cwe, mitre_technique."""
    graph = build_code_graph(FLASK_SQL_SOURCE, vuln_function_names=["search"])

    for edge in graph["edges"]:
        assert "id" in edge
        assert "source" in edge
        assert "target" in edge
        assert "cwe" in edge
        assert "mitre_technique" in edge


def test_entry_points_reported():
    """Entry points list must include the Flask route function name."""
    graph = build_code_graph(FLASK_SQL_SOURCE, vuln_function_names=["search"])
    assert "search" in graph["entry_points_found"]


def test_functions_analyzed_count():
    """functions_analyzed must equal the number of def statements in the source."""
    graph = build_code_graph(CHAINED_SOURCE)
    # CHAINED_SOURCE has: run_job, build_command, execute = 3
    assert graph["functions_analyzed"] == 3


def test_merge_prefers_ast_graph():
    """merge_with_heuristic_graph should return AST graph when it has nodes."""
    ast_g = {"nodes": [{"id": "a"}], "edges": [], "attack_paths": [], "ast_derived": True}
    heur_g = {"nodes": [{"id": "b"}], "edges": [], "attack_paths": []}
    merged = merge_with_heuristic_graph(ast_g, heur_g)
    assert merged["nodes"][0]["id"] == "a"
    assert merged["ast_derived"] is True


def test_merge_falls_back_to_heuristic_when_ast_empty():
    """When AST graph has no nodes, heuristic graph is returned."""
    ast_g = {"nodes": [], "edges": [], "attack_paths": [], "ast_derived": True}
    heur_g = {"nodes": [{"id": "b"}], "edges": [], "attack_paths": []}
    merged = merge_with_heuristic_graph(ast_g, heur_g)
    assert merged["nodes"][0]["id"] == "b"
    assert merged.get("ast_derived") is False


def test_invalid_syntax_does_not_crash():
    """Malformed source must return an empty-but-valid graph."""
    graph = build_code_graph("def broken(: pass")
    assert "nodes" in graph
    assert "edges" in graph
    assert "attack_paths" in graph


def test_vuln_function_not_in_source_returns_stub():
    """When vuln function name is not in source AST, a stub path is returned."""
    graph = build_code_graph(CLEAN_SOURCE, vuln_function_names=["missing_func"])
    # Stub path ensures at least one attack path is returned
    assert len(graph["attack_paths"]) >= 1
    assert graph["attack_paths"][0]["entry_point"] == "missing_func"
