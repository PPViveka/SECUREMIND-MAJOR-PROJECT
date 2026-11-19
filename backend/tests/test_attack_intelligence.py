import sys
import os
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from src.attack_intelligence import (
    classify_exploitability,
    build_risk_ranking,
    generate_attack_graph,
    simulate_breach,
    build_attack_intelligence,
    sanitize_chat_input,
)


class TestAttackIntelligence(unittest.TestCase):
    def test_classify_exploitability_high_case(self):
        vuln = {
            "severity": "High",
            "issue": "SQL Injection in public API",
            "explanation": "Public endpoint runs dynamic SQL",
        }
        result = classify_exploitability(vuln)
        self.assertIn(result["level"], ["High", "Medium"])
        self.assertIn("score", result)

    def test_build_risk_ranking_sorted_descending(self):
        vulns = [
            {"severity": "Low", "issue": "Minor banner leak", "explanation": "Version in header"},
            {"severity": "High", "issue": "IAM wildcard policy", "explanation": "Over-broad policy"},
        ]
        ranking = build_risk_ranking(vulns)
        self.assertEqual(len(ranking), 2)
        self.assertGreaterEqual(ranking[0]["priority_score"], ranking[1]["priority_score"])

    def test_generate_attack_graph_has_nodes_and_edges(self):
        ranking = [
            {
                "issue": "Weak Auth",
                "severity": "High",
                "priority_score": 9.1,
                "exploitability": {"exploitable": True},
            },
            {
                "issue": "IAM wildcard policy",
                "severity": "High",
                "priority_score": 8.8,
                "exploitability": {"exploitable": True},
            },
        ]
        graph = generate_attack_graph(ranking)
        self.assertGreaterEqual(len(graph["nodes"]), 2)
        self.assertGreaterEqual(len(graph["edges"]), 1)

    def test_simulate_breach_returns_data_points(self):
        ranking = [
            {
                "issue": "SQL Injection",
                "severity": "High",
                "priority_score": 9.4,
                "exploitability": {"exploitable": True},
            }
        ]
        graph = generate_attack_graph(ranking)
        simulation = simulate_breach(ranking, graph)
        self.assertIn("accessible_data", simulation)
        self.assertGreaterEqual(len(simulation["accessible_data"]), 1)

    def test_simulate_breach_handles_empty_attack_paths(self):
        ranking = [
            {
                "issue": "Potential SQL Injection",
                "severity": "High",
                "priority_score": 8.9,
                "exploitability": {"exploitable": True},
            }
        ]
        simulation = simulate_breach(ranking, {"attack_paths": []})
        self.assertEqual(simulation["chain_summary"], "No viable multi-step chain found")
        self.assertIsInstance(simulation["accessible_data"], list)

    def test_build_attack_intelligence_shape(self):
        vulns = [
            {
                "severity": "High",
                "issue": "Hardcoded token",
                "explanation": "Token in source",
                "poc_exploit_scenario": "Attacker pulls token from git history",
            }
        ]
        result = build_attack_intelligence(vulns)
        self.assertIn("risk_ranking", result)
        self.assertIn("attack_graph", result)
        self.assertIn("breach_simulation", result)

    def test_build_attack_intelligence_with_code_uses_ast_graph(self):
        code = """
@app.route("/user")
def get_user():
    user = request.args.get("id")
    cursor.execute("SELECT * FROM users WHERE id = " + user)
    return user
"""
        vulns = [
            {
                "severity": "High",
                "issue": "SQL Injection",
                "function_name": "get_user",
            }
        ]
        result = build_attack_intelligence(vulns, context_text=code)
        graph = result["attack_graph"]
        self.assertTrue(graph.get("ast_derived"))
        self.assertGreaterEqual(len(graph.get("attack_paths", [])), 1)
        self.assertTrue(any("CWE-89" in str(edge) for edge in graph.get("edges", [])))

    def test_code_graph_does_not_fabricate_unknown_sink_paths(self):
        result = build_attack_intelligence(
            [{"severity": "Medium", "issue": "Hardcoded token", "function_name": "safe_handler"}],
            context_text="def safe_handler():\n    return 'ok'\n",
        )
        graph = result["attack_graph"]
        self.assertEqual(graph["attack_paths"], [])
        self.assertIn("No source-backed", graph["path_reason"])

    def test_sanitize_chat_input_removes_script_block(self):
        raw = """Hello<script>alert(1)</script>```ignore me```"""
        cleaned = sanitize_chat_input(raw)
        self.assertNotIn("script", cleaned.lower())

    def test_verified_and_reachable_findings_ranked_first(self):
        vulns = [
            {
                "severity": "Critical",
                "issue": "Unverified finding with high score",
                "verified": False,
                "reachable": False,
            },
            {
                "severity": "Medium",
                "issue": "Verified and reachable finding",
                "verified": True,
                "reachable": True,
            },
        ]
        ranking = build_risk_ranking(vulns)
        self.assertEqual(ranking[0]["issue"], "Verified and reachable finding")
        self.assertTrue(ranking[0]["verified"])

    def test_simulation_labeled_illustrative_when_evidence_incomplete(self):
        ranking = [{"issue": "XSS", "severity": "Medium", "verified": False}]
        graph = {"nodes": [], "edges": [], "attack_paths": [], "ast_derived": False}
        sim = simulate_breach(ranking, graph)
        self.assertEqual(sim["mode"], "illustrative")
        self.assertFalse(sim["evidence_complete"])
        self.assertIn("Illustrative", sim["label"])

    def test_simulation_labeled_proven_when_evidence_complete(self):
        ranking = [{"issue": "SQLi", "severity": "High", "verified": True}]
        graph = {"nodes": ["a", "b"], "edges": ["e"], "attack_paths": [{"steps": [{"from": "a", "to": "b"}]}], "ast_derived": True}
        sim = simulate_breach(ranking, graph)
        self.assertEqual(sim["mode"], "proven")
        self.assertTrue(sim["evidence_complete"])
        self.assertEqual(sim["label"], "Proven Breach Simulation")


if __name__ == '__main__':
    unittest.main()
