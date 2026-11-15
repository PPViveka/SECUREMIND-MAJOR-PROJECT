"""
test_ablation_benchmarks.py
Unit and integration tests for Step 7: Benchmark Evaluation & Ablation Framework.
"""

import json
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from benchmarks.ablation_runner import (
    DEFAULT_TEST_CASES_DIR,
    AblationRunner,
    BenchmarkFunction,
    ModeEvaluationMetrics,
)


class TestAblationBenchmarks(unittest.TestCase):
    """Tests the AblationRunner, test case discovery, and 4-mode metrics calculation."""

    @classmethod
    def setUpClass(cls):
        cls.runner = AblationRunner(test_cases_dir=DEFAULT_TEST_CASES_DIR)
        cls.functions = cls.runner.load_benchmark_functions()

    def test_load_benchmark_functions(self):
        """Verifies benchmark functions are loaded and balanced between vulnerable and guarded."""
        self.assertGreaterEqual(len(self.functions), 20)
        vulnerable = [f for f in self.functions if f.ground_truth]
        guarded = [f for f in self.functions if not f.ground_truth]
        self.assertEqual(len(vulnerable), len(guarded))
        self.assertEqual(len(self.functions), 30)

        # Ensure all 3 CWE categories exist
        categories = {f.cwe_type for f in self.functions}
        self.assertIn("sql_injection", categories)
        self.assertIn("path_traversal", categories)
        self.assertIn("command_injection", categories)

    def test_m1_rules_only_evaluation(self):
        """M1 uses 0 tokens and performs static pattern matching."""
        m1 = self.runner.evaluate_m1_rules_only(self.functions[:10])
        self.assertEqual(m1.mode_name, "M1")
        self.assertEqual(m1.total_cases, 10)
        self.assertEqual(m1.total_tokens, 0)
        self.assertEqual(m1.tokens_per_function, 0.0)
        self.assertGreaterEqual(m1.accuracy, 0.5)
        self.assertEqual(m1.patch_success_rate, 0.0)

    def test_m2_ai_only_evaluation(self):
        """M2 uses tokens for every function and exhibits higher false positives."""
        m2 = self.runner.evaluate_m2_ai_only(self.functions[:10])
        self.assertEqual(m2.mode_name, "M2")
        self.assertEqual(m2.total_cases, 10)
        self.assertGreater(m2.total_tokens, 0)
        self.assertGreater(m2.tokens_per_function, 100.0)
        self.assertEqual(m2.patch_success_rate, 0.0)

    def test_m3_hybrid_evaluation(self):
        """M3 filters clean functions with SAST, reducing tokens compared to M2."""
        sample = self.functions[:10]
        m2 = self.runner.evaluate_m2_ai_only(sample)
        m3 = self.runner.evaluate_m3_hybrid(sample)
        self.assertEqual(m3.mode_name, "M3")
        self.assertLessEqual(m3.total_tokens, m2.total_tokens)
        self.assertEqual(m3.patch_success_rate, 0.0)

    def test_m4_full_system_evaluation(self):
        """M4 eliminates false positives via sandbox execution and verifies patches."""
        # Test on 2 vulnerable and 2 guarded functions
        vulns = [f for f in self.functions if f.ground_truth][:2]
        guards = [f for f in self.functions if not f.ground_truth][:2]
        test_subset = vulns + guards

        m4 = self.runner.evaluate_m4_full_system(test_subset)
        self.assertEqual(m4.mode_name, "M4")
        self.assertEqual(m4.total_cases, 4)
        # False positives should be 0 on guarded code
        self.assertEqual(m4.false_positives, 0)
        self.assertEqual(m4.false_positive_rate, 0.0)
        # Patches that were attempted in M4 should pass verification
        if m4.patches_attempted > 0:
            self.assertEqual(m4.patch_success_rate, 1.0)

    def test_markdown_report_formatting(self):
        """Generates a markdown comparison table and checks required sections."""
        results = {
            "M1": self.runner.evaluate_m1_rules_only(self.functions[:4]),
            "M2": self.runner.evaluate_m2_ai_only(self.functions[:4]),
            "M3": self.runner.evaluate_m3_hybrid(self.functions[:4]),
            "M4": self.runner.evaluate_m4_full_system(self.functions[:4]),
        }
        report = self.runner.generate_markdown_report(results)
        self.assertIn("# 🔬 SageArmor Ablation Benchmark Report (Step 7)", report)
        self.assertIn("M1: Rules Only", report)
        self.assertIn("M2: AI Only", report)
        self.assertIn("M3: Hybrid", report)
        self.assertIn("M4: Full System", report)
        self.assertIn("False Positive Rate (FPR)", report)
        self.assertIn("Patch Success Rate", report)

    def test_json_export_structure(self):
        """Checks that ModeEvaluationMetrics serialize to valid JSON dictionary."""
        metrics = self.runner.evaluate_m1_rules_only(self.functions[:2])
        d = metrics.__dict__
        self.assertIn("mode_name", d)
        self.assertIn("precision", d)
        self.assertIn("recall", d)
        self.assertIn("false_positive_rate", d)
        self.assertIn("detailed_results", d)
        json_str = json.dumps(d, default=str)
        self.assertTrue(len(json_str) > 50)


if __name__ == "__main__":
    unittest.main()
