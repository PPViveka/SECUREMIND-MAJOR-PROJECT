"""
test_ablation_benchmarks.py
Unit and integration tests for Section 11: Benchmark Evaluation Harness & Ablation Framework.
"""

import json
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from benchmarks.ablation_runner import (
    DEFAULT_LABELS_PATH,
    DEFAULT_TEST_CASES_DIR,
    AblationRunner,
    BenchmarkFunction,
    ModeEvaluationMetrics,
)


class TestAblationBenchmarks(unittest.TestCase):
    """Tests the AblationRunner, labels.yaml loading, baselines, splits, and metrics."""

    @classmethod
    def setUpClass(cls):
        cls.runner = AblationRunner(
            test_cases_dir=DEFAULT_TEST_CASES_DIR,
            labels_file=DEFAULT_LABELS_PATH,
            llm_mode="mock",
        )
        cls.all_functions = cls.runner.load_benchmark_functions(split="all")
        cls.dev_functions = cls.runner.load_benchmark_functions(split="dev")
        cls.eval_functions = cls.runner.load_benchmark_functions(split="eval")

    def test_load_benchmark_functions_across_splits(self):
        """Verifies benchmark functions are loaded and balanced across dev and eval splits."""
        self.assertEqual(len(self.all_functions), 100)
        self.assertEqual(len(self.dev_functions), 50)
        self.assertEqual(len(self.eval_functions), 50)

        # Ensure all 5 vulnerability classes exist
        categories = {f.cwe_type for f in self.all_functions}
        self.assertEqual(
            categories,
            {"sql_injection", "command_injection", "path_traversal", "eval_injection", "ssrf"}
        )

        # Check ground truth balance (50 vulnerable, 50 guarded)
        vulns = [f for f in self.all_functions if f.ground_truth]
        guards = [f for f in self.all_functions if not f.ground_truth]
        self.assertEqual(len(vulns), 50)
        self.assertEqual(len(guards), 50)

    def test_llm_modes_mock_and_recorded(self):
        """Tests that both mock and recorded LLM modes evaluate correctly."""
        mock_runner = AblationRunner(llm_mode="mock")
        res_mock = mock_runner.evaluate_m2_ai_only(self.dev_functions[:6])
        self.assertGreater(res_mock.total_tokens, 0)
        self.assertEqual(res_mock.total_cases, 6)

        rec_runner = AblationRunner(llm_mode="recorded")
        res_rec = rec_runner.evaluate_m2_ai_only(self.dev_functions[:6])
        self.assertGreater(res_rec.total_tokens, 0)
        self.assertEqual(res_rec.total_cases, 6)

    def test_m1_rules_only_evaluation(self):
        """M1 uses 0 tokens and performs static pattern matching."""
        m1 = self.runner.evaluate_m1_rules_only(self.dev_functions[:10])
        self.assertEqual(m1.mode_name, "M1")
        self.assertEqual(m1.total_cases, 10)
        self.assertEqual(m1.total_tokens, 0)
        self.assertEqual(m1.tokens_per_function, 0.0)
        self.assertGreaterEqual(m1.accuracy, 0.5)

    def test_m4_full_system_and_gates(self):
        """M4 exercises the full production pipeline and per-gate pass metrics."""
        sample = self.dev_functions[:10]
        m4 = self.runner.evaluate_m4_full_system(sample)
        self.assertEqual(m4.mode_name, "M4")
        self.assertEqual(m4.total_cases, 10)
        # Sandbox execution proof eliminates false positives on guarded twins
        self.assertEqual(m4.false_positive_rate, 0.0)
        self.assertEqual(m4.verified_precision, 1.0)

        # Check gate pass metrics
        if m4.patches_attempted > 0:
            self.assertGreater(m4.gate_a_pass_rate, 0.0)
            self.assertGreater(m4.gate_b_pass_rate, 0.0)
            self.assertGreaterEqual(m4.patch_success_rate, 0.8)

    def test_bandit_and_semgrep_baselines(self):
        """Tests Bandit and Semgrep baseline evaluators."""
        sample = self.dev_functions[:10]
        bandit = self.runner.evaluate_bandit_baseline(sample)
        self.assertEqual(bandit.mode_name, "Bandit")
        self.assertEqual(bandit.total_cases, 10)

        semgrep = self.runner.evaluate_semgrep_baseline(sample)
        self.assertEqual(semgrep.mode_name, "Semgrep")
        self.assertEqual(semgrep.total_cases, 10)

    def test_evaluation_hashes_and_report_generation(self):
        """Verifies cryptographic hashes and markdown report generation."""
        hashes = self.runner.compute_evaluation_hashes(self.dev_functions[:5])
        self.assertIn("config_hash", hashes)
        self.assertIn("rule_set_hash", hashes)
        self.assertIn("prompt_hash", hashes)
        self.assertIn("source_hash", hashes)
        self.assertIn("model_hash", hashes)

        sample = self.dev_functions[:6]
        results = {
            "M1": self.runner.evaluate_m1_rules_only(sample),
            "M2": self.runner.evaluate_m2_ai_only(sample),
            "M3": self.runner.evaluate_m3_hybrid(sample),
            "M4": self.runner.evaluate_m4_full_system(sample),
            "Bandit": self.runner.evaluate_bandit_baseline(sample),
            "Semgrep": self.runner.evaluate_semgrep_baseline(sample),
        }
        report = self.runner.generate_markdown_report(results, split="dev")
        self.assertIn("# 🔬 SageArmor Empirical Benchmark Evaluation Report", report)
        self.assertIn("M4: Full SageArmor", report)
        self.assertIn("Bandit Baseline", report)
        self.assertIn("Semgrep Baseline", report)
        self.assertIn("Multi-Gate Verification Breakdown", report)


if __name__ == "__main__":
    unittest.main()
