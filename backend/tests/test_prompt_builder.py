"""
Unit tests for backend/src/prompt_builder.py
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from src.prompt_builder import build_security_prompt


class TestBuildSecurityPrompt(unittest.TestCase):
    def test_returns_non_empty_string(self):
        result = build_security_prompt("print('hello')", "python")
        self.assertIsInstance(result, str)
        self.assertGreater(len(result), 100)

    def test_python_mode_is_sast(self):
        result = build_security_prompt("x = 1", "python")
        self.assertIn("SAST", result)

    def test_javascript_mode_is_sast(self):
        result = build_security_prompt("const x = 1;", "javascript")
        self.assertIn("SAST", result)

    def test_go_mode_is_sast(self):
        result = build_security_prompt("fmt.Println('hi')", "go")
        self.assertIn("SAST", result)

    def test_terraform_mode_is_iac(self):
        result = build_security_prompt('resource "aws_s3_bucket" {}', "terraform")
        self.assertIn("IaC", result)

    def test_yaml_mode_is_iac(self):
        result = build_security_prompt("apiVersion: v1", "yaml")
        self.assertIn("IaC", result)

    def test_prompt_requires_poc_exploit_scenario(self):
        result = build_security_prompt("x = 1", "python")
        self.assertIn("poc_exploit_scenario", result)

    def test_prompt_requires_remediation_object(self):
        result = build_security_prompt("x = 1", "python")
        self.assertIn("remediation", result)

    def test_prompt_contains_cis_nist_guidelines(self):
        result = build_security_prompt("x = 1", "python")
        self.assertTrue("guidelines" in result.lower() or "CIS" in result or "NIST" in result)

    def test_default_language_is_python(self):
        result_explicit = build_security_prompt("x = 1", "python")
        result_default = build_security_prompt("x = 1")
        self.assertEqual(result_explicit, result_default)


if __name__ == "__main__":
    unittest.main()
