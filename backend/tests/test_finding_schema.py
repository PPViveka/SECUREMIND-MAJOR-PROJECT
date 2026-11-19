import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from src.finding_schema import anchor_findings, normalize_finding, validate_finding


class TestFindingSchema(unittest.TestCase):
    def test_normalizes_legacy_location_and_preserves_compatibility_fields(self):
        finding = normalize_finding({
            "type": "sql_injection",
            "issue": "SQL Injection Vulnerability",
            "severity": "High",
            "file": "app.py",
            "line": 12,
            "suggested_fix": "Use parameters",
        }, language="python")

        self.assertTrue(validate_finding(finding))
        self.assertEqual(finding["range"], {"start": 12, "end": 12})
        self.assertEqual(finding["line"], 12)
        self.assertEqual(finding["cwe"], "CWE-89")
        self.assertEqual(finding["verification"]["verdict"], "pending")
        self.assertEqual(finding["remediation"], "Use parameters")

    def test_verification_never_promotes_unknown_state(self):
        finding = normalize_finding({"issue": "Test", "verdict": "verified-ish"})

        self.assertTrue(validate_finding(finding))
        self.assertEqual(finding["verification"]["verdict"], "inconclusive")

    def test_unavailable_isolation_is_not_applicable(self):
        finding = normalize_finding({"issue": "Test", "verification_status": "not_applicable"})
        self.assertEqual(finding["verification"]["verdict"], "not_applicable")

    def test_finding_verification_and_fix_validation_are_separate(self):
        finding = normalize_finding({
            "issue": "SQL Injection",
            "verification": {"verdict": "verified"},
            "fix_validation": {"status": "unvalidated", "gates": []},
        })

        self.assertEqual(finding["verification"]["verdict"], "verified")
        self.assertEqual(finding["fix_validation"]["status"], "unvalidated")

    def test_model_findings_must_anchor_to_source(self):
        anchored = anchor_findings(
            [{"issue": "SQL Injection", "provenance": "model", "matched_code": "query = user_input"}],
            "def search():\n    query = user_input\n",
        )
        unanchored = anchor_findings(
            [{"issue": "SQL Injection", "provenance": "model", "matched_code": "missing()"}],
            "def search():\n    return 1\n",
        )

        self.assertEqual(anchored[0]["line"], 2)
        self.assertEqual(unanchored[0]["verification"]["verdict"], "inconclusive")


if __name__ == "__main__":
    unittest.main()
