"""
Tests for the real SAST (Static Application Security Testing) scanner.
Validates actual vulnerability detection patterns without mocking.
"""

import unittest
import sys
import os

# Add src directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from src.sast_scanner import SASTScanner
from src.prompt_builder import build_candidate_triage_prompt


class TestSASTScanner(unittest.TestCase):
    """Test real vulnerability pattern detection."""

    def test_findings_include_versioned_rule_metadata(self):
        findings = SASTScanner.scan_code(
            'query = "SELECT * FROM users WHERE id = " + user_id',
            'test.py',
        )

        sql_finding = next(finding for finding in findings if finding['type'] == 'sql_injection')
        assert sql_finding['rule_id'] == 'SA-SQL_INJECTION'
        assert sql_finding['cwe_id'] == 'CWE-89'
        assert sql_finding['confidence'] == 'medium'
        assert sql_finding['endLine'] == sql_finding['line']

    def test_sql_injection_concatenation(self):
        """Detect SQL injection with string concatenation."""
        code = '''
query = "SELECT * FROM users WHERE id = " + user_id
cursor.execute(query)
        '''
        findings = SASTScanner.scan_code(code, 'test.py')
        assert len(findings) > 0
        issue_types = [f['issue'] for f in findings]
        assert 'SQL Injection Vulnerability' in issue_types

    def test_sql_injection_string_formatting(self):
        """Detect SQL injection with f-string formatting."""
        code = '''
user_id = request.args.get('id')
query = f"SELECT * FROM users WHERE id = {user_id}"
cursor.execute(query)
        '''
        findings = SASTScanner.scan_code(code, 'test.py')
        assert len(findings) > 0
        assert any('SQL' in f['issue'] for f in findings)

    def test_hardcoded_secret_detection(self):
        """Detect hardcoded secrets and credentials."""
        code = '''
API_KEY = "sk-1234567890abcdefghijklmnop"
password = "my_secure_password_123"
        '''
        findings = SASTScanner.scan_code(code, 'test.py')
        assert len(findings) > 0
        issue_types = [f['issue'] for f in findings]
        assert 'Hardcoded Secret / Credential Exposure' in issue_types

    def test_hardcoded_aws_key(self):
        """Detect hardcoded AWS access keys."""
        code = '''
aws_access_key_id = AKIAQCYABBYVA7ARSRGL
        '''
        findings = SASTScanner.scan_code(code, 'test.py')
        assert len(findings) > 0
        assert any('Secret' in f['issue'] for f in findings)

    def test_hardcoded_github_token(self):
        """Detect hardcoded GitHub personal access tokens."""
        code = '''
github_token = "ghp_abcdef1234567890abcdef1234567890"
        '''
        findings = SASTScanner.scan_code(code, 'test.py')
        assert len(findings) > 0
        assert any('Secret' in f['issue'] for f in findings)

    def test_command_injection_subprocess(self):
        """Detect command injection in subprocess calls."""
        code = '''
import subprocess
user_input = request.args.get('cmd')
subprocess.run(f"process {user_input}", shell=True)
        '''
        findings = SASTScanner.scan_code(code, 'test.py')
        assert len(findings) > 0
        assert any('Command Injection' in f['issue'] for f in findings)

    def test_command_injection_os_system(self):
        """Detect command injection in os.system calls."""
        code = '''
import os
cmd = user_input
os.system(cmd)
        '''
        findings = SASTScanner.scan_code(code, 'test.py')
        assert len(findings) > 0
        assert any('Command Injection' in f['issue'] for f in findings)

    def test_path_traversal_detection(self):
        """Detect path traversal vulnerabilities."""
        code = '''
file_path = request.args.get('file')
with open(file_path, 'r') as f:
    content = f.read()
        '''
        findings = SASTScanner.scan_code(code, 'test.py')
        assert len(findings) > 0
        assert any('Path Traversal' in f['issue'] for f in findings)

    def test_pickle_insecure_deserialization(self):
        """Detect insecure pickle deserialization."""
        code = '''
import pickle
data = pickle.loads(untrusted_data)
        '''
        findings = SASTScanner.scan_code(code, 'test.py')
        assert len(findings) > 0
        assert any('Deserialization' in f['issue'] for f in findings)

    def test_yaml_unsafe_load(self):
        """Detect unsafe YAML loading."""
        code = '''
import yaml
config = yaml.load(user_input)
        '''
        findings = SASTScanner.scan_code(code, 'test.py')
        assert len(findings) > 0
        assert any('Deserialization' in f['issue'] for f in findings)

    def test_weak_md5_hashing(self):
        """Detect weak MD5 hashing."""
        code = 'import hashlib\npassword_hash = hashlib.md5(password.encode()).hexdigest()'
        findings = SASTScanner.scan_code(code, 'test.py')
        assert len(findings) > 0
        assert any('Cryptographic' in f['issue'] for f in findings)

    def test_weak_sha1_hashing(self):
        """Detect weak SHA1 hashing."""
        code = 'hash_value = hashlib.sha1(data).hexdigest()'
        findings = SASTScanner.scan_code(code, 'test.py')
        assert len(findings) > 0
        assert any('Cryptographic' in f['issue'] for f in findings)

    def test_aes_ecb_mode(self):
        """Detect insecure AES ECB mode."""
        code = 'cipher = AES.new(key, AES.MODE_ECB)'
        findings = SASTScanner.scan_code(code, 'test.py')
        assert len(findings) > 0
        assert any('Cryptographic' in f['issue'] for f in findings)

    def test_cors_wildcard(self):
        """Detect overly permissive CORS."""
        code = 'app.config["CORS_ORIGINS"] = "*"'
        findings = SASTScanner.scan_code(code, 'test.py')
        assert len(findings) > 0
        assert any('CORS' in f['issue'] for f in findings)

    def test_jwt_verification_disabled(self):
        """Detect disabled JWT verification."""
        code = '''
payload = jwt.decode(token, secret, verify=False)
        '''
        findings = SASTScanner.scan_code(code, 'test.py')
        assert len(findings) > 0
        assert any('Authentication' in f['issue'] for f in findings)

    def test_eval_statement(self):
        """Detect dangerous eval statements."""
        code = '''
result = eval(user_input)
        '''
        findings = SASTScanner.scan_code(code, 'test.py')
        assert len(findings) > 0
        assert any('Deserialization' in f['issue'] or 'Code Execution' in f['issue'] for f in findings)

    def test_exec_statement(self):
        """Detect dangerous exec statements."""
        code = '''
exec(user_provided_code)
        '''
        findings = SASTScanner.scan_code(code, 'test.py')
        assert len(findings) > 0
        assert any('Deserialization' in f['issue'] or 'Code Execution' in f['issue'] for f in findings)

    def test_clean_code_no_findings(self):
        """Ensure clean code produces no findings."""
        code = '''
import hashlib
def get_user(user_id):
    user_id = int(user_id)  # Validate type
    query = "SELECT * FROM users WHERE id = ?"
    cursor.execute(query, (user_id,))
    return cursor.fetchone()

password_hash = hashlib.sha256(password.encode()).hexdigest()
        '''
        findings = SASTScanner.scan_code(code, 'test.py')
        # Should have no critical or high findings with this secure code
        critical_high = [f for f in findings if f['severity'] in ['Critical', 'High']]
        assert len(critical_high) == 0

    def test_finding_has_remediation(self):
        """Ensure findings include remediation guidance."""
        code = '''
import pickle
data = pickle.loads(untrusted_data)
        '''
        findings = SASTScanner.scan_code(code, 'test.py')
        assert len(findings) > 0
        for finding in findings:
            assert 'remediation' in finding
            assert 'patch' in finding['remediation']
            assert 'explanation' in finding['remediation']
            assert 'suggested_fix' in finding

    def test_safe_json_random_and_path_literals_are_not_context_free_findings(self):
        code = '''
import json
import random
payload = json.loads(serialized_json)
choice = random.choice(items)
message = "../docs/readme.txt"
        '''
        findings = SASTScanner.scan_code(code, 'safe.py')

        assert not any(finding['type'] in {
            'insecure_deserialization', 'weak_cryptography', 'path_traversal'
        } for finding in findings)

    def test_finding_has_attack_vector(self):
        """Ensure findings include attack vector description."""
        code = '''
query = "SELECT * FROM users WHERE id = " + user_id
        '''
        findings = SASTScanner.scan_code(code, 'test.py')
        assert len(findings) > 0
        for finding in findings:
            assert 'attack_vector' in finding
            assert len(finding['attack_vector']) > 0

    def test_finding_has_poc(self):
        """Ensure findings include proof-of-concept scenarios."""
        code = '''
import subprocess
os.system(user_cmd)
        '''
        findings = SASTScanner.scan_code(code, 'test.py')
        assert len(findings) > 0
        for finding in findings:
            assert 'poc_exploit_scenario' in finding
            assert len(finding['poc_exploit_scenario']) > 0

    def test_multiple_vulnerabilities(self):
        """Detect multiple vulnerabilities in same code."""
        code = '''
import pickle
api_key = "sk-1234567890abcdefghijklmnop"
query = "SELECT * FROM users WHERE id = " + user_id
pickle.loads(untrusted_data)
        '''
        findings = SASTScanner.scan_code(code, 'test.py')
        # Should find multiple different vulnerability types
        issues = [f['issue'] for f in findings]
        assert len(set(issues)) >= 2  # At least 2 different types

    def test_line_number_tracking(self):
        """Ensure findings track line numbers correctly."""
        code = '''line 1
line 2
query = "SELECT * FROM users WHERE id = " + user_id
line 4
        '''
        findings = SASTScanner.scan_code(code, 'test.py')
        assert len(findings) > 0
        # Line number should be around where the vulnerability is
        for finding in findings:
            assert 'line' in finding
            assert finding['line'] > 0

    def test_file_path_tracking(self):
        """Ensure findings track file paths."""
        code = 'eval(user_input)'
        findings = SASTScanner.scan_code(code, 'app/routes/auth.py')
        assert len(findings) > 0
        for finding in findings:
            assert finding['file'] == 'app/routes/auth.py'

    def test_per_occurrence_findings(self):
        """Ensure multiple occurrences of the same issue type are not collapsed."""
        code = '''
def func1(u):
    cursor.execute("SELECT * FROM users WHERE id = " + u)

def func2(v):
    cursor.execute("SELECT * FROM posts WHERE id = " + v)
        '''
        findings = SASTScanner.scan_code(code, 'app/db.py')
        sql_findings = [f for f in findings if f['type'] == 'sql_injection']
        self.assertGreaterEqual(len(sql_findings), 2)
        lines = [f['line'] for f in sql_findings]
        self.assertEqual(len(lines), len(set(lines)))  # Distinct lines
        for f in sql_findings:
            self.assertIn('candidate_id', f)
            self.assertIn('file_references', f)
            self.assertEqual(len(f['file_references']), 1)

    def test_safe_twins_regression_suite(self):
        """Ensure every rule has a vulnerable and safe twin tested in regression."""
        self.assertTrue(hasattr(SASTScanner, 'SAFE_TWINS'))
        for vuln_type, twin in SASTScanner.SAFE_TWINS.items():
            vuln_findings = SASTScanner.scan_code(twin['vulnerable'], 'test_vuln.py')
            self.assertGreater(
                len(vuln_findings), 0,
                f"Vulnerable twin for {vuln_type} should have triggered finding"
            )

            safe_findings = SASTScanner.scan_code(twin['safe'], 'test_safe.py')
            severe_safe = [f for f in safe_findings if f['severity'] in ['High', 'Critical'] and f['type'] == vuln_type]
            self.assertEqual(
                len(severe_safe), 0,
                f"Safe twin for {vuln_type} should not trigger High/Critical finding: {severe_safe}"
            )

    def test_generic_eval_constant_not_flagged(self):
        """Constant arithmetic eval is qualified as false positive, dynamic eval is flagged."""
        safe_eval = 'x = eval("1 + 1")'
        findings = SASTScanner.scan_code(safe_eval, 'test.py')
        self.assertEqual(len(findings), 0)

        vuln_eval = 'x = eval(user_input)'
        vuln_findings = SASTScanner.scan_code(vuln_eval, 'test.py')
        self.assertGreater(len(vuln_findings), 0)

    def test_model_triage_prompt_construction(self):
        """Ensure model triage prompt asks for confirm/refute/uncertain and attacker hypothesis."""
        candidates = [
            {
                "candidate_id": "cand-sql-1",
                "issue": "SQL Injection",
                "cwe_id": "CWE-89",
                "line": 10,
                "matched_code": "cursor.execute('SELECT ' + u)",
            }
        ]
        prompt = build_candidate_triage_prompt(candidates, "code...", "test.py")
        self.assertIn("cand-sql-1", prompt)
        self.assertIn("confirm", prompt)
        self.assertIn("refute", prompt)
        self.assertIn("uncertain", prompt)
        self.assertIn("attacker_hypothesis", prompt)
        self.assertIn("quoted_code_span", prompt)


if __name__ == '__main__':
    unittest.main()
