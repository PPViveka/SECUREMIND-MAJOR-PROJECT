"""
test_verified_fixer.py — Tests for Codebase-Aware Verified Fix Loop (Step 5)

All tests are deterministic (no real LLM calls, no network, mocked gates).
"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from unittest.mock import patch, MagicMock
from src.verified_fixer import (
    VerifiedFixer,
    build_verified_fix_prompt,
    find_project_sanitizer_examples,
    run_verified_fix,
    _gate1_exploit_no_longer_reaches_sink,
    _gate2_tests_still_pass,
    _gate3_no_new_sast_findings,
)


# ---------------------------------------------------------------------------
# Shared test data
# ---------------------------------------------------------------------------

VULN_FINDING = {
    "function_name": "search_users",
    "issue": "SQL Injection",
    "cwe_id": "CWE-89",
    "explanation": "User input directly concatenated into SQL query",
    "line_number": 5,
    "severity": "High",
}

ORIGINAL_CODE = """
def search_users(query):
    import sqlite3
    conn = sqlite3.connect("app.db")
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE name = '" + query + "'")
    return cur.fetchall()
"""

PATCHED_CODE = """
def search_users(query):
    import sqlite3
    conn = sqlite3.connect("app.db")
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE name = ?", (query,))
    return cur.fetchall()
"""


# ---------------------------------------------------------------------------
# build_verified_fix_prompt
# ---------------------------------------------------------------------------

def test_prompt_contains_cwe_id():
    prompt = build_verified_fix_prompt(ORIGINAL_CODE, VULN_FINDING, [])
    assert "CWE-89" in prompt


def test_prompt_contains_function_name():
    prompt = build_verified_fix_prompt(ORIGINAL_CODE, VULN_FINDING, [])
    assert "search_users" in prompt


def test_prompt_contains_codebase_examples():
    examples = ["cursor.execute(sql, (param,))", "conn.cursor().execute(query, values)"]
    prompt = build_verified_fix_prompt(ORIGINAL_CODE, VULN_FINDING, examples)
    assert "cursor.execute(sql, (param,))" in prompt


# ---------------------------------------------------------------------------
# Gate 1: exploit_no_longer_reaches_sink — mock SandboxVerifier
# ---------------------------------------------------------------------------

def test_gate1_passes_when_exploit_unconfirmed():
    """Gate 1 passes when the sandbox says 'unconfirmed' (exploit blocked)."""
    mock_result = {
        "verification_status": "unconfirmed",
        "dynamic_trace": {"sink_reached": False},
    }
    with patch("src.verified_fixer.SandboxVerifier") as MockVerifier:
        MockVerifier.return_value.verify.return_value = mock_result
        passed, detail = _gate1_exploit_no_longer_reaches_sink(PATCHED_CODE, VULN_FINDING)
    assert passed is True
    assert "PASS" in detail


def test_gate1_fails_when_exploit_verified():
    """Gate 1 fails when sandbox still confirms exploit reaches sink."""
    mock_result = {
        "verification_status": "verified",
        "dynamic_trace": {"sink_reached": True},
    }
    with patch("src.verified_fixer.SandboxVerifier") as MockVerifier:
        MockVerifier.return_value.verify.return_value = mock_result
        passed, detail = _gate1_exploit_no_longer_reaches_sink(PATCHED_CODE, VULN_FINDING)
    assert passed is False
    assert "FAIL" in detail


# ---------------------------------------------------------------------------
# Gate 2: tests_still_pass
# ---------------------------------------------------------------------------

def test_gate2_skips_when_no_test_dir():
    """Gate 2 skips gracefully when no test directory is provided."""
    passed, detail = _gate2_tests_still_pass(PATCHED_CODE, "search_users", test_dir=None)
    assert passed is True
    assert "SKIP" in detail


def test_gate2_skips_when_nonexistent_dir():
    """Gate 2 skips gracefully when test directory does not exist."""
    passed, detail = _gate2_tests_still_pass(PATCHED_CODE, "search_users", test_dir="/nonexistent/path")
    assert passed is True
    assert "SKIP" in detail


# ---------------------------------------------------------------------------
# Gate 3: no_new_sast_findings — mock SASTScanner
# ---------------------------------------------------------------------------

def test_gate3_passes_when_no_new_high_findings():
    """Gate 3 passes when SAST finds no new high/critical issues."""
    with patch("src.verified_fixer.SASTScanner") as MockScanner:
        MockScanner.return_value.scan.return_value = [
            {"severity": "low", "issue": "Minor style issue"}
        ]
        passed, detail = _gate3_no_new_sast_findings(PATCHED_CODE, "SQL Injection")
    assert passed is True
    assert "PASS" in detail


def test_gate3_fails_when_new_high_finding():
    """Gate 3 fails when SAST finds a new high finding unrelated to original."""
    with patch("src.verified_fixer.SASTScanner") as MockScanner:
        MockScanner.return_value.scan.return_value = [
            {"severity": "high", "issue": "Command Injection introduced by patch"}
        ]
        passed, detail = _gate3_no_new_sast_findings(PATCHED_CODE, "SQL Injection")
    assert passed is False
    assert "FAIL" in detail


# ---------------------------------------------------------------------------
# VerifiedFixer integration tests
# ---------------------------------------------------------------------------

def _make_all_gates_pass():
    """Return a mock context where all three gates pass."""
    mock_sandbox_result = {
        "verification_status": "unconfirmed",
        "dynamic_trace": {"sink_reached": False},
    }
    mock_sast_result = [{"severity": "low", "issue": "Minor"}]
    return mock_sandbox_result, mock_sast_result


def test_verified_fixer_returns_verified_status_when_all_gates_pass():
    """VerifiedFixer returns patch_status='verified' when all gates pass."""
    mock_sandbox, mock_sast = _make_all_gates_pass()

    def fake_llm(_prompt):
        return PATCHED_CODE

    with patch("src.verified_fixer.SandboxVerifier") as MockVerifier, \
         patch("src.verified_fixer.SASTScanner") as MockSAST:
        MockVerifier.return_value.verify.return_value = mock_sandbox
        MockSAST.return_value.scan.return_value = mock_sast

        fixer = VerifiedFixer(invoke_llm_fn=fake_llm, test_dir=None)
        result = fixer.fix(ORIGINAL_CODE, VULN_FINDING)

    assert result["patch_status"] == "verified"
    assert result["patched_code"] == PATCHED_CODE
    assert result["diff"] != ""


def test_verified_fixer_returns_unverified_draft_when_gate1_fails():
    """VerifiedFixer returns 'unverified_draft' when Gate 1 always fails."""
    mock_sandbox_fail = {
        "verification_status": "verified",
        "dynamic_trace": {"sink_reached": True},
    }

    def fake_llm(_prompt):
        return PATCHED_CODE

    with patch("src.verified_fixer.SandboxVerifier") as MockVerifier:
        MockVerifier.return_value.verify.return_value = mock_sandbox_fail

        fixer = VerifiedFixer(invoke_llm_fn=fake_llm, test_dir=None, max_retries=2)
        result = fixer.fix(ORIGINAL_CODE, VULN_FINDING)

    assert result["patch_status"] == "unverified_draft"
    assert result["attempts"] <= 2


def test_verified_fixer_returns_failed_when_llm_fails():
    """VerifiedFixer returns 'failed' when the LLM always raises an exception."""

    def broken_llm(_prompt):
        raise RuntimeError("LLM unavailable")

    fixer = VerifiedFixer(invoke_llm_fn=broken_llm, test_dir=None, max_retries=2)
    result = fixer.fix(ORIGINAL_CODE, VULN_FINDING)

    assert result["patch_status"] == "failed"


def test_verified_fixer_includes_gate_log():
    """Gate log must be a non-empty list with gate and passed keys."""
    def fake_llm(_prompt):
        return PATCHED_CODE

    with patch("src.verified_fixer.SandboxVerifier") as MockVerifier, \
         patch("src.verified_fixer.SASTScanner") as MockSAST:
        MockVerifier.return_value.verify.return_value = {
            "verification_status": "unconfirmed",
            "dynamic_trace": {"sink_reached": False},
        }
        MockSAST.return_value.scan.return_value = []

        fixer = VerifiedFixer(invoke_llm_fn=fake_llm, test_dir=None)
        result = fixer.fix(ORIGINAL_CODE, VULN_FINDING)

    assert isinstance(result["gates"], list)
    assert len(result["gates"]) > 0
    for gate_entry in result["gates"]:
        assert "gate" in gate_entry
        assert "passed" in gate_entry
        assert "detail" in gate_entry


def test_run_verified_fix_convenience_wrapper():
    """run_verified_fix convenience function returns expected structure."""
    def fake_llm(_prompt):
        return PATCHED_CODE

    with patch("src.verified_fixer.SandboxVerifier") as MockVerifier, \
         patch("src.verified_fixer.SASTScanner") as MockSAST:
        MockVerifier.return_value.verify.return_value = {
            "verification_status": "unconfirmed",
            "dynamic_trace": {"sink_reached": False},
        }
        MockSAST.return_value.scan.return_value = []

        result = run_verified_fix(
            original_code=ORIGINAL_CODE,
            finding=VULN_FINDING,
            invoke_llm_fn=fake_llm,
        )

    assert "patch_status" in result
    assert "patched_code" in result
    assert "diff" in result
    assert "gates" in result


def test_find_project_sanitizer_examples_returns_list(tmp_path):
    """find_project_sanitizer_examples scans a temp project and returns examples."""
    # Create a fake Python file with a parameterized query
    (tmp_path / "db.py").write_text(
        'cursor.execute("SELECT * FROM t WHERE id = ?", (user_id,))\n'
    )
    examples = find_project_sanitizer_examples(str(tmp_path), "CWE-89")
    assert isinstance(examples, list)
    # Should find the parameterized query example
    assert len(examples) >= 1
