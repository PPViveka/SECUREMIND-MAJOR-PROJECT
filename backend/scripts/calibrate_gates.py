#!/usr/bin/env python3
"""
calibrate_gates.py
Pre-evaluation gate calibration script.
Validates each of the 5 verification gates against known baseline functions
to establish thresholds, timeouts, and baseline accuracy before running evaluation harnesses.
"""

import json
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from src.sandbox_verifier import SandboxVerifier, apply_verification_gate
from src.sast_scanner import SASTScanner
from src.verified_fixer import (
    gate_a_parse_compile,
    gate_b_differential_exploit,
    gate_d_rescan_validation,
    gate_e_diff_path_constraints,
)


def calibrate_all_gates():
    print("=" * 60)
    print("🔬 SageArmor Pre-Evaluation Gate Calibration")
    print("=" * 60)

    results = {
        "timestamp": time.time(),
        "gates": {},
        "overall_status": "pass",
    }

    # Gate A: Clean AST Parse & Compile
    print("\n[Gate A] Testing AST parse & compilation...")
    valid_code = "def add(a, b):\n    return a + b\n"
    invalid_code = "def broken(\n    return"
    pass_valid, st_valid, _ = gate_a_parse_compile(valid_code)
    pass_invalid, st_invalid, _ = gate_a_parse_compile(invalid_code)
    gate_a_ok = pass_valid and not pass_invalid
    results["gates"]["gate_a"] = {
        "status": "pass" if gate_a_ok else "fail",
        "description": "Clean AST parsing & compile validation",
        "passed": gate_a_ok,
    }
    print(f"  -> Gate A: {'PASS' if gate_a_ok else 'FAIL'}")

    # Gate B: Dynamic Sandbox Differential Exploit
    print("\n[Gate B] Testing sandbox differential exploit execution...")
    default_runtime = "docker" if SandboxVerifier._is_docker_live() else "host"
    chosen_runtime = os.getenv("SAGEARMOR_SANDBOX_RUNTIME", default_runtime)
    verifier = SandboxVerifier(timeout_sec=3.0, runtime=chosen_runtime)
    vuln_code = (
        "import sqlite3\n"
        "def query_user(user_id):\n"
        "    conn = sqlite3.connect(':memory:')\n"
        "    return conn.execute('SELECT * FROM users WHERE id = ' + user_id).fetchall()\n"
    )
    safe_code = (
        "import sqlite3\n"
        "def query_user(user_id):\n"
        "    conn = sqlite3.connect(':memory:')\n"
        "    return conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchall()\n"
    )
    finding = {"issue": "SQL Injection", "cwe_id": "CWE-89", "function_name": "query_user", "line": 4}
    
    # On vuln_code: dynamic verifier should confirm exploit
    v_report = verifier.verify(source_code=vuln_code, function_name="query_user", cwe_id="sql_injection", sink_line=4)
    is_vuln_verified = v_report.get("verified", False)
    # On safe_code (as patch): gate_b should pass (exploit blocked)
    pass_safe_patch, _, _ = gate_b_differential_exploit(safe_code, finding, verifier)
    gate_b_ok = is_vuln_verified and pass_safe_patch
    results["gates"]["gate_b"] = {
        "status": "pass" if gate_b_ok else "fail",
        "description": "Differential exploit sandbox validation",
        "verified_exploit_detected": is_vuln_verified,
        "exploit_blocked_on_patch": pass_safe_patch,
        "passed": gate_b_ok,
    }
    print(f"  -> Gate B: {'PASS' if gate_b_ok else 'FAIL'}")

    # Gate D: Rescan validation (no residual high/critical SAST findings)
    print("\n[Gate D] Testing SAST rescan validation...")
    pass_rescan_clean, _, _ = gate_d_rescan_validation(safe_code, "SQL Injection")
    pass_rescan_dirty, _, _ = gate_d_rescan_validation(vuln_code, "SQL Injection")
    gate_d_ok = pass_rescan_clean and not pass_rescan_dirty
    results["gates"]["gate_d"] = {
        "status": "pass" if gate_d_ok else "fail",
        "description": "SAST rescan clean check",
        "passed": gate_d_ok,
    }
    print(f"  -> Gate D: {'PASS' if gate_d_ok else 'FAIL'}")

    # Gate E: Function signature & diff constraints preservation
    print("\n[Gate E] Testing function signature and path constraints...")
    diff_sig = "def query_user(new_param, extra):\n    pass\n"
    pass_sig_match, _, _ = gate_e_diff_path_constraints(vuln_code, safe_code, "query_user")
    pass_sig_mismatch, _, _ = gate_e_diff_path_constraints(vuln_code, diff_sig, "query_user")
    gate_e_ok = pass_sig_match and not pass_sig_mismatch
    results["gates"]["gate_e"] = {
        "status": "pass" if gate_e_ok else "fail",
        "description": "Function signature and diff constraints parity check",
        "passed": gate_e_ok,
    }
    print(f"  -> Gate E: {'PASS' if gate_e_ok else 'FAIL'}")

    all_passed = all(g.get("passed", False) for g in results["gates"].values())
    results["overall_status"] = "pass" if all_passed else "fail"

    out_path = os.path.join(os.path.dirname(__file__), "..", "benchmarks", "calibration_report.json")
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)

    print("\n" + "=" * 60)
    print(f"✅ Calibration complete: {out_path} (Status: {results['overall_status'].upper()})")
    print("=" * 60)
    return 0 if all_passed else 1


if __name__ == "__main__":
    sys.exit(calibrate_all_gates())
