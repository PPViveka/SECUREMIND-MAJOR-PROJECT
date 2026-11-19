"""
SageArmor Fixer Module
Automated multi-span remediation, 5-gate verified fixer loop, and patch validation.
"""

from ..verified_fixer import (
    VerifiedFixer,
    run_verified_fix,
    build_verified_fix_prompt,
    find_project_sanitizer_examples,
    gate_a_parse_compile,
    gate_b_differential_exploit,
    gate_c_project_tests,
    gate_d_rescan_validation,
    gate_e_diff_path_constraints,
)
from ..autofix_engine import (
    start_autofix_job,
    apply_multi_file_patch,
    _run_snippet_autofix,
    _create_github_pr,
    _resolve_fix_path,
)
from ..autofix_prompt import build_autofix_prompt

__all__ = [
    "VerifiedFixer",
    "run_verified_fix",
    "build_verified_fix_prompt",
    "find_project_sanitizer_examples",
    "gate_a_parse_compile",
    "gate_b_differential_exploit",
    "gate_c_project_tests",
    "gate_d_rescan_validation",
    "gate_e_diff_path_constraints",
    "start_autofix_job",
    "apply_multi_file_patch",
    "_run_snippet_autofix",
    "_create_github_pr",
    "_resolve_fix_path",
    "build_autofix_prompt",
]
