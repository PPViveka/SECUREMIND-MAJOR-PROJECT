"""
SageArmor Verifier Module
Dynamic execution sandbox verification, differential analysis, and canary detection.
"""

from ..sandbox_verifier import (
    SandboxVerifier,
    SandboxExecutionResult,
    apply_verification_gate,
)

__all__ = [
    "SandboxVerifier",
    "SandboxExecutionResult",
    "apply_verification_gate",
]
