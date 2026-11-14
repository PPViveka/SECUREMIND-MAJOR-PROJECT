"""
Deterministic Fast-First Cascade Engine
Part of SageArmor / SecureMind Core Scanning Pipeline

Implements the "Cheap check first, AI second" architectural gate:
1. Runs deterministic SAST pattern matching (SASTScanner) locally on functions.
2. Checks for dangerous sinks (open, os.system, subprocess, execute, eval, pickle, etc.).
3. If a function contains NO regex match and touches NO dangerous sinks:
   - Instantly classifies as clean without invoking the LLM (0 tokens, 0ms model latency).
   - Caches the clean result.
4. If flagged by SAST or dangerous sinks:
   - Extracts only the flagged function with exact source line coordinates and caller context.
   - Forwards only the flagged candidate to LLM reasoning.
"""

from typing import Any, Dict, List, Optional, Tuple
from .sast_scanner import SASTScanner
from .function_cache import RISKY_SINKS, FunctionScanCache


class CascadeEngine:
    """
    Orchestrates the cascade: SAST rules first -> LLM reasoning second.
    Filters out benign code so LLMs are never invoked indiscriminately.
    """

    def __init__(self, cache: Optional[FunctionScanCache] = None):
        self.cache = cache or FunctionScanCache()

    def filter_and_triage(
        self,
        functions_to_scan: List[Dict[str, Any]],
        file_path: str = "<input>",
    ) -> Dict[str, Any]:
        """
        Triages functions needing evaluation into:
        - clean_functions: No SAST matches, no dangerous sinks (skipped from LLM).
        - flagged_functions: SAST match or dangerous sink (forwarded to LLM).
        """
        clean_functions = []
        flagged_functions = []

        for func in functions_to_scan:
            code = func.get("code", "")
            func_name = func.get("name", "<anonymous>")
            start_line = func.get("start_line", 1)
            risky_sinks = func.get("risky_sinks", [])

            # Run deterministic SAST scan locally
            sast_findings = SASTScanner.scan_code(code, file_path=file_path)

            # Adjust SAST finding line numbers to the absolute file line coordinates
            adjusted_sast = []
            for f in sast_findings:
                f_copy = dict(f)
                local_line = f_copy.get("line", 1)
                f_copy["line"] = start_line + local_line - 1
                f_copy["function_name"] = func_name
                adjusted_sast.append(f_copy)

            has_sast_hits = len(adjusted_sast) > 0
            has_risky_sinks = len(risky_sinks) > 0

            if not has_sast_hits and not has_risky_sinks:
                # Clean function: no dangerous sinks, no SAST matches
                clean_entry = dict(func)
                clean_entry["vulnerabilities"] = []
                clean_entry["reason"] = "no_sast_matches_and_no_dangerous_sinks"
                clean_functions.append(clean_entry)

                # Store clean result in cache immediately
                self.cache.set(
                    function_hash=func["hash"],
                    function_name=func_name,
                    language="python",
                    scan_result={"vulnerabilities": []},
                    original_start_line=start_line,
                    file_path=file_path,
                    tokens_used=0,
                    scan_duration_ms=0.5,
                    provider="sast-cascade-clean",
                )
            else:
                # Flagged function: needs deep contextual AI analysis
                flagged_entry = dict(func)
                flagged_entry["sast_findings"] = adjusted_sast
                flagged_entry["triage_reason"] = (
                    f"sast_hits={len(adjusted_sast)}, risky_sinks={','.join(risky_sinks)}"
                )
                flagged_functions.append(flagged_entry)

        return {
            "total_evaluated": len(functions_to_scan),
            "clean_count": len(clean_functions),
            "flagged_count": len(flagged_functions),
            "clean_functions": clean_functions,
            "flagged_functions": flagged_functions,
        }

    @staticmethod
    def build_targeted_prompt_context(
        flagged_functions: List[Dict[str, Any]],
        full_code: str = "",
    ) -> str:
        """
        Constructs focused code context containing only flagged functions and
        their line coordinates, avoiding bloating the LLM prompt with safe code.
        """
        snippets = []
        for func in flagged_functions:
            func_name = func.get("name", "<anonymous>")
            start = func.get("start_line", 1)
            end = func.get("end_line", start)
            code = func.get("code", "")
            sast_hits = func.get("sast_findings", [])
            sast_notes = ""
            if sast_hits:
                sast_notes = " [Rule Flagged: " + ", ".join(h.get("issue", "") for h in sast_hits) + "]"

            snippets.append(
                f"# Function '{func_name}' (Lines {start}-{end}){sast_notes}:\n{code}"
            )

        return "\n\n".join(snippets)
