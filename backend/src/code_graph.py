"""
code_graph.py — AST-Grounded Attack Path Generator (Step 4)

Replaces the keyword-heuristic attack graph with a real AST-derived call graph
showing data flow from entry point → intermediate callers → vulnerable sink.

Design decisions:
  - Uses stdlib `ast` only — no third-party dependencies.
  - Works on a single Python source string (the code submitted for review).
  - Entry points: Flask @app.route decorators, CLI argparse/sys.argv patterns,
    or any function whose name starts with common handler prefixes.
  - Sinks: calls to dangerous functions / methods (execute, os.system,
    subprocess.*, open, eval, pickle, cursor.execute, etc.).
  - CWE + MITRE ATT&CK annotations are looked up from a compact static table.
  - Output is {nodes, edges, attack_paths} — compatible with React Flow.
"""

from __future__ import annotations

import ast
import hashlib
from typing import Any, Dict, List, Optional, Set, Tuple


# ---------------------------------------------------------------------------
# Static annotation tables
# ---------------------------------------------------------------------------

# Maps sink keyword → (CWE-ID, CWE-name, MITRE technique, MITRE tactic)
SINK_ANNOTATIONS: Dict[str, Tuple[str, str, str, str]] = {
    "execute":        ("CWE-89",  "SQL Injection",           "T1190", "Initial Access"),
    "cursor.execute": ("CWE-89",  "SQL Injection",           "T1190", "Initial Access"),
    "os.system":      ("CWE-78",  "OS Command Injection",    "T1059", "Execution"),
    "subprocess":     ("CWE-78",  "OS Command Injection",    "T1059", "Execution"),
    "popen":          ("CWE-78",  "OS Command Injection",    "T1059", "Execution"),
    "open":           ("CWE-22",  "Path Traversal",          "T1083", "Discovery"),
    "eval":           ("CWE-94",  "Code Injection",          "T1059", "Execution"),
    "exec":           ("CWE-94",  "Code Injection",          "T1059", "Execution"),
    "pickle":         ("CWE-502", "Deserialization",         "T1059", "Execution"),
    "loads":          ("CWE-502", "Deserialization",         "T1059", "Execution"),
    "render_template_string": ("CWE-94", "SSTI",             "T1059", "Execution"),
    "send_file":      ("CWE-22",  "Path Traversal",          "T1083", "Discovery"),
    "redirect":       ("CWE-601", "Open Redirect",           "T1189", "Initial Access"),
    "request.args":   ("CWE-20",  "Improper Input Validation","T1190","Initial Access"),
}

ENTRY_PREFIXES = ("route_", "handle_", "view_", "api_", "endpoint_", "get_", "post_",
                  "put_", "delete_", "patch_")

FLASK_DECORATORS = {"route", "get", "post", "put", "delete", "patch"}

SINK_KEYWORDS = set(SINK_ANNOTATIONS.keys())


# ---------------------------------------------------------------------------
# AST helpers
# ---------------------------------------------------------------------------

def _func_name(node: ast.expr) -> str:
    """Return a dotted name string for a Call node's func attribute."""
    if isinstance(node, ast.Attribute):
        return f"{_func_name(node.value)}.{node.attr}"
    if isinstance(node, ast.Name):
        return node.id
    return ""


def _is_flask_route(decorator: ast.expr) -> bool:
    """True if the decorator looks like @app.route(...) or @bp.get(...) etc."""
    if isinstance(decorator, ast.Call):
        name = _func_name(decorator.func)
        parts = name.split(".")
        return len(parts) >= 2 and parts[-1] in FLASK_DECORATORS
    if isinstance(decorator, ast.Attribute):
        return decorator.attr in FLASK_DECORATORS
    return False


def _node_calls(func_node: ast.FunctionDef) -> List[str]:
    """Return all function names called (directly) inside func_node."""
    calls: List[str] = []
    for node in ast.walk(func_node):
        if isinstance(node, ast.Call):
            calls.append(_func_name(node.func))
    return calls


def _sink_hit(call_name: str) -> Optional[Tuple[str, str, str, str]]:
    """Return sink annotation if call_name matches a known sink, else None."""
    name_lower = call_name.lower()
    for key, ann in SINK_ANNOTATIONS.items():
        if key in name_lower or name_lower.endswith(key.split(".")[-1]):
            return ann
    return None


# ---------------------------------------------------------------------------
# Core graph builder
# ---------------------------------------------------------------------------

class CodeGraph:
    """
    Build an AST-derived call graph for a single Python source string.

    Usage::
        cg = CodeGraph(source_code)
        graph = cg.build(vuln_function_names=["login", "search"])
    """

    def __init__(self, source: str) -> None:
        self.source = source
        self._tree: Optional[ast.Module] = None
        self._functions: Dict[str, ast.FunctionDef] = {}   # name → AST node
        self._call_map: Dict[str, List[str]] = {}           # caller → [callees]
        self._entry_points: List[str] = []
        self._parse()

    # ------------------------------------------------------------------
    # Parsing
    # ------------------------------------------------------------------

    def _parse(self) -> None:
        try:
            self._tree = ast.parse(self.source)
        except SyntaxError:
            self._tree = ast.Module(body=[], type_ignores=[])
            return

        # Collect top-level and class-nested function defs
        for node in ast.walk(self._tree):
            if isinstance(node, ast.FunctionDef):
                self._functions[node.name] = node

        # Build call map and identify entry points
        for name, func_node in self._functions.items():
            callees = _node_calls(func_node)
            self._call_map[name] = callees

            # Flask route entry points
            for dec in func_node.decorator_list:
                if _is_flask_route(dec):
                    if name not in self._entry_points:
                        self._entry_points.append(name)
                    break

            # Prefix-based entry points (no decorators found above)
            if name not in self._entry_points:
                if any(name.startswith(p) for p in ENTRY_PREFIXES):
                    self._entry_points.append(name)

    # ------------------------------------------------------------------
    # Path finding (DFS with cycle guard)
    # ------------------------------------------------------------------

    def _find_paths_to_sinks(
        self,
        start: str,
        visited: Optional[Set[str]] = None,
        depth: int = 0,
        max_depth: int = 8,
    ) -> List[List[str]]:
        """DFS from `start`, collecting paths that reach a sink call."""
        if visited is None:
            visited = set()
        if depth > max_depth or start in visited:
            return []

        visited = visited | {start}
        paths: List[List[str]] = []

        callees = self._call_map.get(start, [])
        for callee in callees:
            # Direct sink call
            if _sink_hit(callee):
                paths.append([start, callee])

            # Recursive descent into known function
            if callee in self._functions:
                sub_paths = self._find_paths_to_sinks(callee, visited, depth + 1, max_depth)
                for sp in sub_paths:
                    paths.append([start] + sp)

        return paths

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def build(
        self,
        vuln_function_names: Optional[List[str]] = None,
        findings: Optional[List[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """
        Build the attack graph.

        Parameters
        ----------
        vuln_function_names:
            Names of functions already identified as vulnerable (from LLM/SAST).
            Used to seed path finding even if not entry points.
        findings:
            Raw finding dicts from the scanner — used to annotate edges.

        Returns
        -------
        {nodes, edges, attack_paths}  — compatible with React Flow.
        """
        vuln_names: Set[str] = set(vuln_function_names or [])

        # Augment entry-point list with any vuln function that happens to be
        # reachable from an existing entry point (or is itself an entry point).
        seeds: List[str] = list(self._entry_points)
        for vn in vuln_names:
            if vn in self._functions and vn not in seeds:
                seeds.append(vn)

        # Collect all paths to sinks
        raw_paths: List[List[str]] = []
        for seed in seeds:
            raw_paths.extend(self._find_paths_to_sinks(seed))

        # De-duplicate
        seen_paths: Set[Tuple[str, ...]] = set()
        unique_paths: List[List[str]] = []
        for p in raw_paths:
            key = tuple(p)
            if key not in seen_paths:
                seen_paths.add(key)
                unique_paths.append(p)

        # If no AST-derived paths found, fall back to a minimal stub so the
        # caller always gets a valid graph structure.
        if not unique_paths and vuln_names:
            stub_name = next(iter(vuln_names))
            unique_paths = [[stub_name, "<unknown-sink>"]]

        # Build node and edge sets
        all_node_ids: Set[str] = set()
        for p in unique_paths:
            all_node_ids.update(p)

        nodes: List[Dict[str, Any]] = []
        for node_id in sorted(all_node_ids):
            # Classify node kind
            if node_id in self._entry_points or any(
                node_id.startswith(p) for p in ENTRY_PREFIXES
            ):
                kind = "entry"
                criticality = "entry"
            elif _sink_hit(node_id):
                kind = "sink"
                criticality = "critical"
            elif node_id in self._functions:
                kind = "function"
                criticality = "medium"
            else:
                kind = "external-call"
                criticality = "high"

            # Line number from AST if available
            line_no: Optional[int] = None
            if node_id in self._functions:
                line_no = self._functions[node_id].lineno

            nodes.append(
                {
                    "id": self._stable_id(node_id),
                    "label": node_id,
                    "kind": kind,
                    "criticality": criticality,
                    "line": line_no,
                }
            )

        edges: List[Dict[str, Any]] = []
        attack_paths: List[Dict[str, Any]] = []

        for path_idx, path in enumerate(unique_paths):
            steps: List[Dict[str, Any]] = []
            for hop_idx in range(len(path) - 1):
                src_label = path[hop_idx]
                dst_label = path[hop_idx + 1]
                src_id = self._stable_id(src_label)
                dst_id = self._stable_id(dst_label)

                # Annotate edge with CWE / MITRE
                ann = _sink_hit(dst_label)
                cwe_id = ann[0] if ann else "CWE-20"
                cwe_name = ann[1] if ann else "Input Validation"
                mitre_tech = ann[2] if ann else "T1190"
                mitre_tactic = ann[3] if ann else "Initial Access"

                edge_id = f"edge-{path_idx}-{hop_idx}"
                # Avoid duplicate edges in output
                existing_edge_ids = {e["id"] for e in edges}
                canonical_edge_id = f"edge-{src_id}-{dst_id}"
                if canonical_edge_id not in existing_edge_ids:
                    edges.append(
                        {
                            "id": canonical_edge_id,
                            "source": src_id,
                            "target": dst_id,
                            "label": f"{cwe_id}: {cwe_name}",
                            "cwe": cwe_id,
                            "cwe_name": cwe_name,
                            "mitre_technique": mitre_tech,
                            "mitre_tactic": mitre_tactic,
                        }
                    )

                steps.append(
                    {
                        "step": hop_idx + 1,
                        "from": src_label,
                        "to": dst_label,
                        "cwe": cwe_id,
                        "cwe_name": cwe_name,
                        "mitre_technique": mitre_tech,
                        "mitre_tactic": mitre_tactic,
                    }
                )

            if steps:
                # Determine overall risk from the final sink
                final_sink = path[-1]
                ann = _sink_hit(final_sink)
                risk = "High" if ann and ann[0] in ("CWE-89", "CWE-78", "CWE-94", "CWE-502") else "Medium"
                attack_paths.append(
                    {
                        "name": f"Attack path {path_idx + 1}: {path[0]} → {final_sink}",
                        "steps": steps,
                        "risk_level": risk,
                        "entry_point": path[0],
                        "sink": final_sink,
                    }
                )

        return {
            "nodes": nodes,
            "edges": edges,
            "attack_paths": attack_paths,
            "ast_derived": True,
            "entry_points_found": self._entry_points,
            "functions_analyzed": len(self._functions),
        }

    @staticmethod
    def _stable_id(label: str) -> str:
        """Return a short stable node ID from the label."""
        h = hashlib.sha1(label.encode()).hexdigest()[:6]
        # Keep the name readable but replace chars that break React Flow IDs
        safe = label.replace(".", "_").replace("<", "").replace(">", "").replace(" ", "_")
        return f"{safe}-{h}"


# ---------------------------------------------------------------------------
# Public top-level function (called from attack_intelligence / handler)
# ---------------------------------------------------------------------------

def build_code_graph(
    source: str,
    vuln_function_names: Optional[List[str]] = None,
    findings: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """
    Entry point for the attack path generator.

    Parameters
    ----------
    source:
        Full Python source code of the file being reviewed.
    vuln_function_names:
        Names of vulnerable functions already identified by SAST/LLM.
    findings:
        Raw vulnerability findings (used for annotation, optional).

    Returns
    -------
    AST-derived attack graph: {nodes, edges, attack_paths, ast_derived,
    entry_points_found, functions_analyzed}
    """
    cg = CodeGraph(source)
    return cg.build(vuln_function_names=vuln_function_names, findings=findings)


def merge_with_heuristic_graph(
    ast_graph: Dict[str, Any],
    heuristic_graph: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Merge the AST-derived graph with the heuristic graph from attack_intelligence.
    AST nodes/edges take precedence; heuristic ones are added only if the AST
    graph is empty (graceful fallback).
    """
    if ast_graph.get("nodes"):
        # Prefer AST-derived graph; tag it
        merged = dict(ast_graph)
        merged["fallback_heuristic_nodes"] = heuristic_graph.get("nodes", [])
        return merged
    # Fallback: return heuristic graph with ast_derived=False marker
    fallback = dict(heuristic_graph)
    fallback["ast_derived"] = False
    return fallback
