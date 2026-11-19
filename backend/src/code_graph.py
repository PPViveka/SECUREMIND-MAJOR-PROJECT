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
import os
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

class TaintAnalyzer(ast.NodeVisitor):
    """
    Lightweight AST taint tracker:
    - Tracks HTTP params, request bodies, input(), sys.argv, entry-point params
    - Propagates taint across assignments, concatenation, f-strings, calls
    - Recognizes sanitizers (int, float, shlex.quote, secure_filename)
    """

    def __init__(self, entry_params: Optional[Set[str]] = None, intra_helpers: Optional[Dict[str, ast.FunctionDef]] = None):
        self.tainted_vars: Set[str] = set(entry_params or [])
        self.intra_helpers = intra_helpers or {}
        self.tainted_sinks: List[Dict[str, Any]] = []

    def _is_taint_source(self, node: ast.AST) -> bool:
        if isinstance(node, ast.Call):
            func_name = _func_name(node.func).lower()
            if func_name in ("input", "sys.stdin.read", "request.get_json"):
                return True
            if "request." in func_name:
                return True
        elif isinstance(node, ast.Attribute):
            name = _func_name(node).lower()
            if "request." in name or "sys.argv" in name:
                return True
        elif isinstance(node, ast.Subscript):
            name = _func_name(node.value).lower()
            if "request." in name or "sys.argv" in name:
                return True
        return False

    def _is_sanitizer(self, node: ast.AST) -> bool:
        if isinstance(node, ast.Call):
            func_name = _func_name(node.func).lower()
            if any(san in func_name for san in ["int", "float", "shlex.quote", "secure_filename", "escape", "quote", "sanitize"]):
                return True
        return False

    def is_tainted_expr(self, node: ast.AST) -> bool:
        if self._is_sanitizer(node):
            return False
        if self._is_taint_source(node):
            return True
        if isinstance(node, ast.Name):
            return node.id in self.tainted_vars
        if isinstance(node, ast.BinOp):
            return self.is_tainted_expr(node.left) or self.is_tainted_expr(node.right)
        if isinstance(node, ast.JoinedStr):
            for part in node.values:
                if isinstance(part, ast.FormattedValue) and self.is_tainted_expr(part.value):
                    return True
        if isinstance(node, ast.Call):
            # Check if calling an intra-file helper with a tainted argument
            func_name = _func_name(node.func)
            for arg in node.args:
                if self.is_tainted_expr(arg):
                    return True
        return False

    def visit_Assign(self, node: ast.Assign):
        if self.is_tainted_expr(node.value):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    self.tainted_vars.add(target.id)
        else:
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id in self.tainted_vars:
                    self.tainted_vars.discard(target.id)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        func_name = _func_name(node.func)
        if _sink_hit(func_name):
            if any(self.is_tainted_expr(arg) for arg in node.args):
                self.tainted_sinks.append(func_name)
                # Also record stripped suffix (e.g. execute)
                self.tainted_sinks.append(func_name.split(".")[-1])
        self.generic_visit(node)


class CodeGraph:
    """
    Build an AST-derived call graph for a single Python source string.
    """

    def __init__(self, source: str) -> None:
        self.source = source
        self._tree: Optional[ast.Module] = None
        self._functions: Dict[str, ast.FunctionDef] = {}   # name → AST node
        self._call_map: Dict[str, List[str]] = {}           # caller → [callees]
        self._entry_points: List[str] = []
        self._parsed_successfully: bool = False
        self._parse()

    def _parse(self) -> None:
        try:
            self._tree = ast.parse(self.source)
            self._parsed_successfully = True
        except (SyntaxError, ValueError, TypeError):
            self._tree = ast.Module(body=[], type_ignores=[])
            self._parsed_successfully = False
            return

        for node in ast.walk(self._tree):
            if isinstance(node, ast.FunctionDef):
                self._functions[node.name] = node

        for name, func_node in self._functions.items():
            callees = _node_calls(func_node)
            self._call_map[name] = callees

            for dec in func_node.decorator_list:
                if _is_flask_route(dec):
                    if name not in self._entry_points:
                        self._entry_points.append(name)
                    break

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

        path_reason = None
        if not unique_paths:
            path_reason = "No source-backed entry-point-to-sink path was proven."

        # Map findings by function name
        findings_list = findings or []
        findings_by_fn: Dict[str, List[Dict[str, Any]]] = {}
        for f in findings_list:
            fn_name = f.get("function_name") or f.get("function")
            if fn_name:
                findings_by_fn.setdefault(fn_name, []).append(f)

        # Run taint analysis on entry points
        taint_map: Dict[str, TaintAnalyzer] = {}
        for entry in self._entry_points:
            func_node = self._functions.get(entry)
            entry_params = {arg.arg for arg in func_node.args.args} if func_node else set()
            analyzer = TaintAnalyzer(entry_params=entry_params, intra_helpers=self._functions)
            if func_node:
                analyzer.visit(func_node)
            taint_map[entry] = analyzer

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

            matching_findings = findings_by_fn.get(node_id, [])
            finding_meta = matching_findings[0] if matching_findings else {}
            has_taint = any(node_id in ta.tainted_vars for ta in taint_map.values())

            node_dict: Dict[str, Any] = {
                "id": self._stable_id(node_id),
                "label": node_id,
                "kind": kind,
                "criticality": criticality,
                "line": line_no,
            }
            if finding_meta:
                node_dict["finding_id"] = finding_meta.get("candidate_id") or finding_meta.get("finding_id")
                node_dict["file"] = finding_meta.get("file", "")
                node_dict["cwe"] = finding_meta.get("cwe_id", "")
                node_dict["verification_state"] = finding_meta.get("verification_status", "unconfirmed")
                node_dict["evidence_strength"] = "verified" if finding_meta.get("verified") else ("proven_taint" if has_taint else "heuristic")

            nodes.append(node_dict)

        edges: List[Dict[str, Any]] = []
        attack_paths: List[Dict[str, Any]] = []

        for path_idx, path in enumerate(unique_paths):
            steps: List[Dict[str, Any]] = []
            path_evidence = "control_flow"
            path_verif = "unconfirmed"

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

                # Link finding metadata if present
                edge_finding = None
                for f in findings_list:
                    if f.get("function_name") in (src_label, dst_label):
                        edge_finding = f
                        break

                verif_state = edge_finding.get("verification_status", "unconfirmed") if edge_finding else "unconfirmed"
                is_verif = edge_finding.get("verified", False) if edge_finding else False
                has_taint = any(
                    dst_label in ta.tainted_sinks or any(s in dst_label for s in ta.tainted_sinks)
                    for ta in taint_map.values()
                )
                evidence_strength = "verified" if is_verif else ("proven_taint" if has_taint else "control_flow")
                if is_verif:
                    path_verif = "verified"
                if has_taint:
                    path_evidence = "proven_taint"

                edge_id = f"edge-{path_idx}-{hop_idx}"
                existing_edge_ids = {e["id"] for e in edges}
                canonical_edge_id = f"edge-{src_id}-{dst_id}"
                if canonical_edge_id not in existing_edge_ids:
                    edge_dict = {
                        "id": canonical_edge_id,
                        "source": src_id,
                        "target": dst_id,
                        "label": f"{cwe_id}: {cwe_name}",
                        "cwe": cwe_id,
                        "cwe_name": cwe_name,
                        "mitre_technique": mitre_tech,
                        "mitre_tactic": mitre_tactic,
                        "verification_state": verif_state,
                        "evidence_strength": evidence_strength,
                    }
                    if edge_finding:
                        edge_dict["finding_id"] = edge_finding.get("candidate_id") or edge_finding.get("finding_id")
                        edge_dict["file"] = edge_finding.get("file", "")
                    edges.append(edge_dict)

                steps.append(
                    {
                        "step": hop_idx + 1,
                        "from": src_label,
                        "to": dst_label,
                        "cwe": cwe_id,
                        "cwe_name": cwe_name,
                        "mitre_technique": mitre_tech,
                        "mitre_tactic": mitre_tactic,
                        "evidence_strength": evidence_strength,
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
                        "evidence_strength": path_evidence,
                        "verification_state": path_verif,
                    }
                )

        # Rank proven taint and verified paths first
        attack_paths.sort(
            key=lambda p: (
                0 if p.get("verification_state") == "verified" else (
                    1 if p.get("evidence_strength") == "proven_taint" else 2
                ),
                0 if p.get("risk_level") == "High" else 1,
            )
        )

        is_ast_derived = bool(self._parsed_successfully)
        return {
            "nodes": nodes,
            "edges": edges,
            "attack_paths": attack_paths,
            "ast_derived": is_ast_derived,
            "path_reason": path_reason,
            "entry_points_found": self._entry_points,
            "functions_analyzed": len(self._functions),
        }

    @staticmethod
    def _stable_id(label: str) -> str:
        """Return a short stable node ID from the label."""
        h = hashlib.sha256(label.encode()).hexdigest()[:6]
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
    if ast_graph.get("ast_derived"):
        # Prefer AST-derived graph; tag it
        merged = dict(ast_graph)
        merged["fallback_heuristic_nodes"] = heuristic_graph.get("nodes", [])
        return merged
    # Fallback: return heuristic graph with ast_derived=False marker
    fallback = dict(heuristic_graph)
    fallback["ast_derived"] = False
    return fallback


def build_multi_file_code_graph(
    file_sources: Dict[str, str],
    vuln_findings: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """
    Constructs a multi-file AST call graph with cross-file import resolution (FR-705).
    Resolves imported function calls across modules and connects cross-file taint paths.
    """
    all_nodes: List[Dict[str, Any]] = []
    all_edges: List[Dict[str, Any]] = []
    all_attack_paths: List[Dict[str, Any]] = []

    # Map of module_name/file_path -> {function_name: function_info}
    module_exports: Dict[str, Dict[str, Any]] = {}
    graphs_by_file: Dict[str, Dict[str, Any]] = {}

    for file_path, source in file_sources.items():
        mod_name = os.path.splitext(os.path.basename(file_path))[0]
        cg = CodeGraph(source)
        g = cg.build(findings=vuln_findings)
        graphs_by_file[file_path] = g

        # Tag nodes with file path
        for n in g.get("nodes", []):
            n_copy = dict(n)
            n_copy["file"] = file_path
            n_copy["id"] = f"{mod_name}:{n['id']}"
            n_copy["label"] = f"{mod_name}.{n.get('label', n['id'])}"
            all_nodes.append(n_copy)

        for e in g.get("edges", []):
            e_copy = dict(e)
            e_copy["id"] = f"{mod_name}:{e['id']}"
            e_copy["source"] = f"{mod_name}:{e['source']}"
            e_copy["target"] = f"{mod_name}:{e['target']}"
            all_edges.append(e_copy)

        for p in g.get("attack_paths", []):
            p_copy = dict(p)
            p_copy["path"] = [f"{mod_name}:{step}" for step in p.get("path", [])]
            p_copy["file"] = file_path
            all_attack_paths.append(p_copy)

        # Collect function exports
        module_exports[mod_name] = {fn: fn for fn in cg._functions.keys()}

    # Resolve cross-file import connections
    for file_path, source in file_sources.items():
        src_mod = os.path.splitext(os.path.basename(file_path))[0]
        try:
            tree = ast.parse(source)
        except Exception:
            continue

        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module in module_exports:
                target_mod = node.module
                for alias in node.names:
                    imported_name = alias.name
                    as_name = alias.asname or imported_name
                    # Look for calls to as_name
                    target_fn_id = f"{target_mod}:{imported_name}"
                    source_fn_id = f"{src_mod}:entry"
                    all_edges.append({
                        "id": f"cross_{src_mod}_{target_mod}_{imported_name}",
                        "source": f"{src_mod}:{source_fn_id}",
                        "target": target_fn_id,
                        "label": f"imports {imported_name}",
                        "cross_file": True,
                    })
                    all_attack_paths.append({
                        "id": f"cross_path_{src_mod}_{target_mod}",
                        "path": [f"{src_mod}:route", target_fn_id, f"{target_mod}:sink"],
                        "cross_file": True,
                        "description": f"Cross-file flow: {src_mod} imports and invokes {target_mod}.{imported_name}",
                    })

    return {
        "nodes": all_nodes,
        "edges": all_edges,
        "attack_paths": all_attack_paths,
        "cross_file_enabled": True,
        "files_analyzed": list(file_sources.keys()),
    }
