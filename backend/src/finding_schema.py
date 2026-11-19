"""Shared finding contract and compatibility normalization."""

import hashlib
import json
import re
from typing import Any, Dict, Iterable, List


SCHEMA_VERSION = "1.0"
VERDICTS = {"verified", "refuted", "inconclusive", "not_applicable", "pending"}
TIER_A_LANGUAGES = {"python", "py"}

_SEVERITIES = {"critical", "high", "medium", "low", "info"}
_CWE_BY_TYPE = {
    "sql_injection": "CWE-89",
    "command_injection": "CWE-78",
    "path_traversal": "CWE-22",
    "insecure_deserialization": "CWE-502",
    "weak_cryptography": "CWE-327",
    "hardcoded_secret": "CWE-798",
    "authentication_bypass": "CWE-287",
    "cors_misconfiguration": "CWE-942",
    "unsafe_redirect": "CWE-601",
    "missing_validation": "CWE-20",
}
_ATTACK_BY_CWE = {
    "CWE-78": "T1059",
    "CWE-89": "T1190",
    "CWE-94": "T1059",
    "CWE-502": "T1059",
    "CWE-22": "T1083",
    "CWE-798": "T1552.001",
}


def _first(value: Any, *keys: str, default: Any = None) -> Any:
    if isinstance(value, dict):
        for key in keys:
            if value.get(key) is not None:
                return value[key]
    return default


def _line(value: Any, default: int = 0) -> int:
    try:
        return max(0, int(value))
    except (TypeError, ValueError):
        return default


def _range(finding: Dict[str, Any]) -> Dict[str, int]:
    start = _line(_first(finding, "start_line", "startLine", "line"))
    end = _line(_first(finding, "end_line", "endLine", "line"), start)
    return {"start": start, "end": max(start, end)}


def _verification(finding: Dict[str, Any]) -> Dict[str, Any]:
    explicit = _first(finding, "verification", default={})
    explicit = explicit if isinstance(explicit, dict) else {}
    verdict = _first(explicit, "verdict") or _first(finding, "verdict")
    if not verdict:
        status = finding.get("verification_status")
        if status in VERDICTS:
            verdict = status
        elif finding.get("verified") is True:
            verdict = "verified"
        elif finding.get("verified") is False or finding.get("verification_status") == "unconfirmed":
            verdict = "inconclusive"
        else:
            verdict = "pending"
    if verdict not in VERDICTS:
        verdict = "inconclusive"
    result = dict(explicit)
    result["verdict"] = verdict
    return result


def normalize_finding(finding: Any, *, file_path: str = "", language: str = "") -> Dict[str, Any]:
    """Normalize a legacy or model finding into the shared runtime contract."""
    raw = dict(finding) if isinstance(finding, dict) else {"issue": str(finding)}
    issue = str(_first(raw, "issue", "title", default="Unspecified security finding"))
    finding_type = str(_first(raw, "type", "rule_id", default="unknown"))
    location = _range(raw)
    file_name = str(_first(raw, "file", "path", default=file_path) or file_path)
    cwe = _first(raw, "cwe", "cwe_id") or _CWE_BY_TYPE.get(finding_type)
    attack = _first(raw, "attack", "attack_technique", "mitre_technique")
    if not attack and cwe:
        attack = _ATTACK_BY_CWE.get(cwe)
    identity = {
        "type": finding_type,
        "issue": issue,
        "file": file_name,
        "range": location,
        "matched_code": str(_first(raw, "matched_code", default="")),
    }
    finding_id = str(_first(raw, "finding_id", default="")) or hashlib.sha256(
        json.dumps(identity, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()[:16]
    severity = str(_first(raw, "severity", default="Info")).capitalize()
    if severity.lower() not in _SEVERITIES:
        severity = "Info"
    confidence = _first(raw, "confidence", default="medium")
    confidence = confidence if confidence in {"high", "medium", "low"} else "medium"
    verification = _verification(raw)
    if language and language.lower() not in TIER_A_LANGUAGES and verification["verdict"] == "pending":
        verification["verdict"] = "not_applicable"
        verification["reason"] = "Dynamic verification is unavailable for this language tier."

    normalized = dict(raw)
    normalized.update({
        "finding_id": finding_id,
        "schema_version": SCHEMA_VERSION,
        "issue": issue,
        "severity": severity,
        "language": str(_first(raw, "language", default=language) or language),
        "file": file_name,
        "range": location,
        "function_id": _first(raw, "function_id", "function_name"),
        "provenance": str(_first(raw, "provenance", default="sast")),
        "confidence": confidence,
        "verification": verification,
        "fix_validation": _first(raw, "fix_validation", default=None),
        "remediation": _first(raw, "remediation", "suggested_fix", default={}),
        "cwe": cwe,
        "attack_technique": attack,
        "line": location["start"],
        "endLine": location["end"],
    })
    return normalized


def normalize_findings(findings: Iterable[Any], *, file_path: str = "", language: str = "") -> List[Dict[str, Any]]:
    return [normalize_finding(item, file_path=file_path, language=language) for item in (findings or [])]


def anchor_findings(findings: Iterable[Any], source: str) -> List[Dict[str, Any]]:
    """Anchor model findings to quoted source spans, valid line numbers, or function boundaries."""
    anchored = []
    source_text = source or ""
    source_lines = source_text.splitlines()
    total_lines = len(source_lines)

    fn_matches = list(re.finditer(r"^\s*(?:async\s+)?def\s+([a-zA-Z0-9_]+)\s*\(", source_text, re.MULTILINE))

    for item in findings or []:
        finding = dict(item) if isinstance(item, dict) else {"issue": str(item)}
        line_val = finding.get("line")
        if line_val is None:
            line_val = finding.get("line_number")
        if line_val is None and isinstance(finding.get("range"), dict):
            line_val = finding["range"].get("start")

        try:
            line_val_int = int(line_val) if line_val is not None else 0
        except (ValueError, TypeError):
            line_val_int = 0

        snippet = str(
            finding.get("matched_code")
            or finding.get("code_span")
            or ""
        ).strip()

        start = source_text.find(snippet) if (snippet and len(snippet) > 2) else -1
        if start >= 0:
            line = source_text[:start].count("\n") + 1
            finding["line"] = line
            finding["endLine"] = line + snippet.count("\n")
            finding["range"] = {"start": finding["line"], "end": finding["endLine"]}
        elif snippet and len(snippet) > 2:
            verification = dict(finding.get("verification") or {})
            verification.update({
                "verdict": "inconclusive",
                "reason": "Model finding quoted code not found in the submitted source.",
            })
            finding["verification"] = verification
            finding["unanchored"] = True
            finding["line"] = 0
            finding["range"] = {"start": 0, "end": 0}
        elif 1 <= line_val_int <= max(1, total_lines):
            finding["line"] = line_val_int
            finding["endLine"] = line_val_int
            finding["range"] = {"start": line_val_int, "end": line_val_int}
        else:
            target_fn = finding.get("function_name")
            fn_matched = False
            if target_fn:
                m = re.search(r"^\s*(?:async\s+)?def\s+" + re.escape(target_fn) + r"\s*\(", source_text, re.MULTILINE)
                if m:
                    line = source_text[:m.start()].count("\n") + 1
                    finding["line"] = line
                    finding["endLine"] = line
                    finding["range"] = {"start": line, "end": line}
                    fn_matched = True
            elif len(fn_matches) == 1:
                m = fn_matches[0]
                line = source_text[:m.start()].count("\n") + 1
                finding["line"] = line
                finding["endLine"] = line
                finding["range"] = {"start": line, "end": line}
                finding["function_name"] = m.group(1)
                fn_matched = True

            if not fn_matched:
                verification = dict(finding.get("verification") or {})
                verification.update({
                    "verdict": "inconclusive",
                    "reason": "Model finding could not be anchored to the submitted source.",
                })
                finding["verification"] = verification
                finding["unanchored"] = True
                finding["line"] = 0
                finding["range"] = {"start": 0, "end": 0}

        # Resolve enclosing function name for anchored findings
        if finding.get("line", 0) > 0 and not finding.get("function_name"):
            fline = finding["line"]
            for m in reversed(fn_matches):
                m_line = source_text[:m.start()].count("\n") + 1
                if m_line <= fline:
                    finding["function_name"] = m.group(1)
                    break

        anchored.append(finding)
    return anchored


def validate_finding(finding: Any) -> bool:
    """Return whether a value contains the required normalized contract fields."""
    if not isinstance(finding, dict):
        return False
    required = {"finding_id", "schema_version", "issue", "severity", "file", "range", "verification"}
    return required.issubset(finding) and finding["verification"].get("verdict") in VERDICTS