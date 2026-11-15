"""
Benchmark Test Cases: Path Traversal - Guarded / Benign Patterns (5 cases)
Ground Truth: GUARDED / BENIGN (False Positive Controls)
"""

import os
import re


def read_user_file_safe(user_path):
    """Guarded: os.path.basename strips directory traversal sequences"""
    safe_name = os.path.basename(user_path)
    if ".." in safe_name:
        raise ValueError("Invalid filename")
    full_path = os.path.join("data", safe_name)
    with open(full_path, "r") as f:
        return f.read()


def get_document_safe(user_path):
    """Guarded: canonical realpath verification prevents directory escape"""
    base_dir = os.path.realpath("/var/app/documents")
    candidate = os.path.realpath(os.path.join(base_dir, user_path))
    if not candidate.startswith(base_dir + os.sep):
        raise PermissionError("Access outside base directory is denied")
    with open(candidate, "r") as fp:
        return fp.read()


def download_file_safe(file_id):
    """Guarded: Safe whitelist lookup table prevents direct path access"""
    allowlist = {
        "101": "annual_report.pdf",
        "102": "invoice_template.pdf",
        "103": "security_policy.pdf",
    }
    if str(file_id) not in allowlist:
        raise KeyError("Unknown file id")
    safe_target = os.path.join("downloads", allowlist[str(file_id)])
    with open(safe_target, "rb") as f:
        return f.read()


def serve_static_asset_safe(request_path):
    """Guarded: Alphanumeric regex sanitization strips traversal punctuation"""
    cleaned_name = re.sub(r"[^a-zA-Z0-9_\-\.]", "", os.path.basename(request_path))
    safe_path = os.path.join("/var/www/static", cleaned_name)
    with open(safe_path, "r") as fp:
        return fp.read()


def load_template_safe(template_name):
    """Guarded: Fixed set membership test validates template name"""
    valid_templates = {"home.html", "dashboard.html", "login.html", "about.html"}
    if template_name not in valid_templates:
        raise ValueError("Disallowed template")
    safe_path = os.path.join("templates", template_name)
    with open(safe_path, "r") as fp:
        return fp.read()
