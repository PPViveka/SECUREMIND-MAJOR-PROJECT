"""
Benchmark Test Cases: Path Traversal - Vulnerable Patterns (5 cases)
Ground Truth: VULNERABLE
"""

import os


def read_user_file(user_path):
    """Vulnerable: direct string concatenation into file path open"""
    target = "data/" + str(user_path)
    with open(target, "r") as f:
        return f.read()


def get_document(user_path):
    """Vulnerable: os.path.join with unsanitized user path allows ../ escape"""
    base_dir = "/var/app/documents"
    doc_path = os.path.join(base_dir, user_path)
    with open(doc_path, "r") as fp:
        return fp.read()


def download_file(user_file):
    """Vulnerable: direct file open on user-controlled input"""
    with open(user_file, "rb") as f:
        return f.read()


def serve_static_asset(request_path):
    """Vulnerable: relative path concatenation without normalization"""
    asset_file = "/var/www/static/" + request_path
    with open(asset_file, "r") as fp:
        return fp.read()


def load_template(template_path):
    """Vulnerable: f-string path construction allows ../ directory escape"""
    full_path = f"templates/{template_path}"
    with open(full_path, "r") as fp:
        return fp.read()
