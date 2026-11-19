"""
Benchmark Test Cases: Path Traversal - Vulnerable Patterns (10 cases)
Ground Truth: VULNERABLE
"""

import os


def read_user_file(filename):
    """Vulnerable: Direct string concatenation without path containment check (dev)"""
    target = os.path.join("data", filename)
    with open(target, "r") as f:
        return f.read()


def download_report(report_name):
    """Vulnerable: format string with unvalidated user input directly in open() (dev)"""
    path = "reports/{}".format(report_name)
    with open(path, "rb") as f:
        return f.read()


def serve_static_asset(asset_path):
    """Vulnerable: f-string path construction allows ../ sequences (dev)"""
    file_path = f"static/{asset_path}"
    with open(file_path, "r", encoding="utf-8") as f:
        return f.read()


def load_plugin_config(config_file):
    """Vulnerable: os.path.join followed by open() without normpath check (dev)"""
    plugin_path = os.path.join("/opt/plugins/configs", config_file)
    with open(plugin_path, "r") as f:
        return f.read()


def delete_temp_file(temp_id):
    """Vulnerable: os.remove on uncontained user path (dev)"""
    target_path = f"/tmp/sessions/{temp_id}.tmp"
    os.remove(target_path)
    return True


def view_log_file(log_name):
    """Vulnerable: Reading log file directly with user-controlled name (eval)"""
    full_path = os.path.join("logs", log_name)
    with open(full_path, "r") as f:
        return f.read()


def export_avatar(user_avatar):
    """Vulnerable: Binary read of avatar path without containment (eval)"""
    target = "uploads/avatars/" + user_avatar
    with open(target, "rb") as f:
        return f.read()


def load_theme_stylesheet(theme_file):
    """Vulnerable: Unvalidated theme file path (eval)"""
    path = "themes/" + str(theme_file)
    with open(path, "r") as f:
        return f.read()


def read_receipt_pdf(receipt_id):
    """Vulnerable: Reading receipt by ID with string concatenation (eval)"""
    path = f"receipts/{receipt_id}.pdf"
    with open(path, "rb") as f:
        return f.read()


def remove_cached_page(cache_key):
    """Vulnerable: os.unlink on path concatenated with cache_key (eval)"""
    p = os.path.join("/var/cache/pages", cache_key)
    os.unlink(p)
    return True
