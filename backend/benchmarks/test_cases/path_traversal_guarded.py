"""
Benchmark Test Cases: Path Traversal - Guarded / Benign Patterns (10 cases)
Ground Truth: GUARDED / BENIGN (False Positive Controls)
"""

import os
import re


def read_user_file_safe(filename):
    """Guarded: os.path.basename strips directory traversal sequences (dev)"""
    safe_name = os.path.basename(filename)
    target = os.path.join("data", safe_name)
    with open(target, "r") as f:
        return f.read()


def download_report_safe(report_name):
    """Guarded: Strict alphanumeric regex allows only clean names (dev)"""
    if not re.fullmatch(r"^[a-zA-Z0-9_-]{1,32}$", report_name):
        raise ValueError("Invalid report identifier")
    path = f"reports/{report_name}.pdf"
    with open(path, "rb") as f:
        return f.read()


def serve_static_asset_safe(asset_path):
    """Guarded: Canonical containment check with os.path.realpath (dev)"""
    base_dir = os.path.realpath("static")
    candidate = os.path.realpath(os.path.join(base_dir, asset_path))
    if not candidate.startswith(base_dir + os.sep) and candidate != base_dir:
        raise PermissionError("Access outside base directory denied")
    with open(candidate, "r", encoding="utf-8") as f:
        return f.read()


def load_plugin_config_safe(config_file):
    """Guarded: Strict allowlist prevents unauthorized file access (dev)"""
    allowed_configs = {"auth.json", "database.json", "logging.json", "metrics.json"}
    clean_name = os.path.basename(config_file)
    if clean_name not in allowed_configs:
        raise ValueError("Unauthorized plugin configuration requested")
    plugin_path = os.path.join("/opt/plugins/configs", clean_name)
    with open(plugin_path, "r") as f:
        return f.read()


def delete_temp_file_safe(temp_id):
    """Guarded: UUID hex validation ensures no traversal tokens (dev)"""
    if not re.fullmatch(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$", temp_id):
        raise ValueError("Invalid temporary ID format")
    target_path = f"/tmp/sessions/{temp_id}.tmp"
    os.remove(target_path)
    return True


def view_log_file_safe(log_name):
    """Guarded: os.path.basename ensures log remains in logs folder (eval)"""
    safe_log = os.path.basename(log_name)
    full_path = os.path.join("logs", safe_log)
    with open(full_path, "r") as f:
        return f.read()


def export_avatar_safe(user_avatar):
    """Guarded: Clean basename + extension allowlist (eval)"""
    clean_avatar = os.path.basename(user_avatar)
    if not clean_avatar.endswith((".png", ".jpg", ".jpeg")):
        raise ValueError("Invalid image type")
    target = os.path.join("uploads", "avatars", clean_avatar)
    with open(target, "rb") as f:
        return f.read()


def load_theme_stylesheet_safe(theme_file):
    """Guarded: Theme allowlist check (eval)"""
    allowed = {"dark.css", "light.css", "high_contrast.css"}
    base_file = os.path.basename(theme_file)
    if base_file not in allowed:
        raise ValueError("Invalid theme")
    path = os.path.join("themes", base_file)
    with open(path, "r") as f:
        return f.read()


def read_receipt_pdf_safe(receipt_id):
    """Guarded: Numeric ID validation ensures clean receipt name (eval)"""
    if not str(receipt_id).isdigit():
        raise ValueError("Invalid receipt ID")
    path = f"receipts/{int(receipt_id)}.pdf"
    with open(path, "rb") as f:
        return f.read()


def remove_cached_page_safe(cache_key):
    """Guarded: Alphanumeric hash validation for cache key (eval)"""
    if not re.fullmatch(r"^[a-zA-Z0-9]{32,64}$", cache_key):
        raise ValueError("Invalid cache key")
    p = os.path.join("/var/cache/pages", cache_key)
    os.unlink(p)
    return True
