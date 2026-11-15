"""
Benchmark Test Cases: Command Injection - Guarded / Benign Patterns (5 cases)
Ground Truth: GUARDED / BENIGN (False Positive Controls)
"""

import os
import re
import subprocess


def ping_host_safe(host):
    """Guarded: Strict hostname regex + argument list with shell=False"""
    if not re.match(r"^[a-zA-Z0-9\.\-]+$", host):
        raise ValueError("Invalid hostname format")
    res = subprocess.run(["ping", "-c", "1", host], shell=False, capture_output=True, text=True)
    return res.returncode


def nslookup_domain_safe(domain):
    """Guarded: Domain regex validation + shell=False prevents operator chaining"""
    if not re.match(r"^[a-zA-Z0-9\.\-]+$", domain):
        raise ValueError("Invalid domain name")
    res = subprocess.run(["nslookup", domain], shell=False, capture_output=True, text=True)
    return res.stdout


def run_git_checkout_safe(branch):
    """Guarded: Strict branch name whitelist regex + shell=False"""
    if not re.match(r"^[a-zA-Z0-9_\-\.\/]+$", branch) or branch.startswith("-"):
        raise ValueError("Invalid branch name")
    res = subprocess.run(["git", "checkout", branch], shell=False, capture_output=True, text=True)
    return res.returncode


def archive_folder_safe(target_dir):
    """Guarded: os.path.basename + argument vector execution without shell"""
    safe_name = os.path.basename(os.path.normpath(target_dir))
    if not safe_name or safe_name in (".", ".."):
        raise ValueError("Invalid target folder")
    res = subprocess.run(["tar", "-czf", "archive.tar.gz", safe_name], shell=False, capture_output=True)
    return res.returncode


def kill_process_safe(pid_str):
    """Guarded: Integer conversion + direct os.kill API without shell execution"""
    pid = int(pid_str)
    if pid <= 0:
        raise ValueError("PID must be positive")
    os.kill(pid, 9)
    return 0
