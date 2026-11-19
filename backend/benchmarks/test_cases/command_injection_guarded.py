"""
Benchmark Test Cases: Command Injection - Guarded / Benign Patterns (10 cases)
Ground Truth: GUARDED / BENIGN (False Positive Controls)
"""

import re
import shlex
import subprocess


def ping_host_safe(host):
    """Guarded: List-based arguments + shell=False + regex IP validation (dev)"""
    if not re.fullmatch(r"^[a-zA-Z0-9.-]{1,64}$", host):
        raise ValueError("Invalid host format")
    res = subprocess.run(["ping", "-c", "1", host], shell=False, capture_output=True)
    return res.returncode


def nslookup_domain_safe(domain):
    """Guarded: shlex.split + shell=False prevents subshell injection (dev)"""
    if not re.fullmatch(r"^[a-zA-Z0-9.-]+$", domain):
        raise ValueError("Invalid domain")
    cmd = ["nslookup", domain]
    proc = subprocess.Popen(cmd, shell=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, _ = proc.communicate()
    return stdout.decode()


def run_git_checkout_safe(branch):
    """Guarded: Strict branch name whitelist + list argument form (dev)"""
    allowed_branches = {"main", "master", "develop", "staging"}
    if branch not in allowed_branches:
        raise ValueError(f"Unauthorized branch: {branch}")
    cmd = ["git", "checkout", branch]
    res = subprocess.run(cmd, shell=False, capture_output=True, text=True)
    return res.returncode


def archive_folder_safe(target_dir):
    """Guarded: Safe array form directly into tar binary (dev)"""
    if not re.fullmatch(r"^[a-zA-Z0-9_/.-]+$", target_dir):
        raise ValueError("Invalid directory path")
    cmd = ["tar", "-czf", "archive.tar.gz", target_dir]
    return subprocess.run(cmd, shell=False).returncode


def kill_process_safe(pid_str):
    """Guarded: Strict integer casting ensures no shell metacharacters (dev)"""
    safe_pid = int(pid_str)
    return subprocess.run(["kill", "-9", str(safe_pid)], shell=False).returncode


def traceroute_host_safe(target):
    """Guarded: Target validation and list-based subprocess (eval)"""
    if not re.fullmatch(r"^[a-zA-Z0-9.-]{1,64}$", target):
        raise ValueError("Invalid host")
    res = subprocess.run(["traceroute", target], shell=False, capture_output=True, text=True)
    return res.stdout


def convert_image_safe(input_path, output_path):
    """Guarded: List-based argument execution with shell=False (eval)"""
    cmd = ["convert", str(input_path), str(output_path)]
    return subprocess.run(cmd, shell=False).returncode


def generate_pdf_report_safe(template_name):
    """Guarded: Allowlisted template names + shell=False (eval)"""
    allowed = {"summary.md", "audit.md", "quarterly.md"}
    if template_name not in allowed:
        raise ValueError("Template not allowed")
    return subprocess.run(["pandoc", template_name, "-o", "report.pdf"], shell=False).returncode


def backup_database_safe(db_name):
    """Guarded: Strict database identifier check and shell=False (eval)"""
    if not re.fullmatch(r"^[a-zA-Z0-9_]{1,32}$", db_name):
        raise ValueError("Invalid DB name")
    return subprocess.run(["mysqldump", "-u", "root", db_name], shell=False).returncode


def check_disk_usage_safe(mount_point):
    """Guarded: List execution of df with validated path (eval)"""
    clean_mount = shlex.quote(str(mount_point))
    return subprocess.run(["df", "-h", clean_mount], shell=False).returncode
