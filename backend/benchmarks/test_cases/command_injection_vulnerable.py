"""
Benchmark Test Cases: Command Injection - Vulnerable Patterns (5 cases)
Ground Truth: VULNERABLE
"""

import os
import subprocess


def ping_host(host):
    """Vulnerable: String concatenation in os.system invokes subshell"""
    command = "ping -c 1 " + host
    return os.system(command)


def nslookup_domain(domain):
    """Vulnerable: f-string in subprocess.Popen with shell=True"""
    cmd = f"nslookup {domain}"
    proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = proc.communicate()
    return stdout.decode()


def run_git_checkout(branch):
    """Vulnerable: subprocess.run with shell=True and user-controlled branch"""
    cmd = f"git checkout {branch}"
    res = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return res.returncode


def archive_folder(target_dir):
    """Vulnerable: os.system with unquoted directory parameter"""
    cmd = f"tar -czf archive.tar.gz {target_dir}"
    return os.system(cmd)


def kill_process(pid_str):
    """Vulnerable: subprocess.call with shell=True and string concatenation"""
    return subprocess.call("kill -9 " + str(pid_str), shell=True)
