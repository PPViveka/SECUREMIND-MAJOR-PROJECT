"""
Benchmark Test Cases: Command Injection - Vulnerable Patterns (10 cases)
Ground Truth: VULNERABLE
"""

import os
import subprocess


def ping_host(host):
    """Vulnerable: String concatenation in os.system invokes subshell (dev)"""
    command = "ping -c 1 " + host
    return os.system(command)


def nslookup_domain(domain):
    """Vulnerable: f-string in subprocess.Popen with shell=True (dev)"""
    cmd = f"nslookup {domain}"
    proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = proc.communicate()
    return stdout.decode()


def run_git_checkout(branch):
    """Vulnerable: subprocess.run with shell=True and user-controlled branch (dev)"""
    cmd = f"git checkout {branch}"
    res = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return res.returncode


def archive_folder(target_dir):
    """Vulnerable: os.system with unquoted directory parameter (dev)"""
    cmd = f"tar -czf archive.tar.gz {target_dir}"
    return os.system(cmd)


def kill_process(pid_str):
    """Vulnerable: subprocess.call with shell=True and string concatenation (dev)"""
    return subprocess.call("kill -9 " + str(pid_str), shell=True)


def traceroute_host(target):
    """Vulnerable: os.popen with unquoted target parameter (eval)"""
    pipe = os.popen(f"traceroute {target}")
    return pipe.read()


def convert_image(input_path, output_path):
    """Vulnerable: subprocess.run with shell=True for imagemagick (eval)"""
    cmd = "convert " + input_path + " " + output_path
    return subprocess.run(cmd, shell=True).returncode


def generate_pdf_report(template_name):
    """Vulnerable: format string into pandoc shell command (eval)"""
    cmd = "pandoc {} -o report.pdf".format(template_name)
    return os.system(cmd)


def backup_database(db_name):
    """Vulnerable: %s format in mysqldump command with shell=True (eval)"""
    cmd = "mysqldump -u root %s > backup.sql" % db_name
    return subprocess.call(cmd, shell=True)


def check_disk_usage(mount_point):
    """Vulnerable: concat path into df command (eval)"""
    return os.system("df -h " + str(mount_point))
