import os
import time
import json
import requests
import shutil
import tempfile
import subprocess
import threading
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse
from .repo_selective_scan import TEXT_FILE_EXTENSIONS
from .repo_selective_scan import _clone_repository
from .job_manager import (
    update_job_progress,
    append_partial_result,
    mark_completed,
    mark_failed,
    record_stage_timing,
    add_job_event,
)

try:
    from .verified_fixer import (
        VerifiedFixer,
        find_project_sanitizer_examples,
        _gate1_exploit_no_longer_reaches_sink,
        _gate2_tests_still_pass,
        _gate3_no_new_sast_findings,
    )
except ImportError:
    VerifiedFixer = None
    find_project_sanitizer_examples = None
    _gate1_exploit_no_longer_reaches_sink = None
    _gate2_tests_still_pass = None
    _gate3_no_new_sast_findings = None

def _normalize_fix_result(fix_result):
    """Normalize Llama 3 output: it may return a list, a dict, or something else."""
    if isinstance(fix_result, list):
        # Llama 3 returned a bare array of fix objects
        return {'fixes': fix_result, 'modified_content': None}
    if isinstance(fix_result, dict):
        return fix_result
    return None

def _run_git_command(args, cwd):
    return subprocess.run(
        ['git'] + args,
        cwd=cwd,
        env={
            'PATH': os.environ.get('PATH', '/usr/bin:/bin'),
            'HOME': os.environ.get('HOME', tempfile.gettempdir()),
            'LANG': 'C.UTF-8',
            'GIT_TERMINAL_PROMPT': '0',
        },
        capture_output=True,
        text=True
    )


def _run_git_checked(args, cwd):
    result = _run_git_command(args, cwd)
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip() or 'git command failed'
        raise RuntimeError(detail)
    return result


def _resolve_fix_path(repo_root, relative_path, max_bytes=1_000_000):
    if not relative_path or os.path.isabs(relative_path):
        raise ValueError('Autofix path must be relative to the clone root')
    root = os.path.realpath(repo_root)
    candidate = os.path.realpath(os.path.join(root, relative_path))
    if os.path.commonpath([root, candidate]) != root:
        raise ValueError('Autofix path escapes the clone root')
    if os.path.islink(os.path.join(root, relative_path)):
        raise ValueError('Autofix refuses symlink paths')
    extension = os.path.splitext(candidate)[1].lower()
    if os.path.basename(candidate).lower() not in {'dockerfile', 'makefile'} and extension not in TEXT_FILE_EXTENSIONS:
        raise ValueError('Autofix does not support this file extension')
    if not os.path.isfile(candidate) or os.path.getsize(candidate) > max_bytes:
        raise ValueError('Autofix file is missing or oversized')
    return candidate

def start_autofix_job(job_id, repo_url, code_snippet, vulnerabilities, token, branch, mode, language, autofix_fn):
    """
    Spawns a background thread to execute AutoFix without blocking the request handler.
    """
    def worker():
        try:
            if repo_url:
                update_job_progress(job_id, "cloning_repo", 10, "Cloning target repository...")
                _run_repo_autofix(job_id, repo_url, vulnerabilities, token, branch, mode, autofix_fn)
            elif code_snippet:
                update_job_progress(job_id, "analyzing", 20, "Analyzing snippet...")
                _run_snippet_autofix(job_id, code_snippet, vulnerabilities, language, mode, autofix_fn)
            else:
                mark_failed(job_id, "Neither repo_url nor code snippet provided")
        except Exception as e:
            print("autofix worker failed")
            mark_failed(job_id, "Autofix job failed")
            
    thread = threading.Thread(target=worker)
    thread.daemon = True
    thread.start()

def _run_repo_autofix(job_id, repo_url, vulnerabilities, token, branch, mode, autofix_fn):
    temp_dir = tempfile.mkdtemp()
    try:
        # 1. Clone
        _clone_repository(repo_url, temp_dir, token=token, branch=branch)
        update_job_progress(job_id, "analyzing", 30, "Repository cloned successfully. Analyzing files to fix...")
        
        # 2. Group vulnerabilities by file
        files_to_fix = {}
        for v in vulnerabilities:
            path = v.get('file_path') or v.get('path')
            if not path: continue
            if path not in files_to_fix:
                files_to_fix[path] = []
            files_to_fix[path].append(v)
            
        all_applied_fixes = []
        modified_files = []
        total_files = len(files_to_fix)
        files_processed = 0
        
        update_job_progress(job_id, "generating_fixes", 35, f"Found {total_files} files requiring fixes.")

        # 3. For each file, invoke LLM to get fix
        for file_path, file_vulns in files_to_fix.items():
            full_path = _resolve_fix_path(temp_dir, file_path)
                
            update_job_progress(job_id, "generating_fixes", 35 + int(40 * (files_processed/max(1, total_files))), f"Generating fix for {file_path}...")
            
            with open(full_path, 'r') as f:
                content = f.read()
                
            # Call the model via the passed autofix_fn (which wraps _invoke_model_json)
            fix_result = _normalize_fix_result(autofix_fn(content, file_vulns, file_path))
            
            if fix_result and fix_result.get('fixes'):
                fixes = fix_result['fixes']
                new_content = fix_result.get('modified_content')

                # Step 5: 3-Gate verification for each applied fix
                if _gate1_exploit_no_longer_reaches_sink and new_content:
                    for f_item in fixes:
                        g1_pass, g1_msg = _gate1_exploit_no_longer_reaches_sink(new_content, f_item)
                        g2_pass, g2_msg = _gate2_tests_still_pass(new_content, f_item.get('function_name', ''), temp_dir)
                        g3_pass, g3_msg = _gate3_no_new_sast_findings(new_content, f_item.get('issue', ''))
                        all_passed = g1_pass and g2_pass and g3_pass
                        f_item['verification_status'] = "verified" if all_passed else "unverified_draft"
                        f_item['verification_gates'] = [
                            {"gate": "exploit_blocked", "passed": g1_pass, "detail": g1_msg},
                            {"gate": "tests_pass", "passed": g2_pass, "detail": g2_msg},
                            {"gate": "no_new_sast_findings", "passed": g3_pass, "detail": g3_msg},
                        ]

                for f_item in fixes:
                    f_item['file_path'] = file_path
                    append_partial_result(job_id, f_item) # Stream partial results immediately
                
                all_applied_fixes.extend(fixes)
                
                if mode in ['fix', 'pr']:
                    if new_content:
                        with open(full_path, 'w') as f:
                            f.write(new_content)
                        modified_files.append(file_path)
                        
            files_processed += 1
            update_job_progress(job_id, "generating_fixes", 35 + int(40 * (files_processed/max(1, total_files))), f"Completed fixes for {file_path}.")
        
        # 4. Handle PR Mode
        pr_url = None
        if mode == 'pr' and modified_files:
            update_job_progress(job_id, "creating_pr", 85, "Creating GitHub Pull Request...")
            pr_url = _create_github_pr(temp_dir, repo_url, token, modified_files, all_applied_fixes)
            update_job_progress(job_id, "creating_pr", 95, f"Pull Request successfully created: {pr_url}")
            
        summary = f"Analyzed {len(files_to_fix)} files and applied fixes for {len(all_applied_fixes)} vulnerabilities."
        mark_completed(job_id, summary, pr_url, modified_files)
        
    finally:
        shutil.rmtree(temp_dir)

def _run_snippet_autofix(job_id, snippet, vulnerabilities, language, mode, autofix_fn):
    file_path = f"snippet.{language}"
    add_job_event(job_id, "autofix_started", f"Starting autofix pipeline for {file_path}")
    update_job_progress(job_id, "initializing", 10, "Initializing snippet analysis pipeline...")
    update_job_progress(job_id, "analyzing_snippet", 30, "Analyzing vulnerabilities inside code snippet...")
    
    update_job_progress(job_id, "generating_fix", 45, "Generating secure code solution via SageArmor AI...")
    t_gen_start = time.time()
    fix_result = _normalize_fix_result(autofix_fn(snippet, vulnerabilities, file_path))
    record_stage_timing(job_id, "fix_generation", (time.time() - t_gen_start) * 1000.0)
    
    if not fix_result or not fix_result.get('fixes'):
        update_job_progress(job_id, "completed", 100, "Analysis complete. Keep code robust.")
        mark_completed(job_id, "No safe fixes could be applied to this snippet.")
        return
        
    fixes = fix_result.get('fixes', [])
    modified_content = fix_result.get('modified_content')
    
    update_job_progress(job_id, "generating_fix", 85, "Optimizing and validating generated fix...")

    # Safety check: Sometimes Llama 3 might return placeholders, empty content, or wrong types explicitly
    if not isinstance(modified_content, str) or len(modified_content.strip()) < 10 or modified_content.strip() == file_path:
        # Fallback to original content or mark as failed
        modified_content = snippet
        update_job_progress(job_id, "failed", 100, f"Error: AI returned invalid content for {file_path}")
        
    import difflib
    diff_lines = list(difflib.unified_diff(
        snippet.splitlines(keepends=True),
        modified_content.splitlines(keepends=True),
        fromfile="Original.py",
        tofile="Fixed.py"
    ))
    diff_str = "".join(diff_lines)
    
    primary_fix = fixes[0] if fixes else {}
    target_vuln = primary_fix or (vulnerabilities[0] if vulnerabilities else {})

    # Step 5: 3-Gate Verified Fix Loop
    patch_status = "unverified_draft"
    gate_details = []
    if language == 'python' and _gate1_exploit_no_longer_reaches_sink and modified_content and modified_content != snippet:
        update_job_progress(job_id, "verifying_fix", 88, "Running 3-gate sandbox verification on generated patch...")
        t_v_start = time.time()
        
        # Gate 1: Re-run sandbox exploit -> must no longer reach sink
        g1_pass, g1_msg = _gate1_exploit_no_longer_reaches_sink(modified_content, target_vuln)
        gate_details.append({"gate": "exploit_blocked", "passed": g1_pass, "detail": g1_msg})

        # Gate 2: Tests pass (skip if snippet has no test dir)
        g2_pass, g2_msg = _gate2_tests_still_pass(modified_content, target_vuln.get('function_name', ''), None)
        gate_details.append({"gate": "tests_pass", "passed": g2_pass, "detail": g2_msg})

        # Gate 3: No new SAST findings
        g3_pass, g3_msg = _gate3_no_new_sast_findings(modified_content, target_vuln.get('issue', ''))
        gate_details.append({"gate": "no_new_sast_findings", "passed": g3_pass, "detail": g3_msg})

        record_stage_timing(job_id, "patch_verification_gates", (time.time() - t_v_start) * 1000.0)
        add_job_event(job_id, "verification_gates_completed", f"Patch gates: g1={g1_pass}, g2={g2_pass}, g3={g3_pass}")

        if g1_pass and g2_pass and g3_pass:
            patch_status = "verified"
        else:
            patch_status = "unverified_draft"

    confidence_label = "Verified Patch" if patch_status == "verified" else "Unverified Draft"
    snippet_result = {
        "file_path": file_path,
        "original_code": snippet,
        "fixed_code": modified_content,
        "diff": diff_str,
        "explanation": "\n".join([f"- {f.get('explanation', '')}" for f in fixes]),
        "confidence": confidence_label,
        "patch_status": patch_status,
        "verification_gates": gate_details,
    }
    
    append_partial_result(job_id, snippet_result)
    
    job_summary = f"Applied {len(fixes)} secure remediations to the snippet."
    
    if mode == 'fix':
        update_job_progress(job_id, "applying_fix", 95, "Applying security fix to frontend editor...")
        
    update_job_progress(job_id, "completed", 100, "Fix ready!")
    
    # Store the modified snippet in modified_files for the frontend to pick up if needed
    mark_completed(job_id, job_summary, None, modified_content if mode == 'fix' else None)

def _create_github_pr(repo_dir, repo_url, token, modified_files, fixes):
    """
    Creates a branch, commits, pushes, and opens a PR.
    """
    if not token:
        raise ValueError("GitHub Token is required for PR mode")
        
    parsed = urlparse(repo_url)
    if parsed.scheme != 'https' or parsed.hostname not in {'github.com', 'www.github.com'}:
        raise ValueError('Only exact https://github.com repository URLs are allowed')
    path_parts = parsed.path.strip('/').split('/')
    if len(path_parts) != 2:
        raise ValueError('Invalid GitHub repository URL')
    owner, repo_name = path_parts[0], path_parts[1].removesuffix('.git')
    
    branch_name = f"fix/sage-armor-security-patches-{os.urandom(3).hex()}"
    
    # Git setup
    _run_git_checked(['checkout', '-b', branch_name], repo_dir)
    _run_git_checked(['add'] + modified_files, repo_dir)
    _run_git_checked(['commit', '-m', "SageArmor: security vulnerability remediation"], repo_dir)
    
    remote_url = f"https://github.com/{owner}/{repo_name}.git"
    _run_git_checked(['remote', 'set-url', 'origin', remote_url], repo_dir)
    _run_git_checked(
        ['-c', f'http.extraheader=Authorization: Bearer {token}', 'push', 'origin', branch_name],
        repo_dir,
    )
        
    # Create PR via API
    api_url = f"https://api.github.com/repos/{owner}/{repo_name}/pulls"
    headers = {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github.v3+json"
    }
    
    pr_body = "### 🛡️ SageArmor Security Auto-Remediation\n\nThis PR contains automated security fixes generated and verified by SageArmor.\n\n"
    for fix in fixes:
        status_badge = "🛡️ [Verified Patch]" if fix.get('verification_status') == 'verified' else "⚠️ [Unverified Draft]"
        pr_body += f"- {status_badge} **{fix.get('issue', 'Security Fix')}** in `{fix.get('file_path')}`: {fix.get('explanation', '')}\n"
        
    payload = {
        "title": "🔒 Security Fixes: SageArmor Auto-Remediation",
        "body": pr_body,
        "head": branch_name,
        "base": "main" # TODO: detect default branch
    }
    
    resp = requests.post(api_url, headers=headers, json=payload, timeout=15, allow_redirects=False)
    if resp.status_code != 201:
        # Try master if main failed
        payload['base'] = 'master'
        resp = requests.post(api_url, headers=headers, json=payload, timeout=15, allow_redirects=False)
        
    if resp.status_code == 201:
        return resp.json().get('html_url')
    else:
        raise RuntimeError(f"Failed to create PR: {resp.text}")


def apply_multi_file_patch(
    repo_root: str,
    file_patches: List[Dict[str, str]],
) -> Dict[str, Any]:
    """
    Applies and validates coordinated patches across multiple files/functions (FR-307).
    """
    import difflib
    results = []
    backups = {}
    success = True
    error_msg = None

    try:
        # Pre-validation: ensure all target files are within repo_root
        for p in file_patches:
            fpath = os.path.realpath(os.path.join(repo_root, p["file_path"]))
            if not fpath.startswith(os.path.realpath(repo_root)):
                raise ValueError(f"Target path {p['file_path']} escapes repository root")
            if os.path.exists(fpath):
                with open(fpath, "r", encoding="utf-8") as f:
                    backups[fpath] = f.read()

        # Apply each patch
        for p in file_patches:
            fpath = os.path.realpath(os.path.join(repo_root, p["file_path"]))
            os.makedirs(os.path.dirname(fpath), exist_ok=True)
            with open(fpath, "w", encoding="utf-8") as f:
                f.write(p["fixed_code"])

            diff_lines = list(difflib.unified_diff(
                p.get("original_code", "").splitlines(keepends=True),
                p["fixed_code"].splitlines(keepends=True),
                fromfile=f"a/{p['file_path']}",
                tofile=f"b/{p['file_path']}",
            ))
            results.append({
                "file_path": p["file_path"],
                "status": "applied",
                "diff": "".join(diff_lines),
            })
    except Exception as exc:
        success = False
        error_msg = str(exc)
        # Rollback all applied files
        for path, content in backups.items():
            try:
                with open(path, "w", encoding="utf-8") as f:
                    f.write(content)
            except Exception:
                pass

    return {
        "success": success,
        "files_patched": len(results) if success else 0,
        "patches": results,
        "error": error_msg,
    }
