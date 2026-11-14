import os
import json
import requests
import shutil
import tempfile
import subprocess
import threading
from .repo_selective_scan import _clone_repository
from .job_manager import update_job_progress, append_partial_result, mark_completed, mark_failed

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
        capture_output=True,
        text=True
    )

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
            import traceback
            traceback.print_exc()
            mark_failed(job_id, str(e))
            
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
            full_path = os.path.join(temp_dir, file_path)
            if not os.path.exists(full_path):
                files_processed += 1
                continue
                
            update_job_progress(job_id, "generating_fixes", 35 + int(40 * (files_processed/max(1, total_files))), f"Generating fix for {file_path}...")
            
            with open(full_path, 'r') as f:
                content = f.read()
                
            # Call the model via the passed autofix_fn (which wraps _invoke_model_json)
            fix_result = _normalize_fix_result(autofix_fn(content, file_vulns, file_path))
            
            if fix_result and fix_result.get('fixes'):
                fixes = fix_result['fixes']
                for f_item in fixes:
                    f_item['file_path'] = file_path
                    append_partial_result(job_id, f_item) # Stream partial results immediately
                
                all_applied_fixes.extend(fixes)
                
                if mode in ['fix', 'pr']:
                    new_content = fix_result.get('modified_content')
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
    update_job_progress(job_id, "initializing", 10, "Initializing snippet analysis pipeline...")
    update_job_progress(job_id, "analyzing_snippet", 30, "Analyzing vulnerabilities inside code snippet...")
    
    update_job_progress(job_id, "generating_fix", 45, "Generating secure code solution via SageArmor AI...")
    
    fix_result = _normalize_fix_result(autofix_fn(snippet, vulnerabilities, file_path))
    
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
    snippet_result = {
        "file_path": file_path,
        "original_code": snippet,
        "fixed_code": modified_content,
        "diff": diff_str,
        "explanation": "\n".join([f"- {f.get('explanation', '')}" for f in fixes]),
        "confidence": primary_fix.get('confidence', 'High')
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
        
    # Extract owner/repo from URL
    path_parts = repo_url.rstrip('/').split('/')
    owner = path_parts[-2]
    repo_name = path_parts[-1].replace('.git', '')
    
    branch_name = f"fix/sage-armor-security-patches-{os.urandom(3).hex()}"
    
    # Git setup
    _run_git_command(['checkout', '-b', branch_name], repo_dir)
    _run_git_command(['add'] + modified_files, repo_dir)
    _run_git_command(['commit', '-m', "🔒 AutoFix: Security vulnerability remediation by SageArmor"], repo_dir)
    
    # Auth remote
    remote_url = f"https://x-access-token:{token}@github.com/{owner}/{repo_name}.git"
    _run_git_command(['remote', 'set-url', 'origin', remote_url], repo_dir)
    
    # Push
    push_res = _run_git_command(['push', 'origin', branch_name], repo_dir)
    if push_res.returncode != 0:
        raise RuntimeError(f"Git push failed: {push_res.stderr}")
        
    # Create PR via API
    api_url = f"https://api.github.com/repos/{owner}/{repo_name}/pulls"
    headers = {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github.v3+json"
    }
    
    pr_body = "### 🛡️ SageArmor Security Auto-Remediation\n\nThis PR contains automated security fixes generated by SageArmor AI.\n\n"
    for fix in fixes:
        pr_body += f"- **{fix['issue']}** in `{fix['file_path']}`: {fix['explanation']}\n"
        
    payload = {
        "title": "🔒 Security Fixes: SageArmor Auto-Remediation",
        "body": pr_body,
        "head": branch_name,
        "base": "main" # TODO: detect default branch
    }
    
    resp = requests.post(api_url, headers=headers, json=payload)
    if resp.status_code != 201:
        # Try master if main failed
        payload['base'] = 'master'
        resp = requests.post(api_url, headers=headers, json=payload)
        
    if resp.status_code == 201:
        return resp.json().get('html_url')
    else:
        raise RuntimeError(f"Failed to create PR: {resp.text}")
