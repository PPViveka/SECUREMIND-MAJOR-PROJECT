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
        MAX_RETRIES as _FIX_MAX_RETRIES,
        VerifiedFixer,
        find_project_sanitizer_examples,
        find_test_dir,
    )
except ImportError:  # pragma: no cover
    _FIX_MAX_RETRIES = 3
    VerifiedFixer = None
    find_project_sanitizer_examples = None
    find_test_dir = None


def _normalize_fix_result(fix_result):
    """Normalize Llama 3 output: it may return a list, a dict, or something else."""
    if isinstance(fix_result, list):
        # Llama 3 returned a bare array of fix objects
        return {'fixes': fix_result, 'modified_content': None}
    if isinstance(fix_result, dict):
        return fix_result
    return None


def _drafts_allowed(include_drafts):
    if include_drafts is not None:
        return bool(include_drafts)
    return os.getenv('SAGE_ARMOR_AUTOFIX_ALLOW_DRAFTS') == '1'


def _llm_from_autofix_fn(autofix_fn, file_path):
    """Adapter for callers that only supply the JSON whole-file autofix function: the file it
    returns is fed to the verified fixer, which takes the target function from it. It cannot
    see gate feedback, so the fixer is run with one attempt."""
    state = {}

    def invoke(prompt):
        key = 'result'
        if key not in state:
            state[key] = _normalize_fix_result(autofix_fn(state['code'], state['vulns'], file_path)) or {}
        content = state[key].get('modified_content')
        return content if isinstance(content, str) else ''

    def bind(code, vulns):
        state.clear()
        state['code'], state['vulns'] = code, vulns

    invoke.bind = bind
    return invoke


def _finding_line(v):
    for key in ('line_number', 'line', 'start_line'):
        try:
            n = int(v.get(key))
            if n > 0:
                return n
        except (TypeError, ValueError):
            continue
    return 0


def _summarize_fix(result, finding, file_path=None, applied=None):
    """Compact, UI-ready record of one gated fix."""
    gates = []
    for g in result.get('final_gates') or []:
        item = {k: g.get(k) for k in ('gate', 'label', 'status', 'detail')}
        if g.get('behaviour'):
            item['behaviour'] = g['behaviour']
        if g.get('evidence'):
            item['evidence'] = {k: g['evidence'].get(k) for k in ('payload_source', 'sink', 'attempts') if k in g['evidence']}
        gates.append(item)
    status = result.get('patch_status', 'failed')
    failed = result.get('failed_gate') or {}
    if status == 'verified':
        explanation = 'Verified fix: the recorded exploit and new attacks were blocked, normal inputs behave the same, and the rescan is clean.'
    elif status == 'unverified_draft':
        explanation = f"Unverified draft: {failed.get('label', 'a gate')} did not pass — {failed.get('detail', '')}".strip()
    else:
        explanation = f"No usable patch: {failed.get('detail') or 'the model did not return a valid fix'}"
    return {
        'issue': finding.get('issue') or finding.get('title') or 'Security issue',
        'severity': finding.get('severity'),
        'file_path': file_path or finding.get('file_path'),
        'line_number': _finding_line(finding) or None,
        'function_name': result.get('function_name') or finding.get('function_name'),
        'patch_status': status,
        'confidence': 'Verified Patch' if status == 'verified' else ('Unverified Draft' if status == 'unverified_draft' else 'No Patch'),
        'explanation': explanation,
        'before_code': result.get('original_function'),
        'after_code': result.get('patched_function'),
        'diff': result.get('diff', ''),
        'attempts': result.get('attempts', 0),
        'verification_gates': gates,
        'failed_gate': result.get('failed_gate'),
        'project_helpers_used': [h.get('signature') for h in result.get('project_helpers_used') or []],
        'codebase_examples_used': result.get('codebase_examples_used') or [],
        'added_imports': result.get('added_imports') or [],
        'formatter': (result.get('formatter') or {}).get('detail'),
        **({'applied': applied} if applied is not None else {}),
    }


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


def start_autofix_job(job_id, repo_url, code_snippet, vulnerabilities, token, branch, mode, language, autofix_fn,
                      fix_llm_fn=None, model_invoker=None, include_drafts=None):
    """
    Spawns a background thread to execute AutoFix without blocking the request handler.
    fix_llm_fn (prompt -> text) drives the verified fix loop; model_invoker writes new attacks
    for the exploit re-test. include_drafts lets fix/pr modes write patches that did not pass
    every gate (off by default).
    """
    def worker():
        try:
            if repo_url:
                update_job_progress(job_id, "cloning_repo", 10, "Cloning target repository...")
                _run_repo_autofix(job_id, repo_url, vulnerabilities, token, branch, mode, autofix_fn,
                                  fix_llm_fn=fix_llm_fn, model_invoker=model_invoker, include_drafts=include_drafts)
            elif code_snippet:
                update_job_progress(job_id, "analyzing", 20, "Analyzing snippet...")
                _run_snippet_autofix(job_id, code_snippet, vulnerabilities, language, mode, autofix_fn,
                                     fix_llm_fn=fix_llm_fn, model_invoker=model_invoker)
            else:
                mark_failed(job_id, "Neither repo_url nor code snippet provided")
        except Exception:
            print("autofix worker failed")
            mark_failed(job_id, "Autofix job failed")

    thread = threading.Thread(target=worker)
    thread.daemon = True
    thread.start()


def _verified_fix_file(job_id, content, file_vulns, file_path, autofix_fn, fix_llm_fn, model_invoker,
                       project_root=None, test_dir=None, progress=None):
    """Run the gated fixer for each finding of one Python file (bottom-up, so line numbers of
    the remaining findings stay valid). Yields (result, finding) and threads accepted patches
    through via the returned content callback."""
    llm = fix_llm_fn
    retries = _FIX_MAX_RETRIES
    adapter = None
    if llm is None:
        adapter = _llm_from_autofix_fn(autofix_fn, file_path)
        llm, retries = adapter, 1
    ordered = sorted(file_vulns, key=_finding_line, reverse=True)
    for idx, v in enumerate(ordered):
        if progress:
            progress(idx, len(ordered), v)
        if adapter is not None:
            adapter.bind(content(), [v])
        fixer = VerifiedFixer(
            llm,
            test_dir=test_dir,
            project_root=project_root,
            target_file_path=file_path if project_root else None,
            model_invoker=model_invoker,
            max_retries=retries,
        )
        yield fixer.fix(content(), {**v, 'file_path': file_path}), v


def _run_repo_autofix(job_id, repo_url, vulnerabilities, token, branch, mode, autofix_fn,
                      fix_llm_fn=None, model_invoker=None, include_drafts=None):
    temp_dir = tempfile.mkdtemp()
    allow_drafts = _drafts_allowed(include_drafts)
    try:
        _clone_repository(repo_url, temp_dir, token=token, branch=branch)
        update_job_progress(job_id, "analyzing", 30, "Repository cloned successfully. Analyzing files to fix...")

        files_to_fix = {}
        for v in vulnerabilities:
            path = v.get('file_path') or v.get('path')
            if not path:
                continue
            files_to_fix.setdefault(path, []).append(v)

        all_applied_fixes = []
        modified_files = []
        total_files = len(files_to_fix)
        test_dir = find_test_dir(temp_dir) if find_test_dir else None
        update_job_progress(job_id, "generating_fixes", 35, f"Found {total_files} files requiring fixes.")

        for files_processed, (file_path, file_vulns) in enumerate(files_to_fix.items()):
            full_path = _resolve_fix_path(temp_dir, file_path)
            base_pct = 35 + int(55 * (files_processed / max(1, total_files)))
            update_job_progress(job_id, "generating_fixes", base_pct, f"Generating fix for {file_path}...")
            with open(full_path, 'r', encoding='utf-8', newline='') as f:
                original = f.read()
            new_content = None

            if file_path.endswith('.py') and VerifiedFixer is not None:
                state = {'content': original}

                def _progress(i, n, v, _fp=file_path, _pct=base_pct):
                    update_job_progress(job_id, "verifying_fix", _pct,
                                        f"Fixing and verifying {v.get('issue', 'finding')} in {_fp} ({i + 1}/{n}): exploit replay, behaviour tests, project tests, rescan...")

                for result, v in _verified_fix_file(job_id, lambda: state['content'], file_vulns, file_path, autofix_fn,
                                                    fix_llm_fn, model_invoker, project_root=temp_dir, test_dir=test_dir,
                                                    progress=_progress):
                    accept = result['patch_status'] == 'verified' or (result['patch_status'] == 'unverified_draft' and allow_drafts)
                    if accept:
                        state['content'] = result['patched_code']
                    item = _summarize_fix(result, v, file_path=file_path, applied=bool(accept and mode in ('fix', 'pr')))
                    add_job_event(job_id, "fix_verified" if result['patch_status'] == 'verified' else "fix_unverified",
                                  f"{file_path}: {item['issue']} -> {result['patch_status']}")
                    append_partial_result(job_id, item)
                    all_applied_fixes.append(item)
                if state['content'] != original:
                    new_content = state['content']
            else:
                # No runtime gates exist for this language: the model's fix stays an unverified draft.
                fix_result = _normalize_fix_result(autofix_fn(original, file_vulns, file_path))
                if fix_result and fix_result.get('fixes'):
                    for f_item in fix_result['fixes']:
                        f_item['file_path'] = file_path
                        f_item['patch_status'] = 'unverified_draft'
                        f_item['confidence'] = 'Unverified Draft'
                        f_item['verification_gates'] = []
                        f_item['applied'] = bool(allow_drafts and mode in ('fix', 'pr'))
                        append_partial_result(job_id, f_item)
                    all_applied_fixes.extend(fix_result['fixes'])
                    candidate = fix_result.get('modified_content')
                    if allow_drafts and isinstance(candidate, str) and candidate.strip():
                        new_content = candidate

            if mode in ['fix', 'pr'] and new_content is not None and new_content != original:
                with open(full_path, 'w', encoding='utf-8', newline='') as f:
                    f.write(new_content)
                modified_files.append(file_path)
            update_job_progress(job_id, "generating_fixes", 35 + int(55 * ((files_processed + 1) / max(1, total_files))), f"Completed fixes for {file_path}.")

        pr_url = None
        if mode == 'pr' and modified_files:
            update_job_progress(job_id, "creating_pr", 92, "Creating GitHub Pull Request...")
            pr_url = _create_github_pr(temp_dir, repo_url, token, modified_files, all_applied_fixes)
            update_job_progress(job_id, "creating_pr", 97, f"Pull Request successfully created: {pr_url}")

        n_verified = sum(1 for f in all_applied_fixes if f.get('patch_status') == 'verified')
        summary = (
            f"Analyzed {len(files_to_fix)} files: {n_verified} of {len(all_applied_fixes)} fixes passed every gate"
            + (f"; {len(modified_files)} file(s) changed." if mode in ('fix', 'pr') else ".")
        )
        mark_completed(job_id, summary, pr_url, modified_files)
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


def _run_snippet_autofix(job_id, snippet, vulnerabilities, language, mode, autofix_fn,
                         fix_llm_fn=None, model_invoker=None):
    file_path = f"snippet.{language}"
    add_job_event(job_id, "autofix_started", f"Starting autofix pipeline for {file_path}")
    update_job_progress(job_id, "initializing", 10, "Initializing snippet analysis pipeline...")
    update_job_progress(job_id, "analyzing_snippet", 30, "Analyzing vulnerabilities inside code snippet...")

    if language == 'python' and VerifiedFixer is not None:
        if not vulnerabilities:
            update_job_progress(job_id, "completed", 100, "Analysis complete. Keep code robust.")
            mark_completed(job_id, "No safe fixes could be applied to this snippet.")
            return
        state = {'content': snippet}
        fixes = []

        def _progress(i, n, v):
            update_job_progress(job_id, "verifying_fix", 40 + int(50 * i / max(1, n)),
                                f"Fixing {v.get('issue', 'finding')} ({i + 1}/{n}) and verifying: exploit replay, behaviour tests, rescan...")

        t_gen_start = time.time()
        for result, v in _verified_fix_file(job_id, lambda: state['content'], vulnerabilities, file_path, autofix_fn,
                                            fix_llm_fn, model_invoker, progress=_progress):
            if result['patch_status'] != 'failed':
                state['content'] = result['patched_code']
            fixes.append(_summarize_fix(result, v, file_path=file_path))
        record_stage_timing(job_id, "patch_verification_gates", (time.time() - t_gen_start) * 1000.0)

        modified_content = state['content']
        statuses = [f['patch_status'] for f in fixes]
        if modified_content == snippet:
            patch_status = 'failed'
        elif statuses and all(s == 'verified' for s in statuses):
            patch_status = 'verified'
        else:
            patch_status = 'unverified_draft'
        add_job_event(job_id, "verification_gates_completed", f"Snippet fixes: {', '.join(statuses)}")

        import difflib
        diff_str = "".join(difflib.unified_diff(
            snippet.splitlines(keepends=True), modified_content.splitlines(keepends=True),
            fromfile="Original.py", tofile="Fixed.py",
        ))
        gates = []
        for f in fixes:
            for g in f['verification_gates']:
                gates.append({**g, 'issue': f['issue'], 'passed': g.get('status') == 'pass'})
        snippet_result = {
            "file_path": file_path,
            "original_code": snippet,
            "fixed_code": modified_content,
            "diff": diff_str,
            "explanation": "\n".join(f"- {f['issue']}: {f['explanation']}" for f in fixes),
            "confidence": "Verified Patch" if patch_status == 'verified' else ("Unverified Draft" if patch_status == 'unverified_draft' else "No Patch"),
            "patch_status": patch_status,
            "verification_gates": gates,
            "fixes": fixes,
        }
        append_partial_result(job_id, snippet_result)
        if patch_status == 'failed':
            update_job_progress(job_id, "completed", 100, "No fix could be produced.")
            mark_completed(job_id, "No safe fixes could be applied to this snippet.")
            return
        n_ok = statuses.count('verified')
        update_job_progress(job_id, "completed", 100, "Fix ready!")
        mark_completed(job_id, f"{n_ok} of {len(fixes)} fixes passed every gate.", None, modified_content if mode == 'fix' else None)
        return

    # Other languages: no runtime gates exist, so the model's fix is an unverified draft.
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
    if not isinstance(modified_content, str) or len(modified_content.strip()) < 10 or modified_content.strip() == file_path:
        modified_content = snippet
        update_job_progress(job_id, "failed", 100, f"Error: AI returned invalid content for {file_path}")

    import difflib
    diff_str = "".join(difflib.unified_diff(
        snippet.splitlines(keepends=True), modified_content.splitlines(keepends=True),
        fromfile="Original.py", tofile="Fixed.py",
    ))
    snippet_result = {
        "file_path": file_path,
        "original_code": snippet,
        "fixed_code": modified_content,
        "diff": diff_str,
        "explanation": "\n".join([f"- {f.get('explanation', '')}" for f in fixes]),
        "confidence": "Unverified Draft",
        "patch_status": "unverified_draft",
        "verification_gates": [],
    }
    append_partial_result(job_id, snippet_result)
    update_job_progress(job_id, "completed", 100, "Fix ready!")
    mark_completed(job_id, f"Applied {len(fixes)} secure remediations to the snippet.", None, modified_content if mode == 'fix' else None)


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
    included = [f for f in fixes if f.get('applied', True)]
    skipped = [f for f in fixes if not f.get('applied', True)]
    for fix in included:
        status_badge = "🛡️ [Verified Patch]" if fix.get('patch_status') == 'verified' else "⚠️ [Unverified Draft]"
        pr_body += f"- {status_badge} **{fix.get('issue', 'Security Fix')}** in `{fix.get('file_path')}`: {fix.get('explanation', '')}\n"
    if skipped:
        pr_body += "\n**Not included** (the patch did not pass every verification gate):\n"
        for fix in skipped:
            pr_body += f"- {fix.get('issue', 'Security Fix')} in `{fix.get('file_path')}`: {fix.get('explanation', '')}\n"
    pr_body += (
        "\nVerified = the exploit that proved the finding (plus new attacks) no longer reaches the dangerous call, "
        "normal inputs behave the same, the project's tests still pass, and a security rescan is clean.\n"
    )
        
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
