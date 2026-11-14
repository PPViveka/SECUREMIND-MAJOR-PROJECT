import threading
import time
import uuid
import traceback
import math

from .job_manager import get_job, update_job_progress, _save_jobs, _load_jobs
from .repo_selective_scan import selective_repo_scan
from .prompt_builder import build_fast_scan_prompt, build_deep_enrichment_prompt
from .attack_intelligence import build_attack_intelligence

class RateLimitedEngine:
    def __init__(self, job_id, token, invoke_fn, branch=None, top_k=3):
        self.job_id = job_id
        self.token = token
        self.invoke_fn = invoke_fn
        self.branch = branch
        self.top_k = top_k
        self.max_retries = 4

    def _sync_job(self, **kwargs):
        job = get_job(self.job_id)
        if job:
            job.update(kwargs)
            # Need to update the global registry and save
            jobs = _load_jobs()
            jobs[self.job_id] = job
            _save_jobs(jobs)

    def _log(self, msg):
        job = get_job(self.job_id)
        if job:
            job.setdefault("logs", []).append(msg)
            jobs = _load_jobs()
            jobs[self.job_id] = job
            _save_jobs(jobs)

    def _invoke_with_backoff(self, prompt, max_tokens, retries=0):
        try:
            time.sleep(1.5) # Global minimum rate limit spacing
            return self.invoke_fn(prompt, max_tokens=max_tokens)
        except Exception as e:
            err_str = str(e).lower()
            if "429" in err_str or "quota" in err_str or "rate" in err_str:
                if retries < self.max_retries:
                    delay = min(2 ** retries, 30)
                    self._log(f"Rate limited. Retrying in {delay}s...")
                    time.sleep(delay)
                    return self._invoke_with_backoff(prompt, max_tokens, retries + 1)
            raise e

    def run_scan(self, repo_url, query):
        job = get_job(self.job_id)
        if not job:
            return

        # Initialize scan specific fields
        self._sync_job(
            vulnerabilities_partial=[],
            vulnerabilities_full=[],
            fixes=[],
            queue=[],
            repo_stats={}
        )

        try:
            self._sync_job(stage="scanning", progress=5)
            self._log(f"Stage 1: Cloning and selecting priority files from {repo_url}...")

            # 1. SCAN AND SELECT
            scan_bundle = selective_repo_scan(
                repo_url=repo_url,
                query=query,
                token=self.token,
                branch=self.branch,
                top_k=self.top_k,
            )
            
            selected_files = scan_bundle.get('selected_files', [])
            self._sync_job(repo_stats=scan_bundle.get('repo_stats', {}))
            
            if not selected_files:
                self._sync_job(stage="completed", progress=100, status="completed")
                self._log("No relevant files found. Scan complete.")
                return

            # Prioritize: auth files -> config files -> API routes
            def priority_score(x):
                path = x.get('path', '').lower()
                if 'auth' in path or 'login' in path or 'permission' in path:
                    return 0
                if 'config' in path or 'env' in path or path.endswith('.yml') or path.endswith('.json'):
                    return 1
                if 'api' in path or 'route' in path or 'handler' in path:
                    return 2
                return 3

            selected_files = sorted(selected_files, key=priority_score)

            batch_size = 3
            batches = [selected_files[i:i + batch_size] for i in range(0, len(selected_files), batch_size)]
            
            self._log(f"Split {len(selected_files)} files into {len(batches)} batches.")

            all_raw_vulns = []
            
            for index, batch in enumerate(batches):
                progress = 10 + int((index / len(batches)) * 40)
                self._sync_job(stage="scanning", progress=progress)
                self._log(f"Scanning batch {index + 1}/{len(batches)}...")

                combined_context = "\n\n".join([f"# FILE: {item.get('path', 'unknown')}\n{item.get('excerpt', '')}" for item in batch])
                prompt = build_fast_scan_prompt(combined_context)

                try:
                    # Stage 1 LLM Call - Fast Scan (increased tokens to prevent truncation)
                    analysis_result = self._invoke_with_backoff(prompt, max_tokens=2048)
                    # Normalize: Llama 3 may return a bare list or a dict
                    if isinstance(analysis_result, list):
                        raw_vulns = analysis_result
                    elif isinstance(analysis_result, dict):
                        raw_vulns = analysis_result.get('vulnerabilities', [])
                    else:
                        raw_vulns = []
                    
                    for v in raw_vulns:
                        if not isinstance(v, dict):
                            continue
                        
                        issue = v.get('issue') or 'Unknown Issue'
                        # Push partial view immediately
                        p_vuln = {
                            "issue": issue,
                            "severity": "Pending",
                            "status": "pending_analysis",
                            "line": v.get("line", 0),
                            "file": v.get("file_path", "Detected in batch")
                        }
                        
                        # Persist partial vuln
                        current_job = get_job(self.job_id)
                        if current_job:
                            if "vulnerabilities_partial" not in current_job: current_job["vulnerabilities_partial"] = []
                            current_job["vulnerabilities_partial"].append(p_vuln)
                            jobs = _load_jobs()
                            jobs[self.job_id] = current_job
                            _save_jobs(jobs)
                        
                        # Attach context for Stage 2
                        v["_context"] = combined_context
                        all_raw_vulns.append(v)
                except Exception as e:
                    self._log(f"Batch {index+1} failed ({str(e)}). Skipping...")
                    continue

            # Stage 2 - Deep Analysis Queue
            self._sync_job(stage="analyzing", progress=60)
            self._log(f"Stage 2: Enriching {len(all_raw_vulns)} identified vulnerabilities...")

            for v_idx, v in enumerate(all_raw_vulns):
                progress = 60 + int((v_idx / max(1, len(all_raw_vulns))) * 30)
                self._sync_job(stage="analyzing", progress=progress)
                
                issue = v.get('issue') or 'Unknown Vulnerability'
                matched_code = v.get('matched_code') or 'Not provided'
                context = v.get('_context') or 'Not provided'
                
                try:
                    self._log(f"Deep Analysis: {issue}...")
                    enrich_prompt = build_deep_enrichment_prompt(issue, matched_code, context)
                    enriched_result = self._invoke_with_backoff(enrich_prompt, max_tokens=2048)
                    
                    # Normalize: Llama 3 may return a list instead of a dict
                    if isinstance(enriched_result, list) and enriched_result:
                        enriched_result = enriched_result[0] if isinstance(enriched_result[0], dict) else {}
                    elif not isinstance(enriched_result, dict):
                        enriched_result = {}
                    
                    explanation = enriched_result.get('explanation') or 'No explanation provided.'
                    rem = enriched_result.get('remediation')
                    remediation = {}
                    if isinstance(rem, dict):
                        remediation = {'patch': rem.get('patch') or '', 'explanation': rem.get('explanation') or ''}
                    elif isinstance(rem, str):
                        remediation = {'patch': rem, 'explanation': 'Apply this suggested fix.'}
                    
                    refined_v = {
                        'severity': enriched_result.get('severity', 'Low'),
                        'issue': issue,
                        'explanation': explanation,
                        'poc_exploit_scenario': enriched_result.get('poc_exploit_scenario', 'No scenario provided.'),
                        'attack_vector': enriched_result.get('attack_vector', 'Unknown'),
                        'remediation': remediation,
                        'suggested_fix': enriched_result.get('suggested_fix', ''),
                        'line': v.get('line', 0),
                        'matched_code': matched_code,
                        'file_path': v.get('file_path') or v.get('path')
                    }
                    
                    # Persist enriched vuln
                    current_job = get_job(self.job_id)
                    if current_job:
                        if "vulnerabilities_full" not in current_job: current_job["vulnerabilities_full"] = []
                        current_job["vulnerabilities_full"].append(refined_v)
                        jobs = _load_jobs()
                        jobs[self.job_id] = current_job
                        _save_jobs(jobs)

                except Exception as e:
                    self._log(f"Deep Analysis failed for '{issue}': {str(e)}")
                    # Fallback to minimal object
                    f_vuln = {
                        'severity': 'Unknown',
                        'issue': issue,
                        'explanation': 'Enrichment failed due to rate limits or API error.',
                        'poc_exploit_scenario': 'Unavailable',
                        'attack_vector': 'Unknown',
                        'remediation': {},
                        'suggested_fix': '',
                        'line': v.get('line', 0),
                        'matched_code': matched_code,
                        'file_path': v.get('file_path') or v.get('path')
                    }
                    current_job = get_job(self.job_id)
                    if current_job:
                        current_job["vulnerabilities_full"].append(f_vuln)
                        jobs = _load_jobs()
                        jobs[self.job_id] = current_job
                        _save_jobs(jobs)

            # Build attack intelligence and risk mapping
            self._sync_job(stage="analyzing", progress=90)
            current_job = get_job(self.job_id)
            if current_job:
                intelligence = build_attack_intelligence(current_job.get("vulnerabilities_full", []), "Aggregated insights")
                self._sync_job(
                    risk_ranking=intelligence.get('risk_ranking', []),
                    attack_graph=intelligence.get('attack_graph', {})
                )

            self._sync_job(status="completed", stage="completed", progress=100)
            self._log("Scan completed successfully!")

        except Exception as e:
            self._log(f"Unrecoverable error: {traceback.format_exc()}")
            self._sync_job(status="failed", stage="failed", progress=100)

def start_progressive_scan(job_id, repo_url, query, token, branch, top_k, invoke_fn):
    engine = RateLimitedEngine(job_id, token, invoke_fn, branch, top_k)
    thread = threading.Thread(target=engine.run_scan, args=(repo_url, query))
    thread.daemon = True
    thread.start()
