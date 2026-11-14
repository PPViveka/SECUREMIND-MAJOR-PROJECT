import uuid
import time
import json
import os
from typing import Dict, Any

JOBS_FILE = "jobs.json"

def _load_jobs():
    if os.path.exists(JOBS_FILE):
        try:
            with open(JOBS_FILE, "r") as f:
                return json.load(f)
        except:
            return {}
    return {}

def _save_jobs(jobs):
    with open(JOBS_FILE, "w") as f:
        json.dump(jobs, f, indent=2)

# Load jobs on module load
_jobs: Dict[str, Any] = _load_jobs()

def create_job(job_id: str = None) -> str:
    job_id = job_id or str(uuid.uuid4())
    _jobs[job_id] = {
        "job_id": job_id,
        "status": "running",
        "stage": "initializing",
        "progress": 0,
        "results": [],
        "logs": ["Job started"],
        "pr_url": None,
        "created_at": time.time(),
        "summary": "",
        "vulnerabilities_partial": [],
        "vulnerabilities_full": [],
        "fixes": [],
        "queue": []
    }
    _save_jobs(_jobs)
    return job_id

def get_job(job_id: str) -> Any:
    # Refresh from disk to handle multi-worker or restart scenarios
    global _jobs
    _jobs = _load_jobs()
    return _jobs.get(job_id)

def update_job_progress(job_id: str, stage: str, progress: int, log_msg: str = None):
    job = get_job(job_id)
    if job:
        job["stage"] = stage
        job["progress"] = progress
        if log_msg:
            job["logs"].append(log_msg)
        _jobs[job_id] = job
        _save_jobs(_jobs)

def append_partial_result(job_id: str, result: Any):
    job = get_job(job_id)
    if job:
        job["results"].append(result)
        _jobs[job_id] = job
        _save_jobs(_jobs)

def mark_completed(job_id: str, summary: str, pr_url: str = None, modified_files: list = None):
    job = get_job(job_id)
    if job:
        job["status"] = "completed"
        job["stage"] = "completed"
        job["progress"] = 100
        job["summary"] = summary
        if pr_url:
            job["pr_url"] = pr_url
        if modified_files:
            job["modified_files"] = modified_files
        job["logs"].append("Job completed successfully")
        _jobs[job_id] = job
        _save_jobs(_jobs)

def mark_failed(job_id: str, error_msg: str):
    job = get_job(job_id)
    if job:
        job["status"] = "failed"
        job["stage"] = "failed"
        job["logs"].append(f"ERROR: {error_msg}")
        _jobs[job_id] = job
        _save_jobs(_jobs)
