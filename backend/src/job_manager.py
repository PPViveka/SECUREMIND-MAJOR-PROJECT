"""SQLite-backed job state with transactional updates, observability, and restart-safe reads."""

import json
import os
import sqlite3
import time
import uuid
import threading
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Callable, Dict, List, Optional

try:
    from .llm_provider import redact_secrets
except ImportError:
    def redact_secrets(text: str) -> str:
        return text


# Bounded worker pool for async jobs
_MAX_WORKERS = max(1, int(os.getenv("SAGEARMOR_MAX_WORKERS", "4")))
_WORKER_POOL = ThreadPoolExecutor(max_workers=_MAX_WORKERS)


def submit_job(fn: Callable, *args, **kwargs):
    """Submits a callable to the bounded worker pool."""
    return _WORKER_POOL.submit(fn, *args, **kwargs)


_SHARED_MEM_CONN: Optional[sqlite3.Connection] = None
_DB_LOCK = threading.RLock()


def _db_path() -> str:
    configured = os.getenv("SAGEARMOR_JOBS_DB")
    if configured:
        return configured
    return os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "jobs.db")


def _connect() -> sqlite3.Connection:
    global _SHARED_MEM_CONN
    path = _db_path()
    if path == ":memory:":
        if _SHARED_MEM_CONN is None:
            _SHARED_MEM_CONN = sqlite3.connect(":memory:", timeout=10.0, check_same_thread=False)
            _SHARED_MEM_CONN.row_factory = sqlite3.Row
        return _SHARED_MEM_CONN
    connection = sqlite3.connect(path, timeout=10.0)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA journal_mode=WAL")
    connection.execute("PRAGMA busy_timeout=10000")
    return connection


def _close(connection: sqlite3.Connection) -> None:
    if connection is _SHARED_MEM_CONN:
        return
    try:
        connection.close()
    except Exception:
        pass


def set_db_path(path: str) -> None:
    global _SHARED_MEM_CONN
    if _SHARED_MEM_CONN is not None:
        try:
            _SHARED_MEM_CONN.close()
        except Exception:
            pass
        _SHARED_MEM_CONN = None
    os.environ["SAGEARMOR_JOBS_DB"] = path
    _init_db()


def recover_interrupted_jobs() -> List[str]:
    connection = _connect()
    interrupted_ids = []
    try:
        now = time.time()
        rows = connection.execute("SELECT job_id, payload FROM jobs WHERE status = 'running'").fetchall()
        for row in rows:
            try:
                job_data = json.loads(row["payload"])
                job_data["status"] = "interrupted"
                job_data["stage"] = "interrupted"
                job_data.setdefault("logs", []).append("Job interrupted by process restart")
                job_data.setdefault("events", []).append({
                    "timestamp": now,
                    "type": "restart_interrupted",
                    "detail": "Recovered from prior server crash/restart",
                })
                connection.execute(
                    "UPDATE jobs SET status = 'interrupted', payload = ?, updated_at = ? WHERE job_id = ?",
                    (_serialize(job_data), now, row["job_id"]),
                )
                interrupted_ids.append(row["job_id"])
            except Exception:
                pass
        connection.commit()
        return interrupted_ids
    finally:
        _close(connection)


def _init_db() -> None:
    connection = _connect()
    try:
        connection.execute(
            """CREATE TABLE IF NOT EXISTS jobs (
                job_id TEXT PRIMARY KEY,
                status TEXT NOT NULL,
                payload TEXT NOT NULL,
                created_at REAL NOT NULL,
                updated_at REAL NOT NULL,
                expires_at REAL NOT NULL DEFAULT 0
            )"""
        )
        # Migrate table if expires_at is missing from earlier schema
        columns = [col[1] for col in connection.execute("PRAGMA table_info(jobs)").fetchall()]
        if "expires_at" not in columns:
            connection.execute("ALTER TABLE jobs ADD COLUMN expires_at REAL NOT NULL DEFAULT 0")

        connection.execute("CREATE INDEX IF NOT EXISTS idx_jobs_status ON jobs(status)")
        connection.execute("CREATE INDEX IF NOT EXISTS idx_jobs_expires ON jobs(expires_at)")
        connection.commit()
    finally:
        _close(connection)
    
    recover_interrupted_jobs()


def _serialize(job: Dict[str, Any]) -> str:
    return json.dumps(job, separators=(",", ":"))


def _row_job(row: Optional[sqlite3.Row]) -> Optional[Dict[str, Any]]:
    return json.loads(row["payload"]) if row is not None else None


def _update(job_id: str, mutate) -> Optional[Dict[str, Any]]:
    with _DB_LOCK:
        connection = _connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute("SELECT * FROM jobs WHERE job_id = ?", (job_id,)).fetchone()
            job = _row_job(row)
            if job is None:
                connection.rollback()
                return None
            mutate(job)
            now = time.time()
            expires_at = float(job.get("expires_at", 0))
            connection.execute(
                "UPDATE jobs SET status = ?, payload = ?, updated_at = ?, expires_at = ? WHERE job_id = ?",
                (job.get("status", "running"), _serialize(job), now, expires_at, job_id),
            )
            connection.commit()
            return job
        finally:
            _close(connection)


_init_db()


def create_job(job_id: str = None, ttl_seconds: int = 86400) -> str:
    job_id = job_id or str(uuid.uuid4())
    now = time.time()
    expires_at = now + max(60, int(ttl_seconds))
    job = {
        "job_id": job_id,
        "status": "running",
        "stage": "initializing",
        "progress": 0,
        "results": [],
        "logs": ["Job started"],
        "events": [
            {"timestamp": now, "type": "job_created", "detail": "Job initialized"}
        ],
        "pr_url": None,
        "created_at": now,
        "expires_at": expires_at,
        "summary": "",
        "vulnerabilities_partial": [],
        "vulnerabilities_full": [],
        "fixes": [],
        "queue": [],
        "observability": {
            "stage_timings": {},
            "provider_calls": 0,
            "token_usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
            "cache_hits": 0,
            "verdict_counts": {"verified": 0, "unconfirmed": 0, "inconclusive": 0},
            "gate_health": {},
            "safe_error_details": None,
        },
    }
    with _DB_LOCK:
        connection = _connect()
        try:
            connection.execute(
                "INSERT OR IGNORE INTO jobs(job_id, status, payload, created_at, updated_at, expires_at) VALUES (?, ?, ?, ?, ?, ?)",
                (job_id, "running", _serialize(job), now, now, expires_at),
            )
            connection.commit()
        finally:
            _close(connection)
    return job_id




def cancel_job(job_id: str) -> Optional[Dict[str, Any]]:
    def mutate(job):
        if job.get("status") == "running":
            job.update({"status": "cancelled", "stage": "cancelled"})
            job.setdefault("logs", []).append("Job cancelled")
            job.setdefault("events", []).append({
                "timestamp": time.time(),
                "type": "job_cancelled",
                "detail": "User or timeout cancellation",
            })
    return _update(job_id, mutate)



def reap_stale_jobs(max_age_seconds: int = 3600) -> int:
    now = time.time()
    cutoff = now - max(1, int(max_age_seconds))
    connection = _connect()
    try:
        # 1. Cancel long-running jobs that exceeded max_age_seconds
        rows = connection.execute(
            "SELECT job_id FROM jobs WHERE status = 'running' AND updated_at < ?", (cutoff,)
        ).fetchall()
        for row in rows:
            cancel_job(row["job_id"])

        # 2. Delete expired jobs past TTL
        deleted = connection.execute(
            "DELETE FROM jobs WHERE expires_at > 0 AND expires_at < ?", (now,)
        ).rowcount
        connection.commit()
        return len(rows) + max(0, deleted)
    finally:
        _close(connection)


def get_job(job_id: str) -> Optional[Dict[str, Any]]:
    with _DB_LOCK:
        connection = _connect()
        try:
            return _row_job(connection.execute("SELECT * FROM jobs WHERE job_id = ?", (job_id,)).fetchone())
        finally:
            _close(connection)


def update_job(job_id: str, fields: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    def mutate(job):
        job.update(fields)
    return _update(job_id, mutate)



def update_job_progress(job_id: str, stage: str, progress: int, log_msg: str = None):
    def mutate(job):
        job["stage"] = stage
        job["progress"] = max(0, min(100, int(progress)))
        if log_msg:
            job.setdefault("logs", []).append(log_msg)
        job.setdefault("events", []).append({
            "timestamp": time.time(),
            "type": "stage_changed",
            "detail": f"Stage '{stage}' reached ({job['progress']}%)",
        })
    return _update(job_id, mutate)



def add_job_event(job_id: str, event_type: str, detail: Any = None):
    def mutate(job):
        job.setdefault("events", []).append({
            "timestamp": time.time(),
            "event": event_type,
            "type": event_type,
            "detail": redact_secrets(detail) if isinstance(detail, str) else detail,
        })
    return _update(job_id, mutate)



def record_stage_timing(job_id: str, stage: str, duration_sec: float):
    def mutate(job):
        obs = job.setdefault("observability", {})
        timings = obs.setdefault("stage_timings", {})
        timings[stage] = round(duration_sec, 3)
        metrics = job.setdefault("metrics", {})
        metrics[f"{stage}_ms"] = round(duration_sec, 3)
    return _update(job_id, mutate)



def record_observability(
    job_id: str,
    provider_calls: int = 0,
    tokens: Optional[Dict[str, int]] = None,
    token_usage: Optional[Dict[str, int]] = None,
    cache_hits: int = 0,
    verdict: Optional[str] = None,
    verdicts: Optional[Dict[str, int]] = None,
    gate_name: Optional[str] = None,
    gate_status: Optional[str] = None,
    gate_health: Optional[Dict[str, str]] = None,
):
    def mutate(job):
        obs = job.setdefault("observability", {})
        if provider_calls:
            obs["provider_calls"] = obs.get("provider_calls", 0) + provider_calls
        toks = token_usage or tokens
        if toks:
            tu = obs.setdefault("token_usage", {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0})
            tu["prompt_tokens"] += toks.get("prompt_tokens", 0)
            tu["completion_tokens"] += toks.get("completion_tokens", 0)
            tu["total_tokens"] += toks.get("total_tokens", 0)
        if cache_hits:
            obs["cache_hits"] = obs.get("cache_hits", 0) + cache_hits
        vc = obs.setdefault("verdict_counts", {"verified": 0, "unconfirmed": 0, "inconclusive": 0, "confirmed": 0, "refuted": 0})
        if verdict:
            vc[verdict] = vc.get(verdict, 0) + 1
        if verdicts:
            for v, cnt in verdicts.items():
                vc[v] = vc.get(v, 0) + cnt
        gh = obs.setdefault("gate_health", {})
        if gate_name and gate_status:
            gh[gate_name] = gate_status
        if gate_health:
            gh.update(gate_health)
    return _update(job_id, mutate)



def append_partial_result(job_id: str, result: Any):
    def mutate(job):
        job.setdefault("results", []).append(result)
    return _update(job_id, mutate)



def mark_completed(job_id: str, summary: str, pr_url: Any = None, modified_files: list = None, result: Any = None):
    # Support callers passing result dictionary as 3rd arg
    if isinstance(pr_url, dict) and result is None:
        result = pr_url
        pr_url = None

    def mutate(job):
        job.update({"status": "completed", "stage": "completed", "progress": 100, "summary": summary})
        if pr_url:
            job["pr_url"] = pr_url
        if modified_files:
            job["modified_files"] = modified_files
        if result is not None:
            job["result"] = result
            if isinstance(result, dict) and "vulnerabilities" in result:
                job["vulnerabilities_full"] = result["vulnerabilities"]
        job.setdefault("logs", []).append("Job completed successfully")
        job.setdefault("events", []).append({
            "timestamp": time.time(),
            "type": "job_completed",
            "detail": summary,
        })
    return _update(job_id, mutate)



def mark_failed(job_id: str, error_msg: str):
    def mutate(job):
        safe_msg = redact_secrets(error_msg)
        job.update({"status": "failed", "stage": "failed"})
        job.setdefault("logs", []).append(f"ERROR: {safe_msg}")
        job.setdefault("observability", {})["safe_error_details"] = safe_msg
        job.setdefault("events", []).append({
            "timestamp": time.time(),
            "type": "job_failed",
            "detail": safe_msg,
        })
    return _update(job_id, mutate)


def _load_jobs() -> Dict[str, Dict[str, Any]]:
    conn = _connect()
    try:
        cur = conn.execute("SELECT job_id, payload FROM jobs")
        jobs = {}
        for row in cur.fetchall():
            payload = _row_job(row)
            if payload:
                jobs[row["job_id"]] = payload
        return jobs
    finally:
        _close(conn)


def _save_jobs(jobs: Dict[str, Dict[str, Any]]) -> None:
    for jid, data in jobs.items():
        if isinstance(data, dict):
            update_job(jid, data)

