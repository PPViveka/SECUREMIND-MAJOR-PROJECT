"""
SageArmor API Route Definitions
Modular blueprints for analysis, streaming, remediation, and health checks.
"""

import json
import time
from flask import Blueprint, request, Response

from ..handler import (
    repo_scan_start,
    repo_scan_status,
    repo_autofix_start,
    repo_autofix_status,
    review_code,
    review_status,
    copilot_chat,
    simulate,
    attack_path,
    risk_score,
    healthz,
    repo_scan_cancel,
)
from ..job_manager import get_job

api_bp = Blueprint("api", __name__)


def lambda_bridge(handler_fn, req):
    """Bridges Flask request to Lambda event dictionary format."""
    event = {
        "body": req.get_data().decode("utf-8"),
        "queryStringParameters": req.args.to_dict(),
        "pathParameters": {},
        "requestContext": {"http": {"method": req.method}},
        "headers": dict(req.headers),
    }
    result = handler_fn(event, None)
    status = result.get("statusCode", 200)
    body = result.get("body", "")
    headers = result.get("headers", {})
    return Response(response=body, status=status, headers=headers, mimetype="application/json")


# Core Analysis Routes
@api_bp.route("/review", methods=["POST"])
def review_route():
    return lambda_bridge(review_code, request)


@api_bp.route("/review/status", methods=["GET"])
def review_status_route():
    return lambda_bridge(review_status, request)


# Repo Scanning Routes
@api_bp.route("/repo-scan/start", methods=["POST"])
def scan_start_route():
    return lambda_bridge(repo_scan_start, request)


@api_bp.route("/repo-scan/status", methods=["GET"])
def scan_status_route():
    return lambda_bridge(repo_scan_status, request)


@api_bp.route("/repo-scan/cancel", methods=["POST"])
def scan_cancel_route():
    return lambda_bridge(repo_scan_cancel, request)


# Autofix Routes
@api_bp.route("/repo-autofix/start", methods=["POST"])
def autofix_start_route():
    return lambda_bridge(repo_autofix_start, request)


@api_bp.route("/repo-autofix/status", methods=["GET"])
def autofix_status_route():
    return lambda_bridge(repo_autofix_status, request)


# Copilot & Intelligence Routes
@api_bp.route("/copilot", methods=["POST"])
def copilot_route():
    return lambda_bridge(copilot_chat, request)


@api_bp.route("/simulate", methods=["POST"])
def simulate_route():
    return lambda_bridge(simulate, request)


@api_bp.route("/attack-path", methods=["POST"])
def attack_path_route():
    return lambda_bridge(attack_path, request)


@api_bp.route("/risk-score", methods=["POST"])
def risk_score_route():
    return lambda_bridge(risk_score, request)


# Health Check
@api_bp.route("/healthz", methods=["GET"])
@api_bp.route("/health", methods=["GET"])
def health_route():
    return lambda_bridge(healthz, request)


# SSE Stream Endpoint (FR-805)
@api_bp.route("/v2/jobs/<job_id>/stream", methods=["GET"])
def stream_job(job_id):
    def event_stream():
        last_progress = -1
        last_stage = None
        for _ in range(30):
            job = get_job(job_id)
            if not job:
                yield f"event: error\ndata: {json.dumps({'error': 'Job not found'})}\n\n"
                break
            prog = job.get("progress", 0)
            stage = job.get("stage", "queued")
            if prog != last_progress or stage != last_stage:
                last_progress = prog
                last_stage = stage
                data = {
                    "job_id": job_id,
                    "status": job.get("status", "running"),
                    "stage": stage,
                    "progress": prog,
                    "logs": job.get("logs", [])[-3:],
                }
                yield f"event: update\ndata: {json.dumps(data)}\n\n"
            if job.get("status") in ("succeeded", "failed", "cancelled", "interrupted"):
                yield f"event: done\ndata: {json.dumps({'job_id': job_id, 'status': job.get('status')})}\n\n"
                break
            time.sleep(0.5)

    res = Response(event_stream(), mimetype="text/event-stream")
    res.headers["Cache-Control"] = "no-cache"
    res.headers["X-Accel-Buffering"] = "no"
    return res


# Dashboard Security Score Endpoint (FR-404)
@api_bp.route("/v2/security-score", methods=["POST"])
def security_score_route():
    body = request.get_json(silent=True) or {}
    findings = body.get("findings", [])

    verified = [f for f in findings if f.get("verified") is True or f.get("verification_status") == "verified"]
    unconfirmed = [f for f in findings if f not in verified]

    crit = sum(1 for f in verified if f.get("severity", "").lower() == "critical")
    high = sum(1 for f in verified if f.get("severity", "").lower() == "high")
    med = sum(1 for f in verified if f.get("severity", "").lower() == "medium")
    low = sum(1 for f in verified if f.get("severity", "").lower() == "low")

    score = max(0, 100 - (crit * 30 + high * 18 + med * 8 + low * 2))

    return Response(
        json.dumps({
            "security_score": score,
            "status": "secure" if score >= 80 else ("warning" if score >= 50 else "critical"),
            "verified_count": len(verified),
            "unconfirmed_count": len(unconfirmed),
            "breakdown": {
                "critical": crit,
                "high": high,
                "medium": med,
                "low": low,
            },
            "formula": "100 - (30*critical + 18*high + 8*medium + 2*low) strictly over verified findings",
        }),
        status=200,
        mimetype="application/json",
    )
