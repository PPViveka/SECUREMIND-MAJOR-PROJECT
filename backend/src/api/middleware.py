"""
SageArmor API Middleware
Security, rate limiting, token authentication, and CORS enforcement.
"""

import json
import time
import threading
from collections import defaultdict, deque
from typing import Set, Optional, List
from flask import Request, Response


def is_loopback(host: str) -> bool:
    return host in {"127.0.0.1", "::1", "localhost"}


class SecurityMiddleware:
    """
    Thread-safe sliding-window rate limiter and token authentication guard.
    """

    def __init__(self, bind_host: str, auth_token: str, request_limit: int, allowed_origins: list):
        self.bind_host = bind_host
        self.auth_token = auth_token
        self.request_limit = request_limit
        self.allowed_origins = allowed_origins
        self.lock = threading.Lock()
        self.request_windows = defaultdict(deque)

    def enforce_security_and_rate_limit(self, request: Request) -> Optional[Response]:
        if not is_loopback(self.bind_host) and (
            not self.auth_token or request.headers.get("X-SageArmor-Token") != self.auth_token
        ):
            return Response(
                json.dumps({"error": "Authentication required"}),
                status=401,
                mimetype="application/json",
            )
        now = time.time()
        addr = request.remote_addr or "local"
        with self.lock:
            bucket = self.request_windows[addr]
            while bucket and bucket[0] <= now - 60:
                bucket.popleft()
            if len(bucket) >= self.request_limit:
                retry_after = max(1, int(60 - (now - bucket[0])))
                headers = {
                    "Retry-After": str(retry_after),
                    "X-RateLimit-Limit": str(self.request_limit),
                    "X-RateLimit-Remaining": "0",
                    "X-RateLimit-Reset": str(int(bucket[0] + 60)),
                }
                return Response(
                    json.dumps({"error": "Rate limit exceeded", "retry_after_seconds": retry_after}),
                    status=429,
                    headers=headers,
                    mimetype="application/json",
                )
            bucket.append(now)
        return None

    def add_security_headers(self, request: Request, response: Response) -> Response:
        addr = request.remote_addr or "local"
        with self.lock:
            bucket = self.request_windows.get(addr, deque())
            remaining = max(0, self.request_limit - len(bucket))
        response.headers["X-RateLimit-Limit"] = str(self.request_limit)
        response.headers["X-RateLimit-Remaining"] = str(remaining)
        origin = request.headers.get("Origin")
        if origin in self.allowed_origins:
            response.headers["Access-Control-Allow-Origin"] = origin
        elif self.allowed_origins:
            response.headers["Access-Control-Allow-Origin"] = self.allowed_origins[0]
        response.headers["Vary"] = "Origin"
        return response
