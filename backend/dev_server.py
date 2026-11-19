"""
SageArmor Production Development Server Entrypoint
Integrates modular API application factory with dev-server configuration.
"""

import os
import sys
from dotenv import load_dotenv

# Ensure backend root is on sys.path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from src.api.app import create_app
from src.api.middleware import is_loopback

load_dotenv()

# Server Environment Configuration
bind_host = os.environ.get("HOST", "127.0.0.1")
auth_token = os.environ.get("SAGEARMOR_AUTH_TOKEN", "")
request_limit = max(1, int(os.environ.get("RATE_LIMIT_PER_MINUTE", "120")))
max_bytes = int(os.environ.get("MAX_REQUEST_BYTES", 2 * 1024 * 1024))
allowed_origins = [
    origin.strip()
    for origin in os.environ.get("CORS_ORIGINS", "http://localhost:5173").split(",")
    if origin.strip()
]

# Instantiate Application Factory
app = create_app(
    bind_host=bind_host,
    auth_token=auth_token,
    request_limit=request_limit,
    allowed_origins=allowed_origins,
    max_request_bytes=max_bytes,
)

# Reference middleware state for test compatibility
request_windows = app.security_middleware.request_windows


def _is_loopback(host: str) -> bool:
    return is_loopback(host)


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 6060))
    if not _is_loopback(bind_host) and not auth_token:
        raise RuntimeError("SAGEARMOR_AUTH_TOKEN is required for non-loopback binding")
    print(f"✅ SageArmor Production Server running on http://{bind_host}:{port}")
    debug = os.environ.get("FLASK_DEBUG", "").lower() in {"1", "true", "yes"}
    app.run(host=bind_host, port=port, debug=debug, threaded=True)
