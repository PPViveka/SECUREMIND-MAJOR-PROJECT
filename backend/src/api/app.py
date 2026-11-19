"""
SageArmor Application Factory
Initializes Flask app with security middleware, CORS, blueprints, and configuration.
"""

import os
from flask import Flask, request, Response

try:
    from flask_cors import CORS
except ImportError:
    CORS = None

from .middleware import SecurityMiddleware
from .routes import api_bp


def create_app(
    bind_host: str = "127.0.0.1",
    auth_token: str = "",
    request_limit: int = 120,
    allowed_origins: list = None,
    max_request_bytes: int = 2 * 1024 * 1024,
) -> Flask:
    app = Flask("sagearmor")
    app.config["MAX_CONTENT_LENGTH"] = max_request_bytes

    origins = allowed_origins or ["http://localhost:5173", "http://localhost:3000"]
    middleware = SecurityMiddleware(
        bind_host=bind_host,
        auth_token=auth_token,
        request_limit=request_limit,
        allowed_origins=origins,
    )

    # Attach middleware instance to app for backward-compat and test fixtures
    app.security_middleware = middleware

    @app.before_request
    def before_req():
        if request.method == "OPTIONS":
            res = Response()
            origin = request.headers.get("Origin")
            res.headers["Access-Control-Allow-Origin"] = origin if origin in origins else origins[0]
            res.headers["Access-Control-Allow-Headers"] = "*"
            res.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS, PUT, DELETE"
            res.headers["Allow"] = "GET, POST, OPTIONS, PUT, DELETE"
            return res
        return middleware.enforce_security_and_rate_limit(request)

    @app.after_request
    def after_req(response):
        return middleware.add_security_headers(request, response)

    if CORS:
        CORS(app, origins=origins, supports_credentials=True)

    app.register_blueprint(api_bp)
    return app
