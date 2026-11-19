"""
SageArmor Configuration Module
Centralized, validated environment configuration with production and development defaults.
"""

import os
from dataclasses import dataclass, field
from typing import List, Optional


@dataclass(frozen=True)
class SecurityConfig:
    auth_token: str = field(
        default_factory=lambda: os.getenv("SAGEARMOR_AUTH_TOKEN")
        or os.getenv("SAGE_ARMOR_TOKEN")
        or "sagearmor-dev-secret-token-change-in-prod"
    )
    cors_allowed_origins: List[str] = field(
        default_factory=lambda: [
            o.strip()
            for o in os.getenv(
                "SAGE_ARMOR_CORS_ORIGIN",
                "http://localhost:5173,http://localhost:3000,http://127.0.0.1:5173,vscode-webview://*",
            ).split(",")
            if o.strip()
        ]
    )
    rate_limit_per_minute: int = field(
        default_factory=lambda: int(os.getenv("SAGE_ARMOR_RATE_LIMIT", "120"))
    )
    unsafe_local_sandbox: bool = field(
        default_factory=lambda: os.getenv("SAGE_ARMOR_UNSAFE_LOCAL_SANDBOX") == "1"
    )
    use_gvisor: bool = field(
        default_factory=lambda: os.getenv("SAGE_ARMOR_USE_GVISOR") == "1"
    )


@dataclass(frozen=True)
class ServerConfig:
    host: str = field(default_factory=lambda: os.getenv("HOST", "127.0.0.1"))
    port: int = field(default_factory=lambda: int(os.getenv("PORT", "6060")))
    environment: str = field(default_factory=lambda: os.getenv("ENVIRONMENT", "production"))
    debug: bool = field(default_factory=lambda: os.getenv("DEBUG", "0") == "1")


@dataclass(frozen=True)
class StorageConfig:
    jobs_db_path: str = field(
        default_factory=lambda: os.getenv("SAGE_ARMOR_JOBS_DB", os.path.join(os.path.dirname(__file__), "..", "jobs.db"))
    )
    cache_db_path: str = field(
        default_factory=lambda: os.getenv("SAGE_ARMOR_CACHE_DB", os.path.join(os.path.dirname(__file__), "..", "cache.db"))
    )


@dataclass(frozen=True)
class AIConfig:
    provider: str = field(
        default_factory=lambda: os.getenv("LLM_PROVIDER") or os.getenv("MODEL_PROVIDER") or "mock"
    )
    model: str = field(default_factory=lambda: os.getenv("LLM_MODEL", "meta/llama3-8b-instruct"))
    timeout_seconds: float = field(
        default_factory=lambda: float(os.getenv("LLM_TIMEOUT_SECONDS", "30.0"))
    )
    api_key: Optional[str] = field(
        default_factory=lambda: os.getenv("NVIDIA_API_KEY") or os.getenv("OPENAI_API_KEY")
    )

    @property
    def display_name(self) -> str:
        prov = self.provider.strip().lower()
        mapping = {
            "nvidia": "NVIDIA NIM (meta/llama3-8b-instruct)",
            "bedrock": "Amazon Bedrock (anthropic.claude-3-haiku)",
            "gemini": "Google Gemini (gemini-1.5-pro)",
            "openai": "OpenAI (gpt-4o)",
            "mock": "Deterministic Mock Engine",
            "recorded": "Recorded LLM Dataset",
        }
        return mapping.get(prov, prov.title())


@dataclass(frozen=True)
class AppConfig:
    security: SecurityConfig = field(default_factory=SecurityConfig)
    server: ServerConfig = field(default_factory=ServerConfig)
    storage: StorageConfig = field(default_factory=StorageConfig)
    ai: AIConfig = field(default_factory=AIConfig)


config = AppConfig()
