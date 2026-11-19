"""Explicit LLM provider adapters used by the backend model boundary."""

import hashlib
import json
import os
import random
import re
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

import boto3
import requests


class ProviderError(RuntimeError):
    """A provider failure that is safe to surface as degraded analysis."""


class ProviderAuthError(ProviderError):
    """Authentication or API key error."""


class ProviderRateLimitError(ProviderError):
    """Rate limit (429) error."""


class ProviderTimeoutError(ProviderError):
    """Request timeout error."""


class ProviderUnavailableError(ProviderError):
    """Provider service unavailable (500, 502, 503)."""


@dataclass
class ProviderResult:
    text: str
    usage: Dict[str, Any]


def redact_secrets(text: str) -> str:
    """Remove common credential literals before content is sent to a model."""
    redacted = re.sub(
        r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----",
        "<REDACTED_PRIVATE_KEY>",
        text or "",
        flags=re.DOTALL,
    )
    redacted = re.sub(
        r"(?i)(api[_-]?key|access[_-]?key|auth[_-]?token|password|secret|token|authorization)\s*[:=]\s*(?:bearer\s+)?(['\"]?)[A-Za-z0-9_./+=:-]{8,}\2",
        r"\1=<REDACTED>",
        redacted,
    )
    return redacted


def parse_json_response(text: str) -> Any:
    clean = (text or "").replace("```json", "").replace("```", "").strip()
    if not clean:
        raise ProviderError("Provider returned empty output")
    try:
        return json.loads(clean)
    except json.JSONDecodeError:
        decoder = json.JSONDecoder()
        for marker in ("{", "["):
            start = clean.find(marker)
            if start >= 0:
                try:
                    return decoder.raw_decode(clean, start)[0]
                except json.JSONDecodeError:
                    continue
    raise ProviderError("Provider returned invalid JSON")


def validate_json_schema(data: Any, schema: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
    """
    Lightweight JSON schema validator for model outputs.
    Validates types, required fields, and array item schemas.
    """
    if not isinstance(schema, dict):
        return True, None

    schema_type = schema.get("type")
    if schema_type == "object":
        if not isinstance(data, dict):
            return False, f"Expected object, got {type(data).__name__}"
        required = schema.get("required", [])
        for field in required:
            if field not in data:
                return False, f"Missing required property '{field}'"
        properties = schema.get("properties", {})
        for prop, prop_schema in properties.items():
            if prop in data:
                valid, err = validate_json_schema(data[prop], prop_schema)
                if not valid:
                    return False, f"Property '{prop}': {err}"
    elif schema_type == "array":
        if not isinstance(data, list):
            return False, f"Expected array, got {type(data).__name__}"
        items_schema = schema.get("items")
        if items_schema:
            for idx, item in enumerate(data):
                valid, err = validate_json_schema(item, items_schema)
                if not valid:
                    return False, f"Item [{idx}]: {err}"
    elif schema_type == "string" and not isinstance(data, str):
        return False, f"Expected string, got {type(data).__name__}"
    elif schema_type == "integer" and not (isinstance(data, int) and not isinstance(data, bool)):
        return False, f"Expected integer, got {type(data).__name__}"
    elif schema_type == "number" and not (isinstance(data, (int, float)) and not isinstance(data, bool)):
        return False, f"Expected number, got {type(data).__name__}"
    elif schema_type == "boolean" and not isinstance(data, bool):
        return False, f"Expected boolean, got {type(data).__name__}"

    return True, None


def _estimate_tokens(text: str) -> int:
    return max(1, len(text or "") // 4)


class LLMProvider:
    name = "unknown"

    def complete(self, prompt: str, max_tokens: int = 600, as_json: bool = False) -> ProviderResult:
        raise NotImplementedError

    def complete_json(self, prompt: str, max_tokens: int = 600, schema: Optional[Dict[str, Any]] = None) -> Any:
        result = self.complete(prompt, max_tokens=max_tokens, as_json=True)
        data = parse_json_response(result.text)
        if schema:
            valid, err = validate_json_schema(data, schema)
            if not valid:
                raise ProviderError(f"JSON response failed schema validation: {err}")
        return data


class NvidiaProvider(LLMProvider):
    name = "nvidia"

    def __init__(self):
        self.api_key = os.getenv("NVIDIA_API_KEY", "")
        self.model = os.getenv("NVIDIA_MODEL", "meta/llama3-8b-instruct")
        self.timeout = float(os.getenv("LLM_TIMEOUT_SECONDS", "30"))
        self.retries = max(0, int(os.getenv("LLM_RETRIES", "2")))

    def complete(self, prompt: str, max_tokens: int = 600, as_json: bool = False) -> ProviderResult:
        if not self.api_key:
            raise ProviderAuthError("NVIDIA_API_KEY is missing")
        prompt = redact_secrets(prompt)
        payload = {
            "model": self.model,
            "messages": [{"role": "user", "content": prompt}],
            "max_tokens": max_tokens,
            "temperature": 0 if as_json else 0.2,
        }
        last_error = None
        for attempt in range(self.retries + 1):
            try:
                response = requests.post(
                    "https://integrate.api.nvidia.com/v1/chat/completions",
                    headers={"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"},
                    json=payload,
                    timeout=self.timeout,
                )
                if response.status_code in (401, 403):
                    raise ProviderAuthError(f"NVIDIA authentication failed ({response.status_code})")
                if response.status_code == 429:
                    raise ProviderRateLimitError("NVIDIA rate limit exceeded (429)")
                if response.status_code >= 500:
                    raise ProviderUnavailableError(f"NVIDIA provider unavailable ({response.status_code})")
                if response.status_code != 200:
                    raise ProviderError(f"NVIDIA provider rejected request ({response.status_code})")
                body = response.json()
                text = body["choices"][0]["message"]["content"]
                prompt_tokens = _estimate_tokens(prompt)
                completion_tokens = _estimate_tokens(text)
                usage = body.get("usage") or {
                    "estimated": True,
                    "prompt_tokens": prompt_tokens,
                    "completion_tokens": completion_tokens,
                    "total_tokens": prompt_tokens + completion_tokens,
                    "estimated_cost_usd": round((prompt_tokens + completion_tokens) * 0.000002, 6),
                }
                return ProviderResult(text=text, usage=usage)
            except requests.Timeout as exc:
                last_error = ProviderTimeoutError(f"NVIDIA request timed out after {self.timeout}s")
            except (ProviderAuthError, ProviderRateLimitError, ProviderUnavailableError) as exc:
                last_error = exc
            except (requests.RequestException, KeyError, TypeError) as exc:
                last_error = ProviderError(f"NVIDIA provider request failed: {exc}")

            if attempt < self.retries:
                jitter = random.uniform(0.05, 0.15)
                time.sleep(min(2.0, 0.25 * (2 ** attempt)) + jitter)

        raise last_error or ProviderError("NVIDIA provider failed")


class GeminiProvider(LLMProvider):
    name = "gemini"

    def __init__(self):
        self.api_key = os.getenv("GEMINI_API_KEY", "")
        self.model = os.getenv("GEMINI_MODEL", "gemini-3.5-flash-lite")
        self.timeout = float(os.getenv("LLM_TIMEOUT_SECONDS", "60"))
        self.retries = max(0, int(os.getenv("LLM_RETRIES", "2")))

    def complete(self, prompt: str, max_tokens: int = 600, as_json: bool = False) -> ProviderResult:
        if not self.api_key:
            raise ProviderAuthError("GEMINI_API_KEY is missing")
        prompt = redact_secrets(prompt)
        generation_config: Dict[str, Any] = {
            "temperature": 0 if as_json else 0.2,
            # Gemini 2.5 models spend part of the output budget on internal reasoning,
            # so leave headroom above the caller's requested answer length.
            "maxOutputTokens": max(max_tokens * 4, 2048),
        }
        if as_json:
            generation_config["responseMimeType"] = "application/json"
        payload = {
            "contents": [{"role": "user", "parts": [{"text": prompt}]}],
            "generationConfig": generation_config,
        }
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{self.model}:generateContent"
        last_error = None
        for attempt in range(self.retries + 1):
            try:
                response = requests.post(
                    url,
                    headers={"x-goog-api-key": self.api_key, "Content-Type": "application/json"},
                    json=payload,
                    timeout=self.timeout,
                )
                if response.status_code in (401, 403):
                    raise ProviderAuthError(f"Gemini authentication failed ({response.status_code})")
                if response.status_code == 429:
                    raise ProviderRateLimitError("Gemini rate limit exceeded (429)")
                if response.status_code >= 500:
                    raise ProviderUnavailableError(f"Gemini provider unavailable ({response.status_code})")
                if response.status_code != 200:
                    raise ProviderError(f"Gemini provider rejected request ({response.status_code})")
                body = response.json()
                candidate = (body.get("candidates") or [{}])[0]
                parts = (candidate.get("content") or {}).get("parts") or []
                text = "".join(p.get("text", "") for p in parts if not p.get("thought"))
                if not text:
                    raise ProviderError(f"Gemini returned no text (finishReason={candidate.get('finishReason')})")
                meta = body.get("usageMetadata") or {}
                prompt_tokens = meta.get("promptTokenCount") or _estimate_tokens(prompt)
                completion_tokens = meta.get("candidatesTokenCount") or _estimate_tokens(text)
                usage = {
                    "estimated": not meta,
                    "prompt_tokens": prompt_tokens,
                    "completion_tokens": completion_tokens,
                    "total_tokens": meta.get("totalTokenCount") or (prompt_tokens + completion_tokens),
                }
                return ProviderResult(text=text, usage=usage)
            except requests.Timeout:
                last_error = ProviderTimeoutError(f"Gemini request timed out after {self.timeout}s")
            except (ProviderAuthError,) as exc:
                raise exc
            except (ProviderRateLimitError, ProviderUnavailableError, ProviderError) as exc:
                last_error = exc
            except (requests.RequestException, KeyError, TypeError, ValueError) as exc:
                last_error = ProviderError(f"Gemini provider request failed: {exc}")

            if attempt < self.retries:
                jitter = random.uniform(0.05, 0.15)
                time.sleep(min(4.0, 0.5 * (2 ** attempt)) + jitter)

        raise last_error or ProviderError("Gemini provider failed")


class BedrockProvider(LLMProvider):
    name = "bedrock"

    def __init__(self):
        self.model = os.getenv("BEDROCK_MODEL", "us.anthropic.claude-sonnet-4-5-20250929-v1:0")
        self.client = boto3.client("bedrock-runtime", region_name=os.getenv("AWS_REGION", "us-east-1"))
        self.timeout = float(os.getenv("LLM_TIMEOUT_SECONDS", "30"))
        self.retries = max(0, int(os.getenv("LLM_RETRIES", "2")))

    def complete(self, prompt: str, max_tokens: int = 600, as_json: bool = False) -> ProviderResult:
        prompt = redact_secrets(prompt)
        request_body = json.dumps({
            "anthropic_version": "bedrock-2023-05-31",
            "max_tokens": max_tokens,
            "messages": [{"role": "user", "content": [{"type": "text", "text": prompt}]}],
        })
        last_error = None
        for attempt in range(self.retries + 1):
            try:
                response = self.client.invoke_model(
                    modelId=self.model,
                    contentType="application/json",
                    accept="application/json",
                    body=request_body,
                )
                body = json.loads(response["body"].read())
                text = (body.get("content") or [{}])[0].get("text", "")
                prompt_tokens = _estimate_tokens(prompt)
                completion_tokens = _estimate_tokens(text)
                usage = body.get("usage") or {
                    "estimated": True,
                    "prompt_tokens": prompt_tokens,
                    "completion_tokens": completion_tokens,
                    "total_tokens": prompt_tokens + completion_tokens,
                    "estimated_cost_usd": round((prompt_tokens + completion_tokens) * 0.000003, 6),
                }
                return ProviderResult(text=text, usage=usage)
            except Exception as exc:
                err_str = str(exc).lower()
                if "throttling" in err_str or "rate" in err_str:
                    last_error = ProviderRateLimitError(f"Bedrock rate limit exceeded: {exc}")
                elif "accessdenied" in err_str or "auth" in err_str or "credentials" in err_str:
                    last_error = ProviderAuthError(f"Bedrock authentication error: {exc}")
                elif "timeout" in err_str:
                    last_error = ProviderTimeoutError(f"Bedrock timeout: {exc}")
                else:
                    last_error = ProviderError(f"Bedrock provider request failed: {exc}")

                if attempt < self.retries:
                    jitter = random.uniform(0.05, 0.15)
                    time.sleep(min(2.0, 0.25 * (2 ** attempt)) + jitter)

        raise last_error or ProviderError("Bedrock provider request failed")


class BalancedRouterProvider(LLMProvider):
    name = "balanced"

    def __init__(self, providers: Optional[List[LLMProvider]] = None):
        if providers:
            self.providers = providers
        else:
            self.providers = []
            for name in ["nvidia", "bedrock"]:
                try:
                    self.providers.append(create_provider(name))
                except Exception:
                    pass
            if not self.providers:
                self.providers.append(DeterministicMockProvider())
        self.current_idx = 0

    def complete(self, prompt: str, max_tokens: int = 600, as_json: bool = False) -> ProviderResult:
        errors = []
        start_idx = self.current_idx
        for offset in range(len(self.providers)):
            idx = (start_idx + offset) % len(self.providers)
            provider = self.providers[idx]
            try:
                result = provider.complete(prompt, max_tokens=max_tokens, as_json=as_json)
                self.current_idx = (idx + 1) % len(self.providers)
                return result
            except Exception as e:
                errors.append(f"{provider.name}: {e}")
                continue
        raise ProviderError(f"All balanced providers failed: {'; '.join(errors)}")


class RecordedProvider(LLMProvider):
    name = "recorded"

    def __init__(self, records: Dict[str, Any]):
        self.records = records

    def complete(self, prompt: str, max_tokens: int = 600, as_json: bool = False) -> ProviderResult:
        key = hashlib.sha256(prompt.encode("utf-8")).hexdigest()
        record = self.records.get(key)
        if record is None:
            raise ProviderError("No recorded response for prompt")
        if isinstance(record, dict):
            text = json.dumps(record.get("response", record))
            usage = record.get("usage", {"estimated": False})
        else:
            text = str(record)
            usage = {"estimated": False}
        return ProviderResult(text=text, usage=usage)


class DeterministicMockProvider(LLMProvider):
    name = "mock"

    def complete(self, prompt: str, max_tokens: int = 600, as_json: bool = False) -> ProviderResult:
        text = json.dumps({"vulnerabilities": []}) if as_json else "Mock provider response"
        return ProviderResult(text=text, usage={"estimated": True, "total_tokens": _estimate_tokens(prompt)})


def create_provider(name: Optional[str] = None) -> LLMProvider:
    provider = (name or os.getenv("LLM_PROVIDER") or os.getenv("MODEL_PROVIDER") or "mock").strip().lower()
    if provider == "nvidia":
        return NvidiaProvider()
    if provider == "bedrock":
        return BedrockProvider()
    if provider == "gemini":
        return GeminiProvider()
    if provider == "balanced":
        return BalancedRouterProvider()
    if provider == "mock":
        return DeterministicMockProvider()
    if provider == "recorded":
        path = os.getenv("LLM_RECORDING_FILE", "")
        with open(path, "r", encoding="utf-8") as handle:
            return RecordedProvider(json.load(handle))
    raise ProviderError(f"Unsupported model provider: {provider}")


@dataclass
class ModelProfile:
    name: str
    provider_name: str
    model_id: str
    max_tokens: int = 600
    temperature: float = 0.0


DEFAULT_MODEL_PROFILES = {
    "triage": ModelProfile(name="triage", provider_name="nvidia", model_id="meta/llama3-8b-instruct", max_tokens=500),
    "patch": ModelProfile(name="patch", provider_name="nvidia", model_id="meta/llama3-8b-instruct", max_tokens=1000),
    "copilot": ModelProfile(name="copilot", provider_name="nvidia", model_id="meta/llama3-8b-instruct", max_tokens=800),
    "simulation": ModelProfile(name="simulation", provider_name="nvidia", model_id="meta/llama3-8b-instruct", max_tokens=600),
}


class TaskRouter:
    """Routes specific security scanning tasks to designated model profiles (FR-605)."""

    def __init__(self, profiles: Optional[Dict[str, ModelProfile]] = None):
        self.profiles = dict(DEFAULT_MODEL_PROFILES)
        if profiles:
            self.profiles.update(profiles)
        self._provider_cache: Dict[str, LLMProvider] = {}

    def get_provider_for_task(self, task_type: str) -> Tuple[LLMProvider, ModelProfile]:
        profile = self.profiles.get(task_type, self.profiles.get("triage", ModelProfile("default", "mock", "mock-default")))
        prov_name = profile.provider_name
        if prov_name not in self._provider_cache:
            try:
                self._provider_cache[prov_name] = create_provider(prov_name)
            except Exception:
                self._provider_cache[prov_name] = DeterministicMockProvider()
        return self._provider_cache[prov_name], profile

    def route_and_execute(self, task_type: str, prompt: str, as_json: bool = True) -> ProviderResult:
        provider, profile = self.get_provider_for_task(task_type)
        return provider.complete(prompt, max_tokens=profile.max_tokens, as_json=as_json)