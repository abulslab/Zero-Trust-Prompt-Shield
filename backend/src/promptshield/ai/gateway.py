"""One gateway in front of every model provider.

Every call goes through `ModelGateway.complete`, which enforces the input cap and the deadline and turns any provider
failure into `ModelUnavailable`, so callers always have a no-AI path. Providers speak plain HTTP; no SDKs.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from typing import Any, Protocol

import httpx

from promptshield.config import Settings


class ModelUnavailable(RuntimeError):
    """The model could not answer (not configured, unreachable, timed out, refused, or returned junk)."""


@dataclass(frozen=True)
class ModelReply:
    text: str
    provider: str
    model: str
    latency_ms: int


class ModelProvider(Protocol):
    name: str
    model: str

    def complete(self, system: str, user: str, *, json_mode: bool, max_tokens: int, timeout: float) -> str: ...


class GeminiProvider:
    name = "gemini"

    def __init__(self, api_key: str, model: str) -> None:
        self._key, self.model = api_key, model

    def complete(self, system: str, user: str, *, json_mode: bool, max_tokens: int, timeout: float) -> str:
        body: dict[str, Any] = {
            "systemInstruction": {"parts": [{"text": system}]},
            "contents": [{"role": "user", "parts": [{"text": user}]}],
            "generationConfig": {"temperature": 0.1, "maxOutputTokens": max_tokens},
        }
        if json_mode:
            body["generationConfig"]["responseMimeType"] = "application/json"
        fallbacks = ["gemini-3.5-flash", "gemini-3.5-flash-lite", "gemini-3.1-flash-lite"]
        for attempt in range(4):
            r = httpx.post(
                f"https://generativelanguage.googleapis.com/v1beta/models/{self.model}:generateContent",
                headers={"x-goog-api-key": self._key},
                json=body,
                timeout=timeout,
            )
            if r.status_code in (404, 429):
                nxt = next((m for m in fallbacks if m != self.model), None)
                if nxt is not None:
                    fallbacks.remove(nxt)
                    self.model = nxt
                    continue
            if r.status_code in (429, 500, 502, 503, 504) and attempt < 3:
                time.sleep(0.8 * (attempt + 1))
                continue
            break
        r.raise_for_status()
        data = r.json()
        parts = data.get("candidates", [{}])[0].get("content", {}).get("parts", [])
        return "".join(p.get("text", "") for p in parts)


class OllamaProvider:
    name = "ollama"

    def __init__(self, url: str, model: str) -> None:
        self._url, self.model = url.rstrip("/"), model

    def complete(self, system: str, user: str, *, json_mode: bool, max_tokens: int, timeout: float) -> str:
        body: dict[str, Any] = {
            "model": self.model,
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
            "stream": False,
            "options": {"temperature": 0.1, "num_predict": max_tokens},
        }
        if json_mode:
            body["format"] = "json"
        r = httpx.post(f"{self._url}/api/chat", json=body, timeout=timeout)
        r.raise_for_status()
        return str(r.json().get("message", {}).get("content", ""))


class AnthropicProvider:
    name = "anthropic"

    def __init__(self, api_key: str, model: str) -> None:
        self._key, self.model = api_key, model

    def complete(self, system: str, user: str, *, json_mode: bool, max_tokens: int, timeout: float) -> str:
        r = httpx.post(
            "https://api.anthropic.com/v1/messages",
            headers={"x-api-key": self._key, "anthropic-version": "2023-06-01"},
            json={
                "model": self.model,
                "max_tokens": max_tokens,
                "system": system + ("\nAnswer with a single JSON object and nothing else." if json_mode else ""),
                "messages": [{"role": "user", "content": user}],
            },
            timeout=timeout,
        )
        r.raise_for_status()
        return "".join(b.get("text", "") for b in r.json().get("content", []) if b.get("type") == "text")


class OpenAiCompatibleProvider:
    name = "openai"

    def __init__(self, api_key: str, base_url: str, model: str) -> None:
        self._key, self._url, self.model = api_key, base_url.rstrip("/"), model

    def complete(self, system: str, user: str, *, json_mode: bool, max_tokens: int, timeout: float) -> str:
        body: dict[str, Any] = {
            "model": self.model,
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
            "temperature": 0.1,
            "max_tokens": max_tokens,
        }
        if json_mode:
            body["response_format"] = {"type": "json_object"}
        r = httpx.post(
            f"{self._url}/chat/completions",
            headers={"Authorization": f"Bearer {self._key}"},
            json=body,
            timeout=timeout,
        )
        r.raise_for_status()
        return str(r.json()["choices"][0]["message"]["content"] or "")


class ScriptedProvider:
    """Deterministic provider for tests and demos: answers from a list, in order."""

    name = "scripted"
    model = "scripted"

    def __init__(self, replies: list[str]) -> None:
        self.replies = list(replies)
        self.calls: list[tuple[str, str]] = []

    def complete(self, system: str, user: str, *, json_mode: bool, max_tokens: int, timeout: float) -> str:
        self.calls.append((system, user))
        if not self.replies:
            raise ModelUnavailable("no scripted reply left")
        return self.replies.pop(0)


class ModelGateway:
    def __init__(self, provider: ModelProvider | None, *, timeout: float = 30.0, max_input_chars: int = 24_000) -> None:
        self.provider = provider
        self.timeout = timeout
        self.max_input_chars = max_input_chars

    @property
    def available(self) -> bool:
        return self.provider is not None

    def describe(self) -> dict[str, Any]:
        return {
            "provider": self.provider.name if self.provider else "none",
            "model": self.provider.model if self.provider else None,
        }

    def complete(self, system: str, user: str, *, json_mode: bool = False, max_tokens: int = 2048) -> ModelReply:
        if self.provider is None:
            raise ModelUnavailable("No model provider is configured (SHIELD_AI_PROVIDER=none).")
        if len(user) > self.max_input_chars:
            raise ModelUnavailable(f"Input is {len(user)} characters; the model input cap is {self.max_input_chars}.")
        started = time.perf_counter()
        try:
            try:
                text = self.provider.complete(
                    system, user, json_mode=json_mode, max_tokens=max_tokens, timeout=self.timeout
                )
            except (httpx.HTTPStatusError, httpx.TransportError) as e:
                # One retry for transient failures (a local model reloading, a 5xx, a dropped connection).
                if (isinstance(e, httpx.HTTPStatusError) and e.response.status_code < 500) or isinstance(
                    e, httpx.TimeoutException
                ):
                    raise
                time.sleep(1.0)
                text = self.provider.complete(
                    system, user, json_mode=json_mode, max_tokens=max_tokens, timeout=self.timeout
                )
        except ModelUnavailable:
            raise
        except httpx.TimeoutException as e:
            raise ModelUnavailable(f"{self.provider.name} timed out after {self.timeout:.0f}s") from e
        except httpx.HTTPStatusError as e:
            raise ModelUnavailable(f"{self.provider.name} returned HTTP {e.response.status_code}") from e
        except Exception as e:
            raise ModelUnavailable(f"{self.provider.name} failed: {type(e).__name__}") from e
        if not text.strip():
            raise ModelUnavailable(f"{self.provider.name} returned an empty answer")
        return ModelReply(text, self.provider.name, self.provider.model, int((time.perf_counter() - started) * 1000))

    def complete_json(self, system: str, user: str, *, max_tokens: int = 2048) -> tuple[Any, ModelReply]:
        reply = self.complete(system, user, json_mode=True, max_tokens=max_tokens)
        return parse_json(reply.text), reply


def parse_json(text: str) -> Any:
    t = text.strip()
    if t.startswith("```"):
        t = t.strip("`")
        t = t[4:] if t.lower().startswith("json") else t
    start = min((i for i in (t.find("{"), t.find("[")) if i >= 0), default=-1)
    if start < 0:
        raise ModelUnavailable("The model did not answer with JSON.")
    try:
        return json.JSONDecoder().raw_decode(t[start:])[0]
    except json.JSONDecodeError as e:
        raise ModelUnavailable("The model answered with malformed JSON.") from e


def build_gateway(s: Settings) -> ModelGateway:
    provider: ModelProvider | None = None
    if s.ai_provider == "gemini" and s.gemini_api_key:
        provider = GeminiProvider(s.gemini_api_key.get_secret_value(), s.gemini_model)
    elif s.ai_provider == "ollama":
        provider = OllamaProvider(s.ollama_url, s.ollama_model)
    elif s.ai_provider == "anthropic" and s.anthropic_api_key:
        provider = AnthropicProvider(s.anthropic_api_key.get_secret_value(), s.anthropic_model)
    elif s.ai_provider == "openai" and s.openai_api_key:
        provider = OpenAiCompatibleProvider(s.openai_api_key.get_secret_value(), s.openai_base_url, s.openai_model)
    # Local models on a laptop take tens of seconds per review; cloud APIs answer in a few.
    timeout = s.ai_timeout_s if s.ai_timeout_s is not None else (180.0 if s.ai_provider == "ollama" else 30.0)
    return ModelGateway(provider, timeout=timeout, max_input_chars=s.ai_max_input_chars)
