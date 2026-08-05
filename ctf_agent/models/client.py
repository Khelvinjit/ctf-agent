"""Provider clients normalized to a compact response used by the solver."""
from __future__ import annotations

import json
from collections.abc import Sequence

import httpx

from ctf_agent.config import Settings
from ctf_agent.types import ModelResponse, ToolCall


class ModelError(RuntimeError):
    """An unrecoverable provider response."""


class RateLimitError(ModelError):
    """A retryable quota/rate-limit response."""


class ChatClient:
    def __init__(self, settings: Settings, http_client: httpx.Client | None = None) -> None:
        self.settings = settings
        self.http = http_client or httpx.Client(timeout=90)

    def chat(self, messages: Sequence[dict[str, object]], *, provider: str, model: str,
             tools: list[dict[str, object]] | None = None) -> ModelResponse:
        if provider == "openrouter":
            return self._openrouter(messages, model, tools)
        if provider == "gemini":
            return self._gemini(messages, model, tools)
        raise ModelError(f"unsupported provider: {provider}")

    def _request(self, method: str, url: str, **kwargs: object) -> httpx.Response:
        response = self.http.request(method, url, **kwargs)
        if response.status_code == 429:
            raise RateLimitError(response.text)
        if response.is_error:
            raise ModelError(f"provider returned {response.status_code}: {response.text[:500]}")
        return response

    def _openrouter(self, messages: Sequence[dict[str, object]], model: str,
                    tools: list[dict[str, object]] | None) -> ModelResponse:
        if not self.settings.openrouter_api_key:
            raise ModelError("OPENROUTER_API_KEY is not configured")
        payload: dict[str, object] = {"model": model, "messages": list(messages)}
        if tools:
            payload["tools"] = tools
        data = self._request("POST", "https://openrouter.ai/api/v1/chat/completions", json=payload,
            headers={"Authorization": f"Bearer {self.settings.openrouter_api_key}",
                     "Content-Type": "application/json"}).json()
        message = data["choices"][0]["message"]
        calls = [ToolCall(name=c["function"]["name"], id=c.get("id"),
                          arguments=json.loads(c["function"].get("arguments") or "{}"))
                 for c in message.get("tool_calls", [])]
        return ModelResponse(text=message.get("content") or "", tool_calls=calls, raw=data)

    def _gemini(self, messages: Sequence[dict[str, object]], model: str,
                tools: list[dict[str, object]] | None) -> ModelResponse:
        if not self.settings.gemini_api_key:
            raise ModelError("GEMINI_API_KEY is not configured")
        # Gemini's REST schema separates the system instruction and uses functionDeclarations.
        system = "\n".join(str(m["content"]) for m in messages if m.get("role") == "system")
        contents = [{"role": "model" if m.get("role") == "assistant" else "user",
                     "parts": [{"text": str(m.get("content", ""))}]}
                    for m in messages if m.get("role") != "system"]
        payload: dict[str, object] = {"contents": contents}
        if system:
            payload["system_instruction"] = {"parts": [{"text": system}]}
        if tools:
            declarations = [{"name": t["function"]["name"], "description": t["function"].get("description", ""),
                             "parameters": t["function"].get("parameters", {})} for t in tools]
            payload["tools"] = [{"functionDeclarations": declarations}]
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={self.settings.gemini_api_key}"
        data = self._request("POST", url, json=payload).json()
        parts = data["candidates"][0]["content"].get("parts", [])
        calls = [ToolCall(name=p["functionCall"]["name"], arguments=p["functionCall"].get("args", {}))
                 for p in parts if "functionCall" in p]
        text = "\n".join(p.get("text", "") for p in parts if "text" in p)
        return ModelResponse(text=text, tool_calls=calls, raw=data)

