"""Provider clients normalized to a compact response used by the solver."""
from __future__ import annotations

import json
from collections.abc import Sequence

import httpx

from ctf_agent.config import ModelRoute, Settings
from ctf_agent.types import ModelResponse, ToolCall


class ModelError(RuntimeError):
    """An unrecoverable provider response."""


class RateLimitError(ModelError):
    """A retryable quota/rate-limit response."""


class ModelUnavailableError(ModelError):
    """A configured model is not available from its provider."""


class ChatClient:
    def __init__(self, settings: Settings, http_client: httpx.Client | None = None) -> None:
        self.settings = settings
        self.http = http_client or httpx.Client(timeout=90)

    def chat(self, messages: Sequence[dict[str, object]], *, provider: str, model: str,
             tools: list[dict[str, object]] | None = None,
             timeout_seconds: float | None = None) -> ModelResponse:
        rate_limited: list[str] = []
        unavailable: list[str] = []
        configured_routes = self.settings.model_routes(provider, model)
        for route in configured_routes:
            if not self._has_credentials(route.provider):
                continue
            try:
                response = self._chat_route(route, messages, tools, timeout_seconds)
            except RateLimitError:
                rate_limited.append(f"{route.provider}:{route.model}")
                continue
            except ModelUnavailableError:
                unavailable.append(f"{route.provider}:{route.model}")
                continue
            response.provider, response.model = route.provider, route.model
            response.rate_limited_routes = tuple(rate_limited)
            response.unavailable_routes = tuple(unavailable)
            return response
        if rate_limited and not unavailable:
            raise RateLimitError(f"rate limited by all configured model routes: {', '.join(rate_limited)}")
        if unavailable:
            failed = ", ".join((*unavailable, *rate_limited))
            raise ModelUnavailableError(f"all usable model routes failed or were unavailable: {failed}")
        configured = ", ".join(f"{route.provider}:{route.model}" for route in configured_routes)
        raise ModelError(f"no API key is configured for model routes: {configured}")

    def _has_credentials(self, provider: str) -> bool:
        return {
            "gemini": bool(self.settings.gemini_api_key),
            "groq": bool(self.settings.groq_api_key),
            "openrouter": bool(self.settings.openrouter_api_key),
        }.get(provider, False)

    def _chat_route(self, route: ModelRoute, messages: Sequence[dict[str, object]],
                    tools: list[dict[str, object]] | None,
                    timeout_seconds: float | None) -> ModelResponse:
        if route.provider == "openrouter":
            return self._openrouter(messages, route.model, tools, timeout_seconds)
        if route.provider == "groq":
            return self._groq(messages, route.model, tools, timeout_seconds)
        if route.provider == "gemini":
            return self._gemini(messages, route.model, tools, timeout_seconds)
        raise ModelError(f"unsupported provider in MODEL_ROTATION: {route.provider}")

    def _request(self, method: str, url: str, **kwargs: object) -> httpx.Response:
        try:
            response = self.http.request(method, url, **kwargs)
        except httpx.HTTPError as exc:
            raise ModelError(f"provider request failed: {exc}") from exc
        if response.status_code == 429:
            raise RateLimitError(response.text)
        if response.status_code == 404:
            raise ModelUnavailableError(response.text)
        if response.is_error:
            raise ModelError(f"provider returned {response.status_code}: {response.text[:500]}")
        return response

    def _openrouter(self, messages: Sequence[dict[str, object]], model: str,
                    tools: list[dict[str, object]] | None,
                    timeout_seconds: float | None = None) -> ModelResponse:
        if not self.settings.openrouter_api_key:
            raise ModelError("OPENROUTER_API_KEY is not configured")
        data = self._openai_compatible(
            "https://openrouter.ai/api/v1/chat/completions", self.settings.openrouter_api_key,
            messages, model, tools, timeout_seconds)
        return self._openai_response(data)

    def _groq(self, messages: Sequence[dict[str, object]], model: str,
              tools: list[dict[str, object]] | None,
              timeout_seconds: float | None = None) -> ModelResponse:
        if not self.settings.groq_api_key:
            raise ModelError("GROQ_API_KEY is not configured")
        data = self._openai_compatible(
            "https://api.groq.com/openai/v1/chat/completions", self.settings.groq_api_key,
            messages, model, tools, timeout_seconds)
        return self._openai_response(data)

    def _openai_compatible(self, url: str, api_key: str, messages: Sequence[dict[str, object]],
                           model: str, tools: list[dict[str, object]] | None,
                           timeout_seconds: float | None) -> dict[str, object]:
        payload: dict[str, object] = {"model": model, "messages": self._openrouter_messages(messages)}
        if tools:
            payload["tools"] = tools
        request_options: dict[str, object] = {"json": payload,
            "headers": {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}}
        if timeout_seconds is not None:
            request_options["timeout"] = timeout_seconds
        return self._request("POST", url, **request_options).json()

    @staticmethod
    def _openai_response(data: dict[str, object]) -> ModelResponse:
        message = data["choices"][0]["message"]
        calls = [ToolCall(name=c["function"]["name"], id=c.get("id") or f"call_{index}",
                          arguments=json.loads(c["function"].get("arguments") or "{}"))
                 for index, c in enumerate(message.get("tool_calls", []), start=1)]
        return ModelResponse(text=message.get("content") or "", tool_calls=calls, raw=data)

    @staticmethod
    def _openrouter_messages(messages: Sequence[dict[str, object]]) -> list[dict[str, object]]:
        """Serialize the internal history to OpenAI-compatible tool messages."""
        serialized: list[dict[str, object]] = []
        for message in messages:
            role = str(message.get("role", "user"))
            value: dict[str, object] = {"role": role, "content": str(message.get("content", ""))}
            if role == "assistant" and message.get("tool_calls"):
                calls = message["tool_calls"]
                assert isinstance(calls, list)
                value["tool_calls"] = [{
                    "id": call.id or f"call_{index}", "type": "function",
                    "function": {"name": call.name, "arguments": json.dumps(call.arguments)},
                } for index, call in enumerate(calls, start=1) if isinstance(call, ToolCall)]
            elif role == "tool":
                value["tool_call_id"] = str(message["tool_call_id"])
                value["name"] = str(message["name"])
            serialized.append(value)
        return serialized

    def _gemini(self, messages: Sequence[dict[str, object]], model: str,
                tools: list[dict[str, object]] | None,
                timeout_seconds: float | None = None) -> ModelResponse:
        if not self.settings.gemini_api_key:
            raise ModelError("GEMINI_API_KEY is not configured")
        # Gemini's REST schema separates the system instruction and uses functionDeclarations.
        system = "\n".join(str(m["content"]) for m in messages if m.get("role") == "system")
        contents = self._gemini_contents(messages)
        payload: dict[str, object] = {"contents": contents}
        if system:
            payload["system_instruction"] = {"parts": [{"text": system}]}
        if tools:
            declarations = [{"name": t["function"]["name"], "description": t["function"].get("description", ""),
                             "parameters": t["function"].get("parameters", {})} for t in tools]
            payload["tools"] = [{"functionDeclarations": declarations}]
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={self.settings.gemini_api_key}"
        request_options: dict[str, object] = {"json": payload}
        if timeout_seconds is not None:
            request_options["timeout"] = timeout_seconds
        data = self._request("POST", url, **request_options).json()
        parts = data["candidates"][0]["content"].get("parts", [])
        calls = [ToolCall(name=p["functionCall"]["name"], arguments=p["functionCall"].get("args", {}),
                          id=p["functionCall"].get("id") or f"call_{index}",
                          # This is a Part field, alongside functionCall—not
                          # a member of the functionCall object itself.
                          thought_signature=p.get("thoughtSignature") or p.get("thought_signature"))
                 for index, p in enumerate((part for part in parts if "functionCall" in part), start=1)]
        text = "\n".join(p.get("text", "") for p in parts if "text" in p)
        return ModelResponse(text=text, tool_calls=calls, raw=data)

    @staticmethod
    def _gemini_contents(messages: Sequence[dict[str, object]]) -> list[dict[str, object]]:
        """Serialize the internal history to Gemini function-call/function-response parts."""
        contents: list[dict[str, object]] = []
        index = 0
        while index < len(messages):
            message = messages[index]
            role = str(message.get("role", "user"))
            if role == "system":
                index += 1
                continue
            if role == "tool":
                # Gemini expects all responses to parallel calls in one user
                # turn, after the model's complete functionCall turn.
                parts: list[dict[str, object]] = []
                while index < len(messages) and messages[index].get("role") == "tool":
                    tool = messages[index]
                    function_response: dict[str, object] = {
                        "name": str(tool["name"]),
                        "response": {"result": str(tool.get("content", ""))},
                    }
                    parts.append({"functionResponse": function_response})
                    index += 1
                contents.append({"role": "user", "parts": parts})
                continue
            parts: list[dict[str, object]] = []
            text = str(message.get("content", ""))
            if text:
                parts.append({"text": text})
            if role == "assistant":
                calls = message.get("tool_calls", [])
                if isinstance(calls, list):
                    for call in calls:
                        if not isinstance(call, ToolCall):
                            continue
                        function_call: dict[str, object] = {"name": call.name, "args": call.arguments}
                        if call.thought_signature:
                            # Preserve this opaque provider value byte-for-byte.
                            # Gemini rejects a follow-up function response without it.
                            parts.append({"functionCall": function_call,
                                          "thoughtSignature": call.thought_signature})
                        else:
                            # A function-call turn created by Groq/OpenRouter
                            # has no Gemini signature. This documented marker
                            # permits Gemini to continue after rate-limit
                            # rotation without fabricating model reasoning.
                            parts.append({"functionCall": function_call,
                                          "thoughtSignature": "skip_thought_signature_validator"})
            if not parts:
                parts.append({"text": ""})
            contents.append({"role": "model" if role == "assistant" else "user", "parts": parts})
            index += 1
        return contents
