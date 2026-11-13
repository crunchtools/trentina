"""Anthropic provider — Messages API with raw httpx."""

from __future__ import annotations

import json
from typing import Any

import httpx

from ...errors import MalformedResponseError, QuarantineAgentError
from .base import (
    Provider,
    ProviderResult,
    count,
    dig,
    enforce_no_tools,
    envelope,
    status_error,
)

ANTHROPIC_API_BASE = "https://api.anthropic.com/v1"
ANTHROPIC_TIMEOUT = 60.0
ANTHROPIC_VERSION = "2023-06-01"
DEFAULT_MODEL = "claude-haiku-4-5-20251001"


class AnthropicProvider(Provider):
    """Anthropic Messages API provider using raw httpx."""

    def __init__(
        self,
        api_key: str,
        model: str = DEFAULT_MODEL,
        base_url: str = ANTHROPIC_API_BASE,
    ) -> None:
        self._api_key = api_key
        self._model = model
        self._base_url = base_url.rstrip("/")

    async def generate(
        self,
        system_prompt: str,
        user_content: str,
        response_schema: dict[str, Any] | None = None,
        temperature: float = 0.1,
        max_output_tokens: int = 4096,
    ) -> ProviderResult:
        url = f"{self._base_url}/messages"

        user_msg = user_content
        if response_schema is not None:
            schema_hint = json.dumps(response_schema, indent=2)
            user_msg = (
                f"{user_content}\n\n"
                f"Respond with ONLY valid JSON matching this schema:\n{schema_hint}"
            )

        request_body: dict[str, Any] = {
            "model": self._model,
            "max_tokens": max_output_tokens,
            "system": system_prompt,
            "messages": [
                {"role": "user", "content": user_msg},
            ],
            "temperature": temperature,
        }

        enforce_no_tools(request_body)

        try:
            # nosemgrep: trentina-httpx-client-outside-egress -- fixed or operator URL
            async with httpx.AsyncClient(
                timeout=httpx.Timeout(ANTHROPIC_TIMEOUT),
            ) as client:
                resp = await client.post(
                    url,
                    json=request_body,
                    headers={
                        "x-api-key": self._api_key,
                        "anthropic-version": ANTHROPIC_VERSION,
                        "Content-Type": "application/json",
                    },
                )
                resp.raise_for_status()
                resp_json = envelope(resp)

            if not dig(resp_json, "content", 0):
                raise QuarantineAgentError("No content in Anthropic response")

            text = dig(resp_json, "content", 0, "text")
            if not isinstance(text, str):
                raise MalformedResponseError("no text")
            text = text.strip()
            if text.startswith("```"):
                lines = text.split("\n")
                text = "\n".join(lines[1:-1]).strip()
            return ProviderResult(
                text=text,
                input_tokens=count(dig(resp_json, "usage", "input_tokens")),
                output_tokens=count(dig(resp_json, "usage", "output_tokens")),
                truncated=dig(resp_json, "stop_reason") == "max_tokens",
            )

        except httpx.HTTPStatusError as exc:
            raise status_error(exc) from exc
        except httpx.TimeoutException as exc:
            raise QuarantineAgentError("Request timed out") from exc
        except httpx.RequestError as exc:
            raise QuarantineAgentError(str(exc)) from exc
