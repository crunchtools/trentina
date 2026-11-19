"""Gemini provider — extracted from agent.py's _call_gemini."""

from __future__ import annotations

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

GEMINI_API_BASE = "https://generativelanguage.googleapis.com/v1beta/models"
GEMINI_TIMEOUT = 60.0

#: Google accepts the API key either as a `?key=` query parameter or in this
#: header. It goes in the header, always. httpx logs the full request URL at
#: INFO, so a key in the query string lands in `podman logs` and journald the
#: moment anyone raises TRENTINA_LOG_LEVEL to debug something unrelated — a
#: credential leak armed by a routine troubleshooting step and warned about by
#: nothing. The logger is also clamped (see `_configure_logging`); this is the
#: half that removes the secret rather than hiding it.
GEMINI_API_KEY_HEADER = "x-goog-api-key"


def generate_content_body(
    system_prompt: str,
    user_content: str,
    response_schema: dict[str, Any] | None,
    temperature: float,
    max_output_tokens: int,
) -> dict[str, Any]:
    """A generateContent request body. Vertex AI takes the same shape."""
    gen_config: dict[str, Any] = {
        "temperature": temperature,
        "maxOutputTokens": max_output_tokens,
    }
    if response_schema is not None:
        gen_config["responseMimeType"] = "application/json"
        gen_config["responseSchema"] = response_schema
    return {
        "system_instruction": {"parts": [{"text": system_prompt}]},
        "contents": [{"role": "user", "parts": [{"text": user_content}]}],
        "generationConfig": gen_config,
    }


def generate_content_result(resp_json: dict[str, Any]) -> ProviderResult:
    """The ProviderResult in a generateContent response, Gemini API or Vertex AI."""
    if not dig(resp_json, "candidates", 0):
        raise QuarantineAgentError("No candidates in Gemini response")

    if not dig(resp_json, "candidates", 0, "content", "parts", 0):
        raise QuarantineAgentError("No parts in Gemini response")

    text = dig(resp_json, "candidates", 0, "content", "parts", 0, "text")
    if not isinstance(text, str):
        raise MalformedResponseError("no text")

    return ProviderResult(
        text=text,
        input_tokens=count(dig(resp_json, "usageMetadata", "promptTokenCount")),
        output_tokens=count(dig(resp_json, "usageMetadata", "candidatesTokenCount")),
        truncated=dig(resp_json, "candidates", 0, "finishReason") == "MAX_TOKENS",
    )


class GeminiProvider(Provider):
    """Gemini REST API provider using raw httpx."""

    def __init__(self, api_key: str, model: str) -> None:
        self._api_key = api_key
        self._model = model

    async def generate(
        self,
        system_prompt: str,
        user_content: str,
        response_schema: dict[str, Any] | None = None,
        temperature: float = 0.1,
        max_output_tokens: int = 4096,
    ) -> ProviderResult:
        url = f"{GEMINI_API_BASE}/{self._model}:generateContent"
        request_body = generate_content_body(
            system_prompt, user_content, response_schema, temperature, max_output_tokens
        )

        enforce_no_tools(request_body)

        try:
            # nosemgrep: trentina-httpx-client-outside-egress -- fixed or operator URL
            async with httpx.AsyncClient(
                timeout=httpx.Timeout(GEMINI_TIMEOUT),
            ) as client:
                resp = await client.post(
                    url,
                    json=request_body,
                    headers={
                        "Content-Type": "application/json",
                        GEMINI_API_KEY_HEADER: self._api_key,
                    },
                )
                resp.raise_for_status()
                resp_json = envelope(resp)

            return generate_content_result(resp_json)

        except httpx.HTTPStatusError as exc:
            raise status_error(exc) from exc
        except httpx.TimeoutException as exc:
            raise QuarantineAgentError("Request timed out") from exc
        except httpx.RequestError as exc:
            raise QuarantineAgentError(str(exc)) from exc
