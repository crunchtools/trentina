"""Vertex AI provider: Gemini on Vertex, authenticated with a Google ADC file."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any

import httpx

from ...errors import QuarantineAgentError
from ...gateway.profile import VERTEX_PROJECT_RE, VERTEX_REGION_RE
from .base import Provider, ProviderResult, enforce_no_tools, envelope, status_error
from .gemini import generate_content_body, generate_content_result
from .vertex_auth import TokenSource, parse_credentials

if TYPE_CHECKING:
    from collections.abc import Callable

VERTEX_TIMEOUT = 60.0

# These land in a URL path, so each is an allowlist, not a blocklist. Project
# and region are the profile's own validators, so config and driver agree.
PROJECT_RE = VERTEX_PROJECT_RE
REGION_RE = VERTEX_REGION_RE
MODEL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")


def validate_vertex_target(project: str, region: str) -> None:
    """Raise QuarantineAgentError unless *project* and *region* are safe URL parts."""
    if not PROJECT_RE.fullmatch(project):
        raise QuarantineAgentError("Invalid Vertex project id")
    if not REGION_RE.fullmatch(region):
        raise QuarantineAgentError("Invalid Vertex region")


def vertex_url(project: str, region: str, model: str) -> str:
    """The generateContent URL; the ``global`` location has no host prefix."""
    host = (
        "aiplatform.googleapis.com" if region == "global" else f"{region}-aiplatform.googleapis.com"
    )
    return (
        f"https://{host}/v1/projects/{project}/locations/{region}"
        f"/publishers/google/models/{model}:generateContent"
    )


class VertexProvider(Provider):
    """Gemini on Vertex AI over raw httpx, with OAuth from an ADC file."""

    def __init__(
        self,
        credentials: str,
        model: str,
        project: str,
        region: str,
        clock: Callable[[], float] | None = None,
    ) -> None:
        validate_vertex_target(project, region)
        if not MODEL_RE.fullmatch(model):
            raise QuarantineAgentError("Invalid Vertex model name")
        creds = parse_credentials(credentials)
        self._tokens = TokenSource(creds, clock) if clock else TokenSource(creds)
        self._model = model
        self._url = vertex_url(project, region, model)

    async def _post(
        self, client: httpx.AsyncClient, body: dict[str, Any], token: str
    ) -> httpx.Response:
        return await client.post(
            self._url,
            json=body,
            headers={"Content-Type": "application/json", "Authorization": f"Bearer {token}"},
        )

    async def generate(
        self,
        system_prompt: str,
        user_content: str,
        response_schema: dict[str, Any] | None = None,
        temperature: float = 0.1,
        max_output_tokens: int = 4096,
    ) -> ProviderResult:
        request_body = generate_content_body(
            system_prompt, user_content, response_schema, temperature, max_output_tokens
        )

        enforce_no_tools(request_body)

        try:
            token = await self._tokens.token()
            # nosemgrep: trentina-httpx-client-outside-egress -- fixed or operator URL
            async with httpx.AsyncClient(timeout=httpx.Timeout(VERTEX_TIMEOUT)) as client:
                resp = await self._post(client, request_body, token)
                if resp.status_code == 401:
                    # Revoked or expired early: one fresh token, one retry. A second
                    # 401 falls through to status_error, and 401 is not retryable.
                    token = await self._tokens.refresh_after_401(token)
                    resp = await self._post(client, request_body, token)
                resp.raise_for_status()
                resp_json = envelope(resp)

            return generate_content_result(resp_json)

        except httpx.HTTPStatusError as exc:
            raise status_error(exc) from exc
        except httpx.TimeoutException as exc:
            raise QuarantineAgentError("Request timed out") from exc
        except httpx.RequestError as exc:
            raise QuarantineAgentError(str(exc)) from exc
