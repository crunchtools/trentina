"""The bridge's HTTP surface: the gateway, and only the gateway, asks it to send.

Bearer ``BRIDGE_TOKEN`` on every call. Whatever arrives here has already been
judged by the gateway; the bridge's job is to encrypt it and nothing else.
"""

from __future__ import annotations

import hmac
import logging
from http import HTTPStatus
from typing import TYPE_CHECKING, Any, TypeVar

from pydantic import BaseModel, ConfigDict, Field, ValidationError
from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Route

from ..httpbody import TooLargeError, read_capped, where_invalid
from ..logsafe import exc_kind
from .client import SendError

if TYPE_CHECKING:
    from starlette.requests import Request

    from .client import Bridge

logger = logging.getLogger(__name__)

_Body = TypeVar("_Body", bound=BaseModel)


class SendRequest(BaseModel):
    """One event for the bridge to encrypt and send, as the gateway asks."""

    model_config = ConfigDict(extra="forbid", strict=True)

    room_id: str = Field(min_length=1)
    type: str = Field(min_length=1)
    content: dict[str, Any]
    txn_id: str = Field(min_length=1)


class RedactRequest(BaseModel):
    """One upstream event to redact, idempotent on ``txn_id``."""

    model_config = ConfigDict(extra="forbid", strict=True)

    room_id: str = Field(min_length=1)
    event_id: str = Field(min_length=1)
    txn_id: str = Field(min_length=1)


class TypingRequest(BaseModel):
    """Whether the agent is typing in one upstream room (#1533)."""

    model_config = ConfigDict(extra="forbid", strict=True)

    room_id: str = Field(min_length=1)
    typing: bool


class _Handlers:
    """The endpoints, sharing one bridge and one token check."""

    def __init__(self, bridge: Bridge) -> None:
        self._bridge = bridge
        self._expected = bridge.settings.bridge_token.encode("utf-8")

    async def _parse(self, request: Request, model: type[_Body]) -> _Body | JSONResponse:
        """The validated body of an authorized request, or the response refusing it."""
        header = request.headers.get("authorization", "")
        presented = header[7:].strip() if header.lower().startswith("bearer ") else ""
        if not presented or not hmac.compare_digest(presented.encode("utf-8"), self._expected):
            return JSONResponse({"error": "unauthorized"}, status_code=401)
        try:
            return model.model_validate_json(await read_capped(request))
        except TooLargeError:
            return JSONResponse(
                {"error": "too large"}, status_code=HTTPStatus.REQUEST_ENTITY_TOO_LARGE
            )
        except ValidationError as exc:
            logger.warning(
                "bridge[%s]: malformed request at %s",
                self._bridge.settings.profile,
                where_invalid(exc),
            )
            return JSONResponse({"error": "malformed"}, status_code=400)

    async def send(self, request: Request) -> JSONResponse:
        body = await self._parse(request, SendRequest)
        if isinstance(body, JSONResponse):
            return body
        try:
            event_id = await self._bridge.send(body.room_id, body.type, body.content, body.txn_id)
        except SendError as exc:
            logger.warning(
                "bridge[%s]: send failed: %s", self._bridge.settings.profile, exc_kind(exc)
            )
            return JSONResponse({"error": "send failed"}, status_code=502)
        return JSONResponse({"event_id": event_id})

    async def redact(self, request: Request) -> JSONResponse:
        body = await self._parse(request, RedactRequest)
        if isinstance(body, JSONResponse):
            return body
        try:
            await self._bridge.redact(body.room_id, body.event_id, body.txn_id)
        except SendError as exc:
            logger.warning(
                "bridge[%s]: redact failed: %s", self._bridge.settings.profile, exc_kind(exc)
            )
            return JSONResponse({"error": "redact failed"}, status_code=502)
        return JSONResponse({"event_id": body.event_id})

    async def typing(self, request: Request) -> JSONResponse:
        body = await self._parse(request, TypingRequest)
        if isinstance(body, JSONResponse):
            return body
        try:
            await self._bridge.typing(body.room_id, body.typing)
        except SendError as exc:
            # Best effort: 200 either way, and the gateway tries again on the
            # agent's next push rather than retrying this one.
            logger.info(
                "bridge[%s]: typing not shown: %s", self._bridge.settings.profile, exc_kind(exc)
            )
            return JSONResponse({"shown": False})
        return JSONResponse({"shown": True})

    async def health(self, _request: Request) -> JSONResponse:
        ready = self._bridge.ready.is_set()
        return JSONResponse(
            {"status": "ok" if ready else "starting", "device_id": self._bridge.client.device_id},
            status_code=200 if ready else 503,
        )


def build_app(bridge: Bridge) -> Starlette:
    """The Starlette app serving ``/send``, ``/redact``, ``/typing`` and ``/health``."""
    handlers = _Handlers(bridge)
    return Starlette(
        routes=[
            Route("/send", handlers.send, methods=["POST"]),
            Route("/redact", handlers.redact, methods=["POST"]),
            Route("/typing", handlers.typing, methods=["POST"]),
            Route("/health", handlers.health, methods=["GET"]),
        ]
    )
