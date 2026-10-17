"""The RCS bridge's two HTTP surfaces, on two listeners.

* Private (``BRIDGE_LISTEN_*``, the gateway's network only): ``/send``,
  ``/redact`` and ``/health``, Bearer ``BRIDGE_TOKEN``, the same contract as
  the Matrix bridge's (``bridge/api.py``).
* Public (``RCS_WEBHOOK_*``, reached only through the proxy):
  ``POST /twilio/inbound``. Nothing on it is trusted until the provider's
  signature checks out over the configured URL, and then only a message from
  the owner's number is taken. Everything else is refused without reading
  further, and without logging what it said.
"""

from __future__ import annotations

import hmac
import logging
from http import HTTPStatus
from typing import TYPE_CHECKING, Any, TypeVar
from urllib.parse import parse_qsl

from pydantic import BaseModel, ConfigDict, Field, ValidationError
from starlette.applications import Starlette
from starlette.responses import JSONResponse, Response
from starlette.routing import Route

from ..httpbody import TooLargeError, read_capped, where_invalid
from ..logsafe import redact_source
from .bridge import RefusedError, UnavailableError
from .store import InboxFullError

if TYPE_CHECKING:
    from starlette.requests import Request

    from .bridge import RcsBridge

logger = logging.getLogger(__name__)

_Body = TypeVar("_Body", bound=BaseModel)
# A Twilio inbound form is a few kilobytes; a 1,600-character body at most
# quadruples in form encoding.
WEBHOOK_MAX_BYTES = 32_768
_EMPTY_TWIML = '<?xml version="1.0" encoding="UTF-8"?><Response></Response>'
_FORM = "application/x-www-form-urlencoded"


class SendRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    room_id: str = Field(min_length=1)
    type: str = Field(min_length=1)
    content: dict[str, Any]
    txn_id: str = Field(min_length=1)


class RedactRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    room_id: str = Field(min_length=1)
    event_id: str = Field(min_length=1)
    txn_id: str = Field(min_length=1)


def _twiml(status: int = 200) -> Response:
    """An empty TwiML reply: taken, and nothing to answer with."""
    return Response(_EMPTY_TWIML, status_code=status, media_type="text/xml")


class _Private:
    def __init__(self, bridge: RcsBridge) -> None:
        self._bridge = bridge
        self._label = f"{bridge.settings.profile}/{bridge.settings.channel}"
        self._expected = bridge.settings.bridge_token.encode("utf-8")

    async def _parse(self, request: Request, model: type[_Body]) -> _Body | JSONResponse:
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
            logger.warning("bridge[%s]: malformed request at %s", self._label, where_invalid(exc))
            return JSONResponse({"error": "malformed"}, status_code=400)

    async def send(self, request: Request) -> JSONResponse:
        body = await self._parse(request, SendRequest)
        if isinstance(body, JSONResponse):
            return body
        try:
            event_id = await self._bridge.send(body.room_id, body.type, body.content, body.txn_id)
        except RefusedError as exc:
            # The reason is ours (a type name, a Twilio error number), never
            # the message's text.
            logger.warning("bridge[%s]: refused outbound: %s", self._label, exc.reason)
            return JSONResponse({"error": "not carried"}, status_code=422)
        except UnavailableError as exc:
            logger.warning("bridge[%s]: send failed: %s", self._label, exc.reason)
            return JSONResponse({"error": "send failed"}, status_code=502)
        return JSONResponse({"event_id": event_id})

    async def redact(self, request: Request) -> JSONResponse:
        body = await self._parse(request, RedactRequest)
        if isinstance(body, JSONResponse):
            return body
        # RCS has no unsend. "Never", so the gateway tells the agent.
        return JSONResponse({"error": "rcs cannot unsend"}, status_code=422)

    async def health(self, _request: Request) -> JSONResponse:
        ready = self._bridge.ready.is_set()
        return JSONResponse(
            {"status": "ok" if ready else "starting"}, status_code=200 if ready else 503
        )


class _Public:
    def __init__(self, bridge: RcsBridge) -> None:
        self._bridge = bridge
        self._label = f"{bridge.settings.profile}/{bridge.settings.channel}"

    async def inbound(self, request: Request) -> Response:
        # TRUST: a webhook from the public internet becomes a message for the agent
        #   untrusted: everything in the request until the signature verifies,
        #     and the message text after it (the owner's phone, or whoever holds it)
        #   judged-by: the gateway's L1/L2/L3, once forwarded; nothing here
        #   on-failure: fail-closed; unsigned, foreign or non-owner requests are
        #     refused and nothing is stored
        #   owner: rcs_bridge.api._Public.inbound
        #   evidence: T2 twilio.signature over the configured URL; T3 settings
        #     pin the account SID and the owner's E.164 number
        form = await self._signed_form(request)
        if isinstance(form, Response):
            return form
        message = self._bridge.backend.parse(form)
        if message is None:
            # Signed, but not a message for us (a status callback): fine.
            return _twiml()
        if not hmac.compare_digest(
            message.sender.encode(), self._bridge.settings.owner_number.encode()
        ):
            logger.warning(
                "bridge[%s]: message from a number that is not the owner's refused",
                self._label,
            )
            return Response(status_code=403)
        try:
            taken = await self._bridge.accept(message)
        except InboxFullError:
            logger.error("bridge[%s]: inbox full; the gateway is not taking messages", self._label)
            return _twiml(503)
        if not taken:
            logger.info(
                "bridge[%s]: duplicate webhook %s", self._label, redact_source(message.message_id)
            )
        return _twiml()

    async def _signed_form(self, request: Request) -> list[tuple[str, str]] | Response:
        """The form of a request the provider signed, or the response refusing it."""
        if request.headers.get("content-type", "").split(";")[0].strip() != _FORM:
            return Response(status_code=415)
        try:
            raw = await read_capped(request, WEBHOOK_MAX_BYTES)
            form = parse_qsl(raw.decode("utf-8"), keep_blank_values=True)
        except TooLargeError:
            return Response(status_code=HTTPStatus.REQUEST_ENTITY_TOO_LARGE)
        except UnicodeDecodeError:
            return Response(status_code=400)
        signature = request.headers.get("x-twilio-signature", "")
        if not self._bridge.backend.verify(self._bridge.settings.webhook_url, form, signature):
            logger.warning("bridge[%s]: webhook with a bad signature refused", self._label)
            return Response(status_code=403)
        return form


def build_private_app(bridge: RcsBridge) -> Starlette:
    handlers = _Private(bridge)
    return Starlette(
        routes=[
            Route("/send", handlers.send, methods=["POST"]),
            Route("/redact", handlers.redact, methods=["POST"]),
            Route("/health", handlers.health, methods=["GET"]),
        ]
    )


def build_public_app(bridge: RcsBridge) -> Starlette:
    handlers = _Public(bridge)
    return Starlette(routes=[Route("/twilio/inbound", handlers.inbound, methods=["POST"])])
