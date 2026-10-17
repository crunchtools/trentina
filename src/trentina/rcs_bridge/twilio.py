"""Twilio as the RCS provider.

Sending is the Messages API through the agent's Messaging Service, with the
recipient as ``rcs:+1...`` so a phone that cannot take RCS gets an error
rather than a silent SMS from a number nobody configured for it.

Webhooks are signed: HMAC-SHA1, keyed by the account's auth token, over the
exact URL Twilio called followed by every POST parameter's name and value in
name order, base64. The URL is the configured one, never one rebuilt from
the request, which behind a proxy would differ by scheme, host or port.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
from http import HTTPStatus
from typing import Any

import httpx

from ..httpbody import request_capped
from ..logsafe import exc_kind
from .backend import BackendError, Inbound

logger = logging.getLogger(__name__)

_TIMEOUT = httpx.Timeout(connect=5.0, read=20.0, write=10.0, pool=5.0)
_DEADLINE = 30.0
# Twilio's own cap on a message body.
MAX_BODY = 1600
_ATTACHMENTS_MAX = 10
# Twilio error codes that mean this message will never go, whatever we retry
# (https://www.twilio.com/docs/api/errors): a body or number it refuses.
_PERMANENT_CODES = frozenset({21211, 21610, 21614, 21617, 21658, 63001, 63003})


def signature(auth_token: str, url: str, form: list[tuple[str, str]]) -> str:
    """Twilio's ``X-Twilio-Signature`` for a POST to ``url`` with ``form``."""
    payload = url + "".join(f"{k}{v}" for k, v in sorted(form, key=lambda kv: kv[0]))
    digest = hmac.new(auth_token.encode("utf-8"), payload.encode("utf-8"), hashlib.sha1)
    return base64.b64encode(digest.digest()).decode("ascii")


def _number(address: str) -> str:
    """``rcs:+15551234567`` or ``+15551234567`` as the bare E.164 number."""
    return address.removeprefix("rcs:").strip()


class TwilioBackend:
    """One Twilio account and the Messaging Service holding one agent's sender."""

    def __init__(
        self,
        *,
        account_sid: str,
        auth_token: str,
        messaging_service_sid: str,
        api: str = "https://api.twilio.com",
        client: httpx.AsyncClient | None = None,
    ) -> None:
        self._account_sid = account_sid
        self._auth_token = auth_token
        self._service = messaging_service_sid
        self._url = f"{api}/2010-04-01/Accounts/{account_sid}/Messages.json"
        # nosemgrep: trentina-httpx-client-outside-egress -- operator URL
        self._client = client or httpx.AsyncClient(timeout=_TIMEOUT)

    async def aclose(self) -> None:
        await self._client.aclose()

    def verify(self, url: str, form: list[tuple[str, str]], signature_header: str) -> bool:
        if not signature_header:
            return False
        expected = signature(self._auth_token, url, form)
        return hmac.compare_digest(expected.encode("ascii"), signature_header.encode("ascii"))

    def parse(self, form: list[tuple[str, str]]) -> Inbound | None:
        fields = dict(form)
        # A request for another account, or a status callback (no Body), is
        # not a message for this bridge.
        if not hmac.compare_digest(
            fields.get("AccountSid", "").encode(), self._account_sid.encode()
        ):
            return None
        message_id = fields.get("MessageSid") or fields.get("SmsSid") or ""
        if not message_id or "Body" not in fields:
            return None
        try:
            attachments = min(int(fields.get("NumMedia", "0") or 0), _ATTACHMENTS_MAX)
        except ValueError:
            attachments = 0
        return Inbound(
            message_id=message_id,
            sender=_number(fields.get("From", "")),
            body=fields["Body"],
            attachments=max(attachments, 0),
        )

    async def send_text(self, to: str, body: str) -> str:
        form = {"MessagingServiceSid": self._service, "To": f"rcs:{to}", "Body": body}
        try:
            resp, raw = await request_capped(
                self._client,
                "POST",
                self._url,
                deadline=_DEADLINE,
                data=form,
                auth=(self._account_sid, self._auth_token),
            )
        except (httpx.HTTPError, TimeoutError, ValueError) as exc:
            raise BackendError(f"twilio: {exc_kind(exc)}") from exc
        reply = _json(raw)
        if resp.status_code in (HTTPStatus.OK, HTTPStatus.CREATED):
            sid = reply.get("sid")
            if isinstance(sid, str) and sid:
                return sid
            raise BackendError("twilio: no message sid in the reply")
        code = reply.get("code")
        permanent = code in _PERMANENT_CODES or resp.status_code == HTTPStatus.BAD_REQUEST
        # The code is Twilio's error number, not its text: the text can echo
        # the body or the number.
        raise BackendError(f"twilio: {resp.status_code} code={code}", permanent=permanent)


def _json(raw: bytes) -> dict[str, Any]:
    try:
        value = json.loads(raw)
    except ValueError:
        return {}
    return value if isinstance(value, dict) else {}
