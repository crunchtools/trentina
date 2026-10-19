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

import asyncio
import base64
import hashlib
import hmac
import json
import logging
import re
from http import HTTPStatus
from typing import TYPE_CHECKING, Any

import httpx

from .. import egress
from ..bridge.media import MAX_MEDIA_BYTES, MAX_NAME_CHARS, MEDIA_DEADLINE
from ..errors import EgressRefusedError
from ..httpbody import EncodedBodyError, TooLargeError, request_capped
from ..logsafe import exc_kind
from .backend import BackendError, Inbound

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable

    # GET one URL with no credentials, every hop checked; the final status,
    # content type and body, read under ``MAX_MEDIA_BYTES``.
    CdnFetch = Callable[[str], Awaitable[tuple[int, str, bytes]]]

logger = logging.getLogger(__name__)

_TIMEOUT = httpx.Timeout(connect=5.0, read=20.0, write=10.0, pool=5.0)
_DEADLINE = 30.0
_TYPING_DEADLINE = 5.0
_CDN_TIMEOUT = 20.0
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


async def guarded_get(url: str) -> tuple[int, str, bytes]:
    """The CDN hop of an inbound attachment (#493), through the egress guard.

    Twilio's media URL redirects to a CDN, and wherever that points is
    checked on its resolved address, as is every hop after it, so a redirect
    to an internal address is refused. No credentials go: they are Twilio's,
    and the CDN URL is signed on its own.

    Raises:
        TooLargeError: the body passed ``MAX_MEDIA_BYTES``.
        EgressRefusedError: a hop failed the check, or the body was
            encoded.
        httpx.HTTPError, TimeoutError: as the fetch raises them.
    """
    async with egress.open_guarded(
        "GET", url, timeout=_CDN_TIMEOUT, deadline=MEDIA_DEADLINE
    ) as resp:
        declared = resp.headers.get("content-length")
        if declared is not None and (not declared.isdigit() or int(declared) > MAX_MEDIA_BYTES):
            raise TooLargeError(f"response over {MAX_MEDIA_BYTES} bytes")
        received = bytearray()
        # Identity only (open_guarded refuses anything else): wire bytes.
        async for chunk in resp.aiter_bytes():
            received.extend(chunk)
            if len(received) > MAX_MEDIA_BYTES:
                raise TooLargeError(f"response over {MAX_MEDIA_BYTES} bytes")
        return resp.status_code, resp.headers.get("content-type", ""), bytes(received)


def _number(address: str) -> str:
    """``rcs:+15551234567`` or ``+15551234567`` as the bare E.164 number."""
    return address.removeprefix("rcs:").strip()


class TwilioBackend:
    """One Twilio account and one agent's RCS sender."""

    def __init__(
        self,
        *,
        account_sid: str,
        auth_token: str,
        sender_id: str,
        api: str = "https://api.twilio.com",
        messaging_api: str = "https://messaging.twilio.com",
        client: httpx.AsyncClient | None = None,
        cdn: CdnFetch | None = None,
    ) -> None:
        self._account_sid = account_sid
        self._cdn = cdn or guarded_get
        self._auth_token = auth_token
        self._from = f"rcs:{sender_id}"
        self._url = f"{api}/2010-04-01/Accounts/{account_sid}/Messages.json"
        # Where this account's inbound media lives; a webhook naming any other
        # URL is not fetched, signed or not.
        self._media_url = re.compile(
            re.escape(f"{api}/2010-04-01/Accounts/{account_sid}/Messages/")
            + r"[A-Za-z0-9]{1,64}/Media/[A-Za-z0-9]{1,64}"
        )
        self._typing_url = f"{messaging_api}/v3/Indicators/Typing.json"
        # nosemgrep: trentina-httpx-client-outside-egress -- operator URL
        self._client = client or httpx.AsyncClient(timeout=_TIMEOUT)

    async def aclose(self) -> None:
        await self._client.aclose()

    def verify(self, url: str, form: list[tuple[str, str]], signature_header: str) -> bool:
        if not signature_header or not signature_header.isascii():
            # A real signature is base64; anything else is not one, and must
            # be refused rather than raise in the comparison.
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
            count = min(int(fields.get("NumMedia", "0") or 0), _ATTACHMENTS_MAX)
        except ValueError:
            count = 0
        # An attachment with no URL still counts: it is delivered as one the
        # bridge could not fetch, so the agent hears of it.
        media = tuple(
            (fields.get(f"MediaUrl{i}", ""), fields.get(f"MediaContentType{i}", ""))
            for i in range(max(count, 0))
        )
        return Inbound(
            message_id=message_id,
            sender=_number(fields.get("From", "")),
            body=fields["Body"],
            media=media,
        )

    async def send_text(self, to: str, body: str) -> str:
        return await self._post_message({"From": self._from, "To": f"rcs:{to}", "Body": body})

    async def send_media(self, to: str, media_url: str, body: str) -> str:
        """Twilio fetches ``media_url`` itself, so it must be public (#493)."""
        form = {"From": self._from, "To": f"rcs:{to}", "MediaUrl": media_url}
        if body:
            form["Body"] = body
        return await self._post_message(form)

    async def fetch_media(self, url: str) -> dict[str, Any]:
        """One inbound attachment, from this account's media only (#493).

        The first hop goes to Twilio with the account's credentials and
        follows nothing. Twilio answers with a redirect to its CDN, which is
        fetched without them through the egress guard (``guarded_get``).
        Either body is read under the gateway's cap.
        """
        if self._media_url.fullmatch(url) is None:
            logger.warning("rcs bridge: inbound media URL is not this account's")
            return {"status": "unavailable"}
        try:
            async with asyncio.timeout(MEDIA_DEADLINE):
                status, content_type, raw = await self._fetch_media(url)
        except TooLargeError:
            return {"status": "too_large"}
        except (
            httpx.HTTPError,
            TimeoutError,
            EncodedBodyError,
            EgressRefusedError,
        ) as exc:
            logger.warning("rcs bridge: media fetch failed: %s", exc_kind(exc))
            return {"status": "unavailable"}
        if status != HTTPStatus.OK or not raw:
            logger.warning("rcs bridge: media fetch answered %d", status)
            return {"status": "unavailable"}
        return {
            "status": "ok",
            "content_type": content_type[:MAX_NAME_CHARS],
            "base64": base64.b64encode(raw).decode("ascii"),
        }

    async def _fetch_media(self, url: str) -> tuple[int, str, bytes]:
        """Twilio's answer for a media URL, or its CDN's after one redirect."""
        resp, raw = await request_capped(
            self._client,
            "GET",
            url,
            deadline=MEDIA_DEADLINE,
            limit=MAX_MEDIA_BYTES,
            auth=(self._account_sid, self._auth_token),
        )
        location = resp.headers.get("location")
        if not resp.is_redirect or not location:
            return resp.status_code, resp.headers.get("content-type", ""), raw
        hop = resp.url.join(location)
        if hop.scheme != "https":
            raise EgressRefusedError("downgrade")
        return await self._cdn(str(hop))

    async def _post_message(self, form: dict[str, str]) -> str:
        """Create one message; its sid."""
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
        try:
            parsed = json.loads(raw)
        except ValueError:
            parsed = None
        reply: dict[str, Any] = parsed if isinstance(parsed, dict) else {}
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

    async def send_typing(self, to: str) -> None:
        """Show the agent typing on ``to``'s phone (#1533).

        Twilio's v3 Typing Indicator API: JSON, START only. The bubble lasts
        about 20 s or until the next message arrives; there is no stop.
        """
        body = {"channel": "RCS", "from": self._from, "to": to, "event": "START"}
        try:
            resp, _raw = await request_capped(
                self._client,
                "POST",
                self._typing_url,
                deadline=_TYPING_DEADLINE,
                json=body,
                auth=(self._account_sid, self._auth_token),
            )
        except (httpx.HTTPError, TimeoutError, ValueError) as exc:
            raise BackendError(f"twilio typing: {exc_kind(exc)}") from exc
        if resp.status_code not in (HTTPStatus.OK, HTTPStatus.CREATED, HTTPStatus.ACCEPTED):
            raise BackendError(f"twilio typing: {resp.status_code}")
