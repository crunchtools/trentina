"""Media upstream, for the bridge process (#491).

Inbound, the bridge fetches an event's main media over the authenticated
media API, decrypts it when the room is encrypted (nio checks the sha256
hash), and hands the bytes to the gateway with the event, which judges them
and re-hosts them on the agent's homeserver. Outbound, the gateway hands
over judged bytes and this uploads them, encrypted for an encrypted room.

The bridge judges nothing here either: a fetch that fails, or runs past the
cap, is reported to the gateway as such, and the gateway withholds the event.
"""

from __future__ import annotations

import asyncio
import base64
import json
import logging
import re
from typing import TYPE_CHECKING, Any
from urllib.parse import quote

import httpx
from nio.crypto.attachments import decrypt_attachment, encrypt_attachment
from nio.exceptions import EncryptionError

from ..httpbody import EncodedBodyError, TooLargeError, request_capped
from ..unpack.ocr import MAX_IMAGE_BYTES

if TYPE_CHECKING:
    from collections.abc import Mapping

logger = logging.getLogger(__name__)

MAX_MEDIA_BYTES = MAX_IMAGE_BYTES
"""The gateway's cap (``gateway/matrix_bridge/media.py``): OCR's own."""

MAX_MEDIA_B64 = (MAX_MEDIA_BYTES + 2) // 3 * 4

MAX_NAME_CHARS = 255
"""The longest media type or file name carried."""

# Wall clock for one fetch or upload, the body included.
MEDIA_DEADLINE = 60.0

# Event types whose content can name media.
_WITH_MEDIA = frozenset({"m.room.message", "m.sticker"})
_MXC = re.compile(r"mxc://([A-Za-z0-9.-]+(?::[0-9]{1,5})?|\[[0-9A-Fa-f:.]+\])/([A-Za-z0-9_-]+)")


class UploadError(RuntimeError):
    """The upstream homeserver did not take an upload."""


class UploadRefusedError(RuntimeError):
    """It never will: a 4xx other than a rate limit (too large, forbidden)."""


def media_source(event_type: object, content: Mapping[str, Any]) -> dict[str, Any] | None:
    """Where an event's main media is: an encrypted ``file`` object or
    ``{"url": mxc}``, in the content or else in an edit's new content. None
    for an event that names no media; ``{}`` for one that names it in a
    shape nothing can fetch, which is reported as unavailable."""
    if event_type not in _WITH_MEDIA:
        return None
    new_content = content.get("m.new_content")
    for holder in (content, new_content if isinstance(new_content, dict) else {}):
        file, url = holder.get("file"), holder.get("url")
        if file is not None:
            return file if isinstance(file, dict) else {}
        if url is not None:
            return {"url": url} if isinstance(url, str) else {}
    return None


def _declared(content: Mapping[str, Any]) -> str:
    info = content.get("info")
    mimetype = info.get("mimetype") if isinstance(info, dict) else None
    return mimetype[:MAX_NAME_CHARS] if isinstance(mimetype, str) else ""


async def fetch(
    client: httpx.AsyncClient,
    homeserver: str,
    access_token: str,
    source: dict[str, Any],
    content: Mapping[str, Any],
) -> dict[str, str]:
    """The ``media`` item to send with an event: its bytes, or why not.

    Always returns: a failure is the gateway's to act on, never a reason to
    hold the batch. The upstream server may not redirect (no
    ``allow_redirect``), and the body is read under the cap.
    """
    match = _MXC.fullmatch(str(source.get("url") or ""))
    if match is None:
        return {"status": "unavailable"}
    server, media_id = (quote(part, safe="") for part in match.groups())
    try:
        resp, raw = await request_capped(
            client,
            "GET",
            f"{homeserver}/_matrix/client/v1/media/download/{server}/{media_id}",
            deadline=MEDIA_DEADLINE,
            limit=MAX_MEDIA_BYTES,
            headers={"Authorization": f"Bearer {access_token}"},
        )
    except TooLargeError:
        return {"status": "too_large"}
    except (httpx.HTTPError, TimeoutError, EncodedBodyError) as exc:
        logger.warning("bridge: media fetch failed: %s", type(exc).__name__)
        return {"status": "unavailable"}
    if resp.status_code != 200:
        logger.warning("bridge: media fetch answered %d", resp.status_code)
        return {"status": "unavailable"}
    content_type = resp.headers.get("content-type", "")
    if "key" in source:
        try:
            raw = await asyncio.to_thread(
                decrypt_attachment,
                raw,
                source["key"]["k"],
                source["hashes"]["sha256"],
                source["iv"],
            )
        except (EncryptionError, KeyError, TypeError, ValueError) as exc:
            # A hash that does not match is EncryptionError: the bytes are
            # not what the sender encrypted, so none of them go on.
            logger.warning("bridge: media decrypt failed: %s", type(exc).__name__)
            return {"status": "unavailable"}
        # The server only ever saw ciphertext; the sender's word is all there is.
        content_type = ""
    return {
        "status": "ok",
        "content_type": (_declared(content) or content_type)[:MAX_NAME_CHARS],
        "base64": base64.b64encode(raw).decode("ascii"),
    }


async def upload(
    client: httpx.AsyncClient,
    homeserver: str,
    access_token: str,
    plaintext: bytes,
    content_type: str,
    filename: str,
    *,
    encrypted: bool,
) -> dict[str, Any]:
    """Upload judged media upstream: ``{"url": mxc}``, or ``{"file": ...}``
    (the spec's EncryptedFile) when the room is encrypted, in which case the
    server only ever holds ciphertext."""
    keys: dict[str, Any] | None = None
    body = plaintext
    if encrypted:
        body, keys = await asyncio.to_thread(encrypt_attachment, plaintext)
        content_type = "application/octet-stream"
    try:
        resp, raw = await request_capped(
            client,
            "POST",
            f"{homeserver}/_matrix/media/v3/upload",
            deadline=MEDIA_DEADLINE,
            params={"filename": filename},
            content=body,
            headers={"Authorization": f"Bearer {access_token}", "Content-Type": content_type},
        )
    except (httpx.HTTPError, TimeoutError, TooLargeError, EncodedBodyError) as exc:
        raise UploadError(type(exc).__name__) from exc
    if 400 <= resp.status_code < 500 and resp.status_code != 429:
        raise UploadRefusedError(str(resp.status_code))
    try:
        uri = json.loads(raw).get("content_uri") if resp.status_code == 200 else None
    except (ValueError, AttributeError) as exc:
        raise UploadError(f"{resp.status_code}, not a JSON object") from exc
    if not isinstance(uri, str) or _MXC.fullmatch(uri) is None:
        raise UploadError(f"{resp.status_code}, no content_uri")
    if keys is None:
        return {"url": uri}
    return {"file": {"url": uri, **{k: keys[k] for k in ("key", "iv", "hashes", "v")}}}
