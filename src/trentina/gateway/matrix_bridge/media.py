"""Attachments crossing the bridge (#491): what is re-hosted, and how it is read.

An ``mxc://`` URI names media on one homeserver, and neither side can resolve
the other's: the agent's homeserver does not federate, and matrix.org cannot
reach it. So no URI crosses. The bytes do: the bridge fetches (and, in an
encrypted room, decrypts) the media upstream and hands it over with the
event, the gateway fetches the agent's from its homeserver, and each side
uploads to its own. The bytes are judged with the event they arrived in, as
one document (#371): an image is read by OCR (#370), text as text, and
anything else is binary no layer read, the ``binary_unread`` gap.

Only the main media crosses. Thumbnails are dropped both ways: a second
upload and a second judgement for a picture clients draw from the main one
anyway, and one more URI that would otherwise have to be rewritten.
"""

from __future__ import annotations

import base64
import binascii
import copy
import re
from dataclasses import dataclass
from typing import Any

from ...client import TEXT_CONTENT_SUFFIXES, TEXT_CONTENT_TYPES
from ...unpack.ocr import MAX_IMAGE_BYTES
from ...unpack.signatures import identify

MAX_MEDIA_BYTES = MAX_IMAGE_BYTES
"""The most one attachment may weigh. OCR's own cap: a larger image could not
be read, so it would be refused as unread anyway."""

MAX_MEDIA_B64 = (MAX_MEDIA_BYTES + 2) // 3 * 4
"""``MAX_MEDIA_BYTES`` as base64, the form it crosses the wire in."""

# Why an attachment did not cross. A closed set: these reach the agent's
# notice, the log and the audit row, and carry nothing a sender chose.
UNAVAILABLE = "attachment could not be fetched"
TOO_LARGE = "attachment over the size cap"
FOREIGN = "attachment not on the agent's homeserver"

# The bridge's word on each attachment it was asked to fetch.
STATUS_OK = "ok"
STATUS_TOO_LARGE = "too_large"
STATUS_UNAVAILABLE = "unavailable"
STATUS_REASONS = {STATUS_TOO_LARGE: TOO_LARGE, STATUS_UNAVAILABLE: UNAVAILABLE}

MAX_NAME_CHARS = 255
"""The longest media type or file name carried; a file system's limit."""

_THUMBNAIL_KEYS = ("thumbnail_url", "thumbnail_file", "thumbnail_info")
# A server name (host, optional port) and a media ID, as the spec allows them.
_MXC = re.compile(r"mxc://([A-Za-z0-9.-]+(?::[0-9]{1,5})?|\[[0-9A-Fa-f:.]+\])/([A-Za-z0-9_-]+)")
_OCTET = "application/octet-stream"


def media_source(content: dict[str, Any]) -> dict[str, Any] | None:
    """Where an event's main media is, or None if it carries none.

    ``{"url": mxc}`` for plaintext media; the encrypted file object (``url``,
    ``key``, ``iv``, ``hashes``) for media in an encrypted room. A ``url`` or
    ``file`` of any other shape still counts as media, so the caller refuses
    it rather than delivering it without its bytes.
    """
    file = content.get("file")
    if file is not None:
        return file if isinstance(file, dict) else {}
    url = content.get("url")
    if url is not None:
        return {"url": url} if isinstance(url, str) else {}
    return None


def _holders(content: dict[str, Any]) -> list[dict[str, Any]]:
    """The event's content, then an edit's new content if it has one."""
    new_content = content.get("m.new_content")
    return [content, new_content] if isinstance(new_content, dict) else [content]


def main_holder(content: dict[str, Any]) -> dict[str, Any] | None:
    """The part of ``content`` that names the media: the content itself, or
    an edit's ``m.new_content`` when only that does. None if neither."""
    return next((h for h in _holders(content) if media_source(h) is not None), None)


def has_media(content: dict[str, Any]) -> bool:
    """Whether an event names media, in itself or in an edit's new content."""
    return main_holder(content) is not None


def strip_media(content: dict[str, Any]) -> dict[str, Any]:
    """A copy of ``content`` without any URI that names media.

    The main ``url`` or ``file``, every thumbnail field, and the same inside
    an edit's ``m.new_content``. What is left is what the layers read and
    what the other side receives, with the re-hosted URI added back.
    """
    out = copy.deepcopy(content)
    for holder in _holders(out):
        holder.pop("url", None)
        holder.pop("file", None)
        info = holder.get("info")
        if isinstance(info, dict):
            for key in _THUMBNAIL_KEYS:
                info.pop(key, None)
    return out


def parse_mxc(uri: object) -> tuple[str, str] | None:
    """``(server_name, media_id)`` of a well-formed ``mxc://`` URI, or None."""
    if not isinstance(uri, str):
        return None
    match = _MXC.fullmatch(uri)
    return (match.group(1), match.group(2)) if match else None


def declared_type(content: dict[str, Any]) -> str:
    """The mimetype the sender declared, or "" when it declared none."""
    info = content.get("info")
    mimetype = info.get("mimetype") if isinstance(info, dict) else None
    return mimetype if isinstance(mimetype, str) else ""


def filename(content: dict[str, Any]) -> str:
    """A name to upload under: the event's ``filename``, else its ``body``."""
    for key in ("filename", "body"):
        value = content.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()[:MAX_NAME_CHARS]
    return "attachment"


def decode(encoded: str) -> bytes | None:
    """The bytes of a base64 attachment, or None if it is not valid base64."""
    try:
        return base64.b64decode(encoded, validate=True)
    except (binascii.Error, ValueError):
        return None


def _is_text(media_type: str) -> bool:
    media_type = media_type.split(";", 1)[0].strip().lower()
    return (
        media_type.startswith("text/")
        or media_type in TEXT_CONTENT_TYPES
        or media_type.endswith(TEXT_CONTENT_SUFFIXES)
    )


@dataclass(frozen=True)
class Attachment:
    """One attachment, read for the layers.

    Attributes:
        media_bytes: the bytes, as they will be uploaded on the other side.
        judged: what the layers read: the image as base64, which the unpack
            stage reads by OCR, or the text. None when no layer can read it.
        content_type: what it is uploaded as. The image type its signature
            names, the declared type for text, else ``application/octet-stream``.
    """

    media_bytes: bytes
    judged: str | None
    content_type: str

    @property
    def unread(self) -> bool:
        """No layer can read it: the ``binary_unread`` gap."""
        return self.judged is None


def read_attachment(media_bytes: bytes, declared: str) -> Attachment:
    """Decide how the layers read ``media_bytes``, by its bytes before its label.

    An image signature wins over any declared type. Declared text is read as
    text only if it has no binary signature and decodes as UTF-8; a sender
    calling an executable ``text/plain`` does not get it read as prose.
    """
    kind = identify(media_bytes)
    if kind.name.startswith("image/"):
        return Attachment(media_bytes, base64.b64encode(media_bytes).decode("ascii"), kind.name)
    if kind.name == "binary" and _is_text(declared) and _is_utf8(media_bytes):
        return Attachment(
            media_bytes, media_bytes.decode("utf-8"), declared.split(";", 1)[0].strip().lower()
        )
    return Attachment(media_bytes, None, _OCTET)


def _is_utf8(media_bytes: bytes) -> bool:
    try:
        media_bytes.decode("utf-8")
    except UnicodeDecodeError:
        return False
    return True


def with_media(
    out: dict[str, Any],
    original: dict[str, Any],
    *,
    url: str | None = None,
    file: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """``out`` (stripped, then rewritten) pointing at the re-hosted media,
    wherever ``original`` named media: the content, an edit's new content, or
    both. A new content the rewrite dropped stays dropped."""
    targets = [out]
    if isinstance(out.get("m.new_content"), dict):
        targets.append(out["m.new_content"])
    for target, holder in zip(targets, _holders(original), strict=False):
        if media_source(holder) is None:
            continue
        if file is not None:
            target["file"] = copy.deepcopy(file)
        elif url is not None:
            target["url"] = url
    return out
