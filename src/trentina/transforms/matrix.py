"""Decrypt to build the L2 input; forward the ciphertext untouched.

Everything ``select`` does, plus the one thing that changes what the perimeter
can actually see. Message bodies in an encrypted room are ciphertext at the
proxy, so without this an injection in a chat message crosses Trentina as an
opaque blob and becomes plaintext inside the agent, past the perimeter.

Two properties govern this file. Both are about the Matrix CALL SITE rather
than about pre-processing in general, which is why they live here and not in
``base.py``:

DELIVERY IS UNTOUCHED. What this processor reads never influences the bytes
   forwarded to the client. The response body is built from the upstream
   buffer and never from anything here; the only channel out is the
   ``_trentina_warning`` key.

DECRYPTION IS READ-ONLY, ADDITIVE AND EPHEMERAL. Recovered plaintext exists
   only in the L2 input. Never forwarded, never written to disk, never logged
   in full. Trentina never writes to the homeserver and holds no Matrix device
   identity.

Both are contingent, and it is worth saying on what. They hold because the
agent must decrypt for itself, so the proxy cannot deliver what it read — see
``.specify/specs/013-matrix-scan-view/spec.md``, "Encryption posture": the
homeserver never sees plaintext and E2EE is kept. Issue #162 proposes a
bridge that terminates E2EE and delivers the plaintext. If that lands, this
stops being a document processor at all: it would read exactly what it
delivers, which is the ordinary transform contract, and the L2 input
would simply be its output.

Two habits worth naming, because both are easy to get wrong:

Decrypted text goes back through the SAME ``select`` rules as anything else. A
base64 blob pasted inside a message is still a base64 blob, and plaintext
recovered from ciphertext is no more trustworthy than plaintext that arrived
in the clear. There is no "it was encrypted, so it is ours" shortcut.

Unrecognised shapes fall through to the generic leaf walk rather than being
skipped. This knows the shapes Matrix uses today; the failure mode for a shape
it does not know must be "read it anyway", not "ignore it".
"""

from __future__ import annotations

import asyncio
import json
import logging
from typing import TYPE_CHECKING, Any

from ..channels import Channel, Kind
from ..jsonwalk import iter_leaves
from ..logsafe import exc_kind, redact_source
from .view import Selection, SelectionContext, SkipReason, UndecryptableEvent

if TYPE_CHECKING:
    from ..matrix.keybackup import KeyBackupProvider
    from .select import SelectProcessor

logger = logging.getLogger(__name__)

MEGOLM_ALGORITHM = "m.megolm.v1.aes-sha2"
OLM_ALGORITHM = "m.olm.v1.curve25519-aes-sha2"


class MatrixProcessor:
    """Shape-based selection, plus Megolm decryption of room events."""

    name = "matrix"
    channels = frozenset({Channel.MATRIX})
    kind = Kind.DOCUMENT

    def __init__(
        self,
        *,
        select: SelectProcessor,
        keys: KeyBackupProvider | None = None,
    ) -> None:
        self._select = select
        self._keys = keys

    async def extract(self, payload: Any, ctx: SelectionContext) -> Selection:
        encrypted: list[dict[str, Any]] = []
        _collect_encrypted(payload, encrypted)

        decrypted_texts: list[str] = []
        undecryptable: list[UndecryptableEvent] = []
        skipped: dict[SkipReason, int] = {}
        decrypted = 0

        for event in encrypted:
            content = event.get("content") or {}
            ciphertext = content.get("ciphertext")
            room_id = str(event.get("_room_id") or "")
            event_id = str(event.get("event_id") or "")
            session_id = str(content.get("session_id") or "")
            algorithm = content.get("algorithm")

            if not isinstance(ciphertext, str):
                # Olm to-device payloads are a dict keyed by recipient key.
                # Key backup does not cover olm and never will, so counting
                # them as undecryptable would pin the rate high for ever.
                continue
            if algorithm != MEGOLM_ALGORITHM:
                undecryptable.append(
                    UndecryptableEvent(event_id, room_id, session_id, "unsupported_algorithm")
                )
                _bump(skipped, len(ciphertext))
                continue

            plaintext = await self._decrypt(room_id, session_id, ciphertext)
            if plaintext is None:
                reason = "no_session" if self._keys else "decryption_disabled"
                undecryptable.append(UndecryptableEvent(event_id, room_id, session_id, reason))
                _bump(skipped, len(ciphertext))
                continue

            decrypted += 1
            decrypted_texts.extend(_decrypted_leaves(plaintext))

        view = await asyncio.to_thread(  # off the loop (#295)
            lambda: self._select.select(
                iter_leaves(_without_ciphertext(payload)),
                extra_segments=decrypted_texts,
                extra_skipped=skipped,
                encrypted_events=len(encrypted),
                decrypted_events=decrypted,
                undecryptable=tuple(undecryptable),
                extractor_name=self.name,
            )
        )
        if undecryptable:
            logger.warning(
                "matrix select: %s — %d of %d encrypted event(s) unread",
                redact_source(ctx.path or ctx.source),
                len(undecryptable),
                len(encrypted),
            )
        return view

    async def _decrypt(self, room_id: str, session_id: str, ciphertext: str) -> str | None:
        if self._keys is None or not session_id:
            return None
        try:
            session = await self._keys.session_for(room_id, session_id)
            if session is None:
                return None
            from ..matrix.megolm import decrypt_event

            return decrypt_event(session, ciphertext).decode("utf-8", "replace")
        except Exception as exc:
            # Identity only. Never the ciphertext, never partial plaintext.
            logger.warning(
                "matrix select: decrypt failed for session %s in room %s: %s",
                redact_source(session_id),
                redact_source(room_id),
                exc_kind(exc),
            )
            return None


def _bump(skipped: dict[SkipReason, int], n: int) -> None:
    key = SkipReason.CIPHERTEXT_UNDECRYPTABLE
    skipped[key] = skipped.get(key, 0) + n


def _decrypted_leaves(plaintext: str) -> list[str]:
    """Every string in a decrypted event, keys included, for ``select``.

    Not a list of prose fields (#296). Reading only ``body``,
    ``formatted_body``, ``topic`` and ``name`` left every other key unread
    AND uncounted, so an injection in ``m.relates_to``, an extension key or
    ``m.new_content``'s neighbours crossed with coverage reporting 100%.
    ``select`` decides what is skipped, by the same rules as cleartext, and
    counts it. Text that is not a JSON object is read whole.
    """
    try:
        event = json.loads(plaintext)
    except ValueError:
        return [plaintext]
    if not isinstance(event, dict):
        return [plaintext]
    return iter_leaves(event)


def _collect_encrypted(payload: Any, out: list[dict[str, Any]]) -> None:
    """Find every m.room.encrypted event, tagging each with its room.

    Walks generically rather than by a fixed list of container paths: /sync,
    /messages, /context and /search all nest events differently, and a walk
    that has to know each one is a walk that silently misses the next.
    """
    stack: list[tuple[Any, str]] = [(payload, "")]
    while stack:
        node, room = stack.pop()
        if isinstance(node, dict):
            if node.get("type") == "m.room.encrypted" and "content" in node:
                tagged = dict(node)
                tagged["_room_id"] = node.get("room_id") or room
                out.append(tagged)
                continue
            for key, value in node.items():
                child_room = key if isinstance(key, str) and key.startswith("!") else room
                stack.append((value, child_room))
        elif isinstance(node, list):
            stack.extend((item, room) for item in node)


def _without_ciphertext(payload: Any) -> Any:
    """The payload as the generic rules should see it.

    Returned as-is: ciphertext strings are high-entropy base64 with no
    whitespace, so the generic OPAQUE rule already declines them and counts
    them. Stripping them here would double-count against the accounting
    identity in S3.
    """
    return payload
