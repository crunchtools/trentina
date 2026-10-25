"""What a reducer read, and an account of what it did not.

Types only. The rules live with the processors that apply them — the skip
grammar in ``select.py``, the decryption posture in ``matrix.py``.

This file was the contract of a second driver framework
that #163 called "guard machinery" and #167 undid. The ruling it rested on —
that a transform may never open a gap between what is scanned and what is
delivered — does not survive contact with L1, which has always built a scan
copy that deliberately differs from the delivered bytes. Scan-differs-from-
deliver is the heart of L1, not a violation of it.

What is left after removing that framing is narrower and still true. A
processor that reads less than it delivers owes an ACCOUNT of what it
declined, and this is the shape of that account:

* ``chars_scanned`` + every value in ``skipped_chars`` must equal
  ``chars_total``, exactly. ``accounts()`` checks it and the tests assert it.
  Drift there means a processor dropped content without recording it, which is
  the one bug class the whole design exists to make impossible.
* ``coverage`` below the profile's floor is reported as a finding in its own
  right. A scan that read 2% of a document must not look like a scan that read
  all of it.
* ``degraded`` says the processor fell back. It is never silent.

Which of these bytes reach the agent is the CALL SITE's business, not this
type's: ``gateway/transform.py`` delivers what the chain returned, while
``gateway/matrix_proxy.py`` forwards the upstream ciphertext because the agent
must decrypt for itself (#162). Both use this type; they differ in what they
put on the wire.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

if TYPE_CHECKING:
    from collections.abc import Mapping

    from ..channels import Channel, Kind


class SkipReason(str, Enum):
    """Why a string was not scanned. One entry per structural rule.

    These are reported, so they double as the vocabulary an operator reads in
    an audit row. Keep them specific: "opaque" tells you a blob was skipped,
    "skipped" would tell you nothing.
    """

    EMPTY = "empty"
    NUMERIC = "numeric"
    IDENTIFIER = "identifier"
    OPAQUE = "opaque"
    ENUM_CONSTANT = "enum_constant"
    DUPLICATE = "duplicate"
    CIPHERTEXT_UNDECRYPTABLE = "ciphertext_undecryptable"


@dataclass(frozen=True)
class UndecryptableEvent:
    """An encrypted event the extractor could not read.

    Identity only — never ciphertext, never partial plaintext. This is what
    makes the coverage gap countable instead of assumed (S3).
    """

    event_id: str
    room_id: str
    session_id: str
    reason: str


@dataclass(frozen=True)
class SelectionContext:
    """What an extractor may know about the job. Not a policy channel."""

    source: str = ""
    profile_name: str = ""
    path: str = ""


@dataclass(frozen=True)
class Selection:
    """What the pipeline will read, and an account of what it will not.

    ``segments`` are RAW strings. Normalisation is ``run_l1``'s job and
    happens once, in the defense layer, so that the delivered bytes and the
    L2 input keep being derived in exactly one place.
    """

    extractor: str
    segments: tuple[str, ...] = ()
    chars_total: int = 0
    chars_scanned: int = 0
    skipped_chars: Mapping[SkipReason, int] = field(default_factory=dict)
    encrypted_events: int = 0
    decrypted_events: int = 0
    undecryptable: tuple[UndecryptableEvent, ...] = ()
    degraded: bool = False
    details: Mapping[str, int | float | str] = field(default_factory=dict)

    @property
    def coverage(self) -> float:
        """Fraction of characters actually handed to the pipeline."""
        if self.chars_total <= 0:
            return 1.0
        return self.chars_scanned / self.chars_total

    def accounts(self) -> bool:
        """S3: scanned plus skipped must equal the total, exactly.

        Asserted in tests rather than at runtime. A drift here means an
        extractor dropped content without recording it, which is the one bug
        class this whole design exists to make impossible.
        """
        return self.chars_scanned + sum(self.skipped_chars.values()) == self.chars_total


@runtime_checkable
class DocumentProcessor(Protocol):
    """A transform whose input is a parsed document, not a string.

    The other shape of transform. ``Transform`` in ``base.py`` takes
    ``str`` and returns ``str``; this one takes parsed JSON and returns the
    strings worth reading out of it, because ``m.room.encrypted`` is a
    structure rather than a substring and there is nothing useful to do with
    its serialization.

    Two shapes rather than one union type, deliberately: once #162 lands and
    the Matrix bridge delivers plaintext, ``matrix`` becomes an ordinary
    ``str -> str`` processor and this Protocol may have no implementations
    left. Building the union now would be work paid for twice.

    Implementations are constructed per profile (the Matrix one owns a key
    cache) but hold no per-request state.
    """

    name: str
    kind: Kind
    channels: frozenset[Channel]

    async def extract(self, payload: Any, ctx: SelectionContext) -> Selection:
        """Select what the pipeline should read.

        Must not raise on content it cannot handle. Fail open to MORE
        scanning: return a view covering everything, marked ``degraded``,
        rather than letting the caller decide what an exception means. This is
        the same rule as ``base.py``'s — on failure, do the thing that hides
        nothing — pointed at reading rather than at delivery.
        """
        ...
