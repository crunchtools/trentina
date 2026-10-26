"""Structured — FREE reduction for JSON-shaped tool output.

Output is COMPACT JSON (0.38.0): no indentation, no space after separators.
It re-serialized with ``indent=2`` until then, which is easier on a human and
costs an agent tokens for whitespace it never reads. Compaction alone is now
a reason to apply: a pretty-printed payload with nothing to collapse still
comes out smaller, and still parses to the same document.

Phase 2 of the reduction plan. The sidecar's two dominant decline reasons,
``too_few_lines`` and ``reduction_below_floor``, both say the same thing:
the comparable UNIT is not a line. A Jira search result is one enormous
line, or forty pretty-printed ones that share no repetition petit can see,
and either way petit correctly declines.

So apply petit's idea at the right altitude. Where petit fingerprints a
line, this fingerprints an ARRAY ELEMENT: serialize it, normalize the
tokens that cannot carry meaning, group identical fingerprints, keep the
first few real elements of each group, and account for the rest.

Why fingerprinting and not key-sets. The obvious move — collapse array
elements that share a key-set — is both too aggressive and useless: forty
Jira issues all have the same keys, so a search for forty issues would
deliver three. Fingerprinting the normalized VALUES keeps forty genuinely
different issues distinct (different summaries are different words) while
forty near-identical status rows collapse to one group. The rule from
petit's ``strict.stopwords`` applies: words are never normalized, so an
element carrying a semantic payload keeps its own fingerprint and reaches
the perimeter scan.

What it deletes, it deletes. Elements past the sample budget are dropped,
not summarized, so colliding a payload into a group achieves only its
deletion. The same caveat as petit applies and is worth restating: an
attacker who controls the ORDER of an array can push a victim element past
the sample budget, so this defends against smuggling, not against
suppression by someone who already controls the payload's position. The
count marker still shows the elements existed, and every marker this module
writes is in-band and therefore spoofable — consumers must treat reduced
output as untrusted, which the perimeter already assumes.

Identifier-varying records are LISTED, not sampled (#173). Records that
differ only in identifier-shaped values (``PROJ-1000``, ``"10234"``, a UUID,
an integer id) would otherwise each keep their own fingerprint and reduce by
nothing. petit's ``pull_identifiers`` masks those values; records whose
masked JSON is EXACTLY equal form a group, delivered as its first element
verbatim and one marker listing every other element's values. Exact, not
scrubbed and not cut at ``_FINGERPRINT_MAX_CHARS``: the representative plus
the list reconstructs every record, so the group deletes nothing. A group
past ``_MAX_LISTED`` opens a new group rather than dropping the rest.
Integers are not petit's to pull, so they are stringified first and the
group key records which fields were integers.

Output is always valid JSON. A reducer that emits something a caller cannot
parse has moved the cost rather than removed it.

The truncation cap. ``_MAX_STRING_CHARS`` is a PROSE policy and nothing
else. Record-shaped payloads reduce identically at every setting, because
their win comes from grouping elements rather than clipping values — a
200-issue Jira search measures 1.7% whether the cap is 2,000 or 200,000.
What it decides is how hard an article body or a base64 blob is amputated.
20,000 chars is about 5,000 tokens: above stack traces, embedded documents
and the fields that make tool output pathological, but high enough that
clipping a long article is a trim rather than an amputation. Measured on a
29k-char feed entry, 2,000 delivers 7% of it, 8,000 delivers 28%, 20,000
delivers 68%, and 50,000 declines to touch it. Going lower buys real bytes
and costs the agent the document it asked for — that trade is phase 4's
open question about METERED summarize, and belongs in a decision with
numbers attached rather than in a constant chosen quietly here.

A log in a string is reduced by petit (#419). ``journal_query`` answers
``{"logs": "<a hundred lines>"}``: one string, so nothing here to group, and
petit is only ever offered a whole text block, so nothing reduced it at all.
A string of at least ``_MIN_LOG_LINES`` lines and ``_MIN_LOG_CHARS``
characters is handed to ``PetitProcessor.reduce``, the same reduction a
plain-text block gets, and the value becomes petit's own artifact: the
sample lines as they were written, then its summary, in petit's words
without the ``[petit]`` tag (the #411 lesson, measured again here). It is
kept only when petit NAMED a log format for the value. On its raw fallback
petit groups any repeated line, which in a source file or a page is the
blank lines and the closing brackets: measured on this repository's own
files it deletes a fifth of the lines to save 0.3% to 2% of the bytes, and
a JSON string is where a tool puts the document an agent asked for. A stray
line where petit samples the value can cost it its format, and then the
value is delivered whole. The same deletion rule as the arrays
applies: what petit drops is counted (``log_lines_in``/``log_lines_out``),
never delivered and never judged, and its summary is in-band and spoofable.
A value petit declines, or that makes it raise, is left as it arrived.

Hostile-input hardening: parsing is bounded by ``_MAX_PARSE_BYTES``, the
walk is depth-limited, and fingerprinting reads at most
``_FINGERPRINT_MAX_CHARS`` per element, so neither deep nesting nor one
enormous value can buy unbounded work. ``json.loads`` is synchronous and
``_reduce`` is a plain walk, so both run on a worker thread — a large
payload must not stall the gateway's event loop.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from functools import partial
from typing import Any, NamedTuple

from petit import pull_identifiers
from petit.Filter import Filter

from ..channels import Channel, Kind
from ..unpack.child import run_unpacking
from ..unpack.office import reduce_base64
from .base import Applied, Cost, Declined, Failed, TransformContext, TransformResult
from .pdf import reduce_base64 as reduce_pdf
from .petit import _MIN_BYTES as _MIN_LOG_CHARS
from .petit import _MIN_LINES as _MIN_LOG_LINES
from .petit import PetitProcessor

# The normalization policy, loaded from petit rather than restated here — the
# same file its JSON and mail drivers declare, so this fingerprint and petit's
# are normalized by one table. It replaced a local copy (`volatile.py`) whose
# only possible future was drifting into a second, weaker rule, and it is
# stricter: `<N>` is `(?<![\w-])\d+(?![\w-])`, leaving a digit inside a word
# alone, so `PROJ-1234`/`PROJ-1235` stay distinct. Reduces less; deletes
# nothing real. Module-level because constructing it reads a packaged data
# file and this is the gateway's hot path.
_SCRUB = Filter("strict.stopwords")

# Past this, do not even parse. A parse guard, not a content policy: the
# token count at admission (#225) decides what is judged; this is the
# reducer refusing to be the expensive step on the way there.
_MAX_PARSE_BYTES = 4_000_000

# Arrays shorter than this have nothing worth grouping.
_MIN_ARRAY_ITEMS = 8

# Real elements retained per fingerprint group.
_SAMPLES_PER_GROUP = 3

# A string value longer than this is truncated. See "The truncation cap"
# above: this is a prose policy and does not affect record-shaped payloads.
_MAX_STRING_CHARS = 20_000

# How deep to walk before leaving a subtree alone. Hostile JSON nests.
_MAX_OFFICE_CHARS = 140_000
"""Base64 characters of an office file stage 1 will open: the unpack
stage's own token cap, so a file too big for the layers to read whole is
never reduced into something they can."""

_MAX_DEPTH = 40

_FINGERPRINT_MAX_CHARS = 400

# There is no minimum saving. A reducer that declines a 5% win throws
# away 5%, and across a swarm of agents even 1% compounds. What remains
# is arithmetic rather than policy: the rewrite appends a summary block,
# so content with nothing to collapse can come out no smaller than it
# went in, and delivering that would cost bytes for nothing.

# Elements one listing marker names before the next element of the group
# opens a new one. Bounds a marker, never what is delivered.
_MAX_LISTED = 100

# Marker text. In-band and therefore spoofable, like petit's [petit] prefix.
# It carried a "[structured] " tag until 1.3.0 (#411). A bracketed tag in the
# middle of data is what an injected system note looks like, and L2 read it
# as one: the same rows scored 0.00 as they arrived and 0.99 with one tagged
# marker among them. The words say what the tag said.
_OMITTED = "{count} more element(s) with this shape omitted"
# Rows first, note after (#431). Note first, a run of image digests behind
# "with this shape; /Links /VolumeName:" read to L2 as a sentence handing
# over a payload: a `system_df` reply scored 0.99 that way and 0.01 this way.
_LISTED = "{rows}; {count} more element(s) with this shape, {fields}"
_IDENTICAL = "{count} more element(s) identical to the one above"


class _GroupKey(NamedTuple):
    """What an element must share with the others to be listed with them."""

    masked_json: str
    fields: tuple[str, ...]
    """Identifier pointers, as petit writes them."""
    int_pointers: frozenset[str]
    """Every pointer that held an integer, pulled or not."""


class _Pulled(NamedTuple):
    key: _GroupKey
    values: tuple[str, ...]


def _pointer_token(key: str) -> str:
    """RFC 6901 escaping, as petit writes its pointers."""
    return key.replace("~", "~0").replace("/", "~1")


def _stringify_ints(node: Any, pointer: str, depth: int, found: set[str]) -> Any:
    """``node`` with every integer (never a bool) as its decimal string.

    ``found`` collects the pointers that held one. Copy-on-write: a container
    is copied only once a child has changed, so a record without integers
    costs one walk and no allocation. Past ``_MAX_DEPTH`` the subtree comes
    back as it is.
    """
    if depth >= _MAX_DEPTH:
        return node
    if isinstance(node, int) and not isinstance(node, bool):
        found.add(pointer)
        return str(node)
    if not isinstance(node, (dict, list)):
        return node
    slots = node.items() if isinstance(node, dict) else enumerate(node)
    copied: Any = None
    for k, v in slots:
        new = _stringify_ints(v, f"{pointer}/{_pointer_token(str(k))}", depth + 1, found)
        if new is not v and copied is None:
            copied = dict(node) if isinstance(node, dict) else list(node)
        if copied is not None:
            copied[k] = new
    return node if copied is None else copied


def _identifiers(item: Any) -> _Pulled | None:
    """The element's listing key and its identifier values, or None.

    Tried with integers stringified first; if that finds nothing to pull, or
    too many fields for petit to take, again with integers left alone.
    """
    ints: set[str] = set()
    widened = _stringify_ints(item, "", 0, ints)
    masked, fields, values = pull_identifiers(widened) if ints else (item, (), ())
    if not fields:
        ints = set()
        masked, fields, values = pull_identifiers(item)
    if not fields:
        return None
    # Every integer's pointer, not only the pulled ones: `-1` stringified is
    # not an identifier, stays in the masked text as "-1", and must not
    # match a record whose "-1" was a string all along.
    text = json.dumps(masked, sort_keys=True, ensure_ascii=False)
    return _Pulled(_GroupKey(text, fields, frozenset(ints)), values)


_TRUNCATED = "... {count} more character(s) truncated"

# A string value is offered to petit as a log (#419) at petit's own two
# floors, imported above, and at BOTH of them where a text block needs only
# one: a value under twenty lines cannot hold the twenty records petit asks
# for, and a short one has nothing worth a deletion inside a document.
_PETIT = PetitProcessor()

# What petit reports when no driver recognised the format. A value is
# reduced only under a driver that did; see "A log in a string" above.
_RAW_DRIVER = "RawEntry"

# Base64, wrapped or not: the alphabets and whitespace and nothing else. Such
# a value is a file, which `_document` and the unpack stage read; grouping
# its lines would corrupt it. Linear, one character class, and it stops at
# the first `:` or `.` of a log line.
_BLOB = re.compile(r"[A-Za-z0-9+/=_\-\s]*")


class _Reducer:
    """One walk over one document, accumulating what it removed.

    The counts are the walk's own state rather than an argument threaded
    through every level, because they are the walk's result as much as the
    reduced document is: the sidecar reports them and the apply/decline
    decision reads them.
    """

    def __init__(self, *, truncate: bool = False) -> None:
        # Long strings are clipped only when the payload is over the caller's
        # budget. Under it, the agent asked for the document and gets it.
        self.truncate = truncate
        self.groups_collapsed = 0
        self.elements_dropped = 0
        self.groups_listed = 0
        self.elements_listed = 0
        self.strings_truncated = 0
        self.chars_truncated = 0
        self.office_converted = 0
        self.office_hidden = 0
        self.pdf_converted = 0
        self.pdf_hidden = 0
        self.logs_reduced = 0
        self.log_lines_in = 0
        self.log_lines_out = 0
        self.log_groups_collapsed = 0
        self.logs_failed = 0
        # The class of the last failure, never its message (#262).
        self.log_error = ""

    @property
    def changed(self) -> bool:
        return bool(
            self.elements_dropped
            or self.elements_listed
            or self.strings_truncated
            or self.office_converted
            or self.pdf_converted
            or self.logs_reduced
        )

    def _document(self, node: str) -> dict[str, str] | None:
        """A base64 office file or PDF as its visible text (#368, #369).

        Both are reducer formats, as HTML is: the agent asked for a document
        and gets its text, at a fraction of the tokens. Text the file hides
        is dropped and counted, and L1 is handed the count.
        ``trentina_preprocess: false`` keeps the file itself.
        """
        office = reduce_base64(node, _MAX_OFFICE_CHARS)
        if office is not None:
            kind, markdown, hidden = office
            self.office_converted += 1
            self.office_hidden += hidden
            return {"format": kind, "as_markdown": markdown}
        pdf = reduce_pdf(node)
        if pdf is not None:
            self.pdf_converted += 1
            self.pdf_hidden += pdf[1]
            return {"format": "pdf", "as_markdown": pdf[0]}
        return None

    def _log(self, node: str) -> str:
        """A long log as petit reduces a text block (#419), or ``node`` as it arrived.

        Minifying fails open: a value petit declines, does not name a log
        format for, or raises on is delivered whole.
        """
        if (
            len(node) < _MIN_LOG_CHARS
            or node.count("\n") + 1 < _MIN_LOG_LINES
            or _BLOB.fullmatch(node)
        ):
            return node
        try:
            result = _PETIT.reduce(node, tag="")
        except Exception as exc:
            # Counted by class, never logged: the message may carry the value (#262).
            self.logs_failed += 1
            self.log_error = type(exc).__name__
            return node
        if isinstance(result, Failed) and result.reason == "petit_error":
            self.logs_failed += 1
            # petit.py reports the exception's class. Held to that shape
            # here, so a message can never ride out in the details (#262).
            error = str(result.details.get("error", ""))
            self.log_error = error if error.isidentifier() else "PetitError"
        if not isinstance(result, Applied):
            return node
        details = result.details
        # Degraded is a log too: a driver claimed the value and then met a
        # line it could not parse, so petit grouped the whole of it
        # structurally.
        named = details.get("petit_driver") != _RAW_DRIVER or details.get("petit_degraded")
        if not named:
            return node
        self.logs_reduced += 1
        self.log_lines_in += int(details["lines_in"])
        self.log_lines_out += int(details["lines_out"])
        self.log_groups_collapsed += int(details["groups_collapsed"])
        return result.content

    def _clipped(self, node: str) -> str:
        removed = len(node) - _MAX_STRING_CHARS
        self.strings_truncated += 1
        self.chars_truncated += removed
        return node[:_MAX_STRING_CHARS] + _TRUNCATED.format(count=removed)

    def walk(self, node: Any, depth: int = 0) -> Any:
        """Reduce arrays, logs and long strings, leaving everything else alone.

        Past ``_MAX_DEPTH`` the subtree comes back untouched. Declining to
        reduce is always safe; blowing the stack on attacker-chosen nesting
        is not.

        An array element's fingerprint is its JSON with keys sorted — so two
        objects written in different key orders are one shape, and an
        attacker cannot multiply an array's delivered size by shuffling keys
        — and with volatile tokens normalized, which leaves every word
        intact. Order is preserved: kept elements come back where they were
        and each group's omission marker is appended once at the end.
        """
        if depth >= _MAX_DEPTH or not isinstance(node, (str, list, dict)):
            return node

        if isinstance(node, str):
            document = self._document(node)
            if document is not None:
                return document
            text = self._log(node)
            long = self.truncate and len(text) > _MAX_STRING_CHARS
            return self._clipped(text) if long else text

        if isinstance(node, dict):
            return {key: self.walk(value, depth + 1) for key, value in node.items()}

        if len(node) < _MIN_ARRAY_ITEMS:
            return [self.walk(item, depth + 1) for item in node]
        return self._reduce_array(node, depth)

    def _reduce_array(self, node: list[Any], depth: int) -> list[Any]:
        """Listing groups first, then sample-and-count for everything else."""
        lister = _Lister(node)
        seen: dict[str, int] = {}
        kept: list[Any] = []
        dropped: dict[str, int] = {}

        for item, found in zip(node, lister.pulled, strict=True):
            if lister.take(found):
                continue
            if found is not None and lister.opens(found):
                # Verbatim, not walked: the marker below reconstructs the
                # group from exactly this record.
                kept.append(item)
                lister.open(found, kept)
                continue

            # Every item came out of json.loads, so it is serializable by
            # construction; there is no unserializable case to guard.
            text = json.dumps(item, sort_keys=True, ensure_ascii=False)
            fingerprint = _SCRUB.scrub(text[:_FINGERPRINT_MAX_CHARS])

            count = seen.get(fingerprint, 0) + 1
            seen[fingerprint] = count
            if count <= _SAMPLES_PER_GROUP:
                kept.append(self.walk(item, depth + 1))
            else:
                dropped[fingerprint] = dropped.get(fingerprint, 0) + 1

        kept = lister.finish(kept)
        self.groups_listed += lister.groups
        self.elements_listed += lister.elements
        if dropped:
            self.groups_collapsed += len(dropped)
            self.elements_dropped += sum(dropped.values())
            kept.extend(
                _OMITTED.format(count=count) for count in sorted(dropped.values(), reverse=True)
            )
        return kept


@dataclass
class _Listing:
    """One open group: where its marker goes, the first element's values, the rest's."""

    slot: int
    fields: tuple[str, ...]
    first: tuple[str, ...]
    rows: list[tuple[str, ...]] = field(default_factory=list)

    def marker(self) -> str:
        """Fields constant across the group are named by the element above
        the marker, so only the varying ones are listed."""
        varying = [
            i for i in range(len(self.fields)) if any(r[i] != self.first[i] for r in self.rows)
        ]
        if not varying:
            return _IDENTICAL.format(count=len(self.rows))
        return _LISTED.format(
            count=len(self.rows),
            fields=" ".join(self.fields[i] for i in varying),
            rows=", ".join(" ".join(row[i] for i in varying) for row in self.rows),
        )


class _Lister:
    """The identifier groups of one array (#173).

    An element joins a group only when at least one other element shares its
    key, and a group's marker takes at most ``_MAX_LISTED`` rows; the next
    member after that is delivered verbatim and opens a fresh marker.
    """

    def __init__(self, node: list[Any]) -> None:
        self.pulled = [_identifiers(item) for item in node]
        self._sizes: dict[_GroupKey, int] = {}
        for found in self.pulled:
            if found is not None:
                self._sizes[found.key] = self._sizes.get(found.key, 0) + 1
        self._open: dict[_GroupKey, _Listing] = {}
        self._all: list[_Listing] = []
        self.groups = 0
        self.elements = 0

    def take(self, found: _Pulled | None) -> bool:
        """List the element in its open group, if it has one with room."""
        if found is None:
            return False
        listing = self._open.get(found.key)
        if listing is None or len(listing.rows) >= _MAX_LISTED:
            return False
        listing.rows.append(found.values)
        return True

    def opens(self, found: _Pulled) -> bool:
        """Whether another element of the array shares this element's key."""
        return self._sizes[found.key] > 1

    def open(self, found: _Pulled, kept: list[Any]) -> None:
        """The element just appended to ``kept`` starts a group; reserve its marker."""
        kept.append(None)
        listing = _Listing(len(kept) - 1, found.key.fields, found.values)
        self._open[found.key] = listing
        self._all.append(listing)

    def finish(self, kept: list[Any]) -> list[Any]:
        """Fill each reserved slot with its marker, or remove it if nothing joined."""
        empty = set()
        for listing in self._all:
            if listing.rows:
                kept[listing.slot] = listing.marker()
                self.groups += 1
                self.elements += len(listing.rows)
            else:
                empty.add(listing.slot)
        return [k for i, k in enumerate(kept) if i not in empty]


def _parse_and_reduce(payload: str, *, truncate: bool) -> Declined | tuple[str, _Reducer]:
    """Parse, reduce, re-serialize. Returns the reduced text and its reducer,
    or a ``Declined`` naming why nothing was reduced.

    Every outcome here is a shape decline, named by the producer rather than a
    reason string the caller reclassifies: a document that is not JSON, a
    bare scalar, nesting too deep to walk, or nothing repetitive to collapse.
    An operational failure (a worker crash) raises instead and becomes
    ``Failed`` at the composition, so a required ``structured`` fails closed.
    """
    reducer = _Reducer(truncate=truncate)
    try:
        document = json.loads(payload)
    except (ValueError, RecursionError):
        return Declined("not_json")

    # A bare scalar is JSON but has nothing to reduce.
    if not isinstance(document, (list, dict)):
        return Declined("not_json")

    try:
        reduced = reducer.walk(document)
    except RecursionError:
        return Declined("too_deep")

    # Serializable by construction: everything in `reduced` came out of
    # json.loads or is a marker string this module wrote.
    text = json.dumps(reduced, separators=(",", ":"), ensure_ascii=False)
    if not reducer.changed and len(text.encode("utf-8")) >= len(payload.encode("utf-8")):
        return Declined("nothing_repetitive")
    return text, reducer


class StructuredProcessor:
    """FREE. Collapses repeated JSON elements and logs in strings, truncates long strings."""

    name = "structured"
    cost = Cost.FREE
    channels = frozenset({Channel.TOOL})
    kind = Kind.TEXT

    async def run(self, payload: str, ctx: TransformContext) -> TransformResult:
        bytes_in = len(payload.encode("utf-8"))

        if bytes_in > _MAX_PARSE_BYTES:
            # Like html: a required reducer cannot excuse itself on size, so
            # this is a Failure a floor refuses rather than a shape decline.
            return Failed("too_large")

        # Cheap gate before spending a parse: JSON documents worth reducing
        # start with a bracket.
        stripped = payload.lstrip()
        if not stripped or stripped[0] not in "[{":
            return Declined("not_json")

        over_budget = ctx.target_bytes is not None and bytes_in > ctx.target_bytes
        # A field holding a PDF is read by a worker process (#383).
        outcome = await run_unpacking(partial(_parse_and_reduce, payload, truncate=over_budget))
        if isinstance(outcome, Declined):
            return outcome
        text, reducer = outcome

        bytes_out = len(text.encode("utf-8"))
        if bytes_in > 0 and bytes_out >= bytes_in:
            # See petit.py: the ratio is measured, so report it rather than
            # collapse every near-miss and every no-hoper into one word.
            return Declined(
                "not_smaller",
                {
                    "would_be_bytes": bytes_out,
                    "would_be_ratio": round(bytes_out / bytes_in, 4),
                    "groups_collapsed": reducer.groups_collapsed,
                    "elements_dropped": reducer.elements_dropped,
                },
            )

        return Applied(
            text,
            {
                "groups_collapsed": reducer.groups_collapsed,
                "elements_dropped": reducer.elements_dropped,
                "groups_listed": reducer.groups_listed,
                "elements_listed": reducer.elements_listed,
                "strings_truncated": reducer.strings_truncated,
                "chars_truncated": reducer.chars_truncated,
                "office_converted": reducer.office_converted,
                "office_hidden": reducer.office_hidden,
                "pdf_converted": reducer.pdf_converted,
                "pdf_hidden": reducer.pdf_hidden,
                "logs_reduced": reducer.logs_reduced,
                "log_lines_in": reducer.log_lines_in,
                "log_lines_out": reducer.log_lines_out,
                "log_groups_collapsed": reducer.log_groups_collapsed,
                "logs_failed": reducer.logs_failed,
                "log_error": reducer.log_error,
            },
        )
