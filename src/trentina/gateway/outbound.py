"""Reading an agent's own OUTBOUND request content for judging (#511).

Shared by the ``/proxy/llm`` proxy and the terminating egress route. Both read
the request as one document and must answer the same question: does it carry a
credential the agent should not be sending out, or an injection the layers
catch? These are the pure helpers that prepare that document; the judging itself
— the ``defend()`` call and the refuse decision — lives on the request edge in
``orchestrator.judge_outbound``:

- a deterministic credential-shape scan (``detect_credentials``) over the raw
  document and, if that is clean, its revealed form — the signal the
  prompt-injection layers do not look for;
- ``judge_input`` builds the credential-REDACTED copy the layers read, so the
  secret never reaches the external judge while the injection content, which is
  what L3 is for, is read in full.

The ORIGINAL request is what each caller forwards upstream — never these copies.
"""

from __future__ import annotations

import functools
import html
import json
import re
import sys
import unicodedata
from urllib.parse import unquote

from ..credential_shapes import kinds as credential_kinds
from ..credential_shapes import redact as credential_redact

# The closed reason codes an outbound refusal carries. Credential first: it is
# the most specific and actionable. A honeytoken trip (#865) outranks it.
REASON_DECOY = "honeytoken_in_request"
REASON_CREDENTIAL = "credential_in_request"
REASON_FLAGGED = "flagged"
REASON_UNJUDGED = "not_fully_judged"

#: A JSON ``\\uXXXX`` escape — the other way a body hides a key from a raw scan,
#: which the destination's JSON parser decodes (`\\u0041` -> ``A``).
_JSON_UESC = re.compile(r"\\u([0-9a-fA-F]{4})")


def reveal(document: str) -> str:
    """Decode every escaping the destination would, so a key cannot hide in one.

    Percent-escapes (``%41``, a URL/form/query evasion) and JSON ``\\uXXXX``
    escapes (a JSON-string evasion) are decoded — including a key split across
    literal and escaped characters, which neither a raw scan nor a whole-run
    mask would catch. The result is what the destination parses, so a credential
    in ANY encoding reads as a raw shape here, and a percent- or ``\\u``-encoded
    injection becomes readable to L2.
    """
    decoded = unquote(document)
    return _JSON_UESC.sub(lambda m: chr(int(m.group(1), 16)), decoded)


#: How many rounds of decoding ``unmasked`` applies: enough for a double
#: encoding (``&amp;#103;``, ``%2541``), bounded so a crafted body cannot make
#: the scan loop.
_REVEAL_ROUNDS = 3


def unmasked(document: str) -> str:
    """``reveal`` and more, for DETECTION only — never what the judge reads.

    A key a reader would still see can hide from a shape pattern behind HTML
    entities (decoded up to three rounds, so ``&amp;#103;hp_`` is ``ghp_``),
    zero-width and other format characters or combining marks (Cf, Mn and Me,
    variation selectors included, dropped), or compatibility forms such as
    fullwidth letters (NFKC, bounded: past twice the input it raises
    ``ExpansionError``, which detection reports as ``EXPANSION_KIND``). ASCII
    text skips the Unicode passes. The judge's copy keeps
    ``reveal`` alone: these change how text reads to a model, and the layers
    judge what was sent.
    """
    text = document
    for _ in range(_REVEAL_ROUNDS):
        decoded = html.unescape(reveal(text))
        if decoded == text:
            break
        text = decoded
    if text.isascii():
        return text
    text = _without_marks(text)
    return _without_marks(_bounded_nfkc(text))


#: What ``unmasked`` drops: format characters (zero-width joiners and spaces,
#: bidi controls) and combining marks, variation selectors included — they are
#: category Mn. Each renders as nothing, or as a mark on the letter before it,
#: so a key with one inside still reads as the key.
_INVISIBLE = frozenset({"Cf", "Mn", "Me"})

#: How far NFKC may grow the text before it is a bomb rather than text: a
#: ligature or a fullwidth form is at most a few characters, while U+FDFA is
#: eighteen, and 8 MB of it took 7.5 s and 443 MB to fold (#882 review).
_NFKC_GROWTH = 2
_NFKC_CHUNK = 4096

#: The kind ``detect_credentials`` reports for a document whose NFKC fold blew
#: past ``_NFKC_GROWTH``. Not a ``CredentialKind``: it is not a credential, it is
#: text built to make looking for one expensive, and it is refused as one.
EXPANSION_KIND = "unicode_expansion"


class ExpansionError(ValueError):
    """NFKC grew the text past ``_NFKC_GROWTH``; the fold stopped there."""


@functools.cache
def _invisible_table() -> dict[int, None]:
    """``str.translate``'s table deleting every ``_INVISIBLE`` code point.

    Built once, on first use (a pass over the code space, a few hundred ms), so
    the strip itself runs in C rather than a Python loop per character.
    """
    return {
        cp: None for cp in range(sys.maxunicode + 1) if unicodedata.category(chr(cp)) in _INVISIBLE
    }


def _without_marks(text: str) -> str:
    return text.translate(_invisible_table())


def _bounded_nfkc(text: str) -> str:
    """NFKC, a chunk at a time, stopping once the output passes the growth bound.

    Chunks end before an ASCII character, which composes with nothing before
    it, so the fold matches a whole-text NFKC wherever a credential could be.
    A run with no ASCII is cut at twice the chunk size, which can only change
    how non-ASCII text folds; no credential shape is in that.
    """
    out: list[str] = []
    start = 0
    while start < len(text):
        end = min(start + _NFKC_CHUNK, len(text))
        while end < len(text) and end < start + 2 * _NFKC_CHUNK and not text[end].isascii():
            end += 1
        folded = unicodedata.normalize("NFKC", text[start:end])
        # Per chunk, so a bomb stops at its first chunk rather than after it
        # has already built twice the whole input.
        if len(folded) > _NFKC_GROWTH * (end - start) + 16:
            raise ExpansionError
        out.append(folded)
        start = end
    return "".join(out)


def judge_input(document: str) -> str:
    """The copy L1/L2/L3 read — NOT what is forwarded upstream.

    The document is REVEALED (every escaping decoded) and then every credential
    shape is cut, so a secret — raw, percent-encoded, ``\\u``-escaped or a mix —
    never reaches the external judge in any recoverable form, while injection
    content (now decoded) is read by every layer. The original bytes are what
    each caller forwards.
    """
    return credential_redact(reveal(document))


def body_text(body: bytes) -> str:
    """A request body as text the LAYERS can read.

    A JSON body re-serialized with ``ensure_ascii=True`` (as ``/proxy/llm`` admits it)
    arrives as ``\\uXXXX`` escapes L2 cannot read and L1 does not count; parse
    and re-dump unescaped for judging. The bytes FORWARDED upstream are the
    caller's own and are not touched here.
    """
    try:
        return json.dumps(json.loads(body), ensure_ascii=False)
    except (ValueError, TypeError):
        return body.decode("utf-8", errors="replace")


def detect_credentials(document: str) -> list[str]:
    """Credential kind names in ``document`` or its unmasked form.

    A key the destination would decode — ``%41%4B...``, ``\\u0041...``, an HTML
    entity, or a mix of literal and escaped characters — or one split by a
    zero-width character or written in fullwidth must not slip the check, so the
    unmasked form (``unmasked``) is scanned when the raw one is clean.
    """
    found = credential_kinds(document)
    if not found:
        try:
            revealed = unmasked(document)
        except ExpansionError:
            return [EXPANSION_KIND]
        if revealed != document:
            found = credential_kinds(revealed)
    return sorted(k.value for k in found)


def every_credential(document: str) -> list[str]:
    """Credential kind names in ``document`` AND its unmasked form, both always.

    ``detect_credentials`` stops at the raw text when it holds one, which is
    enough to refuse; an allowlist needs both, or an ALLOWED raw kind would
    hide an escaped kind that is not.
    """
    found = credential_kinds(document)
    try:
        unmasked_form = unmasked(document)
    except ExpansionError:
        return sorted([*(k.value for k in found), EXPANSION_KIND])
    if unmasked_form != document:
        found.update(credential_kinds(unmasked_form))
    return sorted(k.value for k in found)
