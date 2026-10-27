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

import json
import re
from urllib.parse import unquote

from ..credential_shapes import kinds as credential_kinds
from ..credential_shapes import redact as credential_redact

# The closed reason codes an outbound refusal carries. Credential first: it is
# the most specific and actionable.
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
    """Credential kind names in ``document`` or its revealed form.

    A key the destination would decode — ``%41%4B...``, ``\\u0041...``, or a mix
    of literal and escaped characters — must not slip the check, so the revealed
    form (``reveal``) is scanned when the raw one is clean.
    """
    found = credential_kinds(document)
    if not found:
        revealed = reveal(document)
        if revealed != document:
            found = credential_kinds(revealed)
    return sorted(k.value for k in found)
