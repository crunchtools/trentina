"""Credential shapes: the one table of what a leaked secret looks like.

Two readers share it, in opposite directions. ``logsafe`` cuts these out of a
log record so a secret never reaches the journal an agent can read (#262,
#341). The egress and ``/proxy/llm`` request paths (#511) read it the other way: a
credential shape in a request an agent is about to send OUT is the
exfiltration signal the prompt-injection layers do not look for — L1/L2/L3
judge instructions and injected content, not key material, and there is no
other credential detector in the codebase. This module is the single
definition both use, the way ``jsonwalk`` is the one JSON walk.

Deterministic and pure: no I/O, no logging, stdlib only, so it imports before
anything else (``logsafe`` imports it at module load, and ``logsafe`` is
imported for its side effect the moment the package is). It classifies a
shape; it never decides policy — ``block`` vs ``flag`` is the caller's.

Every pattern is linear in the input: a literal lead-in followed by character
classes that exclude their own delimiter, so no start falls inside a run an
earlier start consumed. ``tests/test_credential_shapes.py`` and
``tests/test_log_scrub.py`` hold them to it, with an attack, a near-miss and a
linearity case per shape.
"""

from __future__ import annotations

import re
from collections import Counter
from enum import Enum


class CredentialKind(str, Enum):
    """A closed set: counted, audited, and named in a refusal reason.

    The names are the public contract — a refusal says ``credential_in_request``
    and the audit row carries the kind — so a value here is never renamed, only
    added to.
    """

    # The values are KIND names, not secrets. S105 reads "secret"/"token" as a
    # hardcoded credential, which is backwards here; it is turned off for this
    # file in pyproject (per-file-ignores) rather than per line.
    QUERY_SECRET = "query_secret"
    AUTHORIZATION = "authorization"
    URL_USERINFO = "url_userinfo"
    AWS_ACCESS_KEY = "aws_access_key"
    OPENAI_KEY = "openai_key"
    GOOGLE_API_KEY = "google_api_key"
    GOOGLE_OAUTH_TOKEN = "google_oauth_token"
    MATRIX_TOKEN = "matrix_token"
    GITHUB_TOKEN = "github_token"
    SLACK_TOKEN = "slack_token"
    JWT = "jwt"
    PEM_PRIVATE_KEY = "pem_private_key"
    TRENTINA_PROFILE_TOKEN = "trentina_profile_token"


# --- named shapes -----------------------------------------------------------

#: A credential in a URL query string. Group 1 is the ``?key=`` lead-in a
#: redactor keeps, so the parameter name stays readable; the value is cut.
#: Anchored on ``?``/``&`` so a codebase's own ``key=override`` prose is left
#: alone. The ``(?!\[REDACTED)`` lookahead keeps a value already named by a
#: ``hold()`` substitution from being flattened a second time.
QUERY_SECRET = re.compile(
    r"([?&](?:api[_-]?key|key|access_token|refresh_token|id_token|token"
    r"|client_secret|secret|password|passwd|sig|signature)=)"
    r"(?!\[REDACTED)[^\s&#\"'<>]+",
    re.IGNORECASE,
)

#: An ``Authorization`` value. Group 1 is the scheme a redactor keeps. Twenty
#: characters keeps prose ("Bearer token") and the bare ``Bearer`` of a
#: challenge out of it.
AUTH_VALUE = re.compile(r"\b(Bearer|Basic)\s+[A-Za-z0-9._~+/=-]{20,}", re.IGNORECASE)

#: ``scheme://user:password@host``. Group 1 is the ``://`` a redactor keeps.
USERINFO = re.compile(r"(://)[^/\s:@]{1,256}:[^/\s@]{1,1024}@")

#: A credential cannot start inside an identifier: the lead-in needs a
#: non-``[A-Za-z0-9_-]`` boundary before it.
_BOUNDARY = r"(?<![A-Za-z0-9_-])"

#: ``(kind, body)`` for every self-identifying key shape. The body carries its
#: own trailing boundary only where a fixed length needs one (AWS); a prefixed
#: shape's lead-in is already unambiguous. ``KEY_SHAPE`` is the union of these
#: bodies for ``logsafe``'s single redaction pass; ``_FINDERS`` compiles each
#: on its own so a finding keeps its kind.
_KEY_SHAPES: tuple[tuple[CredentialKind, str], ...] = (
    # OpenAI/Anthropic/OpenRouter ``sk-`` (``sk-proj-``, ``sk-ant-api03-``, ...)
    (CredentialKind.OPENAI_KEY, r"sk-[A-Za-z0-9_-]{20,}"),
    (CredentialKind.GOOGLE_API_KEY, r"AIza[0-9A-Za-z_-]{35,}"),
    (CredentialKind.GOOGLE_OAUTH_TOKEN, r"ya29\.[0-9A-Za-z._-]{20,}"),
    (CredentialKind.MATRIX_TOKEN, r"syt_[A-Za-z0-9_]{20,}"),
    # A bearer token this gateway minted for one of its own profiles (#635).
    # An opaque random string has no shape to recognise, which is the whole
    # reason token_store gives it this lead-in.
    (CredentialKind.TRENTINA_PROFILE_TOKEN, r"trt_[A-Za-z0-9_-]{20,}"),
    (CredentialKind.GITHUB_TOKEN, r"gh[pousr]_[A-Za-z0-9]{36,}"),
    (CredentialKind.GITHUB_TOKEN, r"github_pat_[A-Za-z0-9_]{22,}"),
    (CredentialKind.SLACK_TOKEN, r"xox[abprs]-[A-Za-z0-9-]{10,}"),
    (CredentialKind.JWT, r"eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"),
    # AWS access-key id: a fixed 20 chars (prefix + 16), so it needs a trailing
    # boundary where the prefixed shapes do not. ``AKIA`` long-term, ``ASIA``
    # temporary, and the other documented first pairs.
    (CredentialKind.AWS_ACCESS_KEY, r"A(?:KIA|SIA|GPA|IDA|ROA|NPA|NVA)[0-9A-Z]{16}(?![A-Za-z0-9])"),
)

#: A PEM private-key header, for DETECTION. Its own pattern, not in
#: ``KEY_SHAPE``: it opens on ``-----`` rather than an identifier, so the
#: ``_BOUNDARY`` lookbehind does not apply. Matching the header alone is enough
#: to flag an outbound request; the body need not be read.
#: ``[A-Z0-9 ]*`` (not ``(?:[A-Z0-9]+ )*``) for the optional key-type words, so
#: there is no nested quantifier to backtrack: one bounded character class.
PEM_KEY = re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----")

#: The same key, for REDACTION, consuming the body so a log line does not print
#: a ``[REDACTED]`` marker followed by the whole key (the header-only pattern
#: would). Linear: the body is ``[^-]`` or a ``-`` not starting ``-----``, each
#: character consumed once, and the ``-----END`` footer (optional, a key may be
#: logged mid-write) ends it. Not a lazy ``[\s\S]*?-----END``, which backtracks
#: quadratically on a run of ``BEGIN`` headers with no footer.
PEM_REDACT = re.compile(
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----"
    r"(?:[^-]|-(?!----))*"
    r"(?:-----END [A-Z0-9 ]*PRIVATE KEY-----)?"
)

#: The union of the key-shape bodies, for ``logsafe``'s one ``KEY_SHAPE.sub``.
KEY_SHAPE = re.compile(_BOUNDARY + "(?:" + "|".join(body for _, body in _KEY_SHAPES) + ")")

#: Every finder, kind kept, for ``find``/``kinds``. Built from the same tables
#: as the redaction patterns, so there is genuinely one source.
_FINDERS: tuple[tuple[CredentialKind, re.Pattern[str]], ...] = (
    (CredentialKind.QUERY_SECRET, QUERY_SECRET),
    (CredentialKind.AUTHORIZATION, AUTH_VALUE),
    (CredentialKind.URL_USERINFO, USERINFO),
    *((kind, re.compile(_BOUNDARY + body)) for kind, body in _KEY_SHAPES),
    (CredentialKind.PEM_PRIVATE_KEY, PEM_KEY),
)

#: The cheap prefilter: at least one of every pattern's required lead-in. A
#: line with none of these (almost every line) is checked once and left, which
#: is what keeps both the log factory and the request path cheap.
ANY_SHAPE = re.compile(
    r"[?&]|://|sk-|AIza|ya29\.|syt_|trt_|gh[pousr]_|github_pat_|xox[abprs]-|eyJ"
    r"|A(?:KIA|SIA|GPA|IDA|ROA|NPA|NVA)|-----BEGIN"
    r"|[Bb][Ee][Aa][Rr][Ee][Rr]|[Bb][Aa][Ss][Ii][Cc]"
)


# --- reading ----------------------------------------------------------------

Finding = tuple[CredentialKind, str]


def find(text: str) -> list[Finding]:
    """Every credential shape in ``text``, as ``(kind, matched text)``.

    The ``ANY_SHAPE`` prefilter skips the per-pattern scan for a line with no
    shape in it. A token that is both a query value and a known key shape
    (``?key=sk-...``) is reported under both kinds; presence, not a de-duplicated
    count, is what a caller acts on.
    """
    if ANY_SHAPE.search(text) is None:
        return []
    out: list[Finding] = []
    for kind, pattern in _FINDERS:
        out.extend((kind, m.group(0)) for m in pattern.finditer(text))
    return out


def kinds(text: str) -> Counter[CredentialKind]:
    """How many of each credential kind ``text`` holds (empty if none).

    Counts matches without materializing them: a body within the admission cap
    full of secret-shaped parameters must not amplify into a list of every
    matched string.
    """
    counter: Counter[CredentialKind] = Counter()
    if ANY_SHAPE.search(text) is None:
        return counter
    for kind, pattern in _FINDERS:
        n = sum(1 for _ in pattern.finditer(text))
        if n:
            counter[kind] += n
    return counter


def has_credential(text: str) -> bool:
    """Whether ``text`` holds any credential shape — the request-path signal."""
    if ANY_SHAPE.search(text) is None:
        return False
    return any(pattern.search(text) for _, pattern in _FINDERS)


#: What a cut credential leaves behind; matches ``logsafe.REDACTED``.
REDACTED = "[REDACTED]"


def redact(text: str, placeholder: str = REDACTED) -> str:
    """``text`` with every credential shape cut, each pattern's readable lead-in
    kept (``?key=``, the ``Bearer`` scheme, ``://...@``). The one shape pass:
    ``logsafe.scrub`` calls it after its held-secret substitution, and the
    request paths call it to build the credential-free copy an external L3 judge
    reads, so a secret never leaves in the judge input. Injection content is not
    a credential shape and is left untouched.
    """
    if ANY_SHAPE.search(text) is None:
        return text
    text = QUERY_SECRET.sub(rf"\1{placeholder}", text)
    text = AUTH_VALUE.sub(rf"\1 {placeholder}", text)
    text = USERINFO.sub(rf"\1{placeholder}@", text)
    text = KEY_SHAPE.sub(placeholder, text)
    return PEM_REDACT.sub(placeholder, text)
