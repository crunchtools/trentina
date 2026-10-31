"""Proving that a person, not an agent, is approving (#637).

``pending`` holds what is staged. This decides whether whoever is answering
the approval page is allowed to. It is deliberately the smallest possible
thing: one question, ``is this an approver``, with one answer today and room
for a second.

**Why a secret at all.** The capability to approve cannot be anything the
staging agent can read, or the mechanism protects nothing: an operator profile
that can run code on this gateway would read it and approve its own proposal.
That rules out a link in the tool result, a file under ``/data``, and anything
else the gateway hands back. What is left is a secret a person holds and the
gateway only ever *verifies*.

**Why a hash and not the password.** A gateway's config mount is readable by
anything running inside the container, so storing the password there would
hand it to exactly the caller this is defending against. A scrypt verifier
yields nothing that can be POSTed. ``hashlib.scrypt`` is stdlib, so this costs
no dependency.

**Passkeys.** A WebAuthn credential would be stronger still — the gateway
would hold only a public key, so reading its config would yield nothing at
all, and origin binding would stop a replay. It needs script on the page and
an assertion parser, which is new untrusted-bytes surface and in practice a
dependency, so it is a follow-up rather than the first cut. ``verify`` is the
seam it joins: a second method answers the same question, and either being
satisfied is enough.

With no approver configured there is no way to approve, so nothing may be
staged: ``config_tool`` refuses the two writes exactly as it did before #637.
That is the fail-closed direction — the absence of a password is the absence
of the feature, never an approval that anyone can give.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import logging
import secrets

from ..logsafe import exc_kind

logger = logging.getLogger(__name__)

#: Interactive scrypt parameters: ~16 MiB and a few tens of milliseconds, which
#: is the right trade for a secret typed by hand a handful of times ever. They
#: are stored IN the verifier, so raising them later does not strand an old one.
#: scrypt's cost as a power of two, its block size, and its parallelism.
_COST_LOG2 = 14
_BLOCK_SIZE = 8
_PARALLELISM = 1
_N = 2**_COST_LOG2
_SALT_BYTES = 16
_PREFIX = "scrypt"

#: Short enough to type, long enough that 30 attempts an hour (the approval
#: route's rate limit) is not a search. Enforced when the verifier is MADE,
#: which is the only place the password itself is ever seen.
MIN_PASSWORD_CHARS = 12


def make_verifier(password: str) -> str:
    """A verifier string for ``password``, to put in the gateway's config.

    The only function here that sees a password rather than a verifier, and it
    is not reachable from a request: it exists for the operator-side helper
    that prints one.
    """
    if len(password) < MIN_PASSWORD_CHARS:
        raise ValueError(f"an approval password must be at least {MIN_PASSWORD_CHARS} characters")
    salt = secrets.token_bytes(_SALT_BYTES)
    derived = hashlib.scrypt(
        password.encode("utf-8"), salt=salt, n=_N, r=_BLOCK_SIZE, p=_PARALLELISM
    )
    return "$".join(
        (
            _PREFIX,
            str(_N),
            str(_BLOCK_SIZE),
            str(_PARALLELISM),
            base64.b64encode(salt).decode(),
            base64.b64encode(derived).decode(),
        )
    )


def _matches(password: str, verifier: str) -> bool:
    """Whether ``password`` derives ``verifier``. Never raises.

    A malformed verifier is a configuration error that must not become an
    approval, so every way of failing to parse one answers False. The
    comparison is ``compare_digest`` so a wrong password takes the same time as
    a right one.
    """
    try:
        prefix, n, r, p, salt, expected = verifier.strip().split("$")
        if prefix != _PREFIX:
            return False
        derived = hashlib.scrypt(
            password.encode("utf-8"),
            salt=base64.b64decode(salt),
            n=int(n),
            r=int(r),
            p=int(p),
        )
    except (ValueError, TypeError, MemoryError) as exc:
        logger.warning("approval: the configured verifier could not be read: %s", exc_kind(exc))
        return False
    return hmac.compare_digest(derived, base64.b64decode(expected))


def configured() -> bool:
    """Whether an approver is configured at all.

    Read on every call rather than cached, so a verifier added by a deploy and
    a reload takes effect without a restart — and so removing it takes effect
    just as fast, which is the direction that matters.
    """
    return _verifier() is not None


def _verifier() -> str | None:
    from .loader import read_secret_env

    held = read_secret_env("TRENTINA_APPROVAL_PASSWORD_HASH", record=False)
    return held.strip() or None if held else None


def verify(password: str | None) -> bool:
    """Whether this request is from someone who may approve.

    The seam a second method joins. Fail-closed on every path: no verifier
    configured, nothing presented, or anything that does not match, is not an
    approver.
    """
    verifier = _verifier()
    if verifier is None or not password:
        return False
    return _matches(password, verifier)

