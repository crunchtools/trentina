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
import time
from pathlib import Path

from ..config import get_config
from ..logsafe import exc_kind
from . import secret_file

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

_STORE_DIR = "approval"


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

    Read on every call rather than cached, so a password set through the
    enrolment page, or a verifier added by a deploy, takes effect at once — and
    so removing one takes effect just as fast, which is the direction that
    matters.
    """
    return _verifier() is not None


def _store_path() -> Path:
    """Where a password set through the enrolment page is kept.

    Beside the key and token stores, under ``/data``, which
    ``tools/confine.py`` refuses to every file tool. The config mount is
    read-only by design, so a password set at runtime cannot live there.
    """
    return Path(get_config().db_path).parent / _STORE_DIR / "verifier"


def _verifier() -> str | None:
    """The configured verifier: the environment first, then the store.

    The environment wins so a deploy can pin one and an enrolled password
    cannot quietly override what an administrator put in the image's config.
    """
    from .loader import read_secret_env

    held = read_secret_env("TRENTINA_APPROVAL_PASSWORD_HASH", record=False)
    if held and held.strip():
        return held.strip()
    try:
        stored = _store_path().read_text(encoding="utf-8").strip()
    except OSError:
        return None
    return stored or None


def pinned_by_deployment() -> bool:
    """Whether the verifier came from the environment rather than the store.

    A deployment that pinned one is saying the password is not the gateway's to
    change, so the enrolment page says so instead of offering to.
    """
    from .loader import read_secret_env

    held = read_secret_env("TRENTINA_APPROVAL_PASSWORD_HASH", record=False)
    return bool(held and held.strip())


def set_password(password: str) -> None:
    """Write the verifier for ``password``, replacing any stored one.

    Atomic, because a half-written verifier would lock approvals out until
    somebody noticed. The caller decides WHETHER this may happen — either an
    open enrolment window with nothing configured yet, or a correct current
    password — and this does not second-guess it.
    """
    verifier = make_verifier(password)
    secret_file.private_dir(_STORE_DIR)
    secret_file.replace_atomically(_store_path(), verifier.encode("utf-8"))
    logger.info("approval: an approval password was set")


#: How long an operator-opened enrolment window stands. Long enough to walk to
#: a browser, short enough that an abandoned one is not a standing invitation.
ENROL_WINDOW_SECONDS = 600

_window_opened: float | None = None


def open_enrolment() -> int:
    """Open the window in which a first password may be set; return its length.

    An operator agent asks for this, which is the whole point — it can request
    that a person be prompted, exactly as ``backend_auth`` does for a backend
    sign-in. What it cannot do is answer the prompt: setting the password is a
    POST, and Trentina's own tools do not make one.
    """
    global _window_opened
    _window_opened = time.monotonic()
    logger.info("approval: enrolment opened for %ds", ENROL_WINDOW_SECONDS)
    return ENROL_WINDOW_SECONDS


def enrolling() -> bool:
    """Whether a first password may be set right now.

    Both conditions, and both matter. Nothing configured, so this can never
    replace a working password — that takes the current one. And a window an
    operator opened, so a gateway sitting with no password is not a standing
    offer to whoever reaches the page first.
    """
    if _verifier() is not None or _window_opened is None:
        return False
    return time.monotonic() - _window_opened <= ENROL_WINDOW_SECONDS


def close_enrolment() -> None:
    """Shut the window. Called once a password is set, and by tests."""
    global _window_opened
    _window_opened = None


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

