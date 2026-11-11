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

**Passkeys (#639).** The second method, and the stronger one: the gateway
holds only a public key, so reading its data directory yields nothing at all,
and the browser's origin binding stops a phished or replayed approval.
``webauthn`` checks the ceremony; this module keeps the credentials, under
``/data`` beside the password, at most ``MAX_PASSKEYS``. Either method is
enough, and ``configured`` means any method — so a gateway can drop its
password once a passkey is enrolled, which is where #639 wanted to end up.

With no approver configured there is no way to approve, so nothing may be
staged: ``config_tool`` refuses the two writes exactly as it did before #637.
That is the fail-closed direction — the absence of a password is the absence
of the feature, never an approval that anyone can give.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import secrets
import threading
import time
from pathlib import Path
from typing import Any

from ..config import get_config
from ..logsafe import exc_kind, hold
from . import secret_file, webauthn

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
    """Whether an approver is configured at all: a password or a passkey.

    Read on every call rather than cached, so a password set through the
    enrolment page, or a verifier added by a deploy, takes effect at once — and
    so removing one takes effect just as fast, which is the direction that
    matters.
    """
    return has_password() or bool(passkeys())


def has_password() -> bool:
    """Whether a password approves here: pinned by the deployment or stored."""
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
    except FileNotFoundError:
        # The ordinary case on a gateway nobody has enrolled yet.
        return None
    except OSError as exc:
        # A permission or I/O problem is an operational fault, not first-time
        # setup, and reads identically to one unless it is said out loud. Still
        # fail closed: nothing configured means nothing can be approved.
        logger.warning("approval: the verifier store could not be read: %s", exc_kind(exc))
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
    if pinned_by_deployment():
        raise ApproverError("The password is pinned by this gateway's deployment.")
    verifier = make_verifier(password)
    secret_file.private_dir(_STORE_DIR)
    secret_file.replace_atomically(_store_path(), verifier.encode("utf-8"))
    logger.info("approval: an approval password was set")


#: How long an operator-opened enrolment window stands, as
#: ``gateway.approval_enrol_window_seconds`` in ``profiles.yaml``. A setting
#: rather than a constant because how long is enough belongs to the
#: deployment: an agent relaying the URL into a chat read on a phone needs a
#: round trip, an operator at the same keyboard as the browser needs seconds.
#: Fifteen minutes by default (RT#1609): long enough that an agent relaying the
#: link into a chat read on a phone finishes the handoff without re-opening,
#: since the window is the one interval in which this gateway's approver can be
#: claimed. Bounded both ways — a minute is not actionable, and an hour is where
#: "short" stops being true.
DEFAULT_ENROL_WINDOW_SECONDS = 900.0
MIN_ENROL_WINDOW_SECONDS = 60.0
MAX_ENROL_WINDOW_SECONDS = 3600.0


def clamped_enrol_window(seconds: float) -> float:
    """``seconds`` brought inside the bounds, which is always the safe way.

    Clamping rather than refusing, because both directions are safe here —
    shortening an over-long window and lengthening an unusable one each leave
    the code as the control — and a reload refused over a cosmetic bound would
    strand every other change in the same file.
    """
    return max(MIN_ENROL_WINDOW_SECONDS, min(MAX_ENROL_WINDOW_SECONDS, seconds))


def enrol_window_seconds() -> float:
    """How long the NEXT window will stand, from the running configuration.

    Read here rather than held, so a reload takes effect without a restart.
    An open window keeps the length it was opened with (see
    ``open_enrolment``): a config write must not be able to extend a window
    somebody is already inside.
    """
    from .loader import get_active_config

    active = get_active_config()
    if active is None:
        return DEFAULT_ENROL_WINDOW_SECONDS
    return clamped_enrol_window(active.config.approval_enrol_window_seconds)


#: Lowercase letters and digits with the confusable set removed (0 1 i l o), so
#: a person can read the code off the chat and type it into the browser without
#: a lookalike. 31 symbols, 12 of them: ~59 bits, far past guessing inside a
#: window at the approval route's rate limit.
_CODE_ALPHABET = "abcdefghjkmnpqrstuvwxyz23456789"
_CODE_LEN = 12

_window_opened: float | None = None
#: The code as stored and compared: lowercase, no hyphens.
_window_code: str | None = None
#: When ``_window_code`` was minted. A code stands across re-opens until this is
#: ``MAX_ENROL_WINDOW_SECONDS`` old, so re-opening never invalidates a link a
#: person already holds (RT#1609).
_code_minted: float | None = None
_window_seconds: float = DEFAULT_ENROL_WINDOW_SECONDS


def _mint_code() -> str:
    return "".join(secrets.choice(_CODE_ALPHABET) for _ in range(_CODE_LEN))


def normalise_code(code: str) -> str:
    """The code as stored, from whatever a person typed or a link carried:
    lowercase, with the display hyphens and any stray whitespace removed."""
    return "".join(code.split()).replace("-", "").lower()


def display_code(code: str) -> str:
    """The code grouped for reading and typing: ``xxxx-xxxx-xxxx``."""
    return "-".join(code[i : i + 4] for i in range(0, len(code), 4))


def enrol_seconds_left() -> int:
    """Whole seconds a person still has on the open window, or 0 when none is."""
    if _window_opened is None:
        return 0
    return max(0, int(_window_seconds - (time.monotonic() - _window_opened)))


def open_enrolment() -> tuple[int, str]:
    """Open the window in which a first password may be set.

    Returns how long it stands and the one-time code that must be presented
    with the new password.

    **Why the code is returned to the agent, when the approval password is
    deliberately never returned to anything.** They defend against different
    callers, and each is closed by a different half:

    - The INTERNET can reach this route — the gateway is public — and could
      otherwise claim a brand-new gateway's approver during the window simply
      by being first. The code stops that: a scanner does not have it.
    - The OPERATOR AGENT has the code and still cannot use it, because setting
      a password is a POST and none of Trentina's tools makes one: ``fetch`` is
      GET-only, and ``/proxy/http`` reaches only operator-named upstreams bound
      at startup. It can ask for the prompt and not answer it.

    So the code is not the capability to approve; it is proof that a person was
    pointed here by this gateway's own operator. A profile that also holds a
    code-execution backend defeats this, as it defeats every other control on
    the gateway — see docs/deployment-hardening.md.
    """
    global _window_opened, _window_code, _window_seconds, _code_minted
    now = time.monotonic()
    _window_seconds = enrol_window_seconds()
    # Keep the code a person may already hold. Re-opening — an agent calling
    # again, or a window that ran out — must not invalidate the link already in
    # the chat; that silent rotation was the stale-link failure (RT#1609). Mint
    # afresh only when there is no code, or one has stood for its hard cap.
    capped = _code_minted is not None and now - _code_minted > MAX_ENROL_WINDOW_SECONDS
    if _window_code is None or _code_minted is None or capped:
        _window_code = _mint_code()
        _code_minted = now
        hold(_window_code, "ENROLMENT_CODE")
        hold(display_code(_window_code), "ENROLMENT_CODE")
    _window_opened = now
    logger.info("approval: enrolment opened for %.0fs", _window_seconds)
    return int(_window_seconds), display_code(_window_code)


def enrolling(code: str | None = None) -> bool:
    """Whether a first password may be set right now, by this caller.

    Three conditions, and each closes a different way in. Nothing configured,
    so this can never replace a working password — that takes the current one.
    A window an operator opened, so a gateway with no password is not a
    standing offer. And the code from that window, so being able to reach the
    route is not enough.

    Called with no code to ask whether the window itself is open, which is what
    the page needs to decide what to render.
    """
    if configured() or _window_opened is None or _window_code is None:
        return False
    if time.monotonic() - _window_opened > _window_seconds:
        return False
    if code is None:
        return True
    return hmac.compare_digest(normalise_code(code).encode("utf-8"), _window_code.encode("utf-8"))


def close_enrolment() -> None:
    """Shut the window: once an approver is set, on the operator's ``close``,
    and by tests."""
    global _window_opened, _window_code, _window_seconds, _code_minted
    _window_opened = None
    _window_code = None
    _code_minted = None
    _window_seconds = DEFAULT_ENROL_WINDOW_SECONDS


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


#: How many passkeys one gateway keeps. A person has a phone, a laptop and a
#: hardware key or two; more than this is a store somebody is filling.
MAX_PASSKEYS = 8

_PASSKEYS = "passkeys.json"
_NAME_CHARS = 40

#: Every read-modify-write of the passkey store, so a sign-in's counter update
#: and a removal cannot interleave and bring a deleted passkey back.
_STORE_LOCK = threading.Lock()


class ApproverError(Exception):
    """A credential change refused for a reason a person can act on. The
    message is fixed text, never anything the caller sent."""


def _passkeys_path() -> Path:
    return _store_path().parent / _PASSKEYS


def _read_store() -> list[dict[str, Any]]:
    try:
        raw = _passkeys_path().read_text(encoding="utf-8")
    except FileNotFoundError:
        return []
    except OSError as exc:
        logger.warning("approval: the passkey store could not be read: %s", exc_kind(exc))
        return []
    try:
        stored = json.loads(raw)
    except (ValueError, RecursionError) as exc:
        stored, problem = None, exc_kind(exc)
    else:
        problem = "shape"
    entries = stored.get("passkeys") if isinstance(stored, dict) else None
    if not isinstance(entries, list):
        # Fail closed: an unreadable or misshapen store is no passkeys, never
        # any passkey, and never an exception on the approval routes.
        logger.warning("approval: the passkey store is malformed: %s", problem)
        return []
    return [entry for entry in entries if isinstance(entry, dict)][:MAX_PASSKEYS]


def _write_store(entries: list[dict[str, Any]]) -> None:
    secret_file.private_dir(_STORE_DIR)
    payload = json.dumps({"version": 1, "passkeys": entries}, indent=1, sort_keys=True)
    secret_file.replace_atomically(_passkeys_path(), payload.encode("utf-8"))


def passkeys() -> list[dict[str, Any]]:
    """What a person may see of each enrolled passkey: never the key itself."""
    return [
        {
            "id": entry.get("id", ""),
            "name": entry.get("name", "Passkey"),
            "created": entry.get("created", 0),
            "last_used": entry.get("last_used"),
        }
        for entry in _read_store()
    ]


def _credential(entry: dict[str, Any]) -> webauthn.Credential | None:
    try:
        return webauthn.Credential(
            credential_id=webauthn.from_b64url(entry["id"], limit=webauthn.MAX_CREDENTIAL_ID),
            spki=base64.b64decode(entry["spki"]),
            alg=int(entry["alg"]),
            rp_id=str(entry["rp_id"]),
            origin=str(entry["origin"]),
            sign_count=int(entry.get("sign_count", 0)),
        )
    except (KeyError, ValueError, TypeError, webauthn.WebAuthnError):
        return None


def credential_digest(credential_id: str) -> str:
    """What an audit row or a log line may say about a credential."""
    return "sha256:" + hashlib.sha256(credential_id.encode("ascii", "replace")).hexdigest()[:12]


def clean_name(name: object) -> str:
    """A label a person typed for a passkey, cut to something a page shows."""
    text = " ".join(str(name or "").split())[:_NAME_CHARS]
    return "".join(ch for ch in text if ch.isprintable()) or "Passkey"


def add_passkey(credential: webauthn.Credential, name: object) -> str:
    """Keep ``credential``; returns its id. The caller has authorised this."""
    cred_id = webauthn.b64url(credential.credential_id)
    with _STORE_LOCK:
        entries = _read_store()
        if any(entry.get("id") == cred_id for entry in entries):
            raise ApproverError("That passkey is already enrolled here.")
        if len(entries) >= MAX_PASSKEYS:
            raise ApproverError(
                f"This gateway already keeps {MAX_PASSKEYS} passkeys. Remove one first."
            )
        entries.append(
            {
                "id": cred_id,
                "spki": base64.b64encode(credential.spki).decode("ascii"),
                "alg": credential.alg,
                "rp_id": credential.rp_id,
                "origin": credential.origin,
                "name": clean_name(name),
                "created": int(time.time()),
                "last_used": None,
                "sign_count": credential.sign_count,
            }
        )
        _write_store(entries)
    logger.info("approval: a passkey was enrolled %s", credential_digest(cred_id))
    return cred_id


def remove_passkey(cred_id: str) -> None:
    """Forget one passkey. The last way to approve is never removed here."""
    with _STORE_LOCK:
        entries = _read_store()
        kept = [entry for entry in entries if entry.get("id") != cred_id]
        if len(kept) == len(entries):
            raise ApproverError("That passkey is not enrolled here.")
        if not kept and not has_password():
            raise ApproverError(
                "That is the only way left to approve on this gateway. Add another first."
            )
        _write_store(kept)
    logger.info("approval: a passkey was removed %s", credential_digest(cred_id))


def remove_password() -> None:
    """Drop the stored password, once a passkey can take its place."""
    if pinned_by_deployment():
        raise ApproverError("The password is pinned by this gateway's deployment.")
    with _STORE_LOCK:
        if not _read_store():
            raise ApproverError(
                "The password is the only way to approve on this gateway. Add a passkey first."
            )
        _store_path().unlink(missing_ok=True)
    logger.info("approval: the stored approval password was deleted")


def verify_passkey(
    cred_id: str, *, client_data: bytes, auth_data: bytes, signature: bytes, challenge: bytes
) -> bool:
    """Whether the passkey ``cred_id`` signed ``challenge``. Never raises.

    Fail-closed on every path: an unknown credential, a malformed stored
    entry, and every ceremony failure are all simply not an approver. The
    counter and last-used time are written back only on success, and an
    ``OSError`` writing them propagates.
    """
    with _STORE_LOCK:
        entries = _read_store()
        entry = next((item for item in entries if item.get("id") == cred_id), None)
        credential = _credential(entry) if entry is not None else None
        if entry is None or credential is None:
            return False
        try:
            count = webauthn.verify_assertion(
                credential,
                client_data=client_data,
                auth_data=auth_data,
                signature=signature,
                challenge=challenge,
            )
        except webauthn.WebAuthnError as exc:
            logger.info("approval: a passkey did not verify: %s", exc.reason)
            return False
        # Written before answering yes: a counter that could not be recorded
        # would let the same assertion count twice, so a store that cannot be
        # written fails the sign-in.
        entry["sign_count"] = count
        entry["last_used"] = int(time.time())
        _write_store(entries)
    return True
