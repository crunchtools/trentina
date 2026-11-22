"""The bearer tokens the gateway minted for its own profiles, by name (#635).

A profile authenticates its agent with a bearer token, and until now the only
way to name one was an environment variable. That means a new profile needs a
new variable in the container's environment, which means a restart — and it is
worse than a restart, because the candidate config fails validation before it
is ever written: ``loader._require_env`` refuses a profile whose token variable
is not set, so ``config_tool`` restores the file and the write is refused
outright. There was no way to add an agent profile to a running gateway at all.

Naming a token instead removes that, exactly as ``key_store`` did for
federation keys: ``reload_profiles`` re-runs ``load_profiles``, which re-reads
the store, so a token minted after startup is live on the next reload.

A name, not a path, for the same reason as a key: the operator passes back the
name ``profile_token`` returned, the store joins it to its own directory, and
there is no path to validate and no traversal to defend. The name's shape is
what makes the join safe, so this reuses ``key_store``'s shape rather than
inventing a second one.

A token is stored as its SHA-256 digest, ``sha256:<64 hex>``, never as the
token: the plaintext exists only in the one ``mint`` return, which the operator
hands to the agent. A token is 256 bits of randomness, so an unsalted digest
cannot be searched, and the gateway only ever needs to compare, not recall. A
file left in the old plaintext form is migrated to a digest on first load
(``read_digest``).

The store lives beside the key store and the audit database — ``/data`` in the
container — which ``tools/confine.py`` refuses to every file tool.
"""

from __future__ import annotations

import hashlib
import logging
import os
import re
import secrets
from pathlib import Path

from ..config import get_config
from . import secret_file

logger = logging.getLogger(__name__)

#: The lead-in every minted token carries. An opaque random string has no shape
#: a scrubber could recognise, unlike a PEM; this is what gives it one, so
#: ``credential_shapes`` can hold it out of a log record even somewhere nobody
#: thought to hold it by hand.
MINTED_PREFIX = "trt_"

#: 32 bytes, url-safe. The token is the whole credential for a profile.
_TOKEN_BYTES = 32

_DIGEST_RE = re.compile(r"^sha256:([0-9a-f]{64})$")


def tokens_dir() -> Path:
    """The token directory, beside the key store."""
    return Path(get_config().db_path).parent / "tokens"


def token_path(name: str) -> Path:
    """The file a token name resolves to.

    Call only with a name that matched ``key_store.KEY_NAME_RE``; that shape is
    what makes this join safe, and every caller checks it first.
    """
    return tokens_dir() / name


def ensure_tokens_dir() -> Path:
    """Create the token directory 0700, and hold it there."""
    return secret_file.private_dir("tokens")


def _encode(digest: bytes) -> bytes:
    return b"sha256:" + digest.hex().encode("ascii") + b"\n"


def mint(name: str) -> str:
    """Write the digest of a new bearer token under ``name``; return the token.

    ``secret_file.write_once`` is what refuses an existing name, so a token in
    use is never replaced underneath a live profile; rotation is a new name.

    Only the digest reaches disk. The value is NOT passed to ``logsafe.hold``:
    nothing retains it after this return, and ``credential_shapes`` recognises
    the ``trt_`` lead-in in any log record, so there is nothing to hold.
    """
    ensure_tokens_dir()
    path = token_path(name)
    token = MINTED_PREFIX + secrets.token_urlsafe(_TOKEN_BYTES)
    digest = hashlib.sha256(token.encode("utf-8")).digest()
    secret_file.write_once(path, _encode(digest))
    return token


def _fsync_dir(directory: Path) -> None:
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _write_atomic(path: Path, payload: bytes, *, tmp_suffix: str) -> None:
    """Write ``payload`` to ``path`` 0600: temp, fsync, rename, fsync the directory.

    A reader sees the old file or the whole new one, never a half-written one,
    and a power cut after return cannot bring the old one back.
    """
    staged = path.with_name(path.name + tmp_suffix)
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW
    fd = os.open(staged, flags, secret_file.FILE_MODE)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(payload)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(staged, path)
    except BaseException:
        staged.unlink(missing_ok=True)
        raise
    _fsync_dir(path.parent)


def _read_bytes(path: Path) -> bytes:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as fh:
        return fh.read()


def _parse(raw: bytes) -> bytes | None:
    match = _DIGEST_RE.match(raw.decode("utf-8", errors="replace").strip())
    return bytes.fromhex(match.group(1)) if match else None


def _migrate(path: Path, legacy: bytes) -> bytes:
    """Replace a plaintext token file with its digest, crash-safely.

    The backup goes first so the plaintext is never the only copy at the moment
    of the rename. A crash before the rename leaves the original intact and the
    rerun redoes this; a crash after it leaves a ``.bak`` the next successful
    read removes.
    """
    digest = hashlib.sha256(legacy.decode("utf-8").strip().encode("utf-8")).digest()
    bak = path.with_name(path.name + ".bak")
    _write_atomic(bak, legacy, tmp_suffix=".bak.tmp")
    _write_atomic(path, _encode(digest), tmp_suffix=".migrating")
    _confirm_digest(path, digest)
    bak.unlink(missing_ok=True)
    return digest


def _confirm_digest(path: Path, digest: bytes) -> None:
    """Refuse to drop the backup unless ``path`` now reads back as ``digest``."""
    if _parse(_read_bytes(path)) != digest:
        raise OSError(f"token {path.name!r}: migration did not read back as a digest")


def read_digest(name: str) -> bytes:
    """The stored SHA-256 of the token ``name`` (32 raw bytes), or raise.

    Read on every load and every reload, which is what makes a token minted
    after startup take effect without one. A legacy plaintext file is migrated
    here, on first load. A successful read of a digest file also removes a
    leftover ``.bak`` or ``.migrating``: that is the crash recovery.

    Raises:
        OSError: the file is missing or unreadable.
        ValueError: the file is empty.
    """
    path = token_path(name)
    raw = _read_bytes(path)
    digest = _parse(raw)
    if digest is None:
        if not raw.strip():
            raise ValueError(f"token {name!r} is empty")
        digest = _migrate(path, raw)
        logger.warning("token_store: migrated token %r from plaintext to a digest", name)
        return digest
    for suffix in (".bak", ".migrating"):
        path.with_name(path.name + suffix).unlink(missing_ok=True)
    return digest
