"""Sealing the secrets the gateway keeps on its data volume (#868).

Federation private keys (``key_store``) and profile secrets (``secret_store``)
were 0600 plaintext under ``/data``, so a copy of the volume was a copy of
every credential in it. Each is now sealed under one key-encryption key, the
KEK, which never touches the volume: ``TRENTINA_SECRETS_KEK`` or, preferably,
the file ``TRENTINA_SECRETS_KEK_FILE`` names.

The KEK is a list, one key per line, newest first. Each line is stretched to a
Fernet key with HKDF and the list becomes a ``MultiFernet``: the first key
seals, any key opens. Rotating is adding a new first line and restarting.
Every file is read at startup, and one opened by any key but the first is
resealed under the first, so after one start the old line can go.

A file is sealed when it starts with ``SEALED_MAGIC``; anything else is a
legacy plaintext file, migrated on read whenever there is a KEK. Migration
is idempotent and survives a crash at any point: the plaintext is first copied
to ``<name>.bak``, the sealed form is staged, fsynced and renamed over the
original, and the ``.bak`` is removed only once the sealed file has been read
back. A crash before the rename leaves the original as it was, and the next
read starts again; a crash after it leaves a ``.bak`` that the next successful
sealed read removes. Every store's name shape refuses a dot, so neither a
``.bak`` nor a staged file is ever read as a secret.

Without a KEK the gateway still starts, says so loudly on every start, and
keeps writing plaintext. ``TRENTINA_REQUIRE_HARDENED`` turns that, and a KEK
that is malformed or opens nothing on the volume, into a refusal to start.

Nothing here logs a value or a key; names are the operator's configuration.
"""

from __future__ import annotations

import base64
import contextlib
import errno
import hashlib
import logging
import os
from pathlib import Path
from typing import TYPE_CHECKING, Literal

from ..config import bool_env, get_config
from ..errors import ConfigError
from ..logsafe import exc_kind
from . import secret_file
from .errors import ProfileConfigError

if TYPE_CHECKING:
    from cryptography.fernet import Fernet, MultiFernet

logger = logging.getLogger(__name__)

KEK_ENV = "TRENTINA_SECRETS_KEK"
#: Characters per line. Length is not entropy, but a key this short was
#: typed, not generated; the docs say ``openssl rand -base64 48``.
MIN_KEY_CHARS = 32
#: What a sealed file starts with. A Fernet token is url-safe base64, so it can
#: never begin with this by accident, and nor can a PEM or a token.
SEALED_MAGIC = b"trentina-sealed:v1\n"
BACKUP_SUFFIX = ".bak"
#: What a migration or ``replace_atomically`` leaves beside a file when a crash
#: cuts it short; each may hold plaintext.
_LEFTOVER_SUFFIXES = (BACKUP_SUFFIX, ".staged", BACKUP_SUFFIX + ".staged")

#: The stores whose every file is sealed, by directory under ``<data>``.
SEALED_DIRS = ("keys", "secrets")

_HKDF_SALT = b"trentina-at-rest"


class _Kek:
    """The configured KEK: the first key seals, any key opens.

    ``writable`` False is a KEK that failed its startup check: it still opens
    what it can, but nothing is sealed, migrated or resealed under it, so a
    wrong or mistyped key never locks the right one out.
    """

    __slots__ = ("count", "fingerprint", "multi", "primary", "writable")

    def __init__(self, derived: list[bytes]) -> None:
        from cryptography.fernet import Fernet, MultiFernet

        fernets = [Fernet(key) for key in derived]
        self.primary = fernets[0]
        self.multi: MultiFernet = MultiFernet(fernets)
        self.count = len(fernets)
        #: Names the first key in a log line without revealing it: an operator
        #: compares it across starts to spot a wrong or mistyped key.
        self.fingerprint = hashlib.sha256(derived[0]).hexdigest()[:8]
        self.writable = True


#: None: not configured yet; False: configured, and there is no KEK.
_kek: _Kek | Literal[False] | None = None


def _derive(line: str) -> bytes:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF

    raw = HKDF(algorithm=hashes.SHA256(), length=32, salt=_HKDF_SALT, info=b"fernet").derive(
        line.encode()
    )
    return base64.urlsafe_b64encode(raw)


def _read_kek() -> _Kek | None:
    """The KEK from the environment, None when neither form is set, or raise
    ``ConfigError`` saying what is wrong with it."""
    from .loader import read_secret_env

    try:
        value = read_secret_env(KEK_ENV, record=False)
    except ProfileConfigError as exc:
        raise ConfigError(str(exc)) from exc
    if not value:
        return None
    lines = [line.strip() for line in value.splitlines() if line.strip()]
    if not lines:
        raise ConfigError(f"{KEK_ENV} is empty")
    for number, line in enumerate(lines, start=1):
        if len(line) < MIN_KEY_CHARS:
            raise ConfigError(
                f"{KEK_ENV} line {number} is under {MIN_KEY_CHARS} characters; "
                "generate one with `openssl rand -base64 48`"
            )
    return _Kek([_derive(line) for line in lines])


def configure() -> bool:
    """Read the KEK once, at startup, and seal every file on the volume with it.

    Call before the first profile load (which reads keys and secrets) and
    before ``envscrub`` drops the variable. Returns whether there is a KEK.

    Raises:
        ConfigError: ``TRENTINA_REQUIRE_HARDENED`` is set and the KEK is
            missing, malformed, or opens nothing on the volume; or, hardened or
            not, the KEK is malformed (a typo'd KEK is never silently none).
    """
    global _kek
    hardened = bool_env("TRENTINA_REQUIRE_HARDENED", False)
    kek = _read_kek()
    _kek = kek or False
    if kek is None:
        message = (
            f"at-rest: neither {KEK_ENV} nor {KEK_ENV}_FILE is set; federation keys "
            "and stored secrets are kept UNSEALED on the data volume, where a copy of "
            "it is a copy of every one. See docs/deployment-hardening.md."
        )
    else:
        message = _seal_volume(kek)
        if not message:
            return True
    if hardened:
        raise ConfigError(f"TRENTINA_REQUIRE_HARDENED is set and {message}")
    logger.warning("%s", message)
    return kek is not None


def _seal_volume(kek: _Kek) -> str:
    """Seal the stores under ``kek``; "" when done, else why nothing more was written.

    A KEK that cannot open every sealed file, or a disk that cannot take the
    writes, leaves the KEK read-only for the life of the process.
    """
    try:
        failed = seal_all(kek)
    except OSError as exc:
        kek.writable = False
        code = errno.errorcode.get(exc.errno or 0, "no errno")
        reason = (
            "the data volume is full"
            if exc.errno == errno.ENOSPC
            else f"{exc_kind(exc)} ({code}) while sealing the stores"
        )
        return (
            f"at-rest: sealing under {KEK_ENV} (key {kek.fingerprint}) stopped: {reason}; "
            "what was sealed stays sealed and nothing more is written"
        )
    if failed:
        kek.writable = False
        return (
            f"at-rest: {len(failed)} sealed file(s) do not open with any key in "
            f"{KEK_ENV} (first key {kek.fingerprint}): {', '.join(failed)}; nothing "
            "was sealed or resealed. Check the key; a wrong one would lock out the right one"
        )
    logger.info(
        "at-rest: secrets sealed under %s (first key %s, %d key(s))",
        KEK_ENV,
        kek.fingerprint,
        kek.count,
    )
    return ""


def _current() -> _Kek | None:
    """The KEK, reading the environment once when ``configure`` never ran.

    That covers the ``secret_store`` CLI and tests; the gateway itself calls
    ``configure`` at startup, before ``envscrub`` drops the variable.
    """
    global _kek
    if _kek is None:
        _kek = _read_kek() or False
    return _kek or None


def reset() -> None:
    """Forget the KEK, so the next use reads it again. For tests."""
    global _kek
    _kek = None


def seal(plaintext: bytes) -> bytes:
    """``plaintext`` as it should be written: sealed when there is a KEK.

    Raises:
        ProfileConfigError: there is a KEK and it is read-only this run.
    """
    kek = _current()
    if kek is None:
        return plaintext
    if not kek.writable:
        # A KEK is configured, so plaintext is never the answer; nor is
        # sealing under a key that failed its startup check.
        raise ProfileConfigError(
            f"at-rest: {KEK_ENV} failed its startup check, so nothing new is written "
            "until it is fixed and the gateway restarted"
        )
    return SEALED_MAGIC + kek.primary.encrypt(plaintext)


def _decrypt(fernet: Fernet | MultiFernet, token: bytes) -> bytes | None:
    from cryptography.fernet import InvalidToken

    try:
        return fernet.decrypt(token)
    except InvalidToken:
        return None


def _open(kek: _Kek, path: Path, sealed: bytes) -> tuple[bytes, bool]:
    """The plaintext, and whether it was sealed under a key other than the first."""
    token = sealed[len(SEALED_MAGIC) :]
    plaintext = _decrypt(kek.primary, token)
    if plaintext is not None:
        return plaintext, False
    plaintext = _decrypt(kek.multi, token)
    if plaintext is None:
        raise ProfileConfigError(f"{path.name} is sealed and no key in {KEK_ENV} opens it")
    return plaintext, True


def read(path: Path) -> bytes:
    """The plaintext of the secret at ``path``, sealing or resealing it on the way.

    ``O_NOFOLLOW`` refuses a symlink planted in a store's directory. Held under
    the store's lock, so a ``secret_store put --replace`` in another process
    lands before or after this, never between its read and its write.

    Raises:
        OSError: as ``os.open`` does; ``FileNotFoundError`` for an absent file.
        ProfileConfigError: the file is sealed and no KEK opens it.
    """
    with secret_file.locked(path.parent):
        return _read_locked(path)


def _read_locked(path: Path) -> bytes:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as fh:
        stored = fh.read()
    kek = _current()
    if not stored.startswith(SEALED_MAGIC):
        # An empty file is a write not yet made, never a secret to seal: sealing
        # it would swap the inode a writer still holds open for an empty one.
        if kek is not None and kek.writable and stored:
            _migrate(kek, path, stored)
        return stored
    if kek is None:
        raise ProfileConfigError(
            f"{path.name} is sealed and neither {KEK_ENV} nor {KEK_ENV}_FILE is set"
        )
    plaintext, stale = _open(kek, path, stored)
    if stale and kek.writable:
        secret_file.replace_atomically(path, SEALED_MAGIC + kek.primary.encrypt(plaintext))
    # The first sealed read retires every plaintext copy a migration, or a
    # write a crash cut short, left beside it.
    for suffix in _LEFTOVER_SUFFIXES:
        path.with_name(path.name + suffix).unlink(missing_ok=True)
    return plaintext


def _migrate(kek: _Kek, path: Path, plaintext: bytes) -> None:
    """Replace a plaintext file with its sealed form; see the module docstring."""
    backup = path.with_name(path.name + BACKUP_SUFFIX)
    secret_file.replace_atomically(backup, plaintext)
    secret_file.replace_atomically(path, SEALED_MAGIC + kek.primary.encrypt(plaintext))
    # Read it back before the plaintext copy goes: a sealed file nothing can
    # open must not be the only copy left.
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW), "rb") as fh:
        check, _ = _open(kek, path, fh.read())
    if check != plaintext:
        raise ProfileConfigError(f"{path.name}: sealed copy did not read back; {backup.name} kept")
    backup.unlink(missing_ok=True)


def _store_files(base: Path) -> list[Path]:
    """Every secret file in the sealed stores; never a ``.bak`` or staged file."""
    files: list[Path] = []
    for store in SEALED_DIRS:
        directory = base / store
        if directory.is_dir():
            files.extend(
                path
                for path in sorted(directory.iterdir())
                if "." not in path.name.removesuffix(".pem")
                and not path.is_symlink()
                and path.is_file()
            )
    return files


def seal_all(kek: _Kek) -> list[str]:
    """Seal every plaintext file and reseal every stale one, in two passes.

    The first pass writes nothing: it checks that every file already sealed
    opens under ``kek``. If one does not, the KEK is wrong or its first line
    mistyped, and sealing anything under it would lock out the right key, so
    the names come back and nothing is written. Only then does the second pass
    read each file, which seals or reseals it. Both passes hold every store's
    lock, so ``secret_store put`` in another process waits for them.

    Raises:
        OSError: a write failed part way, the disk full among the causes. What
            was sealed is whole; the rest is as it was.
    """
    base = Path(get_config().db_path).parent
    with contextlib.ExitStack() as held:
        for store in SEALED_DIRS:
            if (base / store).is_dir():
                held.enter_context(secret_file.locked(base / store))
        files = _store_files(base)
        failed = [
            f"{path.parent.name}/{path.name}"
            for path in files
            if (stored := path.read_bytes()).startswith(SEALED_MAGIC)
            and _decrypt(kek.multi, stored[len(SEALED_MAGIC) :]) is None
        ]
        if failed:
            return failed
        for path in files:
            read(path)
    return []
