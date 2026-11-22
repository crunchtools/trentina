"""Writing a secret to a private file under the gateway's data directory.

Three stores keep one: federation keys (``key_store``), profile bearer tokens
(``token_store``) and the approval verifier (``approver``). They had three
copies of the same two disciplines, which is two too many for the part that is
actually load-bearing:

- The directory is 0700, set by an explicit ``chmod`` as well as ``mkdir``.
  ``mkdir(mode=)`` is masked by the umask and does nothing at all to a
  directory that already exists, so the ``chmod`` is the one that decides.
- A file that must not be replaced is created with ``O_EXCL``, which refuses an
  existing file, a planted file and a symlink in one move; a write that fails
  part way is unlinked, so the name stays free rather than becoming
  permanently unusable.
- Both are fsynced, and so is the directory after a rename, so a crash
  leaves either the old file or the new one and never a torn one.

Everything here lives under ``get_config().db_path``'s directory — ``/data`` in
the container — which ``tools/confine.py`` refuses to every file tool.
"""

from __future__ import annotations

import fcntl
import os
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import TYPE_CHECKING

from ..config import get_config

if TYPE_CHECKING:
    from collections.abc import Iterator

DIR_MODE = 0o700
FILE_MODE = 0o600


def private_dir(name: str) -> Path:
    """Create ``<data>/<name>`` 0700 and return it.

    The ``chmod`` is not redundant: see the module docstring.
    """
    directory = Path(get_config().db_path).parent / name
    directory.mkdir(mode=DIR_MODE, parents=True, exist_ok=True)
    os.chmod(directory, DIR_MODE)
    return directory


def write_once(path: Path, payload: bytes) -> None:
    """Create ``path`` 0600 with ``payload``, refusing to replace anything.

    For a secret a name is bound to for its lifetime: a key in use is never
    replaced underneath a live link, and a token in use never underneath a live
    profile. Rotation is a new name, not a second write.

    Raises:
        FileExistsError: the name is taken. The caller turns that into its own
            refusal, because what to say about it is the caller's business.
    """
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, FILE_MODE)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(payload)
            fh.flush()
            os.fsync(fh.fileno())
    except BaseException:
        path.unlink(missing_ok=True)
        raise
    _fsync_dir(path.parent)


def replace_atomically(path: Path, payload: bytes) -> None:
    """Put ``payload`` at ``path`` 0600, replacing whatever was there.

    For a secret that is MEANT to be replaced: an approval password a person
    changes, a rotated outside credential, and a file ``at_rest`` seals or
    reseals. Staged, fsynced and renamed rather than truncated and rewritten,
    because a half-written verifier would lock approvals out until somebody
    noticed, and a half-written sealed key would lose the key. A staged file
    a crash left behind is truncated by the next write; ``O_NOFOLLOW``
    refuses one planted as a symlink.
    """
    staged = path.with_name(path.name + ".staged")
    fd = os.open(staged, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, FILE_MODE)
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


def _fsync_dir(directory: Path) -> None:
    """Make a create or a rename in ``directory`` durable."""
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


class _DirLock:
    """One store directory's lock: a thread lock in this process, ``flock`` across them."""

    __slots__ = ("depth", "fd", "thread_lock")

    def __init__(self) -> None:
        self.thread_lock = threading.RLock()
        self.depth = 0
        self.fd = -1


_locks: dict[Path, _DirLock] = {}
_locks_guard = threading.Lock()


@contextmanager
def locked(directory: Path) -> Iterator[None]:
    """Hold ``directory`` exclusively against every other writer, in any process.

    ``secret_store put`` runs as its own process through ``podman exec``, while
    the gateway may be sealing the same file; without this, a ``--replace``
    landing between the gateway's read and its write is silently undone.
    ``flock`` is per open file, so a second open in this process would wait on
    the first: the thread lock makes the hold reentrant, and nested holds share
    one ``flock``.
    """
    with _locks_guard:
        lock = _locks.setdefault(directory, _DirLock())
    with lock.thread_lock:
        if lock.depth == 0:
            lock.fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
            fcntl.flock(lock.fd, fcntl.LOCK_EX)
        lock.depth += 1
        try:
            yield
        finally:
            lock.depth -= 1
            if lock.depth == 0:
                os.close(lock.fd)  # closing the descriptor releases the flock
