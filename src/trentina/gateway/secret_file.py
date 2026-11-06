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

Everything here lives under ``get_config().db_path``'s directory — ``/data`` in
the container — which ``tools/confine.py`` refuses to every file tool.
"""

from __future__ import annotations

import os
from pathlib import Path

from ..config import get_config

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
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def replace_atomically(path: Path, payload: bytes) -> None:
    """Put ``payload`` at ``path`` 0600, replacing whatever was there.

    For the one secret that is MEANT to be replaced: an approval password a
    person changes. Staged and renamed rather than truncated and rewritten,
    because a half-written verifier would lock approvals out until somebody
    noticed.
    """
    staged = path.with_name(path.name + ".staged")
    fd = os.open(staged, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, FILE_MODE)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(payload)
        os.replace(staged, path)
    except BaseException:
        staged.unlink(missing_ok=True)
        raise
