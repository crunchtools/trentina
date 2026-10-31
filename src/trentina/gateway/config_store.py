"""Writing ``profiles.yaml`` safely, and keeping what was there before (#633).

Scott's requirement for an API-driven config was "changes should be logged,
backed up, version controlled". This module is the backed-up part, and the
mechanics of replacing the file without ever leaving it half-written.

Backups live under the gateway's own data directory, NOT beside the live file.
On lotor the config directory is a git repository with a Nagios drift check on
it, so a backup written next to ``profiles.yaml`` would trip that check on
every write. Version control is the operator agent's job on the host, where it
has git; the gateway's job is to make sure the previous bytes still exist.

The gateway cannot commit for itself: the runtime image is distroless and ships
no ``git``, and ``gateway/git_transport.py`` is a smart-HTTP proxy for a
caller's own client, not a way to author a commit.
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path

from ..config import get_config

#: How many previous versions of the file to keep. Enough to walk back a bad
#: sequence of writes by hand; not so many that the directory becomes a place
#: secrets accumulate unnoticed.
KEEP_BACKUPS = 20

BACKUP_DIR_MODE = 0o700
BACKUP_FILE_MODE = 0o600

#: Sortable, so pruning is "drop the lowest names", and unique per content, so
#: two writes in the same second cannot collide.
_BACKUP_STEM = "profiles"


def config_hash(text: str) -> str:
    """The hash an operator passes back as ``expect_hash``.

    Of the TEXT, not the parsed config: it has to change when a comment
    changes, because a comment is part of what a hand edit may have written.
    """
    return hashlib.sha256(text.encode()).hexdigest()


def backups_dir() -> Path:
    """Where previous versions live: the data directory, never the config one."""
    return Path(get_config().db_path).parent / "config-backups"


def back_up(text: str, *, after_hash: str, now: float) -> Path:
    """Keep ``text`` as a previous version, pruning to ``KEEP_BACKUPS``.

    The name carries the timestamp, the hash of what is INSIDE the file and the
    hash of what replaced it. That makes the backup the change record: it joins
    to the ``gateway_calls`` row for the call by time, and to the next write by
    hash, without a second audit mechanism and without writing a caller-chosen
    path into a log (#262).

    ``now`` is passed in rather than read here so a test can write a known
    sequence, and so two writes within one clock tick still get distinct names
    from the hashes.

    ``mkdir(mode=)`` is masked by the umask and does nothing to a directory
    that already exists, so the explicit ``chmod`` is what decides the mode.
    """
    directory = backups_dir()
    directory.mkdir(mode=BACKUP_DIR_MODE, parents=True, exist_ok=True)
    os.chmod(directory, BACKUP_DIR_MODE)

    stamp = f"{int(now):011d}-{config_hash(text)[:12]}-{after_hash[:12]}"
    path = directory / f"{_BACKUP_STEM}-{stamp}.yaml"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, BACKUP_FILE_MODE)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(text)
    for stale in sorted(directory.glob(f"{_BACKUP_STEM}-*.yaml"))[:-KEEP_BACKUPS]:
        stale.unlink(missing_ok=True)
    return path


def replace_config(path: Path, text: str) -> None:
    """Put ``text`` at ``path`` atomically, or leave the file exactly as it was.

    The staging file is in the SAME directory, because ``os.replace`` is only
    atomic within one filesystem and the config directory may be its own mount.
    A reader never sees a partial file: it sees the old inode or the new one.

    The staged name is fixed rather than random on purpose. The directory is
    the gateway's own config directory, writable only by the gateway's user, so
    predictability buys an attacker nothing; what it buys us is that a crash
    leaves one identifiable leftover instead of an unbounded litter of them.
    ``O_TRUNC`` rather than ``O_EXCL`` so such a leftover cannot wedge every
    later write.

    The replacement inherits the mode the file already had. ``os.replace``
    swaps the inode, so writing the staged file at some mode of our own
    choosing would silently re-permission a file the operator mounted
    deliberately — tightening it is as much of a surprise as loosening it.
    """
    staged = path.with_name(f".{path.name}.staged")
    try:
        mode = os.stat(path).st_mode & 0o777
    except OSError:
        mode = BACKUP_FILE_MODE
    fd = os.open(staged, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    try:
        # open()'s mode is masked by the umask, and a leftover staged file keeps
        # whatever mode it already had, so set it on the descriptor.
        os.fchmod(fd, mode)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(staged, path)
    except BaseException:
        staged.unlink(missing_ok=True)
        raise
