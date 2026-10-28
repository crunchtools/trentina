"""Where read_tool and dir_tool may look (#261).

Both tools take a path from the agent, and until #261 neither asked where it
pointed: ``read_tool /config/profiles.yaml`` delivered every profile's
topology and the credentials inside backend URLs. The rule here is default
deny behind a gateway:

- ``TRENTINA_READ_ROOTS`` lists the directories a path may resolve into.
  A live gateway with none configured refuses every path — production leaves
  it unset on purpose, since the gateway container has no agent workspace.
  A standalone server with none keeps its old reach: one operator, their
  own files.
- ``HARD_DENIED`` and Trentina's own state and config directories are
  refused even when a root would admit them. A root of ``/`` does not
  open ``/proc/self/environ``.

Checking a path and then opening it is a race: swap a component for a
symlink in between and the open lands somewhere the check never saw.
``open_confined`` closes it three ways. ``O_NOFOLLOW`` refuses a symlink in
the final component; ``fstat`` must match the inode stat'd at check time;
and the kernel's own name for the opened descriptor is checked again, which
catches a swapped INTERMEDIATE directory that the other two follow.

Refusals carry a reason code and never the path (see ``FileReadError``).

Since #287 the open itself is a walk: one ``openat`` per component of the
resolved path, each with ``O_NOFOLLOW``, from ``/`` down. A symlink swapped
into ANY component is refused by the kernel at that step, so the walk alone
lands on the path that was checked, and the ``/proc/self/fd`` check above is
a second witness rather than the only one (it is absent where ``/proc`` is).
The checked stat must already be the file type the caller asked for, so a
FIFO or device node in a root is refused before it is ever opened, and a
file whose inode is one of Trentina's own (a hard link from inside a root to
the blocklist, say) is denied like the path it is linked from.

Two more rules since #263 and #278:

- The denylist and roots are checked on the path as written, lexically
  normalized, BEFORE anything is resolved, and again on the resolved path.
  Resolving first answered ``not_found`` for a missing path and
  ``denied_path`` for an existing denied one: a file-existence oracle over
  the container, one bit per call.
- Behind a live gateway, ``not_found``, ``denied_path`` and
  ``outside_read_roots`` are one reason, ``not_found_or_denied``. A symlink
  inside a root that points somewhere denied still has to be resolved to be
  refused, and only the merge keeps that from telling a caller whether its
  target exists. Standalone keeps the three apart: one operator, their own
  files.

A refusal reaches the caller the way the egress guard's does (``refused``):
a ``BlockedSourceError`` with no alternatives, which the router audits as
``blocked_defense``. It was a ``FileReadError`` until #278, audited as
``backend_error``, which filed a hijacked agent's probing as breakage.
"""

from __future__ import annotations

import errno
import os
import stat
from dataclasses import InitVar, dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Literal

from ..config import get_config
from ..errors import BlockedSourceError, FileReadError
from ..gateway.loader import get_active_config
from ..seal import UNSEALED, Seal, require

if TYPE_CHECKING:
    from ..modes import Mode

HARD_DENIED = ("/config", "/data", "/proc", "/sys", "/run", "/dev")
_FD_DIR = Path("/proc/self/fd")


_ADMISSION_REASONS = frozenset({"not_found", "denied_path", "outside_read_roots"})
GATEWAY_REASON = "not_found_or_denied"

REFUSAL_REASONS = frozenset(_ADMISSION_REASONS | {GATEWAY_REASON, "changed_during_read"})
"""Reasons delivered as a refusal (``refused``) rather than a read failure."""


def _refuse(reason: str) -> FileReadError:
    """The refusal for ``reason``, merged behind a live gateway (see the module doc)."""
    if reason in _ADMISSION_REASONS and get_active_config() is not None:
        return FileReadError(GATEWAY_REASON)
    return FileReadError(reason)


def _own_paths() -> list[str]:
    config = get_config()
    own = [config.db_path, config.perimeter_db_path, config.trust_config_path]
    active = get_active_config()
    if active is not None:
        own.append(str(active.path))
    return own


def denied_dirs() -> list[Path]:
    """Directories no root can admit: the kernel's, and Trentina's own state and config."""
    dirs = [Path(d).resolve() for d in HARD_DENIED]
    dirs += [Path(p).resolve().parent for p in _own_paths()]
    return dirs


def _denied_dirs_written() -> list[Path]:
    """``denied_dirs`` as configured, unresolved, for the lexical check."""
    dirs = [Path(d) for d in HARD_DENIED]
    dirs += [Path(os.path.abspath(p)).parent for p in _own_paths()]
    return dirs


def _admit(path: Path, denied: list[Path], roots: tuple[Path, ...]) -> None:
    if any(path.is_relative_to(d) for d in denied):
        raise _refuse("denied_path")
    if roots:
        if not any(path.is_relative_to(r) for r in roots):
            raise _refuse("outside_read_roots")
    elif get_active_config() is not None:
        raise _refuse("outside_read_roots")


def check(resolved: Path) -> None:
    """Refuse a fully resolved path that is denied or outside every root."""
    _admit(resolved, denied_dirs(), get_config().read_roots)


def check_lexical(path: str) -> None:
    """Refuse ``path`` as written, normalized but not resolved, touching no filesystem.

    Compared against the denylist and roots both as configured and resolved,
    so a root spelled through a symlinked directory (a home directory that is
    a link on an image-based host) admits paths spelled the same way. Denying
    on either spelling can only refuse more; ``check`` still runs on the
    resolved path, which is the one that decides what is opened.
    """
    lexical = Path(os.path.abspath(path))
    config = get_config()
    _admit(
        lexical,
        _denied_dirs_written() + denied_dirs(),
        config.read_roots + config.read_roots_written,
    )


def confine(path: str) -> Path:
    """Refuse ``path`` unless admitted as written and again once resolved (it must exist)."""
    check_lexical(path)
    try:
        resolved = Path(path).resolve(strict=True)
    except (OSError, RuntimeError):
        raise _refuse("not_found") from None
    check(resolved)
    return resolved


def refused(exc: FileReadError, mode: Mode) -> BlockedSourceError:
    """A confinement refusal, delivered like the egress guard's (#278).

    No alternatives: no mode reads a path confinement refused. The source is
    a constant, not the path: the caller knows what it sent, and the message
    must not carry a string the caller chose (#262).
    """
    reason = f"confinement refused ({exc.reason})"
    return BlockedSourceError(
        "path",
        reason,
        refusal={
            "reason": reason,
            "mode": mode.value,
            "flagged_by": "confinement",
            "alternatives": [],
        },
    )


def _opened_path(fd: int) -> Path | None:
    """The kernel's name for an open descriptor, or None where /proc is absent."""
    try:
        return Path(os.readlink(_FD_DIR / str(fd)))
    except OSError:
        return None


def _own_inodes() -> set[tuple[int, int]]:
    """Every (dev, ino) in Trentina's own state and config directories."""
    inodes: set[tuple[int, int]] = set()
    for directory in {Path(p).resolve().parent for p in _own_paths()}:
        try:
            with os.scandir(directory) as it:
                for entry in it:
                    st = entry.stat(follow_symlinks=False)
                    inodes.add((st.st_dev, st.st_ino))
        except OSError:
            continue
    return inodes


def _verify_opened(fd: int, checked: os.stat_result) -> os.stat_result:
    """Refuse an fd that is not the inode checked, or whose real path is not admitted."""
    opened = os.fstat(fd)
    if (opened.st_dev, opened.st_ino) != (checked.st_dev, checked.st_ino):
        raise FileReadError("changed_during_read")
    actual = _opened_path(fd)
    if actual is not None:
        check(actual)
    # A directory cannot be hard-linked; a file with one link is only itself.
    linked = opened.st_nlink > 1 and stat.S_ISREG(opened.st_mode)
    if linked and (opened.st_dev, opened.st_ino) in _own_inodes():
        raise _refuse("denied_path")
    return opened


_WALK_FLAGS = getattr(os, "O_PATH", os.O_RDONLY) | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC


def _walk_open(resolved: Path, flags: int) -> int:
    """Open ``resolved`` one component at a time, following no symlink anywhere.

    ``resolved`` has no symlinks (``confine`` resolved it), so a link met
    here was swapped in after the check: ``O_NOFOLLOW`` makes the final open
    fail with ELOOP, and ``O_DIRECTORY`` makes an intermediate one fail with
    ENOTDIR. Both are ``changed_during_read``.
    """
    parent = os.open("/", _WALK_FLAGS)
    try:
        for part in resolved.parts[1:-1]:
            child = os.open(part, _WALK_FLAGS, dir_fd=parent)
            os.close(parent)
            parent = child
        return os.open(resolved.name or "/", flags, dir_fd=parent)
    finally:
        os.close(parent)


FileKind = Literal["file", "dir"]


@dataclass(frozen=True)
class ResolvedPath:
    """A path that passed confinement AND was opened read-only under ``O_NOFOLLOW``.

    One of Trentina 3.0's unforgeable trust types (``tests/test_seal.py``):
    holding one is proof that ``confine()`` admitted the path as written and
    resolved, the ``O_NOFOLLOW`` walk bound the descriptor to what was admitted,
    and the fstat is the descriptor's own. Only ``open_confined`` constructs it,
    so no other code can hand ``read_tool`` / ``dir_tool`` a path claiming to be
    confined. The caller closes ``fd``.
    """

    fd: int
    st: os.stat_result
    path: Path
    _seal: InitVar[Seal] = UNSEALED

    def __post_init__(self, _seal: Seal) -> None:
        require(_seal, _PATH_SEAL, "ResolvedPath")


#: The token ``open_confined`` holds to build a ``ResolvedPath``; see ``core.seal``.
_PATH_SEAL = Seal("open_confined")


def open_confined(path: str, kind: FileKind) -> ResolvedPath:
    """Open ``path`` read-only if confinement admits it; the caller closes the fd.

    Returns a ``ResolvedPath`` — the descriptor, its ``fstat`` and the resolved
    path, the three of them proof confinement ran. ``kind`` is the file type the
    caller reads: anything else is refused before the open, so a FIFO cannot hang
    it and a device is never opened at all. The returned stat is the descriptor's
    own and is of that type too.
    """
    resolved = confine(path)
    try:
        checked = os.stat(resolved)
    except OSError:
        raise _refuse("not_found") from None
    is_dir = stat.S_ISDIR(checked.st_mode)
    if kind == "dir" and not is_dir:
        raise FileReadError("not_a_directory")
    if kind == "file" and not stat.S_ISREG(checked.st_mode):
        raise FileReadError("not_a_file")
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_NOCTTY | os.O_CLOEXEC
    if is_dir:
        flags |= os.O_DIRECTORY
    try:
        # TRUST: opening a caller-supplied path
        #   untrusted: `path`, and every directory on it a caller can write
        #   judged-by: confine() as written and resolved; the walk, inode and
        #     /proc checks bind the descriptor to what confine() admitted
        #   on-failure: fail-closed (changed_during_read or a merged refusal)
        #   owner: confine.open_confined
        #   evidence: T1 openat O_NOFOLLOW fails ELOOP, O_DIRECTORY ENOTDIR; T3 #261 #287
        fd = _walk_open(resolved, flags)
    except OSError as exc:
        # ELOOP and ENOTDIR are a symlink that was not there at check time.
        swapped = exc.errno in (errno.ELOOP, errno.ENOTDIR)
        raise (FileReadError("changed_during_read") if swapped else _refuse("not_found")) from None
    try:
        opened = _verify_opened(fd, checked)
    except BaseException:
        os.close(fd)
        raise
    return ResolvedPath(fd=fd, st=opened, path=resolved, _seal=_PATH_SEAL)
