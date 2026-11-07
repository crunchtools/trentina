"""Where a ``unix://`` backend may connect (#724), on the ``tools/confine.py`` model.

A socket path is the operator's, never an agent's, but where the gateway may
connect is still a list someone wrote down: ``TRENTINA_SOCKET_ROOTS``. Unset,
no ``unix://`` backend loads.

Checked twice. At load, the path as written (normalized) must sit under a
root, so a typo fails the file and not the first call. At connect, the
socket's directory is opened one component at a time under ``O_NOFOLLOW``
(``confine._walk_open``), its resolved path held to the roots again, and the
socket itself ``lstat``'d through that descriptor: a socket, not a link. The
connect goes through ``/proc/self/fd/<dir>/<name>``, so it reaches the
directory that was checked even if a link is swapped in above it afterwards.
What remains is the socket's own name in that directory, which only whoever
can write the operator's socket directory can replace.

Refusals are a closed set of reason codes and never carry the path: the
journal is readable through other backends (#262).
"""

from __future__ import annotations

import errno
import os
import stat
from contextlib import contextmanager
from pathlib import Path
from typing import TYPE_CHECKING
from urllib.parse import urlsplit

if TYPE_CHECKING:
    from collections.abc import Iterator

#: The longest socket file name admitted. ``sun_path`` is 108 bytes and the
#: connect goes through ``/proc/self/fd/<n>/<name>``, so the name must leave
#: room for that prefix.
MAX_SOCKET_NAME = 80

#: Why a socket was refused. Closed: a refusal names one of these and nothing else.
REASONS = frozenset(
    {
        "no_socket_roots",
        "outside_socket_roots",
        "not_found",
        "not_a_socket",
        "changed_during_connect",
    }
)


class SocketRefusedError(Exception):
    """A ``unix://`` backend's socket was refused, for ``reason`` alone."""

    def __init__(self, reason: str) -> None:
        if reason not in REASONS:
            raise ValueError(f"{reason!r} is not a socket refusal reason")
        super().__init__(reason)
        self.reason = reason


def socket_path(url: str) -> str:
    """The absolute socket path a ``unix://`` URL names, or ``ValueError``.

    ``unix:///abs/path``: no host, query, fragment or ``%`` escape, nothing a
    normalization would change, and a file name ``MAX_SOCKET_NAME`` bytes long
    at most.
    """
    parts = urlsplit(url)
    path = parts.path
    if parts.scheme != "unix" or parts.netloc or parts.query or parts.fragment:
        raise ValueError("a unix:// backend URL is unix:///<absolute path>, nothing else")
    if not path.startswith("/") or "%" in path or "\0" in path:
        raise ValueError("a unix:// backend URL names an absolute path without escapes")
    if os.path.normpath(path) != path or path.endswith("/"):
        raise ValueError("a unix:// backend URL's path must already be normalized")
    if len(os.path.basename(path).encode()) > MAX_SOCKET_NAME:
        raise ValueError(f"a socket file name is at most {MAX_SOCKET_NAME} bytes")
    return path


def _under(path: Path, roots: tuple[Path, ...]) -> bool:
    return any(path.is_relative_to(root) for root in roots)


def check_written(path: str) -> None:
    """At load: ``path`` as written sits under a root, touching no filesystem.

    Compared against the roots as configured and as resolved, as
    ``confine.check_lexical`` does, so a root spelled through a symlinked
    directory admits paths spelled the same way.
    """
    from ..config import get_config

    config = get_config()
    if not config.socket_roots:
        raise SocketRefusedError("no_socket_roots")
    if not _under(Path(os.path.abspath(path)), config.socket_roots + config.socket_roots_written):
        raise SocketRefusedError("outside_socket_roots")


@contextmanager
def admitted(path: str) -> Iterator[str]:
    """At connect: the path to connect to, bound to the directory that was checked.

    Yields ``/proc/self/fd/<dir>/<name>`` while the directory is held open.

    Raises:
        SocketRefusedError: outside the roots, missing, not a socket, or a
            link found where the check saw none.
    """
    from ..config import get_config
    from ..tools.confine import _WALK_FLAGS, _walk_open

    check_written(path)
    directory, name = os.path.split(path)
    try:
        resolved = Path(directory).resolve(strict=True)
    except (OSError, RuntimeError):
        raise SocketRefusedError("not_found") from None
    if not _under(resolved, get_config().socket_roots):
        raise SocketRefusedError("outside_socket_roots")
    try:
        fd = _walk_open(resolved, _WALK_FLAGS)
    except FileNotFoundError:
        raise SocketRefusedError("not_found") from None
    except OSError as exc:
        if exc.errno in (errno.ELOOP, errno.ENOTDIR):
            raise SocketRefusedError("changed_during_connect") from None
        raise SocketRefusedError("not_found") from None
    try:
        try:
            found = os.stat(name, dir_fd=fd, follow_symlinks=False)
        except FileNotFoundError:
            raise SocketRefusedError("not_found") from None
        if not stat.S_ISSOCK(found.st_mode):
            raise SocketRefusedError("not_a_socket")
        yield f"/proc/self/fd/{fd}/{name}"
    finally:
        os.close(fd)
