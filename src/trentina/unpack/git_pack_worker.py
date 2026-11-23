"""The git pack reader as a child process (spec 027).

A pack is a format an attacker controls, and reading one inflates up to
``Limits.max_inflated`` bytes and resolves deltas, which is CPU a thread
cannot be made to give back: a thread cannot be stopped, a process can. So
``git_pack.PackReader`` runs here, under CPU and address-space limits, in an
environment with no credential (``child.environment``), started by
``gateway.git_fetch`` with a constant argument list of numbers and a
directory the gateway chose, and killed at the fetch's judging deadline.

The pack arrives on stdin as it streams in. Each object it resolves is
written to stdout as one header line, ``<kind> <oid> <offset> <length>``,
then its content; the stream ends with ``end`` or ``refused <reason>``, a
reason from ``git_pack.REASONS``. The parent checks every header for shape
and every length against the limit before it reads the content.
"""

from __future__ import annotations

import os
import resource
import sys
from typing import IO, TYPE_CHECKING

from .git_pack import Limits, PackReader, PackRefusedError

if TYPE_CHECKING:
    from collections.abc import Iterable

    from .git_pack import PackObject

MEMORY_BYTES = 3 * 1024 * 1024 * 1024
"""Address space: one object at its largest, inflated, beside the reader's
own state. Bases are spooled to disk, not held."""

READ_BYTES = 1024 * 1024
"""What is read from stdin at a time."""

ARGUMENTS = 5
"""argv after the program: object format, arrived bytes, inflated bytes,
CPU seconds, spool directory."""


def _send(out: IO[bytes], objects: Iterable[PackObject]) -> None:
    for obj in objects:
        out.write(
            b"%s %s %d %d\n" % (obj.kind.encode(), obj.oid.encode(), obj.offset, len(obj.content))
        )
        out.write(obj.content)


def main(argv: list[str]) -> int:
    if len(argv) != ARGUMENTS + 1:
        return 2
    object_format, arrived, inflated, cpu, spool = argv[1:]
    seconds = int(cpu)
    resource.setrlimit(resource.RLIMIT_CPU, (seconds, seconds))
    resource.setrlimit(resource.RLIMIT_AS, (MEMORY_BYTES, MEMORY_BYTES))
    reader = PackReader(
        object_format=object_format,
        limits=Limits(max_arrived=int(arrived), max_inflated=int(inflated)),
        spool_dir=spool,
    )
    stdin, out = sys.stdin.fileno(), sys.stdout.buffer
    try:
        # A pipe read returns what has arrived, so objects go out as the pack comes in.
        while piece := os.read(stdin, READ_BYTES):
            _send(out, reader.feed(piece))
        _send(out, reader.finish())
        out.write(b"end\n")
    except PackRefusedError as refused:
        out.write(b"refused %s\n" % refused.reason.encode())
    finally:
        reader.close()
        out.flush()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
