"""Read tools — block_read, flag_read and redact_read."""

from __future__ import annotations

import asyncio
import os
import stat
from typing import Any

from ..config import get_config
from ..errors import FileReadError
from ..gateway.scope import check_blocklist
from ..models import ALLOWED_TEXT_EXTENSIONS
from ..modes import Mode
from ..orchestrator import judge_and_deliver
from .confine import REFUSAL_REASONS, open_confined, refused
from .preprocess import prepare

MAX_FILE_SIZE = 2_000_000
BINARY_CHECK_BYTES = 8192

_EXTENSIONLESS_ALLOWED = frozenset(
    {
        "makefile",
        "dockerfile",
        "containerfile",
        "readme",
        "license",
        "changelog",
        "authors",
        "contributors",
    }
)


def _read_confined(path: str) -> tuple[str, str]:
    """Open ``path`` through confinement (#261) and return (text, resolved path).

    Every check after the open reads the descriptor, never the path again,
    so what is checked is what is read.

    Blocking, and whole: ``read_file`` runs it in ONE worker thread, so the
    confinement checks, the open and the read all happen in the same call and
    nothing is split across threads or back onto the event loop (#267).
    """
    opened = open_confined(path, "file")
    fd, st, resolved = opened.fd, opened.st, opened.path
    with os.fdopen(fd, "rb") as fh:
        if not stat.S_ISREG(st.st_mode):
            raise FileReadError("not_a_file")
        if st.st_size > MAX_FILE_SIZE:
            raise FileReadError("too_large", f"{st.st_size} bytes, max {MAX_FILE_SIZE}")

        suffix = resolved.suffix.lower()
        if suffix and suffix not in ALLOWED_TEXT_EXTENSIONS:
            raise FileReadError("unsupported_type")
        if not suffix and resolved.name.lower() not in _EXTENSIONLESS_ALLOWED:
            raise FileReadError("unsupported_type", "no extension")

        # One byte past the cap, so a file that grew after fstat is caught too.
        raw = fh.read(MAX_FILE_SIZE + 1)
    if len(raw) > MAX_FILE_SIZE:
        raise FileReadError("too_large", f"max {MAX_FILE_SIZE} bytes")
    if b"\x00" in raw[:BINARY_CHECK_BYTES]:
        raise FileReadError("binary")
    return raw.decode("utf-8", errors="replace"), str(resolved)


async def read_file(
    path: str, mode: Mode, prompt: str | None = None, preprocess: Any = None
) -> dict[str, Any]:
    """Read one text file, then hand it to the one judging path.

    ``preprocess`` is the agent's ``trentina_preprocess``. Omitted, nothing
    runs but the policy's floor: an agent that reads a file usually means to
    edit it, and needs the bytes on disk. ``true`` minifies it by format.
    """
    try:
        content, resolved = await asyncio.to_thread(_read_confined, path)
    except FileReadError as exc:
        if exc.reason not in REFUSAL_REASONS:
            raise
        raise refused(exc, mode) from exc

    blocked = check_blocklist(resolved, mode)

    page = await prepare(content, requested=preprocess, tool="read_tool", source=resolved)
    return await judge_and_deliver(
        page.content,
        mode=mode,
        family="read",
        source=resolved,
        source_type="file",
        kind="file",
        ref=resolved,
        prompt=prompt,
        allowlisted=get_config().is_trusted_path(resolved),
        blocklisted=blocked,
        provenance=page.provenance,
        precomputed_l1=page.pipeline,
        l3_context=page.briefing,
        extras=page.extras,
        redact_extras=page.extras,
    )


async def block_read(path: str) -> dict[str, Any]:
    """Refuse a flagged or incompletely judged file; otherwise the exact bytes."""
    return await read_file(path, Mode.BLOCK)


async def flag_read(path: str) -> dict[str, Any]:
    """The bytes on disk, with the verdict attached when there is one."""
    return await read_file(path, Mode.FLAG)


async def redact_read(path: str, prompt: str) -> dict[str, Any]:
    """A verified L3 extraction instead of the file."""
    return await read_file(path, Mode.REDACT, prompt)
