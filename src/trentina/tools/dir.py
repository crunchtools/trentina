"""Directory tools — block_dir, flag_dir and redact_dir.

A directory listing is a payload like any other: file names are text an
attacker chose, and a name can be an instruction. So the listing crosses all
three layers, and the mode decides what is delivered.

This replaces ``quarantine_scan_dir``, a diagnostic that ran L1 and L2 on
every ``.py`` file (up to 500 of them) and returned a bespoke
``recommendation`` string. Module shadowing — a ``struct.py`` that Python
imports instead of the real one — is now an L1 detector (``ShadowStats``)
whose any-hit risk is critical, so a shadowed directory is refused by block,
redacted by redact and flagged by flag through the same rule as everything
else. File CONTENTS are not read here; that is ``*_read``, one file at a
time, all three layers.
"""

from __future__ import annotations

import asyncio
import os
from itertools import islice
from typing import Any

from ..config import get_config
from ..errors import FileReadError
from ..l1.pipeline import run_l1
from ..l1.shadows import ShadowScanResult, ShadowStats, scan_shadows
from ..modes import Mode
from ..orchestrator import judge_and_deliver
from .confine import REFUSAL_REASONS, open_confined, refused
from .judged import check_blocklist

MAX_DIR_ENTRIES = 500


def _entry(entry: os.DirEntry[str]) -> dict[str, Any]:
    if entry.is_symlink():
        kind = "symlink"
    elif entry.is_dir(follow_symlinks=False):
        kind = "dir"
    elif entry.is_file(follow_symlinks=False):
        kind = "file"
    else:
        kind = "other"
    size = entry.stat(follow_symlinks=False).st_size if kind == "file" else None
    return {"name": entry.name, "type": kind, "size": size}


def _list_confined(path: str) -> tuple[list[dict[str, Any]], str, ShadowScanResult]:
    """Open ``path`` through confinement, list it and scan it, all in the calling thread.

    Blocking: ``list_dir`` runs it in ONE worker thread, so the confinement
    checks, the open and the listing through that descriptor never cross a
    thread or touch the event loop (#267).

    The shadow scan reads the SAME entries through the SAME descriptor
    (#287). It re-listed by path until then, which followed symlinks out of
    the root and could see a different directory from the one delivered.
    """
    opened = open_confined(path, "dir")
    fd, confined = opened.fd, opened.path
    resolved = str(confined)
    try:
        # Listed through the checked descriptor, and lazily: a directory of a
        # million entries costs MAX_DIR_ENTRIES + 1 reads, not a million.
        with os.scandir(fd) as it:
            found = list(islice(it, MAX_DIR_ENTRIES + 1))
        if len(found) > MAX_DIR_ENTRIES:
            raise FileReadError("too_many_entries", f"max {MAX_DIR_ENTRIES}")
        entries = sorted((_entry(e) for e in found), key=lambda e: e["name"])
        shadows = scan_shadows(fd, found, resolved)
    finally:
        os.close(fd)
    return entries, resolved, shadows


async def list_dir(path: str, mode: Mode, prompt: str | None = None) -> dict[str, Any]:
    try:
        entries, resolved, shadows = await asyncio.to_thread(_list_confined, path)
    except FileReadError as exc:
        # A confinement refusal (#278), or a directory swapped during the
        # open: both are refusals, never a read error.
        if exc.reason not in REFUSAL_REASONS:
            raise
        raise refused(exc, mode) from exc

    blocked = check_blocklist(resolved, mode)

    listing = "\n".join(
        f"{e['name']}\t{e['type']}\t{e['size'] if e['size'] is not None else '-'}" for e in entries
    )
    pipeline = await asyncio.to_thread(run_l1, listing)
    pipeline.stats.shadows = ShadowStats.from_result(shadows)

    briefing = None
    if shadows.has_shadows:
        # Module names come from the stdlib list, not from the directory.
        modules = ", ".join(sorted({f.shadows_module for f in shadows.shadows_found}))
        briefing = (
            f"{len(shadows.shadows_found)} entr(ies) in this directory shadow "
            f"Python standard-library modules ({modules}). Python run from here "
            "would import them instead of the real modules."
        )

    obfuscated_autoexec = [f.filename for f in shadows.autoexec_found if f.is_obfuscated]
    if obfuscated_autoexec:
        # Names come from the fixed auto-execute registry, not from the directory.
        briefing = (briefing + " " if briefing else "") + (
            f"{len(obfuscated_autoexec)} file(s) a tool runs by name hold obfuscated code "
            f"({', '.join(sorted(obfuscated_autoexec))})."
        )

    shadow_fields = [
        {
            "file": f.filename,
            "shadows_module": f.shadows_module,
            "obfuscated": f.is_obfuscated,
        }
        for f in shadows.shadows_found
    ]
    return await judge_and_deliver(
        listing,
        mode=mode,
        family="dir",
        source=resolved,
        source_type="file",
        kind="dir",
        ref=resolved,
        prompt=prompt,
        allowlisted=get_config().is_trusted_path(resolved),
        blocklisted=blocked,
        precomputed_l1=pipeline,
        l3_context=briefing,
        extras={"entries": entries, "shadows": shadow_fields},
    )


async def block_dir(path: str) -> dict[str, Any]:
    """Refuse a flagged or shadowed directory; otherwise its listing."""
    return await list_dir(path, Mode.BLOCK)


async def flag_dir(path: str) -> dict[str, Any]:
    """The listing, with the verdict attached when there is one."""
    return await list_dir(path, Mode.FLAG)


async def redact_dir(path: str, prompt: str) -> dict[str, Any]:
    """A verified L3 extraction of the listing, never the names themselves."""
    return await list_dir(path, Mode.REDACT, prompt)
