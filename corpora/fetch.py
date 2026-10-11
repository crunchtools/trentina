"""Fetching a pinned third-party corpus: download, hash check, cache.

A corpus this repo does not vendor (``corpora.jailbreak``,
``corpora.injecagent``) is downloaded on first use into ``corpora/data/``
(gitignored) and checked against a SHA-256 written beside its loader, so a
result names exactly the rows it was measured on.
"""

from __future__ import annotations

import hashlib
import os
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING

import httpx

if TYPE_CHECKING:
    from collections.abc import Callable

CACHE_DIR = Path(__file__).resolve().parent / "data"

MAX_DOWNLOAD_BYTES = 5 * 1024 * 1024
"""The constitution's cap on a fetched response. The largest file is 1.3 MB."""


def download(target: str, transport: httpx.BaseTransport | None = None) -> bytes:
    """Stream ``target``, refusing it past ``MAX_DOWNLOAD_BYTES``."""
    body = bytearray()
    with (
        httpx.Client(transport=transport, follow_redirects=True, timeout=60.0) as client,
        client.stream("GET", target) as response,
    ):
        response.raise_for_status()
        for chunk in response.iter_bytes():
            body += chunk
            if len(body) > MAX_DOWNLOAD_BYTES:
                raise ValueError(f"{target} exceeds {MAX_DOWNLOAD_BYTES} bytes")
    return bytes(body)


def pinned(cached: Path, expected: str, fetch: Callable[[], bytes], what: str) -> bytes:
    """A pinned file, from ``cached`` when its hash still matches, else fetched.

    A fetched file that does not match ``expected`` (a SHA-256) is refused,
    never cached: a benchmark measured on different rows than it names is
    worse than one that does not run. ``what`` names the file in that error.
    """
    usable = cached.is_file() and not cached.is_symlink()
    if usable and cached.stat().st_size <= MAX_DOWNLOAD_BYTES:
        held = cached.read_bytes()
        if hashlib.sha256(held).hexdigest() == expected:
            return held
    fetched = fetch()
    actual = hashlib.sha256(fetched).hexdigest()
    if actual != expected:
        raise ValueError(f"{what}: sha256 {actual} does not match the pinned {expected}")
    cached.parent.mkdir(parents=True, exist_ok=True)
    # Written beside the cache and renamed over it: a symlink planted at the
    # cache path is replaced, never followed.
    fd, partial = tempfile.mkstemp(dir=cached.parent, suffix=".part")
    with os.fdopen(fd, "wb") as out:
        out.write(fetched)
    Path(partial).replace(cached)
    return fetched
