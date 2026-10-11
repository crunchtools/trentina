#!/usr/bin/env python3
"""Collect documents from a live, hostile feed, for the judges and the
detonation harness to read (#357).

Every corpus the benchmarks hold is written or academic. This reads what
agents are actually sent: Moltbook, a public network whose posts and
comments are written by agents for agents. Its read API needs no account.

Two samples, half of ``--limit`` each:

* the newest posts, each fetched whole (the feed listing cuts them short);
* the newest comments under the hottest posts, replies included, which is
  where text addressed to whoever reads the thread collects.

What is written is each document's text, the API URL it came from, and an
id that is the hash of the text, so the same text collected twice is one
document. No author name, handle or profile is kept. The output is a run
artifact and never a fixture: an attack found here enters a corpus only
rewritten by hand (security-gateway profile VII).

    uv run python benchmarks/wild_feed.py --json wild.json
    uv run python benchmarks/detonation.py --mode judge --documents wild.json
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import time
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from corpora.fetch import download

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator

API = "https://www.moltbook.com/api/v1"
# Seconds between requests: the read API allows 60 a minute.
PAUSE = 1.1
PAGE = 50
# With HOT_POSTS, half of the default limit: no one thread fills the sample.
COMMENTS_PER_POST = 30
HOT_POSTS = 5
# Characters. Shorter than this is a reaction, not a document.
SHORTEST = 40


@dataclass
class Feed:
    """The read API, one paced request at a time.

    ``fetch`` returns the body at a URL: ``corpora.fetch.download`` by
    default, which refuses an oversized body and an HTTP error. ``pause`` is
    called with ``PAUSE`` before every request after the first.
    """

    fetch: Callable[[str], bytes] = download
    pause: Callable[[float], None] = time.sleep
    asked: int = 0

    def get(self, path: str) -> dict[str, Any]:
        if self.asked:
            self.pause(PAUSE)
        self.asked += 1
        return dict(json.loads(self.fetch(f"{API}/{path}")))

    def comments(self) -> Iterator[tuple[str, str]]:
        """Where each comment under the hottest posts was read, and its
        text: replies included, in reading order."""
        for post in self.get(f"posts?sort=hot&limit={HOT_POSTS}")["posts"]:
            path = f"posts/{post['id']}/comments?sort=new&limit={COMMENTS_PER_POST}"
            unread = list(self.get(path)["comments"])
            while unread:
                comment = unread.pop(0)
                yield path, str(comment.get("content") or "")
                unread[:0] = comment.get("replies") or []

    def posts(self) -> Iterator[tuple[str, str]]:
        """Where each of the newest posts was read, and its title and whole
        body. A post is fetched only when the caller asks for the next one."""
        cursor = ""
        while True:
            more = f"&cursor={cursor}" if cursor else ""
            page = self.get(f"posts?sort=new&limit={PAGE}{more}")
            for listed in page["posts"]:
                path = f"posts/{listed['id']}"
                post = self.get(path)["post"]
                yield path, f"{post.get('title') or ''}\n\n{post.get('content') or ''}"
            cursor = str(page.get("next_cursor") or "")
            if not (page.get("has_more") and cursor):
                return


def collect(limit: int, feed: Feed) -> list[dict[str, str]]:
    """Up to ``limit`` distinct documents: comments under hot posts for at
    most half of it, then new posts.

    Returns:
        One record per document, in collection order: ``id`` (the first 16
        hex digits of the text's SHA-256), ``url`` (the API URL it was read
        from), ``kind`` (``comment`` or ``post``) and ``text``.
    """
    seen: dict[str, dict[str, str]] = {}
    for kind, found, room in (
        ("comment", feed.comments(), limit // 2),
        ("post", feed.posts(), limit),
    ):
        # Asked for one at a time: the next is not fetched once there is no room for it.
        while len(seen) < room and (item := next(found, None)):
            path, text = item
            if len(text) >= SHORTEST:
                name = hashlib.sha256(text.encode()).hexdigest()[:16]
                record = {"id": name, "url": f"{API}/{path}", "kind": kind, "text": text}
                seen.setdefault(name, record)
    return list(seen.values())


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    parser.add_argument("--limit", type=int, default=300, help="documents at most")
    parser.add_argument("--json", required=True, help="write the documents here")
    args = parser.parse_args(argv)
    documents = collect(args.limit, Feed())
    kinds = ", ".join(f"{kind} {n}" for kind, n in Counter(d["kind"] for d in documents).items())
    print(f"{len(documents)} documents from Moltbook: {kinds}")
    Path(args.json).write_text(json.dumps({"source": "moltbook", "documents": documents}, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
