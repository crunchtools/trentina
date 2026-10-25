"""The envelope makers L2 is trained and gated on (corpora/envelopes.py)."""

from __future__ import annotations

import asyncio
import json
import random
import re
from pathlib import Path

import pytest

from corpora.benign_ops import BENIGN, in_tuning
from corpora.envelopes import MAKERS, slug
from scripts.l2_train_data import ANCHOR_REPEATS, anchors

TEXT = "Weekly security roundup\nA patch for the login flow shipped on Tuesday."


@pytest.mark.parametrize("name", sorted(MAKERS))
def test_maker_carries_the_text(name: str) -> None:
    payload = MAKERS[name](random.Random(1), TEXT)
    rendered = payload if isinstance(payload, str) else json.dumps(payload)
    assert "Weekly security roundup" in rendered


@pytest.mark.parametrize("name", sorted(MAKERS))
def test_maker_is_seeded(name: str) -> None:
    first = MAKERS[name](random.Random(7), TEXT)
    again = MAKERS[name](random.Random(7), TEXT)
    assert first == again


def test_github_issue_is_the_full_reply() -> None:
    """The slim shape scores 0.000 on the shipped model; the full reply is what flags."""
    issue = MAKERS["github_issue"](random.Random(3), TEXT)
    assert issue["body"] == TEXT
    assert {"node_id", "user", "labels", "reactions", "timeline_url"} <= issue.keys()


def test_sweep_rss_page_withholds_only_other_records() -> None:
    page = MAKERS["sweep_rss_page"](random.Random(5), TEXT)
    whole = " ".join(TEXT.split())
    mine = [r for r in page["records"] if r["title"] == whole]
    assert len(mine) == 1
    assert mine[0]["flagged"] is False
    assert all(r["title"] is None for r in page["records"] if r["flagged"])


def test_slug() -> None:
    assert slug("Computer Security Is About to Get a Lot Worse!") == (
        "computer-security-is-about-to-get-a-lot-worse"
    )
    assert slug("!!!") == "post"


def test_training_starts_from_the_shipped_revision() -> None:
    """A fine-tune starts from the model production runs, or its gates compare nothing."""
    root = Path(__file__).resolve().parents[1]
    pinned = re.search(r"ARG HORIZON_REVISION=([0-9a-f]{40})", (root / "Containerfile").read_text())
    trained = re.search(
        r'BASE_REVISION = "([0-9a-f]{40})"', (root / "scripts/train_l2_model.py").read_text()
    )
    assert pinned and trained
    assert pinned.group(1) == trained.group(1)


def test_training_anchors_hold_no_held_out_case() -> None:
    """The anchor is benign_ops's tuning split; a held-out case in training voids the gate."""
    rows = asyncio.run(anchors())
    tuning = [c for c in BENIGN if in_tuning(c.id)]
    assert len(rows) == len(tuning) * ANCHOR_REPEATS
    assert all(r["label"] == 0 for r in rows)
