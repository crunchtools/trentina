"""The README is a front page, not a manual (#475).

Each feature PR used to append to it and none trimmed, so it grew 30% in two
weeks. A feature adds one row to the Documentation table and puts the rest in
``docs/``. Raising ``WORD_BUDGET`` is a deliberate change to this file.
"""

import re
from pathlib import Path

README = Path(__file__).resolve().parent.parent / "README.md"

WORD_BUDGET = 900


def _prose_words(text: str) -> int:
    """Words a reader reads: headings, prose and table cells.

    Fenced code (the Quick Start config) and HTML (the logo and demo
    wrappers, whose alt text is not body copy) are left out.
    """
    text = re.sub(r"```.*?```", "", text, flags=re.DOTALL)
    text = re.sub(r"<!--.*?-->", "", text, flags=re.DOTALL)
    text = re.sub(r"<[^>]+>", "", text)
    return len(text.split())


def test_readme_within_word_budget() -> None:
    words = _prose_words(README.read_text(encoding="utf-8"))
    assert words <= WORD_BUDGET, (
        f"README.md is {words} words, budget {WORD_BUDGET}. Add one "
        "Documentation table row and put the detail in docs/."
    )


def test_readme_keeps_the_five_promises() -> None:
    text = README.read_text(encoding="utf-8")
    for promise in (
        "Security",
        "Token savings",
        "Determinism",
        "Authentication",
        "Architectural flexibility",
    ):
        assert f"**{promise}.**" in text


def test_readme_does_not_lead_with_mcp_gateway() -> None:
    intro = README.read_text(encoding="utf-8").split("# Trentina", 1)[1][:600]
    assert "MCP gateway" not in intro
