"""Tests for the EMAIL reducer — phase 3 of the reduction plan.

Every rule here DELETES, so the tests that matter most are the ones about
not deleting the wrong thing: prose must not be mistaken for mail, a short
quote must survive, and a crafted signature delimiter must not be able to
swallow the rest of the message.
"""

from __future__ import annotations

import pytest

from trentina.transforms import (
    Cost,
    EmailProcessor,
    TransformContext,
    TransformResult,
)

pytestmark = pytest.mark.asyncio


def _thread(depth: int = 6, body_lines: int = 12) -> str:
    """A reply chain: each message quotes the whole one before it."""
    lines = [
        "From: alice@example.com",
        "To: team@example.com",
        "Subject: Re: NIGHTJAR planning",
        "Date: Fri, 19 Sep 2026 10:00:00 -0400",
        "",
        "Agreed, let us go with the second option.",
        "",
    ]
    for level in range(1, depth + 1):
        marker = "> " * level
        lines.append(f"{marker}On Sep {level}, 2026, someone wrote:")
        lines.extend(f"{marker}Message {level} body line {i}" for i in range(body_lines))
        lines.append(marker.rstrip())
    return "\n".join(lines)


async def _run(payload: str) -> TransformResult:
    return await EmailProcessor().run(payload, TransformContext())


class TestEmailReduction:
    async def test_collapses_quoted_chain(self) -> None:
        result = await _run(_thread())
        assert result.applied
        assert result.details["quoted_lines_dropped"] > 0
        assert "[email]" in result.content

    async def test_keeps_the_new_message(self) -> None:
        """The part the reader actually wants is the unquoted top."""
        result = await _run(_thread())
        assert "Agreed, let us go with the second option." in result.content

    async def test_keeps_the_head_of_each_quote(self) -> None:
        """Enough quotation to see what is being answered, not all of it."""
        result = await _run(_thread())
        assert "> On Sep 1, 2026, someone wrote:" in result.content

    async def test_strips_signature(self) -> None:
        payload = "\n".join(
            [
                "From: alice@example.com",
                "Subject: Hello",
                "",
                "The actual message.",
                "",
                "-- ",
                "Alice Example",
                "Product Manager",
                "Example Corp",
                "mobile: 555-0100",
            ]
            + [f"Legal disclaimer line {i}" for i in range(12)]
        )
        result = await _run(payload)
        assert result.applied
        assert "The actual message." in result.content
        assert "Legal disclaimer line 5" not in result.content
        assert result.details["signature_lines_dropped"] > 0

    async def test_is_free(self) -> None:
        assert EmailProcessor().cost is Cost.FREE


class TestDoesNotDeleteTheWrongThing:
    async def test_prose_is_not_mistaken_for_mail(self) -> None:
        prose = "\n".join(
            f"An ordinary sentence number {i} with no mail shape at all." for i in range(60)
        )
        result = await _run(prose)
        assert not result.applied
        assert result.details["declined"] == "not_email"
        assert result.content == prose

    async def test_one_angle_bracket_does_not_qualify(self) -> None:
        """A single quoted line in prose is a citation, not a thread."""
        payload = "\n".join([f"Ordinary line {i}." for i in range(40)] + ["> a single quoted line"])
        result = await _run(payload)
        assert not result.applied

    async def test_short_quote_survives_intact(self) -> None:
        payload = "\n".join(
            [
                "From: a@example.com",
                "Subject: Re: question",
                "",
                "Yes, exactly this:",
                "> the one line being answered",
                "> and its second line",
                "",
            ]
            + [f"Further thoughts line {i}." for i in range(30)]
        )
        result = await _run(payload)
        assert not result.applied
        assert "> the one line being answered" in result.content

    async def test_crafted_signature_cannot_swallow_the_message(self) -> None:
        """An attacker who can place "-- " must not be able to suppress an
        unbounded tail. The drop is bounded by _MAX_SIGNATURE_LINES."""
        payload = "\n".join(
            [
                "From: attacker@example.com",
                "Subject: Re: something",
                "",
                "-- ",
            ]
            + [f"victim line {i}" for i in range(200)]
        )
        result = await _run(payload)
        survivors = [i for i in range(200) if f"victim line {i}" in result.content]
        assert survivors, "the bound must leave the tail of the message intact"
        assert len(survivors) >= 150

    async def test_declining_returns_input_untouched(self) -> None:
        payload = "\n".join(f"line {i}" for i in range(40))
        result = await _run(payload)
        assert result.content == payload
        assert result.bytes_in == result.bytes_out

    async def test_short_payload_declines(self) -> None:
        result = await _run("From: a@b.com\nTo: c@d.com\n> quoted")
        assert not result.applied
        assert result.details["declined"] == "not_line_structured"


class TestProperties:
    async def test_same_input_reduces_identically(self) -> None:
        payload = _thread()
        outputs = {(await _run(payload)).content for _ in range(10)}
        assert len(outputs) == 1

    async def test_dropped_quoted_lines_are_gone(self) -> None:
        """Collision is deletion: quoted text past the sample budget is not
        delivered, so it cannot carry anything to the agent."""
        payload = _thread(depth=2, body_lines=30)
        result = await _run(payload)
        assert result.applied
        assert "Message 1 body line 25" not in result.content

    async def test_counts_account_for_what_was_dropped(self) -> None:
        payload = _thread()
        result = await _run(payload)
        before = len(payload.split("\n"))
        after = result.details["lines_out"]
        dropped = int(result.details["quoted_lines_dropped"]) + int(
            result.details["signature_lines_dropped"]
        )
        markers = int(result.details["quoted_runs_collapsed"])
        assert before - dropped + markers == after

    async def test_deeply_nested_quotes_are_handled(self) -> None:
        payload = "\n".join(
            ["From: a@example.com", "Subject: deep", ""]
            + [f"{'> ' * 40}nested line {i}" for i in range(40)]
        )
        result = await _run(payload)
        assert isinstance(result, TransformResult)
