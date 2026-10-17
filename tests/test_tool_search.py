"""Tests for gateway/tool_search.py and its accuracy floor (#473)."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from benchmarks.tool_search import build_index, ranks, summary
from corpora.tool_search import CATALOG, QUERIES
from trentina.gateway.tool_search import MAX_QUERY_CHARS, Entry, ToolIndex, tokens


def _index() -> ToolIndex:
    return ToolIndex(
        [
            Entry("send_gmail_message", "mail", "gws", "Send an email message."),
            Entry("search_gmail_messages", "mail", "gws", "Search messages in the mailbox."),
            Entry("jira_search", "dev", "tracker", "Search issues with a JQL query."),
            Entry("unit_restart", "infra", "systemd", "Restart a systemd unit."),
            Entry("container_logs", "infra", "podman", "Fetch a container's logs."),
        ]
    )


class TestTokens:
    def test_splits_snake_kebab_and_camel_case_and_stems(self) -> None:
        assert tokens("getIssueComments") == ["get", "issu", "comment"]
        assert tokens("changed changes change") == ["chang"] * 3
        assert tokens("running") == ["run"]
        assert tokens("send_gmail-messages") == ["send", "gmail", "messag"]

    def test_drops_stop_words(self) -> None:
        assert tokens("what is the status of my unit") == ["status", "unit"]


class TestSearch:
    def test_ranks_the_tool_that_does_the_job_first(self) -> None:
        index = _index()
        names = [index.entries[i].name for i in index.search("restart the web service", 3)]
        assert names[0] == "unit_restart"

    def test_a_synonym_finds_a_tool_named_otherwise(self) -> None:
        index = _index()
        top = index.entries[index.search("email someone", 1)[0]].name
        assert top == "send_gmail_message"

    def test_category_limits_the_results(self) -> None:
        index = _index()
        found = {index.entries[i].category for i in index.search("search", 5, "dev")}
        assert found == {"dev"}

    def test_limit_and_an_unknown_category(self) -> None:
        index = _index()
        assert len(index.search("search messages", 1)) == 1
        assert index.search("search", 5, "no-such-category") == []
        assert index.search("search", 0) == []

    def test_a_typo_still_finds_by_trigrams(self) -> None:
        index = _index()
        top = index.entries[index.search("contaner_logz", 1)[0]].name
        assert top == "container_logs"

    def test_nothing_matching_returns_nothing(self) -> None:
        assert _index().search("zzzz qqqq", 5) == []

    def test_a_long_query_is_cut_not_refused(self) -> None:
        index = _index()
        assert index.search("restart " + "x" * (MAX_QUERY_CHARS * 10), 1)

    def test_an_empty_index_answers_empty(self) -> None:
        assert ToolIndex([]).search("anything", 5) == []

    def test_results_are_deterministic(self) -> None:
        index = _index()
        assert index.search("search", 5) == index.search("search", 5)


class TestAccuracyFloor:
    """What docs/tool-discovery.md publishes, held as a floor. A ranker change
    that lowers it fails here; one that raises it moves the floor and the doc."""

    def test_every_expected_tool_is_in_the_catalog(self) -> None:
        names = {t.name for t in CATALOG}
        assert len(names) == len(CATALOG)
        assert all(q.expected in names for q in QUERIES)

    def test_recall(self) -> None:
        found = ranks(build_index(), QUERIES, 8)
        overall = summary(found, 8)
        held_out = summary([r for q, r in zip(QUERIES, found, strict=True) if q.held_out], 8)
        assert overall["recall@8"] >= 0.98
        assert overall["recall@1"] >= 0.75
        assert held_out["recall@8"] >= 0.95
        assert held_out["recall@1"] >= 0.65
