"""Tests for gateway/schema_compact.py — tighten-only inputSchema compaction (#199)."""

from __future__ import annotations

import copy
import itertools
from collections import Counter
from typing import Any
from unittest.mock import patch

import jsonschema
import pytest
from pydantic import SecretStr

from trentina.gateway.collect import _collect_strings
from trentina.gateway.profile import AuthConfig, Backend, Profile
from trentina.gateway.schema_compact import MAX_DEPTH, compact_tool
from trentina.transports.mcp import route_jsonrpc

# Shapes taken from the lotor tool_list_cache: FastMCP (gw), jira, memory.
GW_SCHEMA: dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "properties": {
        "query": {"type": "string", "description": "The search query."},
        "user_google_email": {"type": "string", "description": "The user's Google email."},
        "page_size": {"default": 10, "type": "integer", "description": "Max messages."},
        "page_token": {
            "anyOf": [{"type": "string"}, {"type": "null"}],
            "default": None,
            "description": "Token for the next page.",
        },
        "labels": {
            "anyOf": [{"type": "array", "items": {"type": "string"}}, {"type": "null"}],
            "default": None,
        },
    },
    "required": ["query", "user_google_email"],
    "type": "object",
    "additionalProperties": False,
}

JIRA_SCHEMA: dict[str, Any] = {
    "properties": {
        "query": {"description": "Free-form text.", "type": "string"},
        "project_key": {"default": None, "description": "Project key.", "type": "string"},
        "limit": {"default": 20, "maximum": 1000, "minimum": 1, "type": "integer"},
    },
    "required": ["query"],
    "type": "object",
}

MEMORY_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "turns": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "role": {"type": "string"},
                    "note": {"anyOf": [{"type": "string"}, {"type": "null"}], "default": None},
                },
                "required": ["role"],
            },
        },
        "tags": {"oneOf": [{"type": "array", "items": {"type": "string"}}, {"type": "string"}]},
        "filter": {"anyOf": [{"$ref": "#/$defs/Filter"}, {"type": "null"}], "default": None},
    },
    "required": ["turns"],
    "$defs": {
        "Filter": {
            "type": "object",
            "properties": {
                "since": {"anyOf": [{"type": "string"}, {"type": "null"}], "default": None},
            },
        },
    },
}

FIXTURES = [GW_SCHEMA, JIRA_SCHEMA, MEMORY_SCHEMA]


def _schema(props: dict[str, Any], required: list[str] | None = None) -> dict[str, Any]:
    schema: dict[str, Any] = {"type": "object", "properties": props}
    if required is not None:
        schema["required"] = required
    return schema


def _compacted(schema: dict[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = compact_tool({"name": "t", "inputSchema": schema})["inputSchema"]
    return result


def _strings(value: Any) -> Counter[str]:
    out: list[str] = []
    _collect_strings(value, out)
    return Counter(out)


class TestRules:
    """Each rule, and each condition under which it must NOT fire."""

    def test_null_branch_collapses_into_optional_property(self) -> None:
        props = _compacted(GW_SCHEMA)["properties"]
        assert props["page_token"] == {"type": "string", "description": "Token for the next page."}
        assert props["labels"] == {"type": "array", "items": {"type": "string"}}

    def test_null_default_dropped_without_anyof(self) -> None:
        assert _compacted(JIRA_SCHEMA)["properties"]["project_key"] == {
            "description": "Project key.",
            "type": "string",
        }

    def test_schema_keyword_dropped(self) -> None:
        assert "$schema" not in _compacted(GW_SCHEMA)

    def test_non_null_default_and_constraints_kept(self) -> None:
        props = _compacted(JIRA_SCHEMA)["properties"]
        assert props["limit"] == JIRA_SCHEMA["properties"]["limit"]

    def test_additional_properties_false_kept(self) -> None:
        assert _compacted(GW_SCHEMA)["additionalProperties"] is False

    def test_required_property_keeps_null_branch(self) -> None:
        prop = {"anyOf": [{"type": "string"}, {"type": "null"}], "default": None}
        assert _compacted(_schema({"x": prop}, ["x"]))["properties"]["x"] == prop

    def test_three_branches_untouched(self) -> None:
        prop = {
            "anyOf": [{"type": "string"}, {"type": "integer"}, {"type": "null"}],
            "default": None,
        }
        assert _compacted(_schema({"x": prop}))["properties"]["x"] == prop

    def test_key_conflict_untouched(self) -> None:
        prop = {
            "anyOf": [{"type": "string", "description": "branch"}, {"type": "null"}],
            "default": None,
            "description": "property",
        }
        assert _compacted(_schema({"x": prop}))["properties"]["x"] == prop

    def test_anyof_without_null_default_untouched(self) -> None:
        prop = {"anyOf": [{"type": "string"}, {"type": "null"}]}
        assert _compacted(_schema({"x": prop}))["properties"]["x"] == prop

    def test_nested_items_and_defs(self) -> None:
        out = _compacted(MEMORY_SCHEMA)
        assert out["properties"]["turns"]["items"]["properties"]["note"] == {"type": "string"}
        assert out["properties"]["filter"] == {"$ref": "#/$defs/Filter"}
        assert out["$defs"]["Filter"]["properties"]["since"] == {"type": "string"}
        assert out["properties"]["tags"] == MEMORY_SCHEMA["properties"]["tags"]

    def test_property_named_like_a_keyword_is_kept(self) -> None:
        schema = _schema({"$schema": {"type": "string"}, "default": {"type": "string"}})
        assert _compacted(schema) == schema

    def test_input_never_mutated(self) -> None:
        for schema in FIXTURES:
            before = copy.deepcopy(schema)
            _compacted(schema)
            assert schema == before

    def test_tool_without_schema_passes_through(self) -> None:
        tool = {"name": "t", "description": "d"}
        assert compact_tool(tool) == tool

    def test_depth_cap_serves_deep_subtree_as_is(self) -> None:
        leaf = _schema({"x": {"type": "string", "default": None}})
        assert _compacted(leaf) != leaf
        deep = leaf
        for _ in range(MAX_DEPTH + 5):
            deep = {"type": "array", "items": deep}
        out = _compacted(deep)
        for _ in range(MAX_DEPTH + 5):
            out = out["items"]
        assert out == leaf


class TestInvariants:
    """Tighten-only, and a subset of what the perimeter judged."""

    @pytest.mark.parametrize("schema", FIXTURES)
    def test_compacted_schema_is_valid(self, schema: dict[str, Any]) -> None:
        jsonschema.Draft202012Validator.check_schema(_compacted(schema))

    @pytest.mark.parametrize("schema", FIXTURES)
    def test_served_strings_are_a_subset_of_judged_strings(self, schema: dict[str, Any]) -> None:
        assert not _strings(_compacted(schema)) - _strings(schema)

    def test_valid_under_compacted_implies_valid_under_original(self) -> None:
        original = jsonschema.Draft202012Validator(GW_SCHEMA)
        compacted = jsonschema.Draft202012Validator(_compacted(GW_SCHEMA))
        base = {"query": "q", "user_google_email": "a@b.c"}
        values: dict[str, list[Any]] = {
            "page_size": [None, 5, "5"],
            "page_token": [None, "tok", 3],
            "labels": [None, ["x"], "x"],
            "extra": [None, 1],
        }
        for combo in itertools.product(*values.values()):
            args = {**base, **{k: v for k, v in zip(values, combo, strict=True) if v is not None}}
            if compacted.is_valid(args):
                assert original.is_valid(args), args
        # The one thing compaction takes away: an explicit null.
        explicit_null = {**base, "page_token": None}
        assert original.is_valid(explicit_null)
        assert not compacted.is_valid(explicit_null)


def _profile(compact: bool) -> Profile:
    p = Profile(
        name="compactp",
        auth=AuthConfig(bearer_token_env="TEST"),
        backends={
            "gw": Backend(url="http://mcp-gw:8000/mcp", tools_allow=["*"], compact_schemas=compact),
        },
    )
    p.auth.bearer_token = SecretStr("x")
    return p


@pytest.mark.asyncio
class TestRouter:
    """Compaction runs after the perimeter judges the original schema."""

    async def _list(self, compact: bool) -> tuple[dict[str, Any], list[dict[str, Any]]]:
        judged: list[dict[str, Any]] = []

        async def fake_list(_name: str, _backend: Backend, *_: Any) -> list[dict[str, Any]]:
            return [{"name": "search", "description": "d", "inputSchema": copy.deepcopy(GW_SCHEMA)}]

        async def fake_scan(
            _p: Profile, _b: str, _before: list[dict[str, Any]], tools: list[dict[str, Any]]
        ) -> list[dict[str, Any]]:
            judged.extend(tools)
            return tools

        with (
            patch(
                "trentina.gateway.aggregate.list_backend_tools",
                side_effect=fake_list,
            ),
            patch("trentina.gateway.aggregate.scan_tool_list", side_effect=fake_scan),
        ):
            resp = await route_jsonrpc(
                _profile(compact), {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}
            )
        return resp["result"]["tools"][0]["inputSchema"], judged

    async def test_default_compacts_after_scan(self) -> None:
        assert Backend(url="http://x:1/mcp").compact_schemas is True
        served, judged = await self._list(compact=True)
        assert "$schema" not in served
        assert "anyOf" not in served["properties"]["page_token"]
        assert judged[0]["inputSchema"]["$schema"] == GW_SCHEMA["$schema"]

    async def test_opt_out_serves_verbatim(self) -> None:
        served, _ = await self._list(compact=False)
        assert served["properties"] == GW_SCHEMA["properties"]
        assert "$schema" in served


def test_fields_no_agent_reads_are_dropped() -> None:
    """0.38.0: outputSchema and titles that repeat the name: ~40 KB on a 376-tool profile."""
    tool = {
        "name": "list_issues",
        "title": "List Issues",
        "description": "List issues.",
        "inputSchema": {"type": "object", "properties": {}},
        "outputSchema": {"type": "object", "properties": {"items": {"type": "array"}}},
        "annotations": {"title": "List Issues", "readOnlyHint": True},
    }
    out = compact_tool(tool)
    assert "outputSchema" not in out
    assert "title" not in out
    assert out["annotations"] == {"readOnlyHint": True}
    assert tool["annotations"]["title"] == "List Issues", "never mutates its input"


def test_annotations_holding_only_a_title_go_entirely() -> None:
    out = compact_tool({"name": "x", "annotations": {"title": "X"}})
    assert "annotations" not in out
