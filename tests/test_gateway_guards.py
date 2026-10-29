"""Tests for gateway/guards.py — request and response value validation."""

from __future__ import annotations

from trentina.gateway.guards import (
    check_request_guards,
    check_response_guards,
)
from trentina.gateway.profile import Backend, ParameterConstraint


def _backend(
    guards: dict[str, dict[str, ParameterConstraint]] | None = None,
    response: dict[str, dict[str, ParameterConstraint]] | None = None,
) -> Backend:
    return Backend(
        url="http://x/mcp",
        tools_allow=["*"],
        literal_request_guards=guards or {},
        literal_response_guards=response or {},
    )


def _text(*chunks: str) -> list[dict[str, str]]:
    return [{"type": "text", "text": chunk} for chunk in chunks]


def _guarded(field: str, **constraint: list[str]) -> Backend:
    """A backend whose memory_search result is constrained on one field."""
    return _backend(response={"memory_search": {field: ParameterConstraint(**constraint)}})


class TestParameterGuards:
    """check_request_guards behaviour across allow, deny, and edge cases."""

    def test_no_guards_configured_passes(self) -> None:
        result = check_request_guards("send_gmail_message", {"to": "evil@example.com"}, _backend())
        assert result is None

    def test_no_guard_for_this_tool_passes(self) -> None:
        result = check_request_guards(
            "other_tool",
            {"to": "evil@example.com"},
            _backend({"send_gmail_message": {"to": ParameterConstraint(allow=["ok@x.com"])}}),
        )
        assert result is None

    def test_exact_allow_match_passes(self) -> None:
        result = check_request_guards(
            "send_gmail_message",
            {"to": "alice@example.com"},
            _backend(
                {"send_gmail_message": {"to": ParameterConstraint(allow=["alice@example.com"])}}
            ),
        )
        assert result is None

    def test_glob_allow_match_passes(self) -> None:
        result = check_request_guards(
            "send_gmail_message",
            {"to": "you@corp.example.com"},
            _backend(
                {"send_gmail_message": {"to": ParameterConstraint(allow=["*@corp.example.com"])}}
            ),
        )
        assert result is None

    def test_value_not_in_allow_list_rejected(self) -> None:
        result = check_request_guards(
            "send_gmail_message",
            {"to": "evil@example.com"},
            _backend(
                {"send_gmail_message": {"to": ParameterConstraint(allow=["alice@example.com"])}}
            ),
        )
        assert result is not None
        assert "not in allow list" in result

    def test_deny_wins_over_allow(self) -> None:
        result = check_request_guards(
            "send_gmail_message",
            {"to": "banned@corp.example.com"},
            _backend(
                {
                    "send_gmail_message": {
                        "to": ParameterConstraint(
                            allow=["*@corp.example.com"],
                            deny=["banned@corp.example.com"],
                        )
                    }
                }
            ),
        )
        assert result is not None
        assert "deny" in result

    def test_missing_parameter_passes(self) -> None:
        result = check_request_guards(
            "send_gmail_message",
            {"subject": "hello"},
            _backend(
                {"send_gmail_message": {"to": ParameterConstraint(allow=["alice@example.com"])}}
            ),
        )
        assert result is None

    def test_none_parameter_passes(self) -> None:
        result = check_request_guards(
            "send_gmail_message",
            {"to": None},
            _backend(
                {"send_gmail_message": {"to": ParameterConstraint(allow=["alice@example.com"])}}
            ),
        )
        assert result is None

    def test_multiple_params_first_failure_reported(self) -> None:
        guards = {
            "send_gmail_message": {
                "to": ParameterConstraint(allow=["alice@example.com"]),
                "cc": ParameterConstraint(allow=["alice@example.com"]),
            }
        }
        result = check_request_guards(
            "send_gmail_message",
            {"to": "alice@example.com", "cc": "evil@example.com"},
            _backend(guards),
        )
        assert result is not None
        assert "cc" in result

    def test_wildcard_allow_passes_anything(self) -> None:
        result = check_request_guards(
            "send_gmail_message",
            {"to": "anyone@anywhere.com"},
            _backend({"send_gmail_message": {"to": ParameterConstraint(allow=["*"])}}),
        )
        assert result is None

    def test_empty_arguments_passes(self) -> None:
        result = check_request_guards(
            "send_gmail_message",
            {},
            _backend(
                {"send_gmail_message": {"to": ParameterConstraint(allow=["alice@example.com"])}}
            ),
        )
        assert result is None

    def test_error_message_does_not_leak_value(self) -> None:
        secret = "secret-address@evil.com"
        result = check_request_guards(
            "send_gmail_message",
            {"to": secret},
            _backend(
                {"send_gmail_message": {"to": ParameterConstraint(allow=["alice@example.com"])}}
            ),
        )
        assert result is not None
        assert secret not in result


class TestResponseGuards:
    """check_response_guards behaviour on content blocks and structured fields."""

    def test_no_guards_configured_passes(self) -> None:
        result = check_response_guards("memory_search", _text("NIGHTJAR roadmap"), None, _backend())
        assert result is None

    def test_no_guard_for_this_tool_passes(self) -> None:
        result = check_response_guards(
            "memory_list",
            _text("NIGHTJAR roadmap"),
            None,
            _guarded("content", deny=["*NIGHTJAR*"]),
        )
        assert result is None

    def test_content_deny_pattern_blocks(self) -> None:
        result = check_response_guards(
            "memory_search",
            _text("The NIGHTJAR roadmap for next year"),
            None,
            _guarded("content", deny=["*NIGHTJAR*"]),
        )
        assert result is not None
        assert "deny" in result

    def test_content_without_denied_term_passes(self) -> None:
        result = check_response_guards(
            "memory_search",
            _text("The motorcycle trip to Trentino"),
            None,
            _guarded("content", deny=["*NIGHTJAR*"]),
        )
        assert result is None

    def test_deny_all_blocks_every_response(self) -> None:
        result = check_response_guards(
            "memory_search",
            _text("anything at all"),
            None,
            _guarded("content", deny=["*"]),
        )
        assert result is not None

    def test_deny_all_blocks_empty_response(self) -> None:
        result = check_response_guards(
            "memory_search",
            [],
            None,
            _guarded("content", deny=["*"]),
        )
        assert result is not None

    def test_match_spans_multiple_blocks_and_newlines(self) -> None:
        """A memory blob arrives as several blocks; the guard reads them joined."""
        result = check_response_guards(
            "memory_search",
            _text("entry one\nsecond line", "entry two mentioning NIGHTJAR\nand more"),
            None,
            _guarded("content", deny=["*NIGHTJAR*"]),
        )
        assert result is not None
        assert "deny" in result

    def test_embedded_resource_text_is_read(self) -> None:
        blocks = [{"type": "resource", "resource": {"text": "NIGHTJAR internal note"}}]
        result = check_response_guards(
            "memory_search",
            blocks,
            None,
            _guarded("content", deny=["*NIGHTJAR*"]),
        )
        assert result is not None

    def test_structured_field_deny_blocks(self) -> None:
        result = check_response_guards(
            "memory_search",
            _text("harmless"),
            {"summary": "NIGHTJAR product plans"},
            _guarded("summary", deny=["*NIGHTJAR*"]),
        )
        assert result is not None
        assert "summary" in result

    def test_missing_structured_field_passes(self) -> None:
        result = check_response_guards(
            "memory_search",
            _text("harmless"),
            {"other": "value"},
            _guarded("summary", deny=["*NIGHTJAR*"]),
        )
        assert result is None

    def test_structured_field_guard_with_no_structured_content_passes(self) -> None:
        result = check_response_guards(
            "memory_search",
            _text("harmless"),
            None,
            _guarded("summary", deny=["*NIGHTJAR*"]),
        )
        assert result is None

    def test_allow_list_restricts_content(self) -> None:
        result = check_response_guards(
            "status_tool",
            _text("unexpected payload"),
            None,
            _backend(response={"status_tool": {"content": ParameterConstraint(allow=["ok"])}}),
        )
        assert result is not None
        assert "not in allow list" in result

    def test_image_only_response_has_no_text_to_match(self) -> None:
        blocks = [{"type": "image", "data": "...", "mimeType": "image/png"}]
        result = check_response_guards(
            "memory_search",
            blocks,
            None,
            _guarded("content", deny=["*NIGHTJAR*"]),
        )
        assert result is None

    def test_error_message_does_not_leak_content(self) -> None:
        secret = "Example Corp NIGHTJAR ship date is a secret"
        result = check_response_guards(
            "memory_search",
            _text(secret),
            None,
            _guarded("content", deny=["*NIGHTJAR*"]),
        )
        assert result is not None
        assert secret not in result
        assert "ship date" not in result
