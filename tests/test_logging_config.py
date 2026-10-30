"""Tests for logsafe.configure — TRENTINA_LOG_LEVEL must reach uvicorn and
httpx, not just the root logger.

Note: logging.basicConfig() is a no-op once the root logger already has
handlers, which is always true under pytest (it attaches its own capture
handlers). So these tests don't assert on logging.getLogger().level —
that would test pytest's logging setup, not ours. They assert on the
resolved level name (what callers forward to mcp.run(log_level=...)) and
on the httpx logger, which logsafe.configure sets directly via an
unconditional setLevel() call rather than through basicConfig.
"""

from __future__ import annotations

import logging
from collections.abc import Iterator
from unittest.mock import MagicMock, patch

import pytest

from trentina import DEFAULT_PORT, _run_with_gateway, logsafe, main
from trentina.gateway.loader import GatewayConfig


@pytest.fixture(autouse=True)
def _restore_httpx_logger_level() -> Iterator[None]:
    """logsafe.configure mutates the shared httpx logger; restore it after each test."""
    previous = logging.getLogger("httpx").level
    root = logging.getLogger().level
    yield
    logging.getLogger("httpx").setLevel(previous)
    logging.getLogger().setLevel(root)


def test_configure_logging_defaults_to_info(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("TRENTINA_LOG_LEVEL", raising=False)
    assert logsafe.configure("TRENTINA_LOG_LEVEL") == "INFO"


def test_configure_logging_resolves_requested_level(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TRENTINA_LOG_LEVEL", "warning")
    assert logsafe.configure("TRENTINA_LOG_LEVEL") == "WARNING"


def test_configure_logging_is_case_insensitive(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TRENTINA_LOG_LEVEL", "Debug")
    assert logsafe.configure("TRENTINA_LOG_LEVEL") == "DEBUG"


def test_configure_logging_invalid_level_falls_back_to_info(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An unrecognized value must resolve to a real level name rather than being
    passed through verbatim — mcp.run(log_level=...) hands this straight to
    uvicorn.Config, which raises KeyError on anything outside its known set."""
    monkeypatch.setenv("TRENTINA_LOG_LEVEL", "bogus")
    assert logsafe.configure("TRENTINA_LOG_LEVEL") == "INFO"


def test_configure_logging_notset_falls_back_to_info(monkeypatch: pytest.MonkeyPatch) -> None:
    """NOTSET is a real logging level name, but it isn't one of uvicorn's
    recognized levels, and forwarding it verbatim as log_level would raise
    KeyError at server startup instead of just being ignored like it would
    have been before this level was forwarded anywhere."""
    monkeypatch.setenv("TRENTINA_LOG_LEVEL", "NOTSET")
    assert logsafe.configure("TRENTINA_LOG_LEVEL") == "INFO"


def test_configure_logging_rejects_non_level_module_attributes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A naive getattr(logging, level_name, default) resolves *any* uppercase
    attribute of the logging module, not just level constants — e.g. the
    internal _STYLES dict — and passing a non-int through to basicConfig()/
    getLevelName() raises TypeError instead of falling back to INFO. Level
    names must be checked against a fixed allowlist before ever touching
    getattr, not validated after the fact."""
    monkeypatch.setenv("TRENTINA_LOG_LEVEL", "_styles")
    assert logsafe.configure("TRENTINA_LOG_LEVEL") == "INFO"


def test_configure_logging_clamps_httpx_logger(monkeypatch: pytest.MonkeyPatch) -> None:
    """httpx's request logger sits outside uvicorn's logging config entirely, so
    it needs its own explicit level — root-logger configuration alone never
    reaches it in practice (see issue #73)."""
    monkeypatch.setenv("TRENTINA_LOG_LEVEL", "WARNING")
    logsafe.configure("TRENTINA_LOG_LEVEL")
    assert logging.getLogger("httpx").level == logging.WARNING


def test_configure_logging_httpx_tracks_requested_level(monkeypatch: pytest.MonkeyPatch) -> None:
    """DEBUG should restore full httpx verbosity, not stay clamped to WARNING —
    the fix must not hardcode a floor that fights an operator's explicit ask."""
    monkeypatch.setenv("TRENTINA_LOG_LEVEL", "DEBUG")
    logsafe.configure("TRENTINA_LOG_LEVEL")
    assert logging.getLogger("httpx").level == logging.DEBUG


def test_run_with_gateway_forwards_log_level_to_uvicorn() -> None:
    """Regression test for the actual reported symptom: uvicorn.access kept
    logging at INFO regardless of TRENTINA_LOG_LEVEL because FastMCP passes its
    own default log_level to uvicorn.Config, and uvicorn re-applies that level
    to uvicorn.access/error *after* its own dictConfig runs — so nothing short
    of an explicit log_level reaching mcp_server.run() fixes it. This exercises
    the gateway-mode path from the deployment described in issue #73, where
    resolving the right string in logsafe.configure alone would not have
    caught a regression in the plumbing that forwards it."""
    empty_config = GatewayConfig(profiles={})
    mock_server = MagicMock()

    with (
        patch("trentina.gateway.load_profiles", return_value=empty_config),
        patch("trentina.gateway.register_internal_server"),
        patch("trentina.gateway.register_with_fastmcp"),
        patch("trentina._wire_circuit_notifications"),
        patch("trentina.gateway.llm_proxy.load_llm_providers", return_value={}),
        patch("trentina.gateway.llm_proxy.register_llm_routes"),
        patch("trentina.gateway.alert_ingress.register_alert_routes"),
        patch("trentina.gateway.compress.load_compression_cache"),
        patch("trentina.gateway.compress.set_profiles"),
        patch("trentina.gateway.backend.load_tool_list_cache"),
    ):
        _run_with_gateway(mock_server, host="127.0.0.1", port=8019, log_level="WARNING")

    assert mock_server.run.call_count == 1
    kwargs = mock_server.run.call_args.kwargs
    assert kwargs["transport"] == "streamable-http"
    assert kwargs["host"] == "127.0.0.1"
    assert kwargs["port"] == 8019
    assert kwargs["log_level"] == "WARNING"
    # Legacy /mcp is closed by default: the MCP app mounts at a per-boot
    # unguessable path and /mcp itself serves a 410 tombstone.
    assert kwargs["path"].startswith("/mcp-internal-")


def test_main_sse_forwards_log_level(monkeypatch: pytest.MonkeyPatch) -> None:
    """main() calls mcp.run() directly for sse rather than going through
    _run_with_gateway — that call site needs its own coverage."""
    monkeypatch.setenv("TRENTINA_LOG_LEVEL", "WARNING")
    monkeypatch.delenv("TRENTINA_GATEWAY_ENABLED", raising=False)
    monkeypatch.setattr("sys.argv", ["trentina", "--transport", "sse", "--no-dbus"])
    mock_mcp = MagicMock()

    with (
        patch("trentina.database.get_db"),
        patch("trentina.server.mcp", mock_mcp),
    ):
        main()

    mock_mcp.run.assert_called_once_with(
        transport="sse", host="127.0.0.1", port=DEFAULT_PORT, log_level="WARNING"
    )


def test_main_streamable_http_forwards_log_level(monkeypatch: pytest.MonkeyPatch) -> None:
    """Same as test_main_sse_forwards_log_level, but for the non-gateway
    streamable-http branch, which also calls mcp.run() directly."""
    monkeypatch.setenv("TRENTINA_LOG_LEVEL", "DEBUG")
    monkeypatch.delenv("TRENTINA_GATEWAY_ENABLED", raising=False)
    monkeypatch.setattr(
        "sys.argv",
        ["trentina", "--transport", "streamable-http", "--no-dbus"],
    )
    mock_mcp = MagicMock()

    with (
        patch("trentina.database.get_db"),
        patch("trentina.server.mcp", mock_mcp),
    ):
        main()

    mock_mcp.run.assert_called_once()
    kwargs = mock_mcp.run.call_args.kwargs
    assert kwargs["log_level"] == "DEBUG"
    assert kwargs["transport"] == "streamable-http"
    # The request body cap rides along as middleware (#267).
    assert len(kwargs["middleware"]) == 1


class TestStartupCacheVisibility:
    """The startup cache summary must survive production's log level.

    Production runs at TRENTINA_LOG_LEVEL=WARNING. A summary logged at INFO
    is discarded there, which is exactly what happened: after the #118
    deploy the only way to answer "did the verdict cache load?" was to SSH
    to the box and query SQLite. A cold cache predicts a slow first
    tools/list, and that prediction is worth nothing after the timeout.
    """

    def _boot(self, caplog: pytest.LogCaptureFixture, *, verdicts: int) -> str:
        mock_server = MagicMock()
        with (
            patch(
                "trentina.gateway.load_profiles",
                return_value=GatewayConfig(profiles={}),
            ),
            patch("trentina.gateway.register_internal_server"),
            patch("trentina.gateway.register_with_fastmcp"),
            patch("trentina._wire_circuit_notifications"),
            patch(
                "trentina.gateway.llm_proxy.load_llm_providers",
                return_value={},
            ),
            patch("trentina.gateway.llm_proxy.register_llm_routes"),
            patch("trentina.gateway.alert_ingress.register_alert_routes"),
            patch(
                "trentina.gateway.compress.load_compression_cache",
                return_value=7,
            ),
            patch("trentina.gateway.compress.set_profiles"),
            patch(
                "trentina.gateway.backend.load_tool_list_cache",
                return_value=26,
            ),
            patch(
                "trentina.gateway.verdict_cache.load_verdict_cache",
                return_value=verdicts,
            ),
            caplog.at_level(logging.WARNING, logger="trentina"),
        ):
            _run_with_gateway(mock_server, host="127.0.0.1", port=8019, log_level="WARNING")
        return "\n".join(r.getMessage() for r in caplog.records if r.levelno >= logging.WARNING)

    def test_summary_is_visible_at_warning(self, caplog: pytest.LogCaptureFixture) -> None:
        logged = self._boot(caplog, verdicts=331)
        assert "331 perimeter verdict(s)" in logged
        assert "26 tool list(s)" in logged
        assert "7 compression(s)" in logged

    def test_a_cold_cache_says_the_next_request_will_be_slow(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """The whole point. An empty store is not an error, but it is the
        one fact that explains the timeout about to happen."""
        logged = self._boot(caplog, verdicts=0)
        assert "COLD" in logged

    def test_a_warm_cache_does_not_cry_wolf(self, caplog: pytest.LogCaptureFixture) -> None:
        logged = self._boot(caplog, verdicts=331)
        assert "COLD" not in logged
