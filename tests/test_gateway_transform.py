"""Gateway response reduction: config resolution and the router wiring."""

from __future__ import annotations

from typing import Any

import pytest
from pydantic import SecretStr

from trentina.defense import Provenance
from trentina.gateway.profile import (
    AuthConfig,
    Backend,
    PreProcessConfig,
    Profile,
    ToolPreProcess,
)
from trentina.gateway.transform import resolve, transform_response

# Log-shaped and repetitive: exactly what petit collapses. Distinct IPs and
# timestamps per line so only the volatile tokens differ, which is the case
# petit is built for.
LOGGY = "\n".join(
    f"2026-09-17T10:{i // 60:02d}:{i % 60:02d}Z host sshd[{1000 + i}]: "
    f"Accepted publickey for alice from 10.0.0.{i % 250} port {2000 + i}"
    for i in range(400)
)


def _profile(
    preprocess: PreProcessConfig | None = None,
    preprocess_tools: dict[str, ToolPreProcess] | None = None,
) -> Profile:
    p = Profile(
        name="testp",
        auth=AuthConfig(bearer_token_env="TEST"),
        backends={
            "syslog": Backend(
                url="http://syslog:1/mcp",
                tools_allow=["*"],
                preprocess_tools=preprocess_tools or {},
            )
        },
        preprocess=preprocess or PreProcessConfig(),
    )
    p.auth.bearer_token = SecretStr("x")
    return p


def _blocks(text: str) -> list[dict[str, Any]]:
    return [{"type": "text", "text": text}]


async def _run(profile: Profile, tool: str = "syslog_tail_tool", text: str = LOGGY):
    return await transform_response(
        profile=profile,
        backend=profile.backends["syslog"],
        backend_name="syslog",
        tool_name=tool,
        content_blocks=_blocks(text),
    )


class TestResolution:
    def test_no_override_returns_profile_config(self) -> None:
        p = _profile(PreProcessConfig(enabled=True, target_bytes=1234))
        assert resolve(p, p.backends["syslog"], "any_tool").target_bytes == 1234

    def test_tool_override_wins_field_by_field(self) -> None:
        p = _profile(
            PreProcessConfig(enabled=True, strategy="auto", target_bytes=9999),
            {"syslog_tail_tool": ToolPreProcess(strategy="chain")},
        )
        cfg = resolve(p, p.backends["syslog"], "syslog_tail_tool")
        assert cfg.strategy == "chain"  # overridden
        assert cfg.target_bytes == 9999  # inherited
        assert cfg.enabled is True  # inherited

    def test_tool_can_opt_out_of_an_enabled_profile(self) -> None:
        p = _profile(
            PreProcessConfig(enabled=True),
            {"jira_get_issue": ToolPreProcess(enabled=False)},
        )
        assert resolve(p, p.backends["syslog"], "jira_get_issue").enabled is False

    def test_tool_can_opt_in_under_a_disabled_profile(self) -> None:
        p = _profile(
            PreProcessConfig(enabled=False),
            {"syslog_tail_tool": ToolPreProcess(enabled=True)},
        )
        assert resolve(p, p.backends["syslog"], "syslog_tail_tool").enabled is True


@pytest.mark.asyncio
class TestReduction:
    async def test_minified_by_default(self) -> None:
        """0.38.0: output is minified unless the operator or the agent says not."""
        out = await _run(_profile())
        assert out.applied is True
        assert len(out.content_blocks[0]["text"]) < len(LOGGY)

    async def test_disabled_leaves_response_untouched(self) -> None:
        out = await _run(_profile(PreProcessConfig(enabled=False)))
        assert out.applied is False
        assert out.content_blocks == _blocks(LOGGY)

    async def test_petit_reduces_log_shaped_content(self) -> None:
        out = await _run(_profile(PreProcessConfig(enabled=True)))
        assert out.applied is True
        assert len(out.content_blocks[0]["text"]) < len(LOGGY)
        assert out.sidecar is not None
        assert out.sidecar["bytes_out"] < out.sidecar["bytes_in"]

    async def test_free_only_keeps_external_provenance(self) -> None:
        """Deterministic reduction cannot compose a payload, so it does not
        earn the unconditional-L3 tax that model output does."""
        out = await _run(_profile(PreProcessConfig(enabled=True)))
        assert out.provenance is Provenance.EXTERNAL
        assert out.sidecar["metered"] is False

    async def test_min_bytes_floor_skips_small_payloads(self) -> None:
        p = _profile(PreProcessConfig(enabled=True, min_bytes=10_000_000))
        out = await _run(p)
        assert out.applied is False
        assert out.content_blocks == _blocks(LOGGY)

    async def test_strategy_none_is_a_noop(self) -> None:
        out = await _run(_profile(PreProcessConfig(enabled=True, strategy="none")))
        assert out.applied is False

    async def test_empty_processor_list_is_a_noop(self) -> None:
        out = await _run(_profile(PreProcessConfig(enabled=True, processors=[])))
        assert out.applied is False

    async def test_non_log_content_declines_rather_than_mangles(self) -> None:
        """petit declines on prose instead of pretending; the response must
        come back byte-identical."""
        prose = "The quick brown fox. " * 500
        out = await _run(_profile(PreProcessConfig(enabled=True)), text=prose)
        assert out.content_blocks[0]["text"] == prose

    async def test_non_text_blocks_are_untouched(self) -> None:
        p = _profile(PreProcessConfig(enabled=True))
        blocks: list[Any] = [
            {"type": "image", "data": "abc"},
            {"type": "text", "text": LOGGY},
        ]
        out = await transform_response(
            profile=p,
            backend=p.backends["syslog"],
            backend_name="syslog",
            tool_name="t",
            content_blocks=blocks,
        )
        assert out.content_blocks[0] == {"type": "image", "data": "abc"}

    async def test_processor_failure_delivers_content_unchanged(self, monkeypatch) -> None:
        """A reducer that breaks must never cost you the response."""
        import trentina.gateway.transform as transform_mod

        async def boom(*_a: object, **_kw: object) -> object:
            raise RuntimeError("processor exploded")

        monkeypatch.setattr(transform_mod, "run_transforms", boom)
        out = await _run(_profile(PreProcessConfig(enabled=True)))
        assert out.applied is False
        assert out.content_blocks == _blocks(LOGGY)


@pytest.mark.asyncio
class TestRouterOrdering:
    async def test_perimeter_scans_the_reduced_artifact(self, monkeypatch) -> None:
        """Invariant 2: the bytes the wall judges are the bytes the agent gets.

        Reducing after the scan would hand the agent content the perimeter
        never saw, so this pins the order rather than trusting it.
        """
        from trentina.gateway import router

        seen: dict[str, Any] = {}

        async def fake_scan(**kwargs: Any):
            seen["blocks"] = kwargs["content_blocks"]
            seen["provenance"] = kwargs["provenance"]

            class _D:
                blocked = False
                warning = None
                refusal = None
                extraction = None

            return _D()

        monkeypatch.setattr(router, "scan_tool_response", fake_scan)

        profile = _profile(PreProcessConfig(enabled=True))

        class _Result:
            content = _blocks(LOGGY)
            is_error = False
            structured_content = None

        assembled = await router._assemble_call_result(
            profile, profile.backends["syslog"], "syslog", "syslog_tail_tool", _Result()
        )
        result = assembled.result

        scanned = seen["blocks"][0]["text"]
        assert len(scanned) < len(LOGGY), "scanner saw the unreduced payload"
        assert result["content"][0]["text"] == scanned, "delivered != scanned"


class TestDeclineLogLine:
    """The sidecar line is what a human reads at 2am. It has to say what
    happened, and stay greppable by reason string."""

    def test_not_smaller_decline_shows_the_ratio_it_reached(self) -> None:
        from trentina.gateway.transform import _describe_decline
        from trentina.transforms import Cost, Declined, TransformRecord

        record = TransformRecord.of(
            "structured",
            Cost.FREE,
            "x" * 100,
            Declined("not_smaller", {"would_be_bytes": 104, "would_be_ratio": 1.04}),
        )
        line = _describe_decline(record)
        assert "structured:not_smaller" in line, "still greppable"
        assert "would_be=104%" in line

    def test_shape_decline_shows_lines_and_bytes(self) -> None:
        from trentina.gateway.transform import _describe_decline
        from trentina.transforms import Cost, Declined, TransformRecord

        record = TransformRecord.of(
            "petit",
            Cost.FREE,
            "x",
            Declined("not_line_structured", {"lines_in": 1, "bytes_in": 1_645_600}),
        )
        line = _describe_decline(record)
        assert "petit:not_line_structured" in line
        assert "lines=1" in line and "bytes=1645600" in line

    def test_bare_decline_stays_terse(self) -> None:
        from trentina.gateway.transform import _describe_decline
        from trentina.transforms import Cost, Declined, TransformRecord

        record = TransformRecord.of(
            "email",
            Cost.FREE,
            "x",
            Declined("not_email"),
        )
        assert _describe_decline(record) == "email:not_email"
