"""Where a call went (#266): the audit column, its scoping, and the fan-out check."""

from __future__ import annotations

import hashlib
import importlib.machinery
import importlib.util
import sqlite3
import time
from collections.abc import Iterator
from pathlib import Path
from types import ModuleType, SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from pydantic import SecretStr, ValidationError

from trentina import config as config_mod
from trentina import database as db
from trentina.gateway import compress
from trentina.gateway.backend import BackendCall
from trentina.gateway.compress import set_profiles
from trentina.gateway.context import profile_context
from trentina.gateway.destination import (
    MAX_DESTINATION_CHARS,
    NON_SCALAR,
    DestinationKind,
    destination_of,
)
from trentina.gateway.errors import ProfileConfigError
from trentina.gateway.loader import load_profiles, register_active_config
from trentina.gateway.profile import (
    AuthConfig,
    Backend,
    ParameterConstraint,
    Profile,
)
from trentina.gateway.router import NAMESPACE_SEP, route_jsonrpc
from trentina.outcomes import Outcome
from trentina.tools.reload import _lost_destination_rules
from trentina.tools.stats import get_trentina_stats

CHECK = Path(__file__).resolve().parents[1] / "contrib" / "nagios" / "check_trentina_fanout"

SLACK = Backend(
    url="http://mcp-slack:8000/mcp",
    destination_params={"send_message": "channel"},
)
WEB = Backend(url="internal://web")


def _sha16(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()[:16]


@pytest.fixture
def audit_db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    path = tmp_path / "trentina.db"
    monkeypatch.setenv("QUARANTINE_DB", str(path))
    config_mod._config = None
    db._db = None
    yield path
    db._db = None
    config_mod._config = None


# ------------------------------------------------------------ what is recorded


class TestDestinationOf:
    def test_fetch_is_host_and_url_hash(self) -> None:
        url = "https://Example.com:8443/a/b?token=secret"
        dest = destination_of(WEB, "fetch_tool", {"url": url})
        assert dest is not None
        assert dest.kind is DestinationKind.FETCH
        assert dest.value == f"example.com#{_sha16(url)}"
        assert "secret" not in dest.value

    def test_search_is_query_hash(self) -> None:
        dest = destination_of(WEB, "search_tool", {"query": "who is on call"})
        assert dest is not None
        assert dest.kind is DestinationKind.SEARCH
        assert dest.value == f"q#{_sha16('who is on call')}"

    def test_declared_param_is_its_value_truncated(self) -> None:
        dest = destination_of(SLACK, "send_message", {"channel": "C" * 1000, "text": "hi"})
        assert dest is not None
        assert dest.kind is DestinationKind.PARAM
        assert dest.value == "C" * MAX_DESTINATION_CHARS

    def test_a_list_of_recipients_is_recorded_as_json(self) -> None:
        backend = Backend(url="http://mail:1/mcp", destination_params={"send": "to"})
        dest = destination_of(backend, "send", {"to": ["a@x.io", "b@x.io"]})
        assert dest is not None
        assert dest.value == '["a@x.io", "b@x.io"]'

    def test_a_huge_or_nested_value_is_bounded(self) -> None:
        backend = Backend(url="http://mail:1/mcp", destination_params={"send": "to"})
        many = destination_of(backend, "send", {"to": ["x" * 10_000] * 10_000})
        assert many is not None
        assert len(many.value) == MAX_DESTINATION_CHARS
        nested = destination_of(backend, "send", {"to": {"a": ["b"] * 10_000}})
        assert nested is not None
        assert nested.value == NON_SCALAR

    def test_undeclared_or_absent_names_nothing(self) -> None:
        assert destination_of(SLACK, "list_channels", {"channel": "C1"}) is None
        assert destination_of(SLACK, "send_message", {"text": "no channel"}) is None
        assert destination_of(WEB, "read_tool", {"path": "/etc/passwd"}) is None

    def test_a_proxied_fetch_tool_is_not_ours(self) -> None:
        assert destination_of(SLACK, "fetch_tool", {"url": "https://x.io"}) is None

    def test_a_malformed_url_still_records_its_hash(self) -> None:
        dest = destination_of(WEB, "fetch_tool", {"url": "http://[::1"})
        assert dest is not None
        assert dest.value == f"#{_sha16('http://[::1')}"


# ------------------------------------------------------------ profile config


class TestConfig:
    def test_internal_backend_refuses_it(self) -> None:
        with pytest.raises(ValidationError, match="internal"):
            Backend(url="internal://web", destination_params={"fetch_tool": "url"})

    def test_gateway_argument_refused(self) -> None:
        with pytest.raises(ValidationError, match="gateway argument"):
            Backend(url="http://x:1/mcp", destination_params={"send": "trentina_mode"})

    def test_glob_refused(self) -> None:
        with pytest.raises(ValidationError, match="must match"):
            Backend(url="http://x:1/mcp", destination_params={"send_*": "channel"})

    def test_loader_refuses_a_tool_the_allowlist_drops(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("T", "t")
        path = tmp_path / "profiles.yaml"
        path.write_text(
            "profiles:\n  a:\n    auth: {bearer_token_env: T}\n    backends:\n"
            "      slack:\n        url: http://s:1/mcp\n        tools_deny: [send_message]\n"
            "        destination_params: {send_message: channel}\n",
            encoding="utf-8",
        )
        with pytest.raises(ProfileConfigError, match="not allowed"):
            load_profiles(path)

    @staticmethod
    def _profile(backends: dict[str, tuple[str, dict[str, str]]]) -> Profile:
        return Profile(
            name="a",
            auth=AuthConfig(bearer_token_env="T"),
            backends={
                name: Backend(url=url, destination_params=params)
                for name, (url, params) in backends.items()
            },
        )

    @pytest.mark.parametrize(
        "after",
        [
            {"slack": ("http://s:1/mcp", {"send_dm": "user"})},  # dropped
            {"slack": ("http://s:1/mcp", {"send_message": "text"})},  # moved
            {"chat": ("http://relay:1/mcp", {})},  # renamed and repointed
            {},  # backend removed
        ],
    )
    def test_agent_reload_cannot_lose_a_rule(
        self, after: dict[str, tuple[str, dict[str, str]]]
    ) -> None:
        before = self._profile({"slack": ("http://s:1/mcp", {"send_message": "channel"})})
        assert _lost_destination_rules(before, self._profile(after)) == ["send_message:channel"]

    def test_moving_a_rule_onto_a_dummy_backend_is_caught(self) -> None:
        before = self._profile({"slack": ("http://s:1/mcp", {"send_message": "channel"})})
        after = self._profile(
            {
                "slack": ("http://s:1/mcp", {}),
                "dummy": ("http://dummy:1/mcp", {"send_message": "channel"}),
            }
        )
        assert _lost_destination_rules(before, after) == ["send_message:channel"]

    def test_renaming_with_the_rule_intact_is_allowed(self) -> None:
        before = self._profile({"slack": ("http://s:1/mcp", {"send_message": "channel"})})
        after = self._profile(
            {"chat": ("http://relay:1/mcp", {"send_message": "channel", "send_dm": "user"})}
        )
        assert _lost_destination_rules(before, after) == []

    def test_two_copies_need_two_copies(self) -> None:
        rule = {"send_message": "channel"}
        before = self._profile({"a": ("http://a:1/mcp", rule), "b": ("http://b:1/mcp", rule)})
        after = self._profile({"a": ("http://a:1/mcp", rule)})
        assert _lost_destination_rules(before, after) == ["send_message:channel"]


# ------------------------------------------------------------ the audit row


def test_an_old_database_gains_the_columns(audit_db: Path) -> None:
    old = sqlite3.connect(audit_db)
    old.execute(
        "CREATE TABLE gateway_calls (id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp REAL NOT "
        "NULL, profile TEXT NOT NULL, backend TEXT NOT NULL, tool TEXT NOT NULL, success "
        "BOOLEAN NOT NULL, duration_ms INTEGER NOT NULL, error_message TEXT)"
    )
    old.execute(
        "INSERT INTO gateway_calls (timestamp, profile, backend, tool, success, duration_ms) "
        "VALUES (1, 'p', 'b', 't', 1, 1)"
    )
    old.commit()
    old.close()

    columns = {r["name"] for r in db.get_db().execute("PRAGMA table_info(gateway_calls)")}
    assert {"destination", "destination_kind"} <= columns
    row = db.get_db().execute("SELECT destination FROM gateway_calls").fetchone()
    assert row["destination"] is None


def _slack_and_web() -> Profile:
    p = Profile(
        short_names=False,
        name="agent1",
        auth=AuthConfig(bearer_token_env="T"),
        backends={"slack": SLACK, "web": WEB},
    )
    p.auth.bearer_token = SecretStr("x")
    return p


async def _call(profile: Profile, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    return await route_jsonrpc(
        profile,
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": name, "arguments": arguments},
        },
    )


@pytest.mark.asyncio
@pytest.mark.usefixtures("audit_db")
async def test_fetch_search_and_a_declared_tool_are_recorded() -> None:
    ok = BackendCall(
        content=[{"type": "text", "text": "ok"}], is_error=False, structured_content=None
    )

    async def internal(*_a: Any, **_k: Any) -> BackendCall:
        return ok

    async def remote(*_a: Any, **_k: Any) -> BackendCall:
        return ok

    url = "https://docs.example.org/page?id=7"
    # The orchestrated response edge reaches these as ``transports.mcp.*``;
    # patch both namespaces with the SAME mock so either path is captured.
    transform = AsyncMock(side_effect=_passthrough_transform)
    scan = AsyncMock(side_effect=_clean_scan)
    with (
        patch("trentina.gateway.router.call_internal_tool", side_effect=internal),
        patch("trentina.gateway.router.call_backend_tool", side_effect=remote),
        patch("trentina.transports.mcp.transform_response", transform),
        patch("trentina.gateway.router.scan_tool_response", scan),
        patch("trentina.orchestrator.scan_tool_response", scan),
    ):
        await _call(_slack_and_web(), f"web{NAMESPACE_SEP}fetch_tool", {"url": url})
        await _call(_slack_and_web(), f"web{NAMESPACE_SEP}search_tool", {"query": "rhel 11"})
        await _call(
            _slack_and_web(),
            f"slack{NAMESPACE_SEP}send_message",
            {"channel": "C0OPS", "text": "hi"},
        )
        await _call(_slack_and_web(), f"slack{NAMESPACE_SEP}list_channels", {})

    rows = [
        (r["tool"], r["destination_kind"], r["destination"])
        for r in db.get_db().execute("SELECT * FROM gateway_calls ORDER BY id")
    ]
    assert rows == [
        ("fetch_tool", "fetch", f"docs.example.org#{_sha16(url)}"),
        ("search_tool", "search", f"q#{_sha16('rhel 11')}"),
        ("send_message", "param", "C0OPS"),
        ("list_channels", None, None),
    ]


@pytest.mark.asyncio
@pytest.mark.usefixtures("audit_db")
async def test_a_refused_call_still_records_where_it_pointed() -> None:
    profile = _slack_and_web()
    profile.backends["slack"] = Backend(
        url="http://mcp-slack:8000/mcp",
        destination_params={"send_message": "channel"},
        literal_request_guards={"send_message": {"channel": ParameterConstraint(allow=["C0OPS"])}},
    )
    await _call(profile, f"slack{NAMESPACE_SEP}send_message", {"channel": "C0EXFIL"})

    row = db.get_db().execute("SELECT outcome, destination FROM gateway_calls").fetchone()
    assert (row["outcome"], row["destination"]) == (Outcome.DENIED_GUARD.value, "C0EXFIL")


async def _passthrough_transform(**kwargs: Any) -> Any:
    return SimpleNamespace(
        failed=None,
        content_blocks=kwargs["content_blocks"],
        provenance=None,
        sidecar=None,
        briefing=None,
        hidden=None,
    )


async def _clean_scan(**_kwargs: Any) -> Any:
    return SimpleNamespace(blocked=False, extraction=None, warning=None)


# ------------------------------------------------------------ quarantine_stats

YAML = """\
profiles:
  op:
    role: operator
    defense:
      provider: ollama
    auth:
      bearer_token_env: TEST_OP_TOKEN
    backends:
      web:
        url: internal://web
  kage:
    auth:
      bearer_token_env: TEST_KAGE_TOKEN
    backends:
      slack:
        url: http://slack:1/mcp
        destination_params:
          send_message: channel
  take:
    auth:
      bearer_token_env: TEST_TAKE_TOKEN
    backends:
      slack:
        url: http://slack:1/mcp
        destination_params:
          send_message: channel
"""


@pytest.fixture
def gateway(audit_db: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[dict]:
    for name in ("OP", "KAGE", "TAKE"):
        monkeypatch.setenv(f"TEST_{name}_TOKEN", name.lower())
    path = audit_db.parent / "profiles.yaml"
    path.write_text(YAML, encoding="utf-8")
    config = load_profiles(path)
    register_active_config(path, config, {})
    set_profiles(config.profiles)
    _row("kage", "slack", "send_message", "C0KAGE", "param")
    _row("kage", "web", "fetch_tool", "kage-only.example#0123456789abcdef", "fetch")
    _row("take", "slack", "send_message", "take secret channel", "param")
    yield config.profiles
    compress._profiles = None


def _row(profile: str, backend: str, tool: str, dest: str, kind: str) -> None:
    db.record_gateway_call(
        profile, backend, tool, Outcome.OK.value, 1, destination=dest, destination_kind=kind
    )


@pytest.mark.asyncio
class TestStats:
    async def test_an_agent_sees_only_its_own(self, gateway: dict) -> None:
        with profile_context(gateway["kage"]):
            result = await get_trentina_stats()

        assert {d["destination"] for d in result["destinations"]} == {
            "C0KAGE",
            "kage-only.example#0123456789abcdef",
        }
        assert "take" not in str(result["destinations"])
        assert "fanout" not in result

    async def test_the_operator_sees_every_profile(self, gateway: dict) -> None:
        with profile_context(gateway["op"]):
            result = await get_trentina_stats()

        assert set(result["destinations"]) == {"kage", "take"}
        # Text another agent chose is fingerprinted, never shown.
        shown = [d["destination"] for rows in result["destinations"].values() for d in rows]
        assert all(d.startswith("sha256:") for d in shown)
        assert "C0KAGE" not in str(result)
        assert "secret" not in str(result)
        assert result["fanout"]["profiles"] == {
            "kage": {"fetch_hosts": 1, "comms_calls": 1},
            "take": {"fetch_hosts": 0, "comms_calls": 1},
        }

    async def test_an_agent_is_not_shown_its_own_decoy_trips(self, gateway: dict) -> None:
        """#357: the operator reads a trip, with where it was pointed. The
        agent that made it reads neither the call nor the destination."""
        db.record_gateway_call(
            "kage",
            "slack",
            "send_message",
            Outcome.DECOY_TRIPPED.value,
            0,
            "honeytoken aws-key",
            destination="C0EXFIL",
            destination_kind="param",
        )
        with profile_context(gateway["kage"]):
            mine = await get_trentina_stats()
        assert "C0EXFIL" not in str(mine)
        assert "tripped" not in str(mine)
        with profile_context(gateway["op"]):
            everyone = await get_trentina_stats()
        assert everyone["gateway_audit"]["totals"]["tripped"] == 1
        assert "tripped" in everyone["gateway_audit"]["column_meanings"]


# ------------------------------------------------------------ the nagios check


def _load_check() -> ModuleType:
    loader = importlib.machinery.SourceFileLoader("check_trentina_fanout", str(CHECK))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


def test_the_check_and_the_gateway_count_the_same_way() -> None:
    assert _load_check().FANOUT_QUERY == db.FANOUT_QUERY


THRESHOLDS = ["--hosts-warn", "10", "--hosts-crit", "30", "--comms-warn", "5", "--comms-crit", "20"]


class TestFanoutCheck:
    def _check(self, path: Path) -> tuple[int, str]:
        db._db = None  # the check reads the file, not the connection
        status: int
        status, line = _load_check().check(["--db", str(path), *THRESHOLDS])
        return status, line

    def test_quiet_is_ok(self, audit_db: Path) -> None:
        for i in range(3):
            _row("kage", "web", "fetch_tool", f"h{i}.example#{i:016x}", "fetch")
        assert self._check(audit_db)[0] == 0

    def test_a_burst_of_hosts_is_critical(self, audit_db: Path) -> None:
        for i in range(40):
            _row("swarm", "web", "fetch_tool", f"h{i}.example#{i:016x}", "fetch")
        _row("calm", "web", "fetch_tool", "one.example#0000000000000000", "fetch")
        status, line = self._check(audit_db)
        assert status == 2
        assert "swarm fetch_hosts=40" in line
        assert "calm" not in line.split("|")[0]
        assert "h1.example" not in line

    def test_one_host_many_times_is_one_host(self, audit_db: Path) -> None:
        for i in range(40):
            _row("kage", "web", "fetch_tool", f"same.example#{i:016x}", "fetch")
        assert self._check(audit_db)[0] == 0

    def test_comms_burst_warns(self, audit_db: Path) -> None:
        for i in range(6):
            _row("kage", "slack", "send_message", f"C{i}", "param")
        status, line = self._check(audit_db)
        assert status == 1
        assert "comms_calls=6" in line

    def test_old_rows_fall_out_of_the_window(self, audit_db: Path) -> None:
        for i in range(40):
            _row("kage", "web", "fetch_tool", f"h{i}.example#{i:016x}", "fetch")
        db.get_db().execute("UPDATE gateway_calls SET timestamp = ?", (time.time() - 3600,))
        db.get_db().commit()
        assert self._check(audit_db)[0] == 0

    def test_a_missing_database_is_unknown(self, tmp_path: Path) -> None:
        status, _ = _load_check().check(["--db", str(tmp_path / "none.db"), *THRESHOLDS])
        assert status == 3


def test_a_lost_audit_row_is_logged_not_raised(caplog: pytest.LogCaptureFixture) -> None:
    """The audit never fails the call, and never loses a row silently (#281)."""
    from trentina.gateway import audit

    with patch.object(audit, "record_gateway_call", side_effect=OSError("disk full C0SECRET")):
        audit._audit("kage", "slack", "send_message", Outcome.OK, 1)

    lost = [r for r in caplog.records if "audit row lost" in r.getMessage()]
    assert len(lost) == 1
    assert "profile=kage" in lost[0].getMessage()
    assert "OSError" in lost[0].getMessage()
    assert "C0SECRET" not in lost[0].getMessage()
