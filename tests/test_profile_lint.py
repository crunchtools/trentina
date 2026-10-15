"""profiles.yaml posture lint (#269): shared write backends, toxic flows, fail-closed defaults."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
import yaml

from trentina.gateway import profile_lint
from trentina.gateway.profile_lint import (
    check_require_defaults,
    classify,
    held_tools,
    lint_file,
    main,
)

FIXTURES = Path(__file__).parent / "fixtures" / "profile-lint"
REPO = Path(__file__).resolve().parent.parent


def _codes(path: Path) -> list[str]:
    return [f.code for f in lint_file(path)]


class TestClassify:
    @pytest.mark.parametrize(
        "name",
        [
            "create_issue",
            "memory_store",
            "github_update_issue",
            "trigger_workflow",
            "rerun_failed_jobs",
            "set_ticket_status",
            "deletePostTool",
            "add_time_worked",
        ],
    )
    def test_writes(self, name: str) -> None:
        assert "write" in classify(name)

    @pytest.mark.parametrize(
        "name",
        [
            "send_message",
            "personal_send_gmail_message",
            "reply_to_ticket",
            "crunch_create_post",
            "integrationSchedulePostTool",
            "add_ticket_comment",
        ],
    )
    def test_outbound(self, name: str) -> None:
        assert "outbound" in classify(name)

    @pytest.mark.parametrize(
        "name", ["get_ticket", "crunch_get_post", "list_posts", "search_messages", "wiki_search"]
    )
    def test_reads(self, name: str) -> None:
        assert classify(name) == set()

    def test_a_wildcard_holds_what_it_could_admit(self) -> None:
        assert held_tools({"tools_allow": ["*"]})["*"] >= {"write", "outbound"}
        assert "write" in held_tools({"tools_allow": ["memory_*"]})["memory_*"]
        assert held_tools({"tools_allow": ["get_*", "list_*"]}) == {}

    def test_deny_is_honoured(self) -> None:
        backend = {"tools_allow": ["*"], "tools_deny": ["*"]}
        assert held_tools(backend) == {}


class TestFixtures:
    def test_clean(self) -> None:
        assert lint_file(FIXTURES / "clean.yaml") == []

    def test_shared_write_backends(self) -> None:
        messages = [str(f) for f in lint_file(FIXTURES / "shared_write.yaml")]
        shared = sorted(m for m in messages if m.startswith("shared-write-backend"))
        # One finding per URL. memory: kagetora/takeda are declared, but josui
        # shares it with both undeclared, so all three are named. rt: the pair
        # is declared with an empty reason, which does not count.
        assert len(shared) == 2, messages
        (memory,) = [m for m in shared if "mcp-memory" in m]
        (rt,) = [m for m in shared if "mcp-rt" in m]
        assert "mcp-memory" in memory
        assert all(f"'{p}'" in memory for p in ("josui", "kagetora", "takeda"))
        assert "mcp-rt" in rt
        assert "'josui'" in rt
        assert "'kagetora'" in rt

    def test_toxic_flow(self) -> None:
        findings = [str(f) for f in lint_file(FIXTURES / "toxic.yaml")]
        toxic = sorted(f for f in findings if f.startswith("toxic-flow"))
        assert len(toxic) == 2, findings
        assert "'catch-all'" in toxic[0]
        toxic = toxic[1:]
        assert "'toxic'" in toxic[0]
        assert "personal_send_gmail_message" in toxic[0]
        assert "postiz:*" in toxic[0]

    def test_a_declared_group_is_clean_and_output_is_per_url(self) -> None:
        backend = {"url": "http://mcp-m:1/mcp", "tools_allow": ["memory_store"]}
        names = [f"agent-{n}" for n in range(200)]
        profiles_file: dict[str, object] = {
            "profiles": {n: {"backends": {"m": backend}} for n in names}
        }
        (finding,) = profile_lint.check_shared_write_backends(profiles_file)
        assert "200 profiles" in str(finding)
        profiles_file["shared_backends"] = [
            {"url": "http://mcp-m:1/mcp/", "profiles": names, "reason": "one shared memory"}
        ]
        assert profile_lint.check_shared_write_backends(profiles_file) == []

    def test_assistants_are_exempt_and_swarm_seats_are_not(self) -> None:
        """Interactive assistants hold broad tools on purpose; an unattended seat
        writing where they read is still the channel the check is for."""
        memory = {"url": "http://mcp-m:1/mcp", "tools_allow": ["memory_store"]}
        profiles: dict[str, Any] = {
            name: {"backends": {"m": memory}} for name in ("josui", "kagetora")
        }
        profiles_file: dict[str, Any] = {
            "profiles": profiles,
            "assistants": {"profiles": ["josui", "kagetora"], "reason": "used interactively"},
        }
        assert profile_lint.check_shared_write_backends(profiles_file) == []
        profiles["swarm-1"] = {"backends": {"m": memory}}
        (finding,) = profile_lint.check_shared_write_backends(profiles_file)
        assert "'swarm-1'" in str(finding)

    def test_an_assistant_declaration_needs_a_reason(self) -> None:
        assert profile_lint.assistants({"assistants": {"profiles": ["josui"]}}) == frozenset()
        assert profile_lint.assistants(
            {"assistants": {"profiles": ["josui"], "reason": "interactive"}}
        ) == frozenset({"josui"})

    def test_an_assistant_is_exempt_from_toxic_flow(self) -> None:
        profiles_file = yaml.safe_load((FIXTURES / "toxic.yaml").read_text())
        profiles_file["assistants"] = {"profiles": ["toxic", "catch-all"], "reason": "interactive"}
        assert profile_lint.check_toxic_flows(profiles_file) == []

    def test_a_finding_never_prints_a_url_credential(self) -> None:
        backend = {"url": "http://u:pw@mcp-x:8000/api/mcp/KEY?token=TOK", "tools_allow": ["*"]}
        profiles_file = {
            "profiles": {"a": {"backends": {"x": backend}}, "b": {"backends": {"x": backend}}}
        }
        (finding,) = profile_lint.check_shared_write_backends(profiles_file)
        assert "http://mcp-x:8000" in str(finding)
        assert not any(secret in str(finding) for secret in ("pw", "KEY", "TOK", "u:"))

    def test_the_shipped_example_is_clean(self) -> None:
        assert lint_file(REPO / "examples" / "profiles-agent1.yaml") == []


class TestOAuthSubjects:
    """#458: an OAuth seat should name the account, not just the address."""

    @staticmethod
    def _file(**oauth: Any) -> dict[str, Any]:
        return {"profiles": {"seat": {"oauth": {"enabled": True, **oauth}}}}

    def test_email_only_is_a_finding(self) -> None:
        profiles_file = self._file(allowed_emails=["a@b.co"])
        (finding,) = profile_lint.check_oauth_subjects(profiles_file)
        assert finding.code == "oauth-email-only"
        assert "'seat'" in finding.message

    def test_pinned_subjects_are_clean(self) -> None:
        profiles_file = self._file(allowed_emails=["a@b.co"], allowed_subjects=[1001])
        assert profile_lint.check_oauth_subjects(profiles_file) == []

    def test_oauth_off_is_clean(self) -> None:
        profiles_file = {
            "profiles": {"seat": {"oauth": {"enabled": False, "allowed_emails": ["a@b.co"]}}}
        }
        assert profile_lint.check_oauth_subjects(profiles_file) == []


class TestRequireDefaults:
    def test_the_real_config_is_fail_closed(self) -> None:
        assert check_require_defaults() == []

    @pytest.mark.parametrize(
        "source",
        [
            'x = bool_env("TRENTINA_REQUIRE_L3", False)',
            'x = bool_env("TRENTINA_REQUIRE_L2")',
            'x = os.environ.get("TRENTINA_REQUIRE_L2", "true")',
            'x = bool_env(name="TRENTINA_REQUIRE_L2", default=False)',
            'x = os.getenv(key="TRENTINA_REQUIRE_L3")',
        ],
    )
    def test_an_open_default_is_a_finding(self, source: str) -> None:
        assert [f.code for f in check_require_defaults(source)] == ["require-default-open"]

    def test_a_keyword_default_of_true_is_closed(self) -> None:
        assert check_require_defaults('x = bool_env("TRENTINA_REQUIRE_L2", default=True)') == []

    def test_losing_the_switch_is_a_finding(self) -> None:
        assert [f.code for f in check_require_defaults("x = 1")] == ["require-default-open"]


class TestEntrypoint:
    def test_exit_codes(self, capsys: pytest.CaptureFixture[str]) -> None:
        assert main([str(FIXTURES / "clean.yaml")]) == 0
        assert main([str(FIXTURES / "toxic.yaml")]) == 1
        assert "toxic-flow" in capsys.readouterr().out
        assert main([str(FIXTURES / "missing.yaml")]) == 2
        assert main([]) == 2

    def test_module_is_runnable(self) -> None:
        assert callable(profile_lint.main)
