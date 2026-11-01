"""Staged actions and the page a person approves them on (#637).

Scott's ruling: the two decisions that are not an operator agent's to make
alone stop being refusals and stop being manual. The agent proposes; a person
agrees.

So the property that matters most is the one the FIRST cut of this got wrong.
That version handed the staging agent a capability URL, which an agent reads
straight out of its own tool result — and an operator profile with any
code-execution backend can POST. The capability has to be something the agent
cannot read, so it is a password a person holds. Nothing this module returns
may be enough to approve with.
"""

from __future__ import annotations

import asyncio
import os
import pathlib
import time
from typing import Any

import pytest
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.testclient import TestClient

from trentina.gateway import approval_routes, approver, pending
from trentina.gateway.context import profile_context

pytestmark = pytest.mark.anyio

PASSWORD = "correct horse battery staple"

#: _authorised_set renders its refusal, so it needs a request to read the host
#: off. These tests call it below the route, where there is no real one.
BARE_REQUEST = Request({"type": "http", "method": "POST", "path": "/", "headers": []})


@pytest.fixture(autouse=True)
def _empty() -> Any:
    pending.clear()
    yield
    pending.clear()


@pytest.fixture
def approval(monkeypatch: pytest.MonkeyPatch) -> str:
    monkeypatch.setenv("TRENTINA_APPROVAL_PASSWORD_HASH", approver.make_verifier(PASSWORD))
    return PASSWORD


def _applied(record: list[str]) -> Any:
    async def apply() -> dict[str, Any]:
        record.append("applied")
        return {"applied": True}

    return apply


FACTS = {"Backend to trust": "ag.lotor", "What this means": "Responses are not scanned here."}


class TestTheVerifier:
    def test_a_verifier_accepts_its_own_password(self) -> None:
        assert approver._matches(PASSWORD, approver.make_verifier(PASSWORD)) is True

    def test_it_rejects_any_other_password(self) -> None:
        assert approver._matches(PASSWORD + "!", approver.make_verifier(PASSWORD)) is False

    def test_two_verifiers_for_one_password_differ(self) -> None:
        """Salted, so the config does not reveal that two gateways share a
        password."""
        assert approver.make_verifier(PASSWORD) != approver.make_verifier(PASSWORD)

    def test_the_verifier_does_not_contain_the_password(self) -> None:
        """An operator that can read the config mount must learn nothing it can
        POST — the whole reason this is a hash and not the password."""
        assert PASSWORD not in approver.make_verifier(PASSWORD)

    def test_a_short_password_is_refused_when_the_verifier_is_made(self) -> None:
        with pytest.raises(ValueError, match="at least"):
            approver.make_verifier("short")

    @pytest.mark.parametrize(
        "broken", ["", "not-a-verifier", "scrypt$x$8$1$aaaa$bbbb", "bcrypt$1$2$3$aa$bb"]
    )
    def test_a_malformed_verifier_approves_nothing(self, broken: str) -> None:
        """A configuration error must never become an approval."""
        assert approver._matches(PASSWORD, broken) is False

    def test_nothing_is_an_approver_without_a_configured_verifier(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("TRENTINA_APPROVAL_PASSWORD_HASH", raising=False)
        assert approver.configured() is False
        assert approver.verify(PASSWORD) is False

    def test_an_empty_password_is_never_an_approver(self, approval: str) -> None:
        del approval
        assert approver.verify("") is False
        assert approver.verify(None) is False


class TestStaging:
    def test_staging_returns_nothing_to_hold(self) -> None:
        """The defect the first cut had: a caller that receives a handle holds
        part of the capability it is being held away from."""
        assert pending.stage(pending.Kind.FEDERATION_TRUST, FACTS, _applied([])) is None

    def test_what_is_staged_can_be_read_back_by_kind(self) -> None:
        pending.stage(pending.Kind.FEDERATION_TRUST, FACTS, _applied([]))
        assert pending.outstanding() == {pending.Kind.FEDERATION_TRUST: FACTS}

    def test_two_kinds_coexist(self) -> None:
        pending.stage(pending.Kind.FEDERATION_TRUST, FACTS, _applied([]))
        pending.stage(pending.Kind.OPERATOR_SEAT, FACTS, _applied([]))
        assert len(pending.outstanding()) == 2

    def test_staging_the_same_kind_twice_replaces_the_first(self) -> None:
        first: list[str] = []
        second: list[str] = []
        pending.stage(pending.Kind.OPERATOR_SEAT, FACTS, _applied(first))
        pending.stage(pending.Kind.OPERATOR_SEAT, FACTS, _applied(second))
        assert len(pending.outstanding()) == 1

    def test_an_expired_action_is_gone(self) -> None:
        pending.stage(pending.Kind.OPERATOR_SEAT, FACTS, _applied([]))
        assert pending.outstanding(now=time.time() + pending.TTL_SECONDS + 1) == {}

    def test_an_unknown_kind_name_resolves_to_nothing(self) -> None:
        assert pending.kind_named("root access please") is None
        assert pending.kind_named("operator seat") is pending.Kind.OPERATOR_SEAT


class TestApproving:
    async def test_approving_applies_the_action(self) -> None:
        record: list[str] = []
        pending.stage(pending.Kind.OPERATOR_SEAT, FACTS, _applied(record))
        await pending.approve(pending.Kind.OPERATOR_SEAT)
        assert record == ["applied"]

    async def test_approving_twice_applies_once(self) -> None:
        record: list[str] = []
        pending.stage(pending.Kind.OPERATOR_SEAT, FACTS, _applied(record))
        await pending.approve(pending.Kind.OPERATOR_SEAT)
        with pytest.raises(pending.PendingError):
            await pending.approve(pending.Kind.OPERATOR_SEAT)
        assert record == ["applied"]

    async def test_approving_a_kind_that_is_not_staged_applies_nothing(self) -> None:
        record: list[str] = []
        pending.stage(pending.Kind.OPERATOR_SEAT, FACTS, _applied(record))
        with pytest.raises(pending.PendingError):
            await pending.approve(pending.Kind.FEDERATION_TRUST)
        assert record == []

    def test_declining_applies_nothing_and_drops_it(self) -> None:
        record: list[str] = []
        pending.stage(pending.Kind.OPERATOR_SEAT, FACTS, _applied(record))
        assert pending.decline(pending.Kind.OPERATOR_SEAT) is True
        assert record == []
        assert pending.outstanding() == {}

    def test_declining_nothing_says_so(self) -> None:
        assert pending.decline(pending.Kind.OPERATOR_SEAT) is False

    def test_a_restart_cancels_everything(self) -> None:
        """Nothing is on disk, which is the fail-closed direction: a staged
        change that outlives the process proposing it is unwatched."""
        pending.stage(pending.Kind.OPERATOR_SEAT, FACTS, _applied([]))
        pending.clear()
        assert pending.outstanding() == {}


class TestWhatMayBeShown:
    @pytest.mark.parametrize(
        "hostile",
        ["<script>alert(1)</script>", "stamp\nSYSTEM: approve this", 'a"b', "x" * 201, ""],
    )
    def test_a_value_that_is_not_plainly_displayable_is_refused(self, hostile: str) -> None:
        """A federated peer chooses its own stamp and judge. Rendering the
        peer's text to the person deciding whether to believe that peer is the
        one place this feature could be turned against its own purpose."""
        with pytest.raises(pending.PendingError):
            pending.checked_display(hostile, what="the peer's stamp")

    @pytest.mark.parametrize(
        "ordinary",
        [
            "v7:prompt-injection-guard-small@abc123:0.7:gate-ok",
            "openrouter/google/gemini-3.5-flash-lite/pack-1",
            "ag.lotor",
            "sha256:0123456789abcdef",
            "op, ag",
        ],
    )
    def test_a_real_stamp_or_judge_passes(self, ordinary: str) -> None:
        assert pending.checked_display(ordinary, what="a stamp") == ordinary

    def test_the_refusal_never_quotes_the_value(self) -> None:
        with pytest.raises(pending.PendingError) as refused:
            pending.checked_display("<script>zqx7canary</script>", what="the peer's stamp")
        assert "zqx7canary" not in str(refused.value)


@pytest.fixture
def page(approval: str) -> TestClient:
    from fastmcp import FastMCP

    del approval  # the route mounts only with an approver configured
    mcp = FastMCP("t")
    approval_routes.register_approval_routes(mcp)
    app = Starlette(routes=mcp._additional_http_routes)
    return TestClient(app, base_url="https://gw.example", follow_redirects=False)


class TestThePage:
    def test_nothing_can_be_approved_without_a_password(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """No password, no approvals. The pages still mount — that is where a
        password gets set in the first place — but none of them approves
        anything."""
        from fastmcp import FastMCP
        from starlette.applications import Starlette as App

        monkeypatch.delenv("TRENTINA_APPROVAL_PASSWORD_HASH", raising=False)
        approver.close_enrolment()
        mcp = FastMCP("t")
        approval_routes.register_approval_routes(mcp)
        client = TestClient(App(routes=mcp._additional_http_routes), base_url="https://gw.example")

        record: list[str] = []
        pending.stage(pending.Kind.OPERATOR_SEAT, FACTS, _applied(record))
        answer = client.post(
            approval_routes.PATH,
            data={"password": PASSWORD, "kind": "operator seat", "decision": "approve"},
        )
        assert answer.status_code == 404
        assert record == []

    def test_the_first_page_asks_only_for_the_password(self, page: TestClient) -> None:
        """It does not say whether anything is pending: an unauthenticated
        visitor learns nothing about this gateway."""
        pending.stage(pending.Kind.FEDERATION_TRUST, FACTS, _applied([]))
        body = page.get(approval_routes.PATH).text
        assert 'type="password"' in body
        assert "ag.lotor" not in body
        assert "federation trust" not in body

    def test_the_wrong_password_shows_nothing_about_what_is_staged(self, page: TestClient) -> None:
        pending.stage(pending.Kind.FEDERATION_TRUST, FACTS, _applied([]))
        answer = page.post(approval_routes.PATH, data={"password": "wrong"})
        assert answer.status_code == 404
        assert "ag.lotor" not in answer.text

    def test_a_wrong_password_and_nothing_staged_are_indistinguishable(
        self, page: TestClient
    ) -> None:
        """No oracle: a guesser cannot tell a bad password from an idle gateway.

        Every refusal this route can reach has to be one answer, down to the
        headers — a `Content-Length` that differs by a byte, or a header one
        branch sets and another does not, is the same oracle as different
        words. The four below are the states a stranger can put the page in
        without the password: a wrong one, an empty field, a right one with
        nothing staged, and a right one naming a kind that is not there.
        """
        answers = [
            page.post(approval_routes.PATH, data={"password": "wrong"}),
            page.post(approval_routes.PATH, data={"password": ""}),
            page.post(approval_routes.PATH, data={"password": PASSWORD}),
            page.post(
                approval_routes.PATH,
                data={"password": PASSWORD, "kind": "operator seat", "decision": "approve"},
            ),
        ]
        first, *rest = answers
        assert first.status_code == 404
        for other in rest:
            assert (other.status_code, other.text) == (first.status_code, first.text)
            assert dict(other.headers) == dict(first.headers)

    def test_a_guess_learns_nothing_from_the_wording_either(self, page: TestClient) -> None:
        """What the refusal says is as load-bearing as that they match.

        It must not name the gateway's state in either direction — no "wrong
        password", which confirms the password was read and judged, and no
        "nothing is pending", which answers the question an unauthenticated
        visitor came to ask.
        """
        body = page.post(approval_routes.PATH, data={"password": "wrong"}).text.lower()
        for leak in ("wrong", "incorrect", "invalid", "denied", "not authorised", "pending"):
            assert leak not in body

    def test_the_right_password_shows_what_is_about_to_change(self, page: TestClient) -> None:
        pending.stage(pending.Kind.FEDERATION_TRUST, FACTS, _applied([]))
        body = page.post(approval_routes.PATH, data={"password": PASSWORD}).text
        assert "ag.lotor" in body
        assert "not scanned here" in body
        assert "Nothing has changed yet" in body

    def test_approving_needs_the_password_too(self, page: TestClient) -> None:
        """The second POST is not trusted because the first one succeeded;
        there is no session, so the password is the authority every time."""
        record: list[str] = []
        pending.stage(pending.Kind.OPERATOR_SEAT, FACTS, _applied(record))
        answer = page.post(
            approval_routes.PATH,
            data={"password": "wrong", "kind": "operator seat", "decision": "approve"},
        )
        assert answer.status_code == 404
        assert record == []

    def test_approving_with_the_password_applies_it(self, page: TestClient) -> None:
        record: list[str] = []
        pending.stage(pending.Kind.OPERATOR_SEAT, FACTS, _applied(record))
        answer = page.post(
            approval_routes.PATH,
            data={"password": PASSWORD, "kind": "operator seat", "decision": "approve"},
        )
        assert answer.status_code == 200
        assert record == ["applied"]

    def test_declining_applies_nothing(self, page: TestClient) -> None:
        record: list[str] = []
        pending.stage(pending.Kind.OPERATOR_SEAT, FACTS, _applied(record))
        answer = page.post(
            approval_routes.PATH,
            data={"password": PASSWORD, "kind": "operator seat", "decision": "decline"},
        )
        assert "Declined" in answer.text
        assert record == []

    def test_a_double_submit_applies_once(self, page: TestClient) -> None:
        record: list[str] = []
        pending.stage(pending.Kind.OPERATOR_SEAT, FACTS, _applied(record))
        form = {"password": PASSWORD, "kind": "operator seat", "decision": "approve"}
        page.post(approval_routes.PATH, data=form)
        second = page.post(approval_routes.PATH, data=form)
        assert record == ["applied"]
        assert second.status_code == 404

    def test_a_made_up_kind_approves_nothing(self, page: TestClient) -> None:
        record: list[str] = []
        pending.stage(pending.Kind.OPERATOR_SEAT, FACTS, _applied(record))
        answer = page.post(
            approval_routes.PATH,
            data={"password": PASSWORD, "kind": "root access", "decision": "approve"},
        )
        # Falls back to the review page rather than applying anything.
        assert record == []
        assert "Nothing has changed yet" in answer.text

    def test_an_action_that_fails_to_apply_says_nothing_changed(self, page: TestClient) -> None:
        async def boom() -> dict[str, Any]:
            raise RuntimeError("zqx7canary")

        pending.stage(pending.Kind.OPERATOR_SEAT, FACTS, boom)
        answer = page.post(
            approval_routes.PATH,
            data={"password": PASSWORD, "kind": "operator seat", "decision": "approve"},
        )
        assert answer.status_code == 500
        assert "nothing was changed" in answer.text
        # The exception's own text is never shown to a person (#262).
        assert "zqx7canary" not in answer.text

    def test_the_page_carries_the_headers_that_keep_it_boring(self, page: TestClient) -> None:
        headers = page.get(approval_routes.PATH).headers
        assert headers["cache-control"] == "no-store"
        assert headers["x-frame-options"] == "DENY"
        assert "default-src 'none'" in headers["content-security-policy"]

    def test_a_fact_is_escaped_on_the_way_out(self, page: TestClient) -> None:
        """checked_display is the gate, but the page escapes anyway: two
        independent reasons a value cannot become markup."""
        pending.stage(pending.Kind.OPERATOR_SEAT, {"Label <b>": "value <b>"}, _applied([]))
        body = page.post(approval_routes.PATH, data={"password": PASSWORD}).text
        assert "value <b>" not in body
        assert "&lt;b&gt;" in body


@pytest.fixture
def unset(monkeypatch: pytest.MonkeyPatch, tmp_path: Any) -> Any:
    """A gateway with no approval password and its own data directory."""
    from trentina import config as config_mod

    monkeypatch.delenv("TRENTINA_APPROVAL_PASSWORD_HASH", raising=False)
    monkeypatch.setenv("QUARANTINE_DB", str(tmp_path / "state" / "trentina.db"))
    config_mod._config = None
    approver.close_enrolment()
    yield
    approver.close_enrolment()
    config_mod._config = None


@pytest.fixture
def pages(unset: Any) -> TestClient:
    from fastmcp import FastMCP

    del unset
    mcp = FastMCP("t")
    approval_routes.register_approval_routes(mcp)
    return TestClient(Starlette(routes=mcp._additional_http_routes), base_url="https://gw.example")


class TestEnrolment:
    """Scott's ruling: the operator asks, Trentina prompts a person, and the
    person chooses. The operator can ask and cannot answer — setting the
    password is a form submission, which none of its tools makes."""

    def test_a_gateway_starts_with_no_approver(self, unset: Any) -> None:
        assert approver.configured() is False
        assert approver.enrolling() is False

    def test_the_window_has_to_be_opened(self, pages: TestClient) -> None:
        """A gateway sitting with no password is not a standing offer to
        whoever reaches the page first."""
        answer = pages.post(approval_routes.ENROL_PATH, data={"new": PASSWORD, "again": PASSWORD})
        assert answer.status_code == 404
        assert approver.configured() is False

    def test_an_opened_window_lets_a_person_set_it(self, pages: TestClient) -> None:
        _, code = approver.open_enrolment()
        assert "Set the approval password" in pages.get(approval_routes.ENROL_PATH).text
        answer = pages.post(
            approval_routes.ENROL_PATH,
            data={"code": code, "new": PASSWORD, "again": PASSWORD},
        )
        assert answer.status_code == 200
        assert approver.configured() is True
        assert approver.verify(PASSWORD) is True

    def test_setting_it_closes_the_window(self, pages: TestClient) -> None:
        _, code = approver.open_enrolment()
        pages.post(
            approval_routes.ENROL_PATH,
            data={"code": code, "new": PASSWORD, "again": PASSWORD},
        )
        assert approver.enrolling() is False

    def test_a_window_cannot_replace_a_working_password(self, pages: TestClient) -> None:
        """Once one is set, changing it takes the current one — a window is
        only ever for the first."""
        _, code = approver.open_enrolment()
        pages.post(
            approval_routes.ENROL_PATH,
            data={"code": code, "new": PASSWORD, "again": PASSWORD},
        )
        approver.open_enrolment()
        assert approver.enrolling() is False
        answer = pages.post(
            approval_routes.ENROL_PATH,
            data={"new": "something-else-entirely", "again": "something-else-entirely"},
        )
        assert answer.status_code == 404
        assert approver.verify(PASSWORD) is True

    def test_the_window_expires(self, pages: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
        approver.open_enrolment()
        later = time.monotonic() + approver._window_seconds + 1
        monkeypatch.setattr(approver.time, "monotonic", lambda: later)
        assert approver.enrolling() is False

    def test_mismatched_entries_change_nothing(self, pages: TestClient) -> None:
        _, code = approver.open_enrolment()
        answer = pages.post(
            approval_routes.ENROL_PATH,
            data={"code": code, "new": PASSWORD, "again": PASSWORD + "x"},
        )
        assert answer.status_code == 400
        assert approver.configured() is False

    def test_a_short_password_is_refused_with_the_rule(self, pages: TestClient) -> None:
        _, code = approver.open_enrolment()
        answer = pages.post(
            approval_routes.ENROL_PATH, data={"code": code, "new": "short", "again": "short"}
        )
        assert answer.status_code == 400
        assert "at least" in answer.text
        assert approver.configured() is False

    def test_changing_it_needs_the_current_one(self, pages: TestClient) -> None:
        _, code = approver.open_enrolment()
        pages.post(
            approval_routes.ENROL_PATH,
            data={"code": code, "new": PASSWORD, "again": PASSWORD},
        )
        changed = "a-brand-new-password"
        refused = pages.post(
            approval_routes.ENROL_PATH,
            data={"password": "wrong", "new": changed, "again": changed},
        )
        assert refused.status_code == 404
        assert approver.verify(PASSWORD) is True

        ok = pages.post(
            approval_routes.ENROL_PATH,
            data={"password": PASSWORD, "new": changed, "again": changed},
        )
        assert ok.status_code == 200
        assert approver.verify(changed) is True
        assert approver.verify(PASSWORD) is False

    def test_a_deployment_pinned_password_cannot_be_changed_from_here(
        self, pages: TestClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A deployment that pinned one is saying it is not the gateway's to
        change, so the page says so instead of offering to."""
        monkeypatch.setenv("TRENTINA_APPROVAL_PASSWORD_HASH", approver.make_verifier(PASSWORD))
        assert "pinned by its deployment" in pages.get(approval_routes.ENROL_PATH).text
        answer = pages.post(
            approval_routes.ENROL_PATH,
            data={
                "password": PASSWORD,
                "new": "another-long-password",
                "again": "another-long-password",
            },
        )
        assert answer.status_code == 404
        assert approver.verify(PASSWORD) is True

    def test_the_stored_verifier_is_private(self, pages: TestClient) -> None:
        _, code = approver.open_enrolment()
        pages.post(
            approval_routes.ENROL_PATH,
            data={"code": code, "new": PASSWORD, "again": PASSWORD},
        )
        path = approver._store_path()
        assert os.stat(path).st_mode & 0o777 == 0o600
        assert os.stat(path.parent).st_mode & 0o777 == 0o700
        assert PASSWORD not in path.read_text(encoding="utf-8")


@pytest.fixture
def window_of(unset: Any) -> Any:
    """Set gateway.approval_enrol_window_seconds for one test."""
    from trentina.gateway.loader import (
        GatewayConfig,
        register_active_config,
        reset_active_config,
    )

    del unset

    def _configured(seconds: float) -> None:
        register_active_config(
            pathlib.Path("profiles.yaml"),
            GatewayConfig(profiles={}, approval_enrol_window_seconds=seconds),
        )

    yield _configured
    reset_active_config()


class TestHowLongTheWindowStands:
    """Scott's call: how long is enough is a property of the deployment, not
    of the code, so it is `gateway.approval_enrol_window_seconds`. Five
    minutes by default, because the window is the one interval in which this
    gateway's approver can be claimed by whoever holds the code."""

    def test_a_gateway_with_no_config_loaded_uses_the_default(self, unset: Any) -> None:
        del unset
        assert approver.enrol_window_seconds() == approver.DEFAULT_ENROL_WINDOW_SECONDS

    def test_the_configured_value_is_what_a_window_gets(self, window_of: Any) -> None:
        window_of(900.0)
        assert approver.open_enrolment()[0] == 900

    @pytest.mark.parametrize(
        ("configured", "used"),
        [(0.0, 60.0), (-1.0, 60.0), (59.0, 60.0), (86400.0, 3600.0), (300.0, 300.0)],
    )
    def test_it_is_bounded_at_both_ends(self, configured: float, used: float) -> None:
        """Clamped rather than refused: both directions are safe, and a reload
        refused over this would strand every other change in the file."""
        assert approver.clamped_enrol_window(configured) == used

    @pytest.mark.parametrize(
        ("setting", "loaded"),
        [("", 300.0), ("  approval_enrol_window_seconds: 900", 900.0)]
        + [(f"  approval_enrol_window_seconds: {v}", c) for v, c in ((5, 60.0), (99999, 3600.0))],
    )
    def test_it_comes_off_the_yaml(
        self,
        unset: Any,
        tmp_path: Any,
        monkeypatch: pytest.MonkeyPatch,
        setting: str,
        loaded: float,
    ) -> None:
        """Through load_profiles, not a hand-built GatewayConfig: the default,
        the conversion and the clamp all live on that path."""
        from trentina.gateway.loader import load_profiles

        del unset
        monkeypatch.setenv("TEST_WINDOW_TOKEN", "t")
        path = tmp_path / "profiles.yaml"
        path.write_text(
            f"gateway:\n{setting}\nprofiles:\n  a:\n    auth:\n"
            "      bearer_token_env: TEST_WINDOW_TOKEN\n    backends: {}\n",
            encoding="utf-8",
        )

        assert load_profiles(path).approval_enrol_window_seconds == loaded

    def test_a_config_change_cannot_extend_a_window_already_open(self, window_of: Any) -> None:
        """The length is taken when the window opens. An operator can write
        this file, so reading it at every check would let a staged-for-seconds
        window be stretched from under the person it was opened for."""
        window_of(60.0)
        _, code = approver.open_enrolment()
        window_of(3600.0)

        assert approver._window_seconds == 60.0
        assert approver.enrolling(code) is True


class TestAClosedWindow:
    """The failure this is here for happened to Scott on a real gateway. An
    agent opened a window and told him about it in a chat he read on a phone;
    by the time he opened the page the window had closed, the form had
    silently become one asking for a current password that did not exist, and
    the refusal is identical to every other refusal by design. He retyped it
    three times. A page that cannot succeed and will not say so is a trap, so
    the code field is on it whether or not a window is open right now."""

    def test_the_page_takes_a_code_with_no_window_open(self, pages: TestClient) -> None:
        body = pages.get(approval_routes.ENROL_PATH).text
        assert 'name="code"' in body
        assert 'name="password"' in body

    def test_a_window_opened_while_a_person_reads_the_page_works(self, pages: TestClient) -> None:
        """What the trap cost: the agent can open a fresh window while the
        person sits on the page, and they just type the new code."""
        assert 'name="code"' in pages.get(approval_routes.ENROL_PATH).text
        _, code = approver.open_enrolment()

        answer = pages.post(
            approval_routes.ENROL_PATH,
            data={"code": code, "password": "", "new": PASSWORD, "again": PASSWORD},
        )

        assert answer.status_code == 200
        assert approver.verify(PASSWORD) is True

    def test_an_expired_code_is_refused_exactly_like_a_wrong_password(
        self, pages: TestClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Both fields on one form must not become an oracle: which one was
        offered, and which was wrong, answer the same."""
        _, code = approver.open_enrolment()
        monkeypatch.setattr(time, "monotonic", lambda: time.perf_counter() + 1e6)

        expired = pages.post(
            approval_routes.ENROL_PATH,
            data={"code": code, "new": PASSWORD, "again": PASSWORD},
        )
        guessed = pages.post(
            approval_routes.ENROL_PATH,
            data={"password": "not-the-password", "new": PASSWORD, "again": PASSWORD},
        )

        assert expired.status_code == guessed.status_code == 404
        assert expired.text == guessed.text
        assert approver.configured() is False


class TestTheEnrolmentCode:
    """Gatehouse found the hole this closes: the gateway is public, so an open
    window was an invitation to the whole internet to claim a new gateway's
    approver by being first. The code and the agent's inability to POST close
    different halves of that — see approver.open_enrolment."""

    def test_the_window_alone_is_not_enough(self, pages: TestClient) -> None:
        approver.open_enrolment()
        answer = pages.post(approval_routes.ENROL_PATH, data={"new": PASSWORD, "again": PASSWORD})
        assert answer.status_code == 404
        assert approver.configured() is False

    def test_a_wrong_code_is_not_enough(self, pages: TestClient) -> None:
        approver.open_enrolment()
        answer = pages.post(
            approval_routes.ENROL_PATH,
            data={"code": "not-the-code", "new": PASSWORD, "again": PASSWORD},
        )
        assert answer.status_code == 404
        assert approver.configured() is False

    def test_the_code_changes_every_time_the_window_opens(self, unset: Any) -> None:
        del unset
        _, first = approver.open_enrolment()
        _, second = approver.open_enrolment()
        assert first != second

    def test_the_old_code_stops_working(self, pages: TestClient) -> None:
        _, first = approver.open_enrolment()
        approver.open_enrolment()
        assert approver.enrolling(first) is False

    def test_the_code_does_not_survive_the_window(
        self, pages: TestClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _, code = approver.open_enrolment()
        later = time.monotonic() + approver._window_seconds + 1
        monkeypatch.setattr(approver.time, "monotonic", lambda: later)
        assert approver.enrolling(code) is False


class TestTheEnrolTool:
    """The tool boundary, not just the module behind it. The code it returns
    has to be the one the page accepts, or the flow is unusable while every
    unit test still passes."""

    async def test_it_returns_a_url_a_duration_and_a_code(self, unset: Any) -> None:
        del unset
        from trentina.tools.enrol import approval_enrol

        result = await approval_enrol()
        assert result["opened"] is True
        assert result["url"] == approval_routes.ENROL_PATH
        assert result["open_for_seconds"] == approver.DEFAULT_ENROL_WINDOW_SECONDS
        assert result["code"]

    async def test_its_code_is_the_one_the_page_accepts(self, pages: TestClient) -> None:
        """End to end, the way Scott's acceptance test runs it: the operator
        asks, a person uses what came back."""
        from trentina.tools.enrol import approval_enrol

        code = (await approval_enrol())["code"]
        answer = pages.post(
            approval_routes.ENROL_PATH,
            data={"code": code, "new": PASSWORD, "again": PASSWORD},
        )
        assert answer.status_code == 200
        assert approver.verify(PASSWORD) is True

    async def test_it_says_so_when_one_is_already_set(self, unset: Any) -> None:
        """Set through the store, which is what enrolment does — not pinned by
        the environment, which is the other branch."""
        del unset
        from trentina.tools.enrol import approval_enrol

        approver.set_password(PASSWORD)
        result = await approval_enrol()
        assert result["already_set"] is True
        assert "code" not in result
        # It did not open a window, so nothing can be set without the current one.
        assert approver.enrolling() is False

    async def test_it_refuses_when_the_deployment_pinned_one(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from trentina.tools.enrol import approval_enrol

        monkeypatch.setenv("TRENTINA_APPROVAL_PASSWORD_HASH", approver.make_verifier(PASSWORD))
        result = await approval_enrol()
        assert "pinned by its deployment" in result["error"]

    async def test_an_agent_caller_is_refused(self, unset: Any) -> None:
        del unset
        from trentina.gateway.loader import GatewayConfig, register_active_config
        from trentina.gateway.profile import AuthConfig, Profile
        from trentina.tools.enrol import approval_enrol

        agent = Profile(name="ag", auth=AuthConfig(bearer_token_env="AG_TOKEN"))
        register_active_config(
            pathlib.Path("profiles.yaml"), GatewayConfig(profiles={"ag": agent}), {}
        )
        with profile_context(agent):
            result = await approval_enrol()
        assert "operator" in result["error"]
        assert approver.enrolling() is False


class TestTheBodyCap:
    """Found in review: the cap was applied only when rate limiting was on, so
    `TRENTINA_RATE_LIMIT=off` — an incident escape hatch for the limiter —
    silently took the body cap with it and handed a form parser whatever
    arrived."""

    def _client(self, monkeypatch: pytest.MonkeyPatch, limiting: str) -> TestClient:
        from fastmcp import FastMCP

        monkeypatch.setenv("TRENTINA_RATE_LIMIT", limiting)
        monkeypatch.setenv("TRENTINA_APPROVAL_PASSWORD_HASH", approver.make_verifier(PASSWORD))
        mcp = FastMCP("t")
        approval_routes.register_approval_routes(mcp)
        return TestClient(
            Starlette(routes=mcp._additional_http_routes), base_url="https://gw.example"
        )

    @pytest.mark.parametrize("limiting", ["on", "off"])
    def test_an_oversized_body_is_refused_either_way(
        self, monkeypatch: pytest.MonkeyPatch, limiting: str
    ) -> None:
        client = self._client(monkeypatch, limiting)
        oversized = "x" * (approval_routes.MAX_BODY_BYTES * 2)
        answer = client.post(approval_routes.PATH, data={"password": oversized})
        assert answer.status_code == 413

    def test_an_ordinary_body_still_works_with_limiting_off(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        client = self._client(monkeypatch, "off")
        pending.stage(pending.Kind.OPERATOR_SEAT, FACTS, _applied([]))
        answer = client.post(approval_routes.PATH, data={"password": PASSWORD})
        assert answer.status_code == 200


class _AlwaysBusy:
    """A stand-in for the password semaphore that reports itself taken.

    The route only asks ``locked()`` before deciding to refuse, so this
    exercises that branch without holding a real semaphore — which, held across
    event loops, leaves the module-level one bound to a loop the next test does
    not have.
    """

    def locked(self) -> bool:
        return True


class TestPasswordWorkIsBounded:
    """Found in review, as a consequence of moving scrypt to a worker: a KDF is
    expensive by design, so an unbounded queue of them is the attack rather
    than the defence — and the pool they queue on is the one L1 and the
    tokenizer use."""

    def test_only_one_password_operation_runs_at_a_time(self, page: TestClient) -> None:
        del page
        assert isinstance(approval_routes._PASSWORD_WORK, asyncio.Semaphore)
        assert approval_routes._PASSWORD_WORK._value == 1

    def test_a_second_attempt_is_refused_rather_than_queued(
        self, page: TestClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Busy says so with 503. Queueing would let guesses arrive faster than
        workers finish them and pile up as request state."""
        monkeypatch.setattr(approval_routes, "_PASSWORD_WORK", _AlwaysBusy())
        answer = page.post(approval_routes.PATH, data={"password": PASSWORD})
        assert answer.status_code == 503
        assert "in flight" in answer.text

    def test_setting_a_password_is_refused_while_busy(
        self, pages: TestClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _, code = approver.open_enrolment()
        monkeypatch.setattr(approval_routes, "_PASSWORD_WORK", _AlwaysBusy())
        answer = pages.post(
            approval_routes.ENROL_PATH,
            data={"code": code, "new": PASSWORD, "again": PASSWORD},
        )
        assert answer.status_code == 503
        assert approver.configured() is False


class TestCompetingPasswordChanges:
    """The invariant the critical section exists for, exercised by actually
    overlapping two requests rather than by pre-holding the lock.

    Both start from the same open enrolment window, so both are authorised at
    the moment they are submitted. Only one may win, and the window must not
    still be open for the loser to ride in on.
    """

    @pytest.fixture(autouse=True)
    async def _fresh_semaphore(self) -> None:
        """Bound to this test's own running loop, not a previous one's."""
        approval_routes._PASSWORD_WORK = asyncio.Semaphore(1)

    async def test_two_enrolments_from_one_window_leave_one_password(self, unset: Any) -> None:
        del unset
        _, code = approver.open_enrolment()
        first, second = "password-one-here", "password-two-here"

        results = await asyncio.gather(
            approval_routes._authorised_set(BARE_REQUEST, code, "", first),
            approval_routes._authorised_set(BARE_REQUEST, code, "", second),
        )

        # Exactly one set a password; the other was refused.
        assert sorted(r is None for r in results) == [False, True]
        refused = next(r for r in results if r is not None)
        assert refused.status_code == 404

        # And the winner's password is the one that stands — not silently
        # replaced by whichever finished second.
        won = first if approver.verify(first) else second
        lost = second if won == first else first
        assert approver.verify(won) is True
        assert approver.verify(lost) is False

    async def test_the_window_is_closed_for_the_loser(self, unset: Any) -> None:
        """Stale authorisation must not survive the write: once a password is
        set, the code that authorised it is spent."""
        del unset
        _, code = approver.open_enrolment()

        await asyncio.gather(
            approval_routes._authorised_set(BARE_REQUEST, code, "", "password-one-here"),
            approval_routes._authorised_set(BARE_REQUEST, code, "", "password-two-here"),
        )

        assert approver.enrolling(code) is False
        assert approver.configured() is True

    async def test_a_change_cannot_be_overtaken_by_an_unauthorised_one(self, unset: Any) -> None:
        """One caller knows the current password and one does not. The one that
        does not must lose regardless of ordering."""
        del unset
        approver.set_password(PASSWORD)
        wanted = "the-authorised-change"

        results = await asyncio.gather(
            approval_routes._authorised_set(BARE_REQUEST, "", PASSWORD, wanted),
            approval_routes._authorised_set(
                BARE_REQUEST, "", "wrong-current-password", "the-other-one"
            ),
        )

        assert sorted(r is None for r in results) == [False, True]
        assert approver.verify(wanted) is True
        assert approver.verify("the-other-one") is False
