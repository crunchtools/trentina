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
import base64
import hashlib
import os
import pathlib
import re
import time
from typing import Any, ClassVar

import pytest
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.testclient import TestClient

from trentina.gateway import approval_routes, approval_session, approver, pending
from trentina.gateway.context import profile_context

pytestmark = pytest.mark.anyio

PASSWORD = "correct horse battery staple"

#: _authorised_set renders its refusal, so it needs a request to read the host
#: off. These tests call it below the route, where there is no real one.
BARE_REQUEST = Request({"type": "http", "method": "POST", "path": "/", "headers": []})


@pytest.fixture(autouse=True)
def _empty() -> Any:
    pending.clear()
    approval_session.clear()
    yield
    pending.clear()
    approval_session.clear()


@pytest.fixture
def approval(monkeypatch: pytest.MonkeyPatch) -> str:
    monkeypatch.setenv("TRENTINA_APPROVAL_PASSWORD_HASH", approver.make_verifier(PASSWORD))
    return PASSWORD


def _applied(record: list[str]) -> Any:
    async def apply() -> dict[str, Any]:
        record.append("applied")
        return {"applied": True}

    return apply


FACTS = {"Backend to trust": "ag.peergw", "What this means": "Responses are not scanned here."}
#: What the review page puts in its hidden ``facts`` field for ``FACTS``.
_FACTS_DIGEST = pending.digest_of(FACTS)

PATH = approval_routes.PATH
SETUP = approval_routes.SETUP_PATH


def _csrf_from(body: str) -> str:
    found = re.search(r'name="csrf" value="([^"]+)"', body)
    assert found, "no CSRF token on the page"
    return found.group(1)


def _sign_in(client: TestClient, password: str = PASSWORD, next_path: str = PATH) -> Any:
    """Sign in with the password, as the form under "Use the password instead"."""
    return client.post(PATH, data={"password": password, "next": next_path})


def _decide(
    client: TestClient,
    *,
    kind: str = "operator profile",
    decision: str = "approve",
    facts: str = _FACTS_DIGEST,
    csrf: str | None = None,
) -> Any:
    token = csrf if csrf is not None else _csrf_from(client.get(PATH).text)
    return client.post(
        PATH, data={"csrf": token, "kind": kind, "decision": decision, "facts": facts}
    )


def _enrol(
    client: TestClient, code: str | None, new: str = PASSWORD, again: str | None = None
) -> Any:
    data = {"action": "enrol_password", "new": new, "again": new if again is None else again}
    if code is not None:
        data["code"] = code
    return client.post(SETUP, data=data)


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
        pending.stage(pending.Kind.OPERATOR_PROFILE, FACTS, _applied([]))
        assert len(pending.outstanding()) == 2

    def test_staging_the_same_kind_twice_replaces_the_first(self) -> None:
        first: list[str] = []
        second: list[str] = []
        pending.stage(pending.Kind.OPERATOR_PROFILE, FACTS, _applied(first))
        pending.stage(pending.Kind.OPERATOR_PROFILE, FACTS, _applied(second))
        assert len(pending.outstanding()) == 1

    def test_an_expired_action_is_gone(self) -> None:
        pending.stage(pending.Kind.OPERATOR_PROFILE, FACTS, _applied([]))
        assert pending.outstanding(now=time.time() + pending.TTL_SECONDS + 1) == {}

    def test_an_unknown_kind_name_resolves_to_nothing(self) -> None:
        assert pending.kind_named("root access please") is None
        assert pending.kind_named("operator profile") is pending.Kind.OPERATOR_PROFILE


class TestApproving:
    async def test_approving_applies_the_action(self) -> None:
        record: list[str] = []
        pending.stage(pending.Kind.OPERATOR_PROFILE, FACTS, _applied(record))
        await pending.approve(pending.Kind.OPERATOR_PROFILE, pending.digest_of(FACTS))
        assert record == ["applied"]

    async def test_approving_twice_applies_once(self) -> None:
        record: list[str] = []
        pending.stage(pending.Kind.OPERATOR_PROFILE, FACTS, _applied(record))
        await pending.approve(pending.Kind.OPERATOR_PROFILE, pending.digest_of(FACTS))
        with pytest.raises(pending.PendingError):
            await pending.approve(pending.Kind.OPERATOR_PROFILE, pending.digest_of(FACTS))
        assert record == ["applied"]

    async def test_approving_a_kind_that_is_not_staged_applies_nothing(self) -> None:
        record: list[str] = []
        pending.stage(pending.Kind.OPERATOR_PROFILE, FACTS, _applied(record))
        with pytest.raises(pending.PendingError):
            await pending.approve(pending.Kind.FEDERATION_TRUST, pending.digest_of(FACTS))
        assert record == []

    def test_declining_applies_nothing_and_drops_it(self) -> None:
        record: list[str] = []
        pending.stage(pending.Kind.OPERATOR_PROFILE, FACTS, _applied(record))
        assert pending.decline(pending.Kind.OPERATOR_PROFILE) is True
        assert record == []
        assert pending.outstanding() == {}

    def test_declining_nothing_says_so(self) -> None:
        assert pending.decline(pending.Kind.OPERATOR_PROFILE) is False

    def test_a_restart_cancels_everything(self) -> None:
        """Nothing is on disk, which is the fail-closed direction: a staged
        change that outlives the process proposing it is unwatched."""
        pending.stage(pending.Kind.OPERATOR_PROFILE, FACTS, _applied([]))
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
            "ag.peergw",
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
    def test_nothing_can_be_approved_without_an_approver(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """No approver, no approvals. The pages still mount — that is where the
        first one gets set — but none of them approves anything."""
        from fastmcp import FastMCP
        from starlette.applications import Starlette as App

        monkeypatch.delenv("TRENTINA_APPROVAL_PASSWORD_HASH", raising=False)
        approver.close_enrolment()
        mcp = FastMCP("t")
        approval_routes.register_approval_routes(mcp)
        client = TestClient(App(routes=mcp._additional_http_routes), base_url="https://gw.example")

        record: list[str] = []
        pending.stage(pending.Kind.OPERATOR_PROFILE, FACTS, _applied(record))
        assert _sign_in(client).status_code == 404
        assert _decide(client, csrf="anything").status_code == 404
        assert record == []

    def test_the_first_page_asks_only_to_sign_in(self, page: TestClient) -> None:
        """It does not say whether anything is pending: an unauthenticated
        visitor learns nothing about this gateway."""
        pending.stage(pending.Kind.FEDERATION_TRUST, FACTS, _applied([]))
        body = page.get(PATH).text
        assert "Sign in with a passkey" in body
        assert 'type="password"' in body
        assert "ag.peergw" not in body
        assert "federation trust" not in body

    def test_the_wrong_password_shows_nothing_about_what_is_staged(self, page: TestClient) -> None:
        pending.stage(pending.Kind.FEDERATION_TRUST, FACTS, _applied([]))
        answer = _sign_in(page, "wrong")
        assert answer.status_code == 404
        assert "ag.peergw" not in answer.text

    def test_every_unauthenticated_failure_is_one_answer(self, page: TestClient) -> None:
        """No oracle: a stranger cannot tell one refusal from another.

        Down to the headers — a `Content-Length` that differs by a byte, or a
        header one branch sets and another does not, is the same oracle as
        different words — and none of them hands out a cookie.
        """
        pending.stage(pending.Kind.OPERATOR_PROFILE, FACTS, _applied([]))
        answers = [
            _sign_in(page, "wrong"),
            _sign_in(page, ""),
            _decide(page, csrf="guessed"),
            _decide(page, csrf=""),
            page.post(PATH, data={"kind": "operator profile", "decision": "approve"}),
            page.post(PATH, data={"csrf": "x"}, cookies={approval_session.SECURE_COOKIE: "forged"}),
        ]
        first, *rest = answers
        assert first.status_code == 404
        for other in answers:
            assert "set-cookie" not in other.headers
        for other in rest:
            assert (other.status_code, other.text) == (first.status_code, first.text)
            assert dict(other.headers) == dict(first.headers)

    def test_a_guess_learns_nothing_from_the_wording_either(self, page: TestClient) -> None:
        """It must not name the gateway's state in either direction — no "wrong
        password", which confirms the password was judged, and no "pending",
        which answers the question an unauthenticated visitor came to ask."""
        body = _sign_in(page, "wrong").text.lower()
        for leak in ("wrong", "incorrect", "invalid", "denied", "not authorised", "pending"):
            assert leak not in body

    def test_signing_in_shows_what_is_about_to_change(self, page: TestClient) -> None:
        pending.stage(pending.Kind.FEDERATION_TRUST, FACTS, _applied([]))
        answer = _sign_in(page)
        assert answer.status_code == 303
        assert answer.headers["location"] == PATH
        body = page.get(PATH).text
        assert "ag.peergw" in body
        assert "not scanned here" in body
        assert "Nothing has changed yet" in body

    def test_the_password_is_never_written_back_into_a_page(self, page: TestClient) -> None:
        """The reason for sessions (#639): the review page used to carry the
        password forward in a hidden field — the DOM, form history, a shared
        screen."""
        pending.stage(pending.Kind.FEDERATION_TRUST, FACTS, _applied([]))
        signed_in = _sign_in(page)
        assert PASSWORD not in signed_in.text
        assert PASSWORD not in page.get(PATH).text
        assert 'name="password"' not in page.get(PATH).text

    def test_once_signed_in_an_idle_gateway_says_so(self, page: TestClient) -> None:
        """The no-oracle rule is for strangers; a signed-in person is who the
        page is for."""
        _sign_in(page)
        answer = page.get(PATH)
        assert answer.status_code == 200
        assert "Nothing is waiting" in answer.text

    def test_approving_needs_a_session(self, page: TestClient) -> None:
        record: list[str] = []
        pending.stage(pending.Kind.OPERATOR_PROFILE, FACTS, _applied(record))
        assert _decide(page, csrf="no-session").status_code == 404
        assert record == []

    def test_approving_needs_the_sessions_own_csrf_token(self, page: TestClient) -> None:
        record: list[str] = []
        pending.stage(pending.Kind.OPERATOR_PROFILE, FACTS, _applied(record))
        _sign_in(page)
        assert _decide(page, csrf="not-this-sessions").status_code == 404
        assert record == []

    def test_approving_while_signed_in_applies_it(self, page: TestClient) -> None:
        record: list[str] = []
        pending.stage(pending.Kind.OPERATOR_PROFILE, FACTS, _applied(record))
        _sign_in(page)
        answer = _decide(page)
        assert answer.status_code == 200
        assert record == ["applied"]

    def test_a_post_from_another_origin_is_refused(self, page: TestClient) -> None:
        record: list[str] = []
        pending.stage(pending.Kind.OPERATOR_PROFILE, FACTS, _applied(record))
        _sign_in(page)
        csrf = _csrf_from(page.get(PATH).text)
        answer = page.post(
            PATH,
            data={
                "csrf": csrf,
                "kind": "operator profile",
                "decision": "approve",
                "facts": _FACTS_DIGEST,
            },
            headers={"Origin": "https://evil.example"},
        )
        assert answer.status_code == 404
        assert record == []

    def test_declining_applies_nothing(self, page: TestClient) -> None:
        record: list[str] = []
        pending.stage(pending.Kind.OPERATOR_PROFILE, FACTS, _applied(record))
        _sign_in(page)
        answer = _decide(page, decision="decline")
        assert "Declined" in answer.text
        assert record == []

    def test_a_double_submit_applies_once(self, page: TestClient) -> None:
        record: list[str] = []
        pending.stage(pending.Kind.OPERATOR_PROFILE, FACTS, _applied(record))
        _sign_in(page)
        csrf = _csrf_from(page.get(PATH).text)
        _decide(page, csrf=csrf)
        second = _decide(page, csrf=csrf)
        assert record == ["applied"]
        assert "Nothing is waiting" in second.text

    def test_a_made_up_kind_approves_nothing(self, page: TestClient) -> None:
        record: list[str] = []
        pending.stage(pending.Kind.OPERATOR_PROFILE, FACTS, _applied(record))
        _sign_in(page)
        answer = _decide(page, kind="root access")
        # Falls back to the review page rather than applying anything.
        assert record == []
        assert "Nothing has changed yet" in answer.text

    def test_an_action_that_fails_to_apply_says_nothing_changed(self, page: TestClient) -> None:
        async def boom() -> dict[str, Any]:
            raise RuntimeError("zqx7canary")

        pending.stage(pending.Kind.OPERATOR_PROFILE, FACTS, boom)
        _sign_in(page)
        answer = _decide(page)
        assert answer.status_code == 500
        assert "nothing was changed" in answer.text
        # The exception's own text is never shown to a person (#262).
        assert "zqx7canary" not in answer.text

    def test_the_page_carries_the_headers_that_keep_it_boring(self, page: TestClient) -> None:
        headers = page.get(PATH).headers
        policy = headers["content-security-policy"]
        assert headers["cache-control"] == "no-store"
        assert headers["x-frame-options"] == "DENY"
        assert "default-src 'none'" in policy
        # One script, by hash; nothing inline by permission, nothing fetched.
        assert f"script-src 'sha256-{approval_routes._SCRIPT_HASH}'" in policy
        assert "unsafe-inline' ; " not in policy and "script-src 'unsafe" not in policy
        assert "connect-src 'self'" in policy

    def test_the_script_on_the_page_is_the_one_the_policy_allows(self, page: TestClient) -> None:
        body = page.get(PATH).text
        script = body.split("<script>")[1].split("</script>")[0]
        digest = base64.b64encode(hashlib.sha256(script.encode()).digest()).decode()
        assert digest == approval_routes._SCRIPT_HASH

    def test_a_fact_is_escaped_on_the_way_out(self, page: TestClient) -> None:
        """checked_display is the gate, but the page escapes anyway: two
        independent reasons a value cannot become markup."""
        pending.stage(pending.Kind.OPERATOR_PROFILE, {"Label <b>": "value <b>"}, _applied([]))
        _sign_in(page)
        body = page.get(PATH).text
        assert "value <b>" not in body
        assert "&lt;b&gt;" in body


class TestTheSession:
    """What replaced the reflected password: short, in memory, and strict."""

    def test_the_cookie_is_host_bound_secure_httponly_and_strict(self, page: TestClient) -> None:
        cookie = _sign_in(page).headers["set-cookie"].lower()
        assert cookie.startswith(approval_session.SECURE_COOKIE.lower() + "=")
        for attribute in ("httponly", "secure", "samesite=strict", "path=/"):
            assert attribute in cookie
        assert "domain=" not in cookie

    def test_signing_out_ends_it(self, page: TestClient) -> None:
        pending.stage(pending.Kind.OPERATOR_PROFILE, FACTS, _applied([]))
        _sign_in(page)
        csrf = _csrf_from(page.get(PATH).text)
        out = page.post(approval_routes.SIGN_OUT_PATH, data={"csrf": csrf})
        assert out.status_code == 303
        assert _decide(page, csrf=csrf).status_code == 404
        assert "Sign in with a passkey" in page.get(PATH).text

    def test_it_ends_when_idle(self, page: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
        pending.stage(pending.Kind.OPERATOR_PROFILE, FACTS, _applied([]))
        _sign_in(page)
        csrf = _csrf_from(page.get(PATH).text)
        later = time.monotonic() + approval_session.IDLE_SECONDS + 1
        monkeypatch.setattr(approval_session.time, "monotonic", lambda: later)
        assert _decide(page, csrf=csrf).status_code == 404

    def test_a_restart_signs_everyone_out(self, page: TestClient) -> None:
        pending.stage(pending.Kind.OPERATOR_PROFILE, FACTS, _applied([]))
        _sign_in(page)
        csrf = _csrf_from(page.get(PATH).text)
        approval_session.clear()
        assert _decide(page, csrf=csrf).status_code == 404

    def test_the_page_shows_how_long_is_left(self, page: TestClient) -> None:
        _sign_in(page)
        body = page.get(PATH).text
        assert 'id="ttl"' in body
        assert "Sign out" in body


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
    return TestClient(
        Starlette(routes=mcp._additional_http_routes),
        base_url="https://gw.example",
        follow_redirects=False,
    )


class TestEnrolment:
    """Scott's ruling: the operator asks, Trentina prompts a person, and the
    person chooses. The operator can ask and cannot answer — a passkey needs the
    person's device and a password is a form submission none of its tools makes."""

    def test_a_gateway_starts_with_no_approver(self, unset: Any) -> None:
        assert approver.configured() is False
        assert approver.enrolling() is False

    def test_the_window_has_to_be_opened(self, pages: TestClient) -> None:
        """A gateway sitting with no approver is not a standing offer to
        whoever reaches the page first."""
        assert _enrol(pages, None).status_code == 404
        assert approver.configured() is False

    def test_with_no_window_the_page_says_what_to_ask_for(self, pages: TestClient) -> None:
        body = pages.get(SETUP).text
        assert "Let me set my passkey in Trentina" in body

    def test_an_opened_window_offers_a_passkey_first(self, pages: TestClient) -> None:
        approver.open_enrolment()
        body = pages.get(SETUP).text
        assert "Create passkey" in body
        assert "Set a password instead" in body

    def test_an_opened_window_lets_a_person_set_a_password(self, pages: TestClient) -> None:
        _, code = approver.open_enrolment()
        answer = _enrol(pages, code)
        assert answer.status_code == 303
        assert approver.configured() is True
        assert approver.verify(PASSWORD) is True

    def test_enrolling_signs_the_person_straight_in(self, pages: TestClient) -> None:
        _, code = approver.open_enrolment()
        answer = _enrol(pages, code)
        assert "set-cookie" in answer.headers
        assert "Password set." in pages.get(answer.headers["location"]).text

    def test_setting_it_closes_the_window(self, pages: TestClient) -> None:
        _, code = approver.open_enrolment()
        _enrol(pages, code)
        assert approver.enrolling() is False

    def test_a_window_cannot_replace_a_working_password(self, pages: TestClient) -> None:
        """Once one is set, changing it takes a fresh sign-in — a window is only
        ever for the first."""
        _, code = approver.open_enrolment()
        _enrol(pages, code)
        approver.open_enrolment()
        assert approver.enrolling() is False
        assert _enrol(pages, code, "something-else-entirely").status_code == 404
        assert approver.verify(PASSWORD) is True

    def test_the_window_expires(self, pages: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
        approver.open_enrolment()
        later = time.monotonic() + approver._window_seconds + 1
        monkeypatch.setattr(approver.time, "monotonic", lambda: later)
        assert approver.enrolling() is False

    def test_mismatched_entries_change_nothing(self, pages: TestClient) -> None:
        _, code = approver.open_enrolment()
        assert _enrol(pages, code, PASSWORD, PASSWORD + "x").status_code == 400
        assert approver.configured() is False

    def test_a_short_password_is_refused_with_the_rule(self, pages: TestClient) -> None:
        _, code = approver.open_enrolment()
        answer = _enrol(pages, code, "short")
        assert answer.status_code == 400
        assert "at least" in answer.text
        assert approver.configured() is False

    def test_changing_it_needs_a_fresh_sign_in(
        self, pages: TestClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        approver.set_password(PASSWORD)
        changed = "a-brand-new-password"
        unsigned = pages.post(
            SETUP, data={"action": "set_password", "csrf": "x", "new": changed, "again": changed}
        )
        assert unsigned.status_code == 404

        _sign_in(pages, next_path=SETUP)
        csrf = _csrf_from(pages.get(SETUP).text)
        later = time.monotonic() + approval_session.FRESH_SECONDS + 1
        monkeypatch.setattr(approval_session.time, "monotonic", lambda: later)
        assert "Confirm it is you" in pages.get(SETUP).text
        stale = pages.post(
            SETUP, data={"action": "set_password", "csrf": csrf, "new": changed, "again": changed}
        )
        assert stale.status_code == 404
        assert approver.verify(PASSWORD) is True

    def test_a_fresh_sign_in_changes_it_and_signs_others_out(self, pages: TestClient) -> None:
        approver.set_password(PASSWORD)
        other = TestClient(pages.app, base_url="https://gw.example")
        _sign_in(other)
        _sign_in(pages, next_path=SETUP)
        csrf = _csrf_from(pages.get(SETUP).text)
        changed = "a-brand-new-password"
        ok = pages.post(
            SETUP, data={"action": "set_password", "csrf": csrf, "new": changed, "again": changed}
        )
        assert ok.status_code == 303
        assert approver.verify(changed) is True
        assert approver.verify(PASSWORD) is False
        # Whoever signed in with the old one is out; this person is not.
        assert "Sign in with a passkey" in other.get(PATH).text
        assert "Sign-in for approvals" in pages.get(SETUP).text

    def test_a_deployment_pinned_password_cannot_be_changed_from_here(
        self, pages: TestClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A deployment that pinned one is saying it is not the gateway's to
        change, so the page says so instead of offering to."""
        monkeypatch.setenv("TRENTINA_APPROVAL_PASSWORD_HASH", approver.make_verifier(PASSWORD))
        _sign_in(pages, next_path=SETUP)
        body = pages.get(SETUP).text
        assert "pinned by this gateway's deployment" in body
        changed = "another-long-password"
        answer = pages.post(
            SETUP,
            data={
                "action": "set_password",
                "csrf": _csrf_from(body),
                "new": changed,
                "again": changed,
            },
        )
        assert answer.status_code == 400
        assert approver.verify(PASSWORD) is True

    def test_the_last_way_to_approve_cannot_be_removed(self, pages: TestClient) -> None:
        approver.set_password(PASSWORD)
        _sign_in(pages, next_path=SETUP)
        body = pages.get(SETUP).text
        assert "Remove the password" not in body
        answer = pages.post(SETUP, data={"action": "remove_password", "csrf": _csrf_from(body)})
        assert answer.status_code == 400
        assert approver.verify(PASSWORD) is True

    def test_the_old_password_page_lands_on_the_new_one(self, pages: TestClient) -> None:
        answer = pages.get(approval_routes.OLD_ENROL_PATH, follow_redirects=False)
        assert answer.status_code == 303
        assert answer.headers["location"] == SETUP

    def test_the_stored_verifier_is_private(self, pages: TestClient) -> None:
        _, code = approver.open_enrolment()
        _enrol(pages, code)
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
    """The failure this is here for happened to Scott on a real gateway: by the
    time he opened the page the window had closed, and the page silently became
    one he could not complete. A page that cannot succeed must say so, and a
    window opened while he sits there must still work."""

    def test_a_closed_window_says_what_to_ask_for(self, pages: TestClient) -> None:
        _, code = approver.open_enrolment()
        approver.close_enrolment()
        assert "Let me set my passkey in Trentina" in pages.get(SETUP).text
        assert _enrol(pages, code).status_code == 404

    def test_a_window_opened_while_a_person_reads_the_page_works(self, pages: TestClient) -> None:
        pages.get(SETUP)
        _, code = approver.open_enrolment()
        assert _enrol(pages, code).status_code == 303
        assert approver.verify(PASSWORD) is True

    def test_an_expired_code_is_refused_exactly_like_a_wrong_one(
        self, pages: TestClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _, code = approver.open_enrolment()
        monkeypatch.setattr(time, "monotonic", lambda: time.perf_counter() + 1e6)
        expired = _enrol(pages, code)
        guessed = _enrol(pages, "not-the-code")
        assert expired.status_code == guessed.status_code == 404
        assert expired.text == guessed.text
        assert dict(expired.headers) == dict(guessed.headers)
        assert approver.configured() is False


class TestTheEnrolmentCode:
    """Gatehouse found the hole this closes: the gateway is public, so an open
    window was an invitation to the whole internet to claim a new gateway's
    approver by being first. The code and the agent's inability to POST close
    different halves of that — see approver.open_enrolment."""

    def test_the_window_alone_is_not_enough(self, pages: TestClient) -> None:
        approver.open_enrolment()
        assert _enrol(pages, None).status_code == 404
        assert approver.configured() is False

    def test_a_wrong_code_is_not_enough(self, pages: TestClient) -> None:
        approver.open_enrolment()
        assert _enrol(pages, "not-the-code").status_code == 404
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

    async def test_it_returns_a_link_a_duration_and_a_code(self, unset: Any) -> None:
        del unset
        from trentina.tools.enrol import approval_enrol

        result = await approval_enrol()
        assert result["opened"] is True
        assert result["url"] == f"{approval_routes.SETUP_PATH}#code={result['code']}"
        assert result["open_for_seconds"] == approver.DEFAULT_ENROL_WINDOW_SECONDS
        # No address known, so no absolute link: never a guessed one.
        assert "open_url" not in result

    async def test_the_link_is_on_the_address_the_call_arrived_on(self, unset: Any) -> None:
        del unset
        from trentina.gateway.context import current_origin
        from trentina.tools.enrol import approval_enrol

        reset = current_origin.set("https://gw.example")
        try:
            result = await approval_enrol()
        finally:
            current_origin.reset(reset)
        assert result["open_url"] == f"https://gw.example{SETUP}#code={result['code']}"

    async def test_a_configured_public_address_wins(
        self, unset: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        del unset
        from trentina.gateway.context import current_origin
        from trentina.tools.enrol import approval_enrol

        monkeypatch.setenv("TRENTINA_OAUTH_BASE_URL", "https://public.example/")
        reset = current_origin.set("http://localhost:8020")
        try:
            result = await approval_enrol()
        finally:
            current_origin.reset(reset)
        assert result["open_url"].startswith("https://public.example/approve/setup#code=")

    async def test_its_code_is_the_one_the_page_accepts(self, pages: TestClient) -> None:
        """End to end, the way Scott's acceptance test runs it: the operator
        asks, a person uses what came back."""
        from trentina.tools.enrol import approval_enrol

        code = (await approval_enrol())["code"]
        assert _enrol(pages, code).status_code == 303
        assert approver.verify(PASSWORD) is True

    async def test_with_an_approver_set_it_links_to_manage_it(self, unset: Any) -> None:
        """ "Let me change my password" — no code, no window, just the page."""
        del unset
        from trentina.tools.enrol import approval_enrol

        approver.set_password(PASSWORD)
        result = await approval_enrol()
        assert result["already_set"] is True
        assert result["url"] == SETUP
        assert "code" not in result
        assert approver.enrolling() is False

    async def test_a_deployment_pinned_password_still_links_to_manage(
        self, unset: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A pinned password cannot be changed here, but a passkey can be
        added beside it, so the page is still where to go."""
        del unset
        from trentina.tools.enrol import approval_enrol

        monkeypatch.setenv("TRENTINA_APPROVAL_PASSWORD_HASH", approver.make_verifier(PASSWORD))
        result = await approval_enrol()
        assert result["already_set"] is True

    async def test_close_shuts_an_open_window(self, unset: Any) -> None:
        del unset
        from trentina.tools.enrol import approval_enrol

        code = (await approval_enrol())["code"]
        closed = await approval_enrol("close")
        assert closed == {"closed": True, "was_open": True}
        assert approver.enrolling(code) is False

    async def test_an_unknown_action_is_refused(self, unset: Any) -> None:
        del unset
        from trentina.tools.enrol import approval_enrol

        assert "error" in await approval_enrol("reset")
        assert approver.enrolling() is False

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
        pending.stage(pending.Kind.OPERATOR_PROFILE, FACTS, _applied([]))
        answer = client.post(
            approval_routes.PATH, data={"password": PASSWORD}, follow_redirects=False
        )
        assert answer.status_code == 303


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
        assert _enrol(pages, code).status_code == 503
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

    @staticmethod
    def _form(code: str, new: str) -> dict[str, str]:
        return {"code": code, "new": new, "again": new}

    async def test_two_enrolments_from_one_window_leave_one_password(self, unset: Any) -> None:
        del unset
        _, code = approver.open_enrolment()
        first, second = "password-one-here", "password-two-here"

        results = await asyncio.gather(
            approval_routes._enrol_password(BARE_REQUEST, self._form(code, first)),
            approval_routes._enrol_password(BARE_REQUEST, self._form(code, second)),
        )

        # Exactly one set a password. The loser is refused: busy if it arrived
        # while the winner held the lock, or "nothing" once the window had
        # closed. Never queued.
        winner, loser = sorted(r.status_code for r in results)
        assert winner == 303
        assert loser in (404, 503)

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
            approval_routes._enrol_password(BARE_REQUEST, self._form(code, "password-one-here")),
            approval_routes._enrol_password(BARE_REQUEST, self._form(code, "password-two-here")),
        )

        assert approver.enrolling(code) is False
        assert approver.configured() is True

    async def test_an_enrolment_cannot_be_overtaken_by_an_unauthorised_one(
        self, unset: Any
    ) -> None:
        del unset
        _, code = approver.open_enrolment()
        wanted = "the-authorised-one"

        results = await asyncio.gather(
            approval_routes._enrol_password(BARE_REQUEST, self._form(code, wanted)),
            approval_routes._enrol_password(BARE_REQUEST, self._form("wrong", "the-other-one")),
        )

        # The loser is refused: busy if it arrived while the winner held the
        # lock, or "nothing" once the window had closed. Never queued.
        winner, loser = sorted(r.status_code for r in results)
        assert winner == 303
        assert loser in (404, 503)
        assert approver.verify(wanted) is True
        assert approver.verify("the-other-one") is False


class TestADecisionNamesItsProposal:
    """An approval must answer the proposal a person READ, not merely its kind.

    The agent chooses when to stage and `stage` replaces silently, so before
    this the sequence "stage K1 → person reads K1 → stage K2 → person clicks"
    applied K2. It needs no code execution on the operator profile, only
    `config_tool`, which is exactly the "can it be talked into it" threat the
    feature exists for.
    """

    OTHER: ClassVar[dict[str, str]] = {
        "Backend to trust": "evil.example",
        "What this means": "Responses are not scanned here.",
    }

    async def test_a_proposal_swapped_after_it_was_read_is_not_applied(self) -> None:
        first: list[str] = []
        second: list[str] = []
        pending.stage(pending.Kind.FEDERATION_TRUST, FACTS, _applied(first))
        shown = pending.digest_of(FACTS)  # what the review page carried
        pending.stage(pending.Kind.FEDERATION_TRUST, self.OTHER, _applied(second))

        with pytest.raises(pending.PendingError):
            await pending.approve(pending.Kind.FEDERATION_TRUST, shown)
        assert first == [] and second == []

    async def test_the_swapped_in_proposal_is_left_staged(self) -> None:
        """Not consumed and not dropped: a person comes back to the real
        thing rather than to an empty page."""
        pending.stage(pending.Kind.FEDERATION_TRUST, FACTS, _applied([]))
        shown = pending.digest_of(FACTS)
        pending.stage(pending.Kind.FEDERATION_TRUST, self.OTHER, _applied([]))
        with pytest.raises(pending.PendingError):
            await pending.approve(pending.Kind.FEDERATION_TRUST, shown)
        assert pending.outstanding() == {pending.Kind.FEDERATION_TRUST: self.OTHER}

    async def test_the_proposal_that_is_staged_still_applies(self) -> None:
        record: list[str] = []
        pending.stage(pending.Kind.FEDERATION_TRUST, FACTS, _applied(record))
        await pending.approve(pending.Kind.FEDERATION_TRUST, pending.digest_of(FACTS))
        assert record == ["applied"]

    @pytest.mark.parametrize("digest", ["", "0" * 64, "not-a-digest"])
    async def test_a_decision_carrying_no_usable_digest_applies_nothing(self, digest: str) -> None:
        """A hand-made form, or one from before this field existed."""
        record: list[str] = []
        pending.stage(pending.Kind.FEDERATION_TRUST, FACTS, _applied(record))
        with pytest.raises(pending.PendingError):
            await pending.approve(pending.Kind.FEDERATION_TRUST, digest)
        assert record == []

    def test_the_digest_does_not_depend_on_the_label_order(self) -> None:
        """The page renders in insertion order; the fingerprint is canonical,
        so re-ordered labels are the same proposal and not a mismatch."""
        reordered = dict(reversed(list(FACTS.items())))
        assert list(reordered) != list(FACTS)  # a different render order
        assert pending.digest_of(reordered) == pending.digest_of(FACTS)

    def test_the_review_page_carries_the_fingerprint_of_what_it_shows(
        self, page: TestClient
    ) -> None:
        pending.stage(pending.Kind.FEDERATION_TRUST, FACTS, _applied([]))
        _sign_in(page)
        body = page.get(PATH).text
        assert f'name="facts" value="{pending.digest_of(FACTS)}"' in body

    def test_a_swap_through_the_page_applies_nothing_and_says_so(self, page: TestClient) -> None:
        """End to end: the hidden field the page gave is replayed after the
        agent re-staged.

        This person has already signed in, so the
        "an unauthenticated visitor learns nothing" rule has done its job and
        the useful answer is the truth. Answering with the generic
        "nothing to approve" hid the one thing they most need to know — that
        what they agreed to is not what is staged — and left them to guess.
        """
        record: list[str] = []
        pending.stage(pending.Kind.FEDERATION_TRUST, FACTS, _applied(record))
        _sign_in(page)
        body = page.get(PATH).text
        shown = body.split('name="facts" value="')[1].split('"')[0]
        pending.stage(pending.Kind.FEDERATION_TRUST, self.OTHER, _applied(record))

        answer = _decide(page, kind="federation trust", facts=shown, csrf=_csrf_from(body))
        assert answer.status_code == 200
        assert record == []  # nothing applied, which is the point
        assert "Nothing was applied" in answer.text
        # And they are shown what IS staged, so they can decide on the real one.
        assert "evil.example" in answer.text
        assert pending.outstanding() == {pending.Kind.FEDERATION_TRUST: self.OTHER}

    def test_an_unauthenticated_visitor_still_learns_nothing(self, page: TestClient) -> None:
        """The rule the above does not weaken: without a session, a guessed
        kind and an idle gateway answer identically."""
        pending.stage(pending.Kind.FEDERATION_TRUST, self.OTHER, _applied([]))
        answer = _decide(page, kind="federation trust", facts="0" * 64, csrf="guessed")
        assert answer.status_code == 404
        assert "evil.example" not in answer.text

    def test_declining_needs_no_digest(self, page: TestClient) -> None:
        """A person who did not expect this wants whatever is staged gone,
        whichever proposal is sitting there now."""
        pending.stage(pending.Kind.FEDERATION_TRUST, FACTS, _applied([]))
        _sign_in(page)
        answer = _decide(page, kind="federation trust", decision="decline", facts="")
        assert answer.status_code == 200
        assert pending.outstanding() == {}
