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

import time
from typing import Any

import pytest
from starlette.applications import Starlette
from starlette.testclient import TestClient

from trentina.gateway import approval_routes, approver, pending

pytestmark = pytest.mark.anyio

PASSWORD = "correct horse battery staple"


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
    def test_the_route_does_not_exist_without_an_approver(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """No password, no feature. The absence of an approver is never an
        approval anyone can give."""
        from fastmcp import FastMCP

        monkeypatch.delenv("TRENTINA_APPROVAL_PASSWORD_HASH", raising=False)
        mcp = FastMCP("t")
        approval_routes.register_approval_routes(mcp)
        assert mcp._additional_http_routes == []

    def test_the_first_page_asks_only_for_the_password(self, page: TestClient) -> None:
        """It does not say whether anything is pending: an unauthenticated
        visitor learns nothing about this gateway."""
        pending.stage(pending.Kind.FEDERATION_TRUST, FACTS, _applied([]))
        body = page.get(approval_routes.PATH).text
        assert 'type="password"' in body
        assert "ag.lotor" not in body
        assert "federation trust" not in body

    def test_the_wrong_password_shows_nothing_about_what_is_staged(
        self, page: TestClient
    ) -> None:
        pending.stage(pending.Kind.FEDERATION_TRUST, FACTS, _applied([]))
        answer = page.post(approval_routes.PATH, data={"password": "wrong"})
        assert answer.status_code == 404
        assert "ag.lotor" not in answer.text

    def test_a_wrong_password_and_nothing_staged_are_indistinguishable(
        self, page: TestClient
    ) -> None:
        """No oracle: a guesser cannot tell a bad password from an idle gateway."""
        wrong = page.post(approval_routes.PATH, data={"password": "wrong"})
        right_but_idle = page.post(approval_routes.PATH, data={"password": PASSWORD})
        assert wrong.status_code == right_but_idle.status_code == 404
        assert wrong.text == right_but_idle.text

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
