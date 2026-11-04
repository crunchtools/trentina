"""Approving with a passkey, end to end through the pages (#639).

The software authenticator in ``passkey_helper`` stands in for a browser and a
device. Every path a stranger can reach must fail the same way and hand out no
cookie; every path a signed-in person takes must work and be audited.
"""

from __future__ import annotations

import json
import os
import re
import time
from typing import Any

import pytest
from starlette.applications import Starlette
from starlette.testclient import TestClient

from tests.passkey_helper import Authenticator, b64url
from trentina.gateway import approval_routes, approval_session, approver, pending, webauthn

PATH = approval_routes.PATH
SETUP = approval_routes.SETUP_PATH
BEGIN = approval_routes.BEGIN_PATH
FINISH = approval_routes.FINISH_PATH
ORIGIN = {"Origin": "https://gw.example"}
FACTS = {"Backend to trust": "ag.peergw"}


@pytest.fixture(autouse=True)
def gateway(monkeypatch: pytest.MonkeyPatch, tmp_path: Any) -> Any:
    from trentina import config as config_mod

    monkeypatch.delenv("TRENTINA_APPROVAL_PASSWORD_HASH", raising=False)
    # The failure table below makes more attempts than a person would; the
    # limiter has its own test.
    monkeypatch.setenv("TRENTINA_RATE_LIMIT", "off")
    monkeypatch.setenv("QUARANTINE_DB", str(tmp_path / "state" / "trentina.db"))
    config_mod._config = None
    approver.close_enrolment()
    approval_session.clear()
    pending.clear()
    audited: list[str] = []
    monkeypatch.setattr(approval_routes, "_audit_change", audited.append)
    yield audited
    approver.close_enrolment()
    approval_session.clear()
    pending.clear()
    config_mod._config = None


def _client(base: str = "https://gw.example") -> TestClient:
    from fastmcp import FastMCP

    mcp = FastMCP("t")
    approval_routes.register_approval_routes(mcp)
    return TestClient(
        Starlette(routes=mcp._additional_http_routes), base_url=base, follow_redirects=False
    )


@pytest.fixture
def client() -> TestClient:
    return _client()


def _post(client: TestClient, path: str, body: dict[str, Any], **headers: str) -> Any:
    return client.post(
        path,
        content=json.dumps(body),
        headers={"Content-Type": "application/json", **ORIGIN, **headers},
    )


def _enrol_passkey(client: TestClient, auth: Authenticator, name: str = "Laptop") -> Any:
    _, code = approver.open_enrolment()
    begun = _post(client, BEGIN, {"ceremony": "register", "code": code})
    assert begun.status_code == 200, begun.text
    return _post(
        client, FINISH, auth.register_json(begun.json()["challenge"], code=code, name=name)
    )


def _sign_in(client: TestClient, auth: Authenticator, **extra: Any) -> Any:
    begun = _post(client, BEGIN, {"ceremony": "signin"})
    return _post(client, FINISH, auth.sign_in_json(begun.json()["challenge"], **extra))


@pytest.fixture
def enrolled(client: TestClient) -> Authenticator:
    auth = Authenticator()
    assert _enrol_passkey(client, auth).status_code == 200
    client.cookies.clear()
    approval_session.clear()
    return auth


class TestEnrollingTheFirstPasskey:
    def test_the_window_code_enrols_a_passkey_and_signs_in(
        self, client: TestClient, gateway: list[str]
    ) -> None:
        answer = _enrol_passkey(client, Authenticator())
        assert answer.status_code == 200
        assert answer.json() == {"ok": True, "next": f"{SETUP}?done=passkey_added"}
        assert approval_session.SECURE_COOKIE in answer.headers["set-cookie"]
        assert approver.configured() is True
        assert approver.enrolling() is False
        assert "Passkey added" in client.get(answer.json()["next"]).text
        cred_id = approver.passkeys()[0]["id"]
        # A digest, never the id itself: the id is a string a browser chose.
        assert gateway == [f"passkey enrolled {approver.credential_digest(cred_id)} alg=-7"]
        assert cred_id not in gateway[0]

    def test_without_the_code_no_challenge_is_even_issued(self, client: TestClient) -> None:
        approver.open_enrolment()
        for body in ({"ceremony": "register"}, {"ceremony": "register", "code": "guess"}):
            answer = _post(client, BEGIN, body)
            assert answer.status_code == 400
        assert approval_session._challenges == {}

    def test_a_registration_challenge_is_bound_to_its_code(self, client: TestClient) -> None:
        """A challenge issued under one window's code does not survive the
        window being reopened with another."""
        _, code = approver.open_enrolment()
        challenge = _post(client, BEGIN, {"ceremony": "register", "code": code}).json()["challenge"]
        _, fresh = approver.open_enrolment()
        answer = _post(client, FINISH, Authenticator().register_json(challenge, code=fresh))
        assert answer.status_code == 400
        assert approver.configured() is False

    def test_the_stored_passkey_is_private_and_holds_no_secret(self, client: TestClient) -> None:
        auth = Authenticator()
        _enrol_passkey(client, auth)
        path = approver._passkeys_path()
        assert os.stat(path).st_mode & 0o777 == 0o600
        stored = json.loads(path.read_text())["passkeys"][0]
        assert stored["origin"] == "https://gw.example"
        assert stored["rp_id"] == "gw.example"
        assert set(stored) == {
            "id",
            "spki",
            "alg",
            "rp_id",
            "origin",
            "name",
            "created",
            "last_used",
            "sign_count",
        }

    def test_the_name_a_person_typed_is_cleaned(self, client: TestClient) -> None:
        _enrol_passkey(client, Authenticator(), name="  my\x00 <b>key</b>  " + "x" * 80)
        name = approver.passkeys()[0]["name"]
        assert len(name) <= 40
        assert name.isprintable()
        _sign_in(client, Authenticator())  # not enrolled; just to be sure nothing breaks
        assert "<b>key" not in client.get(SETUP).text

    def test_registration_on_another_origin_is_refused(self, client: TestClient) -> None:
        auth = Authenticator(origin="https://evil.example", rp_id="evil.example")
        answer = _enrol_passkey(client, auth)
        assert answer.status_code == 400
        assert approver.configured() is False


class TestSigningIn:
    def test_a_passkey_signs_in_and_approves(
        self, client: TestClient, enrolled: Authenticator
    ) -> None:
        record: list[str] = []

        async def apply() -> dict[str, Any]:
            record.append("applied")
            return {}

        pending.stage(pending.Kind.FEDERATION_TRUST, FACTS, apply)
        answer = _sign_in(client, enrolled, next=PATH)
        assert answer.json() == {"ok": True, "next": PATH}
        body = client.get(PATH).text
        assert "ag.peergw" in body
        csrf = re.search(r'name="csrf" value="([^"]+)"', body).group(1)  # type: ignore[union-attr]
        client.post(
            PATH,
            data={
                "csrf": csrf,
                "kind": "federation trust",
                "decision": "approve",
                "facts": pending.digest_of(FACTS),
            },
        )
        assert record == ["applied"]

    def test_a_sign_in_records_when_it_was_used(
        self, client: TestClient, enrolled: Authenticator
    ) -> None:
        _sign_in(client, enrolled)
        assert approver.passkeys()[0]["last_used"]

    def test_next_is_a_closed_set(self, client: TestClient, enrolled: Authenticator) -> None:
        answer = _sign_in(client, enrolled, next="https://evil.example/")
        assert answer.json()["next"] == PATH

    def test_an_empty_store_issues_the_same_kind_of_challenge(self, client: TestClient) -> None:
        """Whether any passkey exists is not something BEGIN answers."""
        empty = _post(client, BEGIN, {"ceremony": "signin"})
        approver.add_passkey(
            webauthn.Credential(
                os.urandom(16), Authenticator().spki, -7, "gw.example", "https://gw.example", 0
            ),
            "x",
        )
        full = _post(client, BEGIN, {"ceremony": "signin"})
        assert empty.status_code == full.status_code == 200
        assert set(empty.json()) == set(full.json())

    def test_the_ceremony_routes_require_an_origin(
        self, client: TestClient, enrolled: Authenticator
    ) -> None:
        answer = client.post(
            BEGIN,
            content=json.dumps({"ceremony": "signin"}),
            headers={"Content-Type": "application/json"},
        )
        assert answer.status_code == 400
        assert (
            _post(client, BEGIN, {"ceremony": "signin"}, Origin="https://evil.example").status_code
            == 400
        )


class TestEveryFailureIsOneAnswer:
    """The pairwise table the CTO ruling asked for: every unauthenticated
    passkey failure answers identically and hands out no cookie."""

    def _failures(self, client: TestClient, auth: Authenticator) -> list[Any]:
        stranger = Authenticator()

        def spent() -> Any:
            challenge = _post(client, BEGIN, {"ceremony": "signin"}).json()["challenge"]
            client.cookies.clear()
            first = _post(client, FINISH, auth.sign_in_json(challenge))
            assert first.status_code == 200
            client.cookies.clear()
            approval_session.clear()
            return _post(client, FINISH, auth.sign_in_json(challenge))

        def expired() -> Any:
            challenge = _post(client, BEGIN, {"ceremony": "signin"}).json()["challenge"]
            approval_session._challenges[next(reversed(approval_session._challenges))] = (
                approval_session._Challenge(
                    b"", "signin", "", time.monotonic() - approval_session.CHALLENGE_SECONDS - 1
                )
            )
            return _post(client, FINISH, auth.sign_in_json(challenge))

        def wrong_origin() -> Any:
            challenge = _post(client, BEGIN, {"ceremony": "signin"}).json()["challenge"]
            auth.origin = "https://gw.example.evil.test"
            try:
                return _post(client, FINISH, auth.sign_in_json(challenge))
            finally:
                auth.origin = "https://gw.example"

        def bad_signature() -> Any:
            challenge = _post(client, BEGIN, {"ceremony": "signin"}).json()["challenge"]
            body = auth.sign_in_json(challenge)
            body["signature"] = b64url(stranger.sign(b"something else"))
            return _post(client, FINISH, body)

        def unknown_credential() -> Any:
            challenge = _post(client, BEGIN, {"ceremony": "signin"}).json()["challenge"]
            return _post(client, FINISH, stranger.sign_in_json(challenge))

        def made_up_challenge() -> Any:
            return _post(client, FINISH, auth.sign_in_json(b64url(os.urandom(32))))

        def unregistered_registration() -> Any:
            return _post(client, BEGIN, {"ceremony": "register", "code": "guess"})

        def not_json() -> Any:
            return client.post(
                FINISH, content=b"{", headers={"Content-Type": "application/json", **ORIGIN}
            )

        results = []
        for make in (
            spent,
            expired,
            wrong_origin,
            bad_signature,
            unknown_credential,
            made_up_challenge,
            unregistered_registration,
            not_json,
        ):
            client.cookies.clear()
            results.append(make())
        return results

    def test_all_identical_and_cookie_free(
        self, client: TestClient, enrolled: Authenticator
    ) -> None:
        answers = self._failures(client, enrolled)
        first = answers[0]
        assert first.status_code == 400
        for answer in answers:
            assert "set-cookie" not in answer.headers
            assert (answer.status_code, answer.text) == (first.status_code, first.text)
            assert dict(answer.headers) == dict(first.headers)

    def test_a_cloned_counter_is_refused_like_the_rest(self, client: TestClient) -> None:
        auth = Authenticator(counter=5)
        _enrol_passkey(client, auth)
        client.cookies.clear()
        approval_session.clear()
        auth.counter = 2
        answer = _sign_in(client, auth)
        assert answer.status_code == 400
        assert "set-cookie" not in answer.headers


class TestManaging:
    def _signed_in(self, client: TestClient, auth: Authenticator) -> str:
        assert _sign_in(client, auth).status_code == 200
        found = re.search(r'name="csrf" value="([^"]+)"', client.get(SETUP).text)
        assert found
        return found.group(1)

    def test_a_second_passkey_needs_a_fresh_session(
        self, client: TestClient, enrolled: Authenticator, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        csrf = self._signed_in(client, enrolled)
        later = time.monotonic() + approval_session.FRESH_SECONDS + 1
        monkeypatch.setattr(approval_session.time, "monotonic", lambda: later)
        assert _post(client, BEGIN, {"ceremony": "register", "csrf": csrf}).status_code == 400

    def test_a_fresh_session_adds_a_second_passkey(
        self, client: TestClient, enrolled: Authenticator, gateway: list[str]
    ) -> None:
        csrf = self._signed_in(client, enrolled)
        phone = Authenticator(alg=-8)
        begun = _post(client, BEGIN, {"ceremony": "register", "csrf": csrf})
        done = _post(client, FINISH, phone.register_json(begun.json()["challenge"], csrf=csrf))
        assert done.json()["ok"] is True
        assert len(approver.passkeys()) == 2
        # Adding does not re-issue the cookie: the person is already in.
        assert "set-cookie" not in done.headers
        assert any("alg=-8" in row for row in gateway)

    def test_the_csrf_token_is_needed_to_add_one(
        self, client: TestClient, enrolled: Authenticator
    ) -> None:
        self._signed_in(client, enrolled)
        assert _post(client, BEGIN, {"ceremony": "register", "csrf": "nope"}).status_code == 400

    def test_removing_a_passkey_signs_out_everyone_else(
        self, client: TestClient, enrolled: Authenticator
    ) -> None:
        other = _client()
        assert _sign_in(other, enrolled).status_code == 200
        csrf = self._signed_in(client, enrolled)
        approver.set_password("a-long-enough-password")
        removed = client.post(
            SETUP,
            data={"csrf": csrf, "action": "remove_passkey", "id": approver.passkeys()[0]["id"]},
        )
        assert removed.status_code == 303
        assert approver.passkeys() == []
        assert "Sign in with a passkey" in other.get(PATH).text

    def test_the_last_passkey_cannot_be_removed(
        self, client: TestClient, enrolled: Authenticator
    ) -> None:
        csrf = self._signed_in(client, enrolled)
        refused = client.post(
            SETUP,
            data={"csrf": csrf, "action": "remove_passkey", "id": approver.passkeys()[0]["id"]},
        )
        assert refused.status_code == 400
        assert "only way left" in refused.text
        assert len(approver.passkeys()) == 1

    def test_a_password_can_be_dropped_once_a_passkey_exists(
        self, client: TestClient, enrolled: Authenticator
    ) -> None:
        """Where #639 wanted to end up: no password anywhere."""
        approver.set_password("a-long-enough-password")
        csrf = self._signed_in(client, enrolled)
        assert "Remove the password" in client.get(SETUP).text
        done = client.post(SETUP, data={"csrf": csrf, "action": "remove_password"})
        assert done.status_code == 303
        assert approver.has_password() is False
        assert approver.configured() is True

    def test_the_store_is_bounded(self, client: TestClient) -> None:
        for _ in range(approver.MAX_PASSKEYS):
            approver.add_passkey(
                webauthn.Credential(
                    os.urandom(16), b"k", -7, "gw.example", "https://gw.example", 0
                ),
                "k",
            )
        with pytest.raises(approver.ApproverError):
            approver.add_passkey(
                webauthn.Credential(
                    os.urandom(16), b"k", -7, "gw.example", "https://gw.example", 0
                ),
                "k",
            )

    @pytest.mark.parametrize(
        "content",
        ["{not json", '{"passkeys": null}', '{"passkeys": 5}', "[]", "null", "[" * 3000],
    )
    def test_a_malformed_store_is_no_passkeys(self, content: str) -> None:
        path = approver._passkeys_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
        assert approver.passkeys() == []
        assert approver.configured() is False


class TestTheChallengePool:
    def test_a_full_pool_evicts_rather_than_refuses(self) -> None:
        """Refusing when full would let anyone lock the real person out."""
        for _ in range(approval_session.MAX_CHALLENGES + 10):
            approval_session.issue_challenge("signin")
        assert len(approval_session._challenges) == approval_session.MAX_CHALLENGES
        latest = approval_session.issue_challenge("signin")
        assert approval_session.take_challenge(latest, "signin") is True

    def test_a_challenge_is_for_one_ceremony(self) -> None:
        value = approval_session.issue_challenge("signin")
        assert approval_session.take_challenge(value, "register") is False
        # And it was spent by the attempt.
        assert approval_session.take_challenge(value, "signin") is False


class TestOnLocalhost:
    """A gateway on the same machine: plain http, which browsers allow passkeys
    on only for localhost, and a cookie that cannot take the __Host- prefix."""

    def test_a_local_gateway_enrols_and_signs_in(self) -> None:
        client = _client("http://localhost:8020")
        auth = Authenticator(rp_id="localhost", origin="http://localhost:8020")
        _, code = approver.open_enrolment()
        headers = {"Content-Type": "application/json", "Origin": "http://localhost:8020"}
        begun = client.post(
            BEGIN, content=json.dumps({"ceremony": "register", "code": code}), headers=headers
        )
        assert begun.json()["rpId"] == "localhost"
        done = client.post(
            FINISH,
            content=json.dumps(auth.register_json(begun.json()["challenge"], code=code)),
            headers=headers,
        )
        assert done.status_code == 200, done.text
        cookie = done.headers["set-cookie"].lower()
        assert cookie.startswith(approval_session.PLAIN_COOKIE + "=")
        assert "path=/approve" in cookie
        assert "secure" not in cookie
        assert "Sign-in for approvals" in client.get(SETUP).text


class TestTheBodyCap:
    @pytest.mark.parametrize("path", [BEGIN, FINISH])
    def test_an_oversized_ceremony_body_is_refused_unread(
        self, client: TestClient, path: str
    ) -> None:
        approver.open_enrolment()
        huge = {"ceremony": "signin", "pad": "x" * (approval_routes.MAX_CEREMONY_BYTES * 2)}
        assert _post(client, path, huge).status_code == 413
        assert approval_session._challenges == {}
        assert approver.passkeys() == []


class TestTheLimits:
    def test_drawing_pages_does_not_spend_the_attempts(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Ordinary browsing must not lock a person out of signing in."""
        monkeypatch.setenv("TRENTINA_RATE_LIMIT", "on")
        approver.set_password("a-long-enough-password")
        client = _client()
        for _ in range(approval_routes.PAGE_LIMIT[0] * 2):
            assert client.get(PATH).status_code == 200
            assert _post(client, BEGIN, {"ceremony": "signin"}).status_code == 200
        signed_in = client.post(PATH, data={"password": "a-long-enough-password"})
        assert signed_in.status_code == 303

    def test_guesses_are_still_bounded(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("TRENTINA_RATE_LIMIT", "on")
        approver.set_password("a-long-enough-password")
        client = _client()
        codes = [
            client.post(PATH, data={"password": "guess"}).status_code
            for _ in range(approval_routes.PAGE_LIMIT[0] + 1)
        ]
        assert codes[-1] == 429


class TestHostileInput:
    """Found by Gatehouse on the second push: each of these raised instead of
    refusing."""

    def test_a_deeply_nested_body_is_refused_not_raised(self, client: TestClient) -> None:
        nested = b"[" * 5000 + b"]" * 5000
        for path in (BEGIN, FINISH):
            answer = client.post(
                path, content=nested, headers={"Content-Type": "application/json", **ORIGIN}
            )
            assert answer.status_code == 400

    @pytest.mark.parametrize("origin", ["https://[", "http://[::1", "https://a:b:c"])
    def test_a_malformed_origin_is_refused_not_raised(
        self, client: TestClient, origin: str
    ) -> None:
        assert _post(client, BEGIN, {"ceremony": "signin"}, Origin=origin).status_code == 400
        form = client.post(PATH, data={"password": "x"}, headers={"Origin": origin})
        assert form.status_code == 404

    @pytest.mark.parametrize(
        "host",
        ["gw.example:443@evil.example", "gw.example:99999", "gw.example:0", "gw.example:+1"],
    )
    def test_a_crafted_host_never_becomes_a_link(self, host: str) -> None:
        from starlette.requests import Request

        from trentina.gateway.page import served_origin

        request = Request(
            {"type": "http", "scheme": "https", "path": "/", "headers": [(b"host", host.encode())]}
        )
        assert served_origin(request) is None

    def test_a_plain_host_and_port_become_a_link(self) -> None:
        from starlette.requests import Request

        from trentina.gateway.page import served_origin

        def origin(host: str, scheme: str = "https") -> str | None:
            scope = {
                "type": "http",
                "scheme": scheme,
                "path": "/",
                "headers": [(b"host", host.encode())],
            }
            return served_origin(Request(scope))

        assert origin("gw.example:8443") == "https://gw.example:8443"
        assert origin("127.0.0.1:8020", "http") == "http://localhost:8020"
