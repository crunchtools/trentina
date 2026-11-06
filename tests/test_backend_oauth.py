"""The backend OAuth client flow and its public pages (#479, part 2).

A fake MCP resource and authorization server answer through the real egress
guard (``tests.egress_harness.route``): every request is address-checked,
pinned and refused on a redirect, exactly as in production.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import timedelta
from typing import TYPE_CHECKING, Any
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest
from starlette.applications import Starlette
from starlette.testclient import TestClient

from tests.backend_oauth_harness import (
    ISSUER,
    MCP,
    FakeServer,
    authorize_url,
    login,
    profile_with_era,
    token_store,
)
from trentina.gateway import backend_oauth, backend_tokens
from trentina.gateway.backend_oauth import (
    CALLBACK_PATH,
    DONE_PATH,
    START_PATH,
    BackendAuthError,
    complete,
    fresh_grant,
    start,
)

if TYPE_CHECKING:
    from trentina.gateway.profile import Profile


CANARY = "zqx7canary"


class TestTheFlow:
    async def test_start_to_grant(self, server: FakeServer, profiles: dict[str, Profile]) -> None:
        link = await start(profiles["josui"], "era", authorized_by="self")
        assert link.startswith(f"https://gw.example{START_PATH}?flow=")
        authorize = await authorize_url(link)
        query = parse_qs(urlsplit(authorize).query)
        assert query["code_challenge_method"] == ["S256"]
        assert query["redirect_uri"] == [f"https://gw.example{CALLBACK_PATH}"]
        assert query["resource"] == [MCP]
        assert query["scope"] == ["read"]
        (client,) = server.clients.values()
        assert client["token_endpoint_auth_method"] == "client_secret_basic"
        assert client["application_type"] == "web"

        state, code = server.authorize(authorize)
        await complete(state, code, None, None)
        grant = await token_store().get_grant("josui", "era", profiles["josui"].backends["era"])
        assert grant is not None
        assert grant.access_token.get_secret_value() == "access-1"
        assert grant.token_endpoint == "https://auth.era.example/token"
        assert grant.generation == 1
        assert grant.expires_at is not None

    async def test_honours_server_preferred_auth_method(
        self, server: FakeServer, profiles: dict[str, Profile]
    ) -> None:
        # A server that lists client_secret_post first must get a client
        # registered for post and authenticate the token exchange with it.
        # Some servers advertise client_secret_basic but only accept
        # client_secret_post (the Red Hat AI Factory Workspace MCP), so a
        # fixed basic-first order failed the exchange with 401 invalid_client.
        server.auth_methods = ["client_secret_post", "client_secret_basic", "none"]
        link = await start(profiles["josui"], "era", authorized_by="self")
        authorize = await authorize_url(link)
        (client,) = server.clients.values()
        assert client["token_endpoint_auth_method"] == "client_secret_post"
        state, code = server.authorize(authorize)
        await complete(state, code, None, None)
        grant = await token_store().get_grant("josui", "era", profiles["josui"].backends["era"])
        assert grant is not None
        assert grant.access_token.get_secret_value() == "access-1"

    async def test_the_registration_is_reused(
        self, server: FakeServer, profiles: dict[str, Profile]
    ) -> None:
        await start(profiles["josui"], "era", authorized_by="self")
        await start(profiles["josui"], "era", authorized_by="self")
        assert len(server.clients) == 1

    async def test_a_grant_lands_only_in_the_startingprofile_with_era(
        self, server: FakeServer, profiles: dict[str, Profile]
    ) -> None:
        await login(server, profiles["josui"])
        era = profiles["kagetora"].backends["era"]
        assert await token_store().get_grant("kagetora", "era", era) is None
        assert await token_store().get_client("kagetora", "era", era) is None

    async def test_self_authorize_is_required_for_self(
        self, server: FakeServer, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        locked = profile_with_era("takeda", self_authorize=False)
        with pytest.raises(BackendAuthError, match="not_self_authorized"):
            await start(locked, "era", authorized_by="self")
        assert server.requests == []
        assert await start(locked, "era", authorized_by="operator")

    async def test_at_most_three_live_flows_per_slot(
        self, server: FakeServer, profiles: dict[str, Profile]
    ) -> None:
        links = [await start(profiles["josui"], "era", authorized_by="self") for _ in range(4)]
        first = parse_qs(urlsplit(links[0]).query)["flow"][0]
        assert await token_store().peek_flow(backend_tokens.flow_key(first)) is None
        assert await authorize_url(links[3])


class TestState:
    async def test_a_state_is_spent_once(
        self, server: FakeServer, profiles: dict[str, Profile]
    ) -> None:
        link = await start(profiles["josui"], "era", authorized_by="self")
        state, code = server.authorize(await authorize_url(link))
        await complete(state, code, None, None)
        with pytest.raises(BackendAuthError, match="state_unknown"):
            await complete(state, code, None, None)

    async def test_two_racing_callbacks_complete_once(
        self, server: FakeServer, profiles: dict[str, Profile]
    ) -> None:
        link = await start(profiles["josui"], "era", authorized_by="self")
        state, code = server.authorize(await authorize_url(link))
        results = await asyncio.gather(
            complete(state, code, None, None),
            complete(state, code, None, None),
            return_exceptions=True,
        )
        assert sum(r is None for r in results) == 1

    async def test_an_unknown_state_is_refused(self, server: FakeServer) -> None:
        with pytest.raises(BackendAuthError, match="state_unknown"):
            await complete("made-up", "code", None, None)

    async def test_an_expired_flow_is_refused(
        self, server: FakeServer, profiles: dict[str, Profile], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        link = await start(profiles["josui"], "era", authorized_by="self")
        state, code = server.authorize(await authorize_url(link))
        later = backend_tokens._now() + timedelta(minutes=11)
        monkeypatch.setattr(backend_tokens, "_now", lambda: later)
        with pytest.raises(BackendAuthError, match="state_unknown"):
            await complete(state, code, None, None)

    async def test_an_error_callback_spends_the_flow(
        self, server: FakeServer, profiles: dict[str, Profile]
    ) -> None:
        link = await start(profiles["josui"], "era", authorized_by="self")
        state, code = server.authorize(await authorize_url(link))
        with pytest.raises(BackendAuthError, match="authorization_denied"):
            await complete(state, None, None, "access_denied")
        with pytest.raises(BackendAuthError, match="state_unknown"):
            await complete(state, code, None, None)

    async def test_a_moved_or_removed_backend_refuses_the_callback(
        self, server: FakeServer, profiles: dict[str, Profile]
    ) -> None:
        for change in (
            {"josui": profile_with_era("josui", url="https://elsewhere.example/mcp")},
            {},
        ):
            link = await start(profiles["josui"], "era", authorized_by="self")
            state, code = server.authorize(await authorize_url(link))
            saved = dict(profiles)
            profiles.clear()
            profiles.update(change)
            with pytest.raises(BackendAuthError, match=r"backend_(moved|gone)"):
                await complete(state, code, None, None)
            profiles.update(saved)

    async def test_a_wrong_iss_is_refused(
        self, server: FakeServer, profiles: dict[str, Profile]
    ) -> None:
        server.iss_supported = True
        for iss in ("https://evil.example", None):
            link = await start(profiles["josui"], "era", authorized_by="self")
            state, code = server.authorize(await authorize_url(link))
            with pytest.raises(BackendAuthError, match="iss_mismatch"):
                await complete(state, code, iss, None)
        link = await start(profiles["josui"], "era", authorized_by="self")
        state, code = server.authorize(await authorize_url(link))
        await complete(state, code, ISSUER, None)


class TestDiscoveryRefuses:
    @pytest.mark.parametrize(
        ("change", "code"),
        [
            ({"pkce": ["plain"]}, "no_pkce"),
            ({"resource": "https://other.example/mcp"}, "resource_mismatch"),
        ],
    )
    async def test_metadata_it_cannot_trust(
        self, server: FakeServer, profiles: dict[str, Profile], change: dict[str, Any], code: str
    ) -> None:
        for key, value in change.items():
            setattr(server, key, value)
        with pytest.raises(BackendAuthError, match=code):
            await start(profiles["josui"], "era", authorized_by="self")

    async def test_an_issuer_that_does_not_match_its_metadata(
        self, server: FakeServer, profiles: dict[str, Profile]
    ) -> None:
        metadata = {**server.metadata(), "issuer": "https://auth.era.example/other"}
        server.overrides[("auth.era.example", "/.well-known/oauth-authorization-server")] = (
            httpx.Response(200, json=metadata)
        )
        with pytest.raises(BackendAuthError, match="issuer_mismatch"):
            await start(profiles["josui"], "era", authorized_by="self")

    async def test_a_pinned_issuer_is_enforced(self, server: FakeServer) -> None:
        pinned = profile_with_era("josui", issuer="https://auth.other.example")
        with pytest.raises(BackendAuthError, match="issuer_not_pinned"):
            await start(pinned, "era", authorized_by="self")

    async def test_an_issuer_change_is_not_followed(
        self, server: FakeServer, profiles: dict[str, Profile]
    ) -> None:
        await login(server, profiles["josui"])
        server.issuer = "https://auth.era.example/v2"
        server.overrides[("auth.era.example", "/.well-known/oauth-authorization-server/v2")] = (
            httpx.Response(200, json=server.metadata())
        )
        with pytest.raises(BackendAuthError, match="issuer_changed"):
            await start(profiles["josui"], "era", authorized_by="self")

    async def test_a_redirect_is_not_followed(
        self, server: FakeServer, profiles: dict[str, Profile]
    ) -> None:
        server.overrides[("auth.era.example", "/.well-known/oauth-authorization-server")] = (
            httpx.Response(302, headers={"Location": "https://internal.example/"})
        )
        with pytest.raises(BackendAuthError, match="egress_redirect"):
            await start(profiles["josui"], "era", authorized_by="self")

    async def test_a_private_authorization_server_is_refused(
        self, server: FakeServer, profiles: dict[str, Profile]
    ) -> None:
        server.issuer = "https://internal.example"
        with pytest.raises(BackendAuthError, match="egress_non_global_address"):
            await start(profiles["josui"], "era", authorized_by="self")

    async def test_the_gateway_itself_is_refused(
        self, server: FakeServer, profiles: dict[str, Profile]
    ) -> None:
        server.issuer = "https://gw.example"
        with pytest.raises(BackendAuthError, match="self_host"):
            await start(profiles["josui"], "era", authorized_by="self")


class TestRefresh:
    async def _expire(self, monkeypatch: pytest.MonkeyPatch) -> None:
        later = backend_tokens._now() + timedelta(hours=2)
        monkeypatch.setattr(backend_tokens, "_now", lambda: later)
        monkeypatch.setattr(backend_oauth, "_now", lambda: later)

    async def test_a_fresh_grant_is_returned_as_is(
        self, server: FakeServer, profiles: dict[str, Profile]
    ) -> None:
        await login(server, profiles["josui"])
        grant = await fresh_grant(profiles["josui"], "era")
        assert grant is not None
        assert grant.generation == 1

    async def test_an_expired_grant_refreshes_once_for_concurrent_callers(
        self, server: FakeServer, profiles: dict[str, Profile], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        await login(server, profiles["josui"])
        await self._expire(monkeypatch)
        grants = await asyncio.gather(*(fresh_grant(profiles["josui"], "era") for _ in range(5)))
        assert {g.access_token.get_secret_value() for g in grants if g} == {"access-2"}
        assert server.issued == 2

    async def test_refresh_uses_the_pinned_endpoint(
        self, server: FakeServer, profiles: dict[str, Profile], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        await login(server, profiles["josui"])
        server.issuer = "https://evil.example"
        await self._expire(monkeypatch)
        assert await fresh_grant(profiles["josui"], "era") is not None
        assert server.requests[-1].url.host == "auth.era.example"

    async def test_a_refused_generation_forces_a_refresh(
        self, server: FakeServer, profiles: dict[str, Profile]
    ) -> None:
        await login(server, profiles["josui"])
        grant = await fresh_grant(profiles["josui"], "era", stale_generation=1)
        assert grant is not None
        assert grant.generation == 2

    @pytest.mark.parametrize(
        ("status", "error", "grant_kept", "client_kept"),
        [
            (400, "invalid_grant", False, True),
            (401, "invalid_client", False, False),
            (503, None, True, True),
            (429, None, True, True),
        ],
    )
    async def test_refresh_failures(
        self,
        server: FakeServer,
        profiles: dict[str, Profile],
        monkeypatch: pytest.MonkeyPatch,
        status: int,
        error: str | None,
        grant_kept: bool,
        client_kept: bool,
    ) -> None:
        await login(server, profiles["josui"])
        await self._expire(monkeypatch)
        server.token_status, server.token_error = status, error
        assert await fresh_grant(profiles["josui"], "era") is None
        era = profiles["josui"].backends["era"]
        assert (await token_store().get_grant("josui", "era", era) is not None) is grant_kept
        assert (await token_store().get_client("josui", "era", era) is not None) is client_kept


@pytest.fixture
def pages(server: FakeServer, profiles: dict[str, Profile]) -> TestClient:
    from fastmcp import FastMCP

    del server, profiles  # set up the store and the live config the pages read
    mcp = FastMCP("t")
    backend_oauth.register_backend_oauth_routes(mcp)
    app = Starlette(routes=mcp._additional_http_routes)
    return TestClient(app, base_url="https://gw.example", follow_redirects=False)


class TestPages:
    async def test_the_start_page_names_the_slot(
        self, pages: TestClient, profiles: dict[str, Profile]
    ) -> None:
        link = await start(profiles["josui"], "era", authorized_by="self")
        page = pages.get(urlsplit(link).path + "?" + urlsplit(link).query)
        assert page.status_code == 200
        assert "<b>josui</b>" in page.text
        assert "<b>era</b>" in page.text
        assert "auth.era.example/authorize?" in page.text
        assert page.headers["cache-control"] == "no-store"
        assert "default-src 'none'" in page.headers["content-security-policy"]

    async def test_the_callback_redirects_to_a_clean_page(
        self, pages: TestClient, server: FakeServer, profiles: dict[str, Profile]
    ) -> None:
        link = await start(profiles["josui"], "era", authorized_by="self")
        state, code = server.authorize(await authorize_url(link))
        reply = pages.get(CALLBACK_PATH, params={"state": state, "code": code})
        assert reply.status_code == 303
        assert reply.headers["location"] == DONE_PATH
        assert pages.get(DONE_PATH).status_code == 200

    @pytest.mark.parametrize(
        "params",
        [
            {"state": f"<script>{CANARY}</script>", "code": CANARY},
            {"state": "x" * 3000, "code": "c"},
            {"code": CANARY},
            {"state": CANARY, "error": "access_denied", "error_description": CANARY},
        ],
    )
    def test_a_bad_callback_reflects_nothing(
        self, pages: TestClient, params: dict[str, str]
    ) -> None:
        reply = pages.get(CALLBACK_PATH, params=params)
        assert reply.status_code == 400
        assert CANARY not in reply.text
        assert "script" not in reply.text
        assert reply.headers["cache-control"] == "no-store"

    def test_an_unknown_start_page_is_refused(self, pages: TestClient) -> None:
        reply = pages.get(START_PATH, params={"flow": CANARY})
        assert reply.status_code == 400
        assert CANARY not in reply.text

    async def test_these_pages_wear_the_same_sheet_as_the_approval_page(
        self, pages: TestClient, profiles: dict[str, Profile]
    ) -> None:
        """A person meets one gateway, so they should meet one page (#637).
        Checked at the route rather than on `page.render`, because what makes
        it true here is that the handlers pass their request down."""
        link = await start(profiles["josui"], "era", authorized_by="self")
        signing_in = pages.get(urlsplit(link).path + "?" + urlsplit(link).query)
        refused = pages.get(START_PATH, params={"flow": "nope"})

        for reply in (signing_in, refused):
            assert "data:image/png;base64," in reply.text
            assert "gw.example" in reply.text
            assert "img-src data:" in reply.headers["content-security-policy"]
            assert reply.headers["referrer-policy"] == "no-referrer"
            assert reply.headers["x-content-type-options"] == "nosniff"

    def test_a_host_that_is_not_a_hostname_shows_no_host_line(self, pages: TestClient) -> None:
        reply = pages.get(START_PATH, params={"flow": "nope"}, headers={"host": "a b c"})
        assert reply.status_code == 400
        assert "a b c" not in reply.text

    def test_the_pages_are_rate_limited(
        self, monkeypatch: pytest.MonkeyPatch, server: FakeServer
    ) -> None:
        from fastmcp import FastMCP

        monkeypatch.setattr(backend_oauth, "PAGE_LIMIT", (2, 1))
        mcp = FastMCP("t")
        backend_oauth.register_backend_oauth_routes(mcp)
        client = TestClient(Starlette(routes=mcp._additional_http_routes))
        statuses = [client.get(START_PATH, params={"flow": "x"}).status_code for _ in range(4)]
        assert statuses[-1] == 429

    def test_no_store_no_routes(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from fastmcp import FastMCP

        monkeypatch.setattr(backend_tokens, "_store", None)
        mcp = FastMCP("t")
        backend_oauth.register_backend_oauth_routes(mcp)
        assert mcp._additional_http_routes == []


class TestNothingLeaks:
    async def test_tokens_codes_and_errors_stay_out_of_logs(
        self,
        server: FakeServer,
        profiles: dict[str, Profile],
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        caplog.set_level(logging.DEBUG)
        server.overrides[("auth.era.example", "/register")] = httpx.Response(
            400, json={"error": "invalid_client_metadata", "error_description": CANARY}
        )
        with pytest.raises(BackendAuthError, match="registration_refused"):
            await start(profiles["josui"], "era", authorized_by="self")
        del server.overrides[("auth.era.example", "/register")]
        link = await start(profiles["josui"], "era", authorized_by="self")
        state, _code = server.authorize(await authorize_url(link))
        with pytest.raises(BackendAuthError):
            await complete(state, f"{CANARY}-code", None, None)
        with pytest.raises(BackendAuthError):
            await complete(f"{CANARY}-state", "c", None, None)
        assert CANARY not in caplog.text
        assert state not in caplog.text
        assert "access-" not in caplog.text
