"""A derived federation ingress spends its SEAT's OAuth grants (#479, #592).

Before this, a grant belonged to ``(profile, backend)`` and a federated call
ran as the ingress, so a seat already signed in to a backend held nothing for
the link: the same person authorized the same account twice, and the second
sign-in had to be driven through a tool offered across the link — which on a
multi-peer ingress let one peer revoke another's grant, or start one that
repointed every peer's calls at its own human's account.

Fable ruled GO-WITH-CONDITIONS on the privilege model. The peer reaches a
strict subset of what the seat's own agent already can, since the offered set
IS the seat's backends with the seat's guards; what spending the seat's grant
removes is a ``needs_auth`` refusal, not a boundary. Its four conditions are
the tests marked below.
"""

from __future__ import annotations

import ast
import pathlib
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import SecretStr

from trentina.gateway.backend import _cooldown_key
from trentina.gateway.backend_tokens import (
    KEY_ENV,
    BackendGrant,
    BackendTokenStore,
    open_backend_token_store,
)
from trentina.gateway.federation_link import derive_ingress
from trentina.gateway.profile import (
    AuthConfig,
    Backend,
    BackendAuth,
    FederationConfig,
    FederationPeer,
    Profile,
)

if TYPE_CHECKING:
    import pytest

SRC = pathlib.Path(__file__).resolve().parent.parent / "src" / "trentina"

ERA = Backend(url="https://context.era.app/mcp", auth=BackendAuth(type="oauth"))
GRANT = BackendGrant(
    access_token=SecretStr("zqx7canary-access-token-0123456789"),
    refresh_token=SecretStr("zqx7canary-refresh-token-0123456789"),
    expires_at=datetime.now(UTC) + timedelta(hours=1),
    scopes=("read",),
    issuer="https://auth.era.app",
    token_endpoint="https://auth.era.app/token",
    client_id="c1",
    obtained_at=datetime.now(UTC),
)


def _seat(name: str = "josui") -> Profile:
    public_pem = (
        Ed25519PrivateKey.generate()
        .public_key()
        .public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        .decode()
    )
    return Profile(
        name=name,
        auth=AuthConfig(bearer_token_env="JOSUI_TOKEN"),
        federation=FederationConfig(peers={"breetai": FederationPeer(public_key=public_pem)}),
        backends={"era": ERA},
    )


def _store(tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch) -> BackendTokenStore:
    monkeypatch.setenv(KEY_ENV, "k" * 48)
    store = open_backend_token_store(tmp_path)
    assert store is not None
    return store


class TestWhoOwnsTheGrant:
    def test_an_ordinary_profile_owns_its_own(self) -> None:
        assert _seat().grant_owner == "josui"

    def test_a_derived_ingress_owns_its_seats(self) -> None:
        ingress = derive_ingress(_seat())
        assert ingress.name == "josui-federation"
        assert ingress.grant_owner == "josui"

    async def test_the_seats_sign_in_is_the_links_sign_in(
        self, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The whole point: one human sign-in serves both sides.

        Written against the real store, because the bug was not in the
        reasoning — it was that the ingress named itself when reading a slot.
        """
        store = _store(tmp_path, monkeypatch)
        seat = _seat()
        ingress = derive_ingress(seat)

        async with store.locked(seat.grant_owner, "era"):
            await store.put_grant(seat.grant_owner, "era", ERA, GRANT, expected_generation=0)

        # The ingress finds it under the seat's name, and would have found
        # nothing under its own.
        assert await store.get_grant(ingress.grant_owner, "era", ERA) is not None
        assert await store.get_grant(ingress.name, "era", ERA) is None

    async def test_an_unrelated_seat_still_sees_nothing(
        self, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Seat-owned grants are not shared grants: the isolation `(profile,
        backend)` keying exists for is untouched for everyone else."""
        store = _store(tmp_path, monkeypatch)
        async with store.locked("josui", "era"):
            await store.put_grant("josui", "era", ERA, GRANT, expected_generation=0)

        other = derive_ingress(_seat("takeda"))
        assert await store.get_grant(other.grant_owner, "era", ERA) is None


def test_the_reauth_cooldown_is_shared_with_the_seat() -> None:
    """One grant, one cooldown. Keying it per profile would let the seat and
    the link each spend a failed refresh against the same server."""
    seat = _seat()
    assert _cooldown_key(derive_ingress(seat), "era") == _cooldown_key(seat, "era")


# --- Fable's conditions ---


def _grant_calls(path: pathlib.Path) -> list[tuple[str, int]]:
    """Every call to a grant-store method, with the line it is on."""
    methods = {
        "get_grant",
        "put_grant",
        "delete_grant",
        "get_client",
        "put_client",
        "delete_client",
        "locked",
    }
    tree = ast.parse(path.read_text(encoding="utf-8"))
    found = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
            continue
        if node.func.attr not in methods:
            continue
        caller = node.func.value
        # Only the token store's methods: `store.get_grant(...)`, not an
        # unrelated `asyncio.Lock.locked()` or the OAuth client registry.
        if not (isinstance(caller, ast.Name) and caller.id == "store"):
            continue
        found.append((ast.unparse(node), node.lineno))
    return found


def test_no_grant_call_site_names_the_acting_profile() -> None:
    """**[C]** The grant slot is the OWNER's, so a call site may not pass
    `.name`.

    An AST check rather than review, in the shape of `test_log_scrub.py`'s
    single-`basicConfig` check: this converted four modules, and the failure
    mode of missing one is that a link silently answers `needs_auth` forever
    while the seat is signed in. A new call site gets this for free.
    """
    offenders = []
    for path in sorted(SRC.rglob("*.py")):
        for source, line in _grant_calls(path):
            if ".name" in source and ".grant_owner" not in source:
                offenders.append(f"{path.relative_to(SRC)}:{line}: {source}")

    assert not offenders, (
        "grant store called with a profile name, not its grant_owner:\n" + "\n".join(offenders)
    )


def test_at_least_one_call_site_is_checked() -> None:
    """The AST check above passes trivially if the matcher stops matching."""
    calls = [c for path in sorted(SRC.rglob("*.py")) for c in _grant_calls(path)]
    assert len(calls) >= 8, f"the grant-call matcher found only {len(calls)}"


async def test_a_sign_in_at_the_seat_refreshes_the_links_tool_list(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """**[C]** A backend with `auth` is skipped from a tools/list while its
    profile holds no grant — and the ingress was skipping it for want of a
    grant that now exists. Without this the link answers `needs_auth` after a
    successful sign-in until something flushes the cache.
    """
    import trentina
    from trentina.gateway.loader import GatewayConfig, register_active_config, reset_active_config

    seat = _seat()
    config = GatewayConfig(profiles={"josui": seat, "josui-federation": derive_ingress(seat)})
    register_active_config(pathlib.Path("/nonexistent/profiles.yaml"), config, {})

    invalidated: list[str] = []
    told: list[str] = []

    def _record(name: str) -> None:
        invalidated.append(name)

    monkeypatch.setattr("trentina.gateway.aggregate.invalidate_profile_cache", _record)

    class _Sessions:
        async def broadcast_tools_changed(self, name: str) -> int:
            told.append(name)
            return 1

    callbacks: list[Any] = []

    def _capture(callback: Any) -> None:
        callbacks.append(callback)

    monkeypatch.setattr("trentina.gateway.backend_oauth.on_grant_stored", _capture)
    try:
        trentina._wire_login_notifications(_Sessions())
        await callbacks[0]("josui")
    finally:
        reset_active_config()

    assert invalidated == ["josui", "josui-federation"]
    assert told == ["josui", "josui-federation"]


async def test_a_grant_spending_call_records_which_peer_spent_it(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """**[C]** The audit names the peer and sub, not just the ingress.

    Fable's condition, and the only place the "the peers are the seat owner's
    own gateways" assumption is checkable after the fact. One account answers
    at the backend for every peer on a link, so if that assumption is ever
    wrong, this row is what says which peer spent the seat's grant.

    The actor stays the INGRESS, deliberately: the grant owner is derivable
    from the ingress name and would be a second column saying the same thing.
    """
    import trentina.database as db_mod
    from trentina.gateway import audit
    from trentina.gateway.context import current_caller
    from trentina.outcomes import Outcome

    db_mod._db = None
    cfg = type(
        "Cfg",
        (),
        {
            "db_path": str(tmp_path / "audit.db"),
            "ensure_db_dir": lambda self: None,
            "blocklist_ttl_days": 30,
        },
    )()
    monkeypatch.setattr(db_mod, "get_config", lambda: cfg)

    ingress = derive_ingress(_seat())
    token = current_caller.set(("breetai", "primary-sub"))
    try:
        audit._audit(ingress.name, "era", "search", Outcome.OK, 1)
    finally:
        current_caller.reset(token)
        row = (
            db_mod.get_db()
            .execute("SELECT profile, caller_peer, caller_sub FROM gateway_calls")
            .fetchone()
        )
        db_mod._db = None

    assert tuple(row) == ("josui-federation", "breetai", "primary-sub")
