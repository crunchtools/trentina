"""C2: the federated caller reaches the secondary's audit, and the directed edge (#592).

C1 authenticated an primary JWT and threw the ``(peer, sub)`` away; C2 binds it to
``current_caller`` so the secondary's audit records who really called through the
federation profile, adds two nullable ``gateway_calls`` columns that enter the
hash chain only when set, and refuses a federation ingress that is not a
directed edge (``role: agent``; no egress/disk tool offered to a peer).
"""

from __future__ import annotations

import logging
import time
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import SecretStr
from starlette.requests import Request

from trentina import audit_chain
from trentina.gateway import audit, vsa
from trentina.gateway.app import _authorize
from trentina.gateway.context import current_caller, current_federated_verdict
from trentina.gateway.federation_keys import sign_primary_jwt
from trentina.gateway.federation_link import derive_ingress
from trentina.gateway.profile import (
    AuthConfig,
    Backend,
    FederationConfig,
    FederationPeer,
    Profile,
)
from trentina.outcomes import Outcome

DAY = 86400
_PUB = (
    "-----BEGIN PUBLIC KEY-----\n"
    "MCowBQYDK2VwAyEAGb9ECWmEzf6FQbrBZ9w7lshQhqowtrbLDFw4rXAxZuE=\n"
    "-----END PUBLIC KEY-----\n"
)


def _seat(**over: Any) -> dict[str, Any]:
    """A seat that shares itself: `federation` plus a way in of its own."""
    base: dict[str, Any] = {
        "name": "up",
        "auth": AuthConfig(bearer_token_env="UP_TOKEN"),
        "federation": FederationConfig(peers={"breetai": FederationPeer(public_key=_PUB)}),
        "backends": {"peer": Backend(url="https://real/mcp", tools_allow=["*"])},
    }
    base.update(over)
    return base


# --- the shared seat and its derived ingress (validators) ---


def test_a_shared_seat_loads_and_derives_an_ingress() -> None:
    seat = Profile(**_seat())
    ingress = derive_ingress(seat)

    assert ingress.name == "up-federation"
    assert ingress.role == "agent"
    assert ingress.federation_of == "up"
    # The seat's own remote backend, plus the paging reader and nothing else.
    assert ingress.backends["peer"].is_remote
    assert ingress.backends["trentina"].tools_allow == ["read_part_tool"]


def test_the_seats_internal_surface_is_not_offered() -> None:
    """A seat's internal backend serves the whole native surface, admin tools
    included. The derived ingress gets a fresh one, not a filtered copy."""
    seat = Profile(
        **_seat(
            backends={
                "peer": Backend(url="https://real/mcp", tools_allow=["*"]),
                "web": Backend(url="internal://web", tools_allow=["*"]),
            }
        )
    )
    ingress = derive_ingress(seat)

    assert "web" not in ingress.backends
    assert ingress.backends["trentina"].tools_allow == ["read_part_tool"]


def test_an_operator_seat_may_not_be_shared() -> None:
    with pytest.raises(ValueError, match="role must be agent"):
        Profile(**_seat(role="operator"))


def test_a_seat_with_no_way_in_is_the_old_ingress_shape() -> None:
    """The pre-5.0.0 shape loaded with no `auth`, because `peers` WAS its
    authentication. Requiring one refuses exactly that shape."""
    with pytest.raises(ValueError, match="a shared seat needs auth or oauth"):
        Profile(**_seat(auth=None))


def test_a_seat_may_not_take_the_ingress_suffix() -> None:
    with pytest.raises(ValueError, match="may not end in"):
        Profile(**_seat(name="up-federation"))


@pytest.mark.parametrize(
    "allow",
    [
        ["*"],  # the whole native surface, including admin tools
        ["read_*"],  # a glob is refused as written, before it can match
        ["fetch_tool"],
        ["cache_flush"],  # an admin tool: a denylist of egress tools would miss this
        ["read_part_tool", "cache_flush"],
    ],
)
def test_a_derived_ingress_may_not_widen_its_internal_tools(allow: list[str]) -> None:
    """Derivation builds these, so this guards the derivation, not the file."""
    with pytest.raises(ValueError, match="may offer a peer only"):
        Profile(
            name="up-federation",
            federation_of="up",
            federation=FederationConfig(peers={"breetai": FederationPeer(public_key=_PUB)}),
            backends={"web": Backend(url="internal://web", tools_allow=allow)},
        )


def test_a_profile_without_peers_is_unconstrained() -> None:
    # No federation block: an internal backend may serve everything, as ever.
    profile = Profile(
        name="agent",
        auth=AuthConfig(bearer_token_env="A"),
        backends={"web": Backend(url="internal://web", tools_allow=["*"])},
    )
    profile.auth.bearer_token = SecretStr("t")
    assert profile.federation is None
    assert profile.backends["web"].tools_allow == ["*"]  # unrestricted, as ever


# --- the caller reaches the audit (DB + the hash chain) ---


@pytest.fixture
def db(tmp_path: Any, monkeypatch: pytest.MonkeyPatch) -> Any:
    import trentina.database as db_mod

    db_mod._db = None
    cfg = type(
        "Cfg",
        (),
        {
            "db_path": str(tmp_path / "caller.db"),
            "ensure_db_dir": lambda self: None,
            "blocklist_ttl_days": 30,
        },
    )()
    monkeypatch.setattr(db_mod, "get_config", lambda: cfg)
    monkeypatch.setenv("TRENTINA_AUDIT_RETENTION_DAYS", "1")
    monkeypatch.setattr(db_mod, "_last_sweep", time.monotonic())
    yield db_mod
    db_mod._db = None


def _caller_of(db: Any, call_id: int) -> tuple[Any, Any]:
    row = (
        db.get_db()
        .execute("SELECT caller_peer, caller_sub FROM gateway_calls WHERE id = ?", (call_id,))
        .fetchone()
    )
    return row["caller_peer"], row["caller_sub"]


def test_a_federated_call_records_its_caller(db: Any) -> None:
    token = current_caller.set(("breetai", "primary"))
    try:
        audit._audit("up", "web", "echo", Outcome.OK, 1)
    finally:
        current_caller.reset(token)
    assert _caller_of(db, 1) == ("breetai", "primary")


def test_a_non_federated_call_has_a_null_caller(db: Any) -> None:
    # current_caller defaults to None; the columns stay NULL.
    audit._audit("agent", "web", "echo", Outcome.OK, 1)
    assert _caller_of(db, 1) == (None, None)


def test_the_chain_verifies_with_and_without_a_caller(db: Any) -> None:
    audit._audit("agent", "web", "plain", Outcome.OK, 1)  # no caller
    token = current_caller.set(("breetai", "primary"))
    try:
        audit._audit("up", "web", "echo", Outcome.OK, 1)  # federated
    finally:
        current_caller.reset(token)
    report = audit_chain.verify(db.get_db(), ttl_seconds=30 * DAY)
    assert report["ok"], report


def test_a_null_caller_hashes_as_a_pre_c2_row_did() -> None:
    # An old row carried no caller keys at all; a new non-federated row carries
    # them as None. Both must hash identically, or old rows would stop verifying.
    base = dict.fromkeys(audit_chain.CHAIN_FIELDS, "x")
    assert audit_chain.row_hash(base) == audit_chain.row_hash(
        {**base, "caller_peer": None, "caller_sub": None}
    )


def test_a_caller_commits_in_the_hash() -> None:
    base = dict.fromkeys(audit_chain.CHAIN_FIELDS, "x")
    with_caller = audit_chain.row_hash({**base, "caller_peer": "breetai", "caller_sub": "down"})
    assert with_caller != audit_chain.row_hash(base)
    # Editing the caller breaks the commitment — the point of folding it in.
    assert with_caller != audit_chain.row_hash(
        {**base, "caller_peer": "breetai", "caller_sub": "someone-else"}
    )


class _RowLike:
    """A stand-in for ``sqlite3.Row``: ``in`` tests the VALUES, ``keys()`` the
    columns — the exact trap that made ``name in row`` drop the caller."""

    def __init__(self, data: dict[str, Any]) -> None:
        self._d = dict(data)

    def __getitem__(self, key: str) -> Any:
        return self._d[key]

    def keys(self) -> list[str]:
        return list(self._d)

    def __contains__(self, value: object) -> bool:
        return value in self._d.values()


def test_row_hash_reads_caller_columns_by_name_not_value() -> None:
    # A federated row read back as a sqlite3.Row must still commit to its caller;
    # row_hash finds the columns via keys(), so the _RowLike (which, like a Row,
    # answers `in` by value) hashes the same as the plain mapping.
    full = {**dict.fromkeys(audit_chain.CHAIN_FIELDS, "x"), "caller_peer": "p", "caller_sub": "s"}
    assert audit_chain.row_hash(_RowLike(full)) == audit_chain.row_hash(full)


# --- _authorize captures the caller onto request.state (the one hop) ---


def _signing_pair() -> tuple[Ed25519PrivateKey, str]:
    priv = Ed25519PrivateKey.generate()
    pub = (
        priv.public_key()
        .public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        .decode()
    )
    return priv, pub


def _request(authorization: str | None) -> Request:
    headers = [(b"authorization", authorization.encode())] if authorization else []
    return Request(
        {
            "type": "http",
            "method": "POST",
            "path": "/up/mcp",
            "query_string": b"",
            "headers": headers,
            "client": ("127.0.0.1", 1234),
        }
    )


def _peer_ingress(pub: str) -> Profile:
    """The DERIVED ingress a peer authenticates to, as the gateway builds it.

    A primary's JWT is audience-pinned to the profile name it calls, which for
    a derived ingress is `<seat>-federation` — so the audience now follows from
    the seat rather than from a name an operator invented.
    """
    peers = {"breetai": FederationPeer(public_key=pub)}
    return derive_ingress(Profile(**_seat(federation=FederationConfig(peers=peers))))


async def test_authorize_captures_the_federated_caller() -> None:
    priv, pub = _signing_pair()
    profile = _peer_ingress(pub)
    jwt = sign_primary_jwt(priv, sub="primary", aud=profile.name)
    request = _request(f"Bearer {jwt}")
    assert await _authorize(request, profile, None) is None
    assert request.state.federation_caller == ("breetai", "primary")


async def test_authorize_leaves_no_caller_without_an_edge_jwt() -> None:
    _, pub = _signing_pair()
    request = _request(None)
    response = await _authorize(request, _peer_ingress(pub), None)
    assert response is not None and response.status_code == 401  # no credential: fail closed
    assert getattr(request.state, "federation_caller", None) is None


@pytest.mark.usefixtures("db")
def test_the_caller_sub_is_never_logged(caplog: pytest.LogCaptureFixture) -> None:
    # caller_sub is peer-chosen: an audit fact, never a log line (#262).
    with caplog.at_level(logging.DEBUG, logger="trentina"):
        token = current_caller.set(("breetai", "secret-sub-canary"))
        try:
            audit._audit("up", "web", "echo", Outcome.OK, 1)
        finally:
            current_caller.reset(token)
    assert "secret-sub-canary" not in caplog.text


# --- the trust decision reaches the audit too (#637) ---


def _verdict_of(db: Any, call_id: int) -> Any:
    row = (
        db.get_db()
        .execute("SELECT federated_verdict FROM gateway_calls WHERE id = ?", (call_id,))
        .fetchone()
    )
    return row["federated_verdict"]


def test_a_trusted_response_records_its_verdict(db: Any) -> None:
    token = current_federated_verdict.set(vsa.TRUSTED)
    try:
        audit._audit("down", "fed", "echo", Outcome.OK, 1)
    finally:
        current_federated_verdict.reset(token)
    assert _verdict_of(db, 1) == "trusted"


def test_a_non_federated_call_has_a_null_verdict(db: Any) -> None:
    audit._audit("agent", "web", "echo", Outcome.OK, 1)
    assert _verdict_of(db, 1) is None


def test_the_chain_verifies_with_and_without_a_verdict(db: Any) -> None:
    audit._audit("agent", "web", "plain", Outcome.OK, 1)
    token = current_federated_verdict.set("stamp_mismatch")
    try:
        audit._audit("down", "fed", "echo", Outcome.OK, 1)
    finally:
        current_federated_verdict.reset(token)
    report = audit_chain.verify(db.get_db(), ttl_seconds=30 * DAY)
    assert report["ok"], report


def test_a_null_verdict_hashes_as_a_pre_637_row_did() -> None:
    """The whole reason this column is optional in the chain: a row written
    before it existed must still verify after the upgrade."""
    base = dict.fromkeys(audit_chain.CHAIN_FIELDS, "x")
    assert audit_chain.row_hash(base) == audit_chain.row_hash({**base, "federated_verdict": None})


def test_a_verdict_commits_in_the_hash() -> None:
    """An operator deciding how much of a link runs on the peer's scan is
    reading this column, so editing it must break the chain."""
    base = dict.fromkeys(audit_chain.CHAIN_FIELDS, "x")
    trusted = audit_chain.row_hash({**base, "federated_verdict": "trusted"})
    assert trusted != audit_chain.row_hash(base)
    assert trusted != audit_chain.row_hash({**base, "federated_verdict": "absent"})
