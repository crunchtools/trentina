"""D1 emission: a federation ingress signs a verdict beside a delivered response (#592).

Drives ``_federated_vsa`` — the ``_assemble`` hook — directly: given a signing
federation-ingress profile and a delivered result, it attaches a
``_meta._trentina_vsa`` a primary verifies with the pinned key and binds to
the exact delivered bytes (D2a trusts it). Deterministic, no servers: the scan
is secondary of this hook and the signature is pure.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import SecretStr

from trentina.core.stages import IngressDecision
from trentina.gateway.backend import BackendCall
from trentina.gateway.names import NAMESPACE_SEP
from trentina.gateway.profile import (
    AuthConfig,
    Backend,
    FederationConfig,
    FederationPeer,
    Profile,
)
from trentina.gateway.vsa import VSA_KEY, content_digest, verify_assertion
from trentina.modes import Mode
from trentina.transports.mcp import _federated_vsa, route_jsonrpc

_PEER_PUB = (
    "-----BEGIN PUBLIC KEY-----\n"
    "MCowBQYDK2VwAyEAGb9ECWmEzf6FQbrBZ9w7lshQhqowtrbLDFw4rXAxZuE=\n"
    "-----END PUBLIC KEY-----\n"
)


def _keypair() -> tuple[str, str]:
    priv = Ed25519PrivateKey.generate()
    private_pem = priv.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    public_pem = (
        priv.public_key()
        .public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        .decode()
    )
    return private_pem, public_pem


def _ingress(*, private_pem: str | None) -> Profile:
    # A directed federation ingress: role agent (default), a remote offered
    # backend, internal surface read_part only. With a key it signs verdicts.
    federation = FederationConfig(peers={"breetai": FederationPeer(public_key=_PEER_PUB)})
    if private_pem is not None:
        federation.secondary_key = SecretStr(private_pem)
    # No `auth`: `peers` IS a federation ingress's authentication, and a
    # second way in is refused since it would admit a caller with no peer.
    return Profile(
        name="lotor",
        federation=federation,
        backends={
            "demo": Backend(url="https://peer.invalid/mcp"),
            "web": Backend(url="internal://web", tools_allow=["read_part_tool"]),
        },
    )


def _deliver(profile: Profile, result: dict, *, warning=None, mode=Mode.FLAG):
    return _federated_vsa(
        profile,
        result,
        blocks=result.get("content"),
        structured=result.get("structuredContent"),
        is_error=result.get("isError", False),
        warning=warning,
        mode=mode,
    )


def test_a_signing_ingress_attaches_a_verifiable_assertion() -> None:
    private_pem, public_pem = _keypair()
    result = {"content": [{"type": "text", "text": "hello"}], "isError": False}
    out = _deliver(_ingress(private_pem=private_pem), result)
    assertion = verify_assertion(out["_meta"][VSA_KEY], public_pem)
    assert assertion is not None
    assert assertion["verifier"] == "lotor"
    assert assertion["content_sha256"] == content_digest(result["content"], None, False)
    assert assertion["verdict"] == {
        "flagged_by": None,
        "risk_level": None,
        "gaps": [],
        "oversize": False,
        "unread_kinds": [],
        "mode": "flag",
    }
    assert isinstance(assertion["ts"], int) and assertion["perimeter_stamp"]
    # a key the ingress did not sign with does not verify
    _, other_pub = _keypair()
    assert verify_assertion(out["_meta"][VSA_KEY], other_pub) is None


def test_the_digest_binds_to_the_delivered_bytes() -> None:
    private_pem, public_pem = _keypair()
    result = {
        "content": [{"type": "text", "text": "A"}],
        "isError": True,
        "structuredContent": {"k": 1},
    }
    out = _deliver(_ingress(private_pem=private_pem), result)
    assertion = verify_assertion(out["_meta"][VSA_KEY], public_pem)
    assert assertion is not None
    assert assertion["content_sha256"] == content_digest(result["content"], {"k": 1}, True)
    # a different delivered body would not match the signed digest
    assert assertion["content_sha256"] != content_digest(
        [{"type": "text", "text": "B"}], {"k": 1}, True
    )


def test_a_flagged_warning_is_summarised_into_the_verdict() -> None:
    private_pem, public_pem = _keypair()
    warning = {"flagged_by": "l2", "risk_level": "high", "l3_truncated": True}
    out = _deliver(
        _ingress(private_pem=private_pem),
        {"content": [], "isError": False},
        warning=warning,
        mode=Mode.BLOCK,
    )
    assertion = verify_assertion(out["_meta"][VSA_KEY], public_pem)
    assert assertion is not None
    assert assertion["verdict"]["flagged_by"] == "l2"
    assert assertion["verdict"]["gaps"] == ["l3_truncated"]
    assert assertion["verdict"]["mode"] == "block"


def test_no_secondary_key_emits_no_assertion() -> None:
    result = {"content": [], "isError": False}
    out = _deliver(_ingress(private_pem=None), result)
    assert out is result  # untouched; a primary re-judges as today


def test_a_non_federation_profile_emits_no_assertion() -> None:
    profile = Profile(
        name="plain",
        auth=AuthConfig(bearer_token_env="UP"),
        backends={"web": Backend(url="internal://web", tools_allow=["*"])},
    )
    profile.auth.bearer_token = SecretStr("t")
    result = {"content": [], "isError": False}
    assert _deliver(profile, result) is result


def test_an_existing_meta_is_preserved() -> None:
    private_pem, _ = _keypair()
    result = {"content": [], "isError": False, "_meta": {"other": 1}}
    out = _deliver(_ingress(private_pem=private_pem), result)
    assert out["_meta"]["other"] == 1  # the VSA rides alongside, not over
    assert VSA_KEY in out["_meta"]


# --- the transport invokes the hook on a real call (single gateway, mocked backend) ---


def _served_ingress(private_pem: str) -> Profile:
    # short_names off so `remote__echo` resolves without a name registry; a real
    # remote backend so the response is judged (an internal tool would not be).
    federation = FederationConfig(peers={"breetai": FederationPeer(public_key=_PEER_PUB)})
    federation.secondary_key = SecretStr(private_pem)
    return Profile(
        name="lotor",
        short_names=False,
        federation=federation,
        backends={"remote": Backend(url="http://peer:8000/mcp", tools_allow=["*"])},
    )


@pytest.mark.asyncio
async def test_the_transport_delivers_the_assertion_on_a_real_call() -> None:
    private_pem, public_pem = _keypair()
    profile = _served_ingress(private_pem)

    async def fake_call(_b: str, _be: Any, _t: str, _a: dict[str, Any]) -> BackendCall:
        return BackendCall(
            content=[{"type": "text", "text": "ok"}], is_error=False, structured_content=None
        )

    clean = AsyncMock(return_value=IngressDecision(warning=None))
    with (
        patch("trentina.transports.mcp.call_backend_tool", side_effect=fake_call),
        patch("trentina.gateway.parts.scan_tool_response", clean),
        patch("trentina.orchestrator.scan_tool_response", clean),
        patch("trentina.gateway.audit._audit"),
    ):
        resp = await route_jsonrpc(
            profile,
            {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {"name": f"remote{NAMESPACE_SEP}echo", "arguments": {}},
            },
        )
    result = resp["result"]
    assertion = verify_assertion(result["_meta"][VSA_KEY], public_pem)
    assert assertion is not None  # the transport called the hook and delivered the VSA
    assert assertion["verifier"] == "lotor"
    assert assertion["content_sha256"] == content_digest(result["content"], None, False)
