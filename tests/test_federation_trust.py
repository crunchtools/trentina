"""D2a: a downstream trusts a federated peer's signed verdict and skips its own
layers (#592) — scan-once at the trust boundary.

``_federated_trust`` is the decision: it returns a delivered ``Assembled`` when
the assertion verifies and binds (trusted), or ``None`` to fall through to the
full local pipeline (fail-closed). Driven directly for the decision, and once
through the transport to show a trusted response is delivered without the scan.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import SecretStr

from trentina.core.stages import Arrived, IngressDecision
from trentina.gateway import vsa
from trentina.gateway.backend import BackendCall
from trentina.gateway.names import NAMESPACE_SEP
from trentina.gateway.profile import (
    AuthConfig,
    Backend,
    DefenseConfig,
    FederatedConfig,
    Profile,
    TrustVerdict,
)
from trentina.modes import Mode
from trentina.outcomes import Outcome
from trentina.reserved import WARNING_KEY
from trentina.transports.mcp import _federated_trust, route_jsonrpc

STAMP = "test-perimeter-v1"
CONTENT = [{"type": "text", "text": "federated-ok"}]
JUDGE = "openrouter/google/gemini-x/pack-v1"


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


def _downstream(public_pem: str, *, stamp: str = STAMP, enforcement: str = "flag") -> Profile:
    backend = Backend(
        url="http://up:9000/mcp",
        tools_allow=["*"],
        federated=FederatedConfig(
            trust_verdict=TrustVerdict(public_key=public_pem, perimeter_stamp=stamp, judge=JUDGE)
        ),
    )
    profile = Profile(
        name="breetai",
        short_names=False,
        auth=AuthConfig(bearer_token_env="D"),
        defense=DefenseConfig(enforcement=enforcement),
        backends={"fed": backend},
    )
    assert profile.auth is not None
    profile.auth.bearer_token = SecretStr("t")
    return profile


def _envelope(
    private_pem: str, *, digest: str | None = None, stamp: str = STAMP, judge: str = JUDGE,
    verdict: dict[str, Any] | None = None, mode: str = "flag",
) -> dict[str, Any]:
    assertion = vsa.build_assertion(
        verifier="lotor",
        content_sha256=digest if digest is not None else vsa.content_digest(CONTENT, None, False),
        verdict=verdict if verdict is not None else vsa.verdict_summary(None, mode),
        perimeter_stamp=stamp,
        judge=judge,
        ts=1_000_000,
    )
    return vsa.sign_assertion(assertion, private_pem)


def _decide(profile: Profile, meta: dict[str, Any] | None, *, mode: Mode = Mode.FLAG) -> Any:
    call = BackendCall(content=CONTENT, is_error=False, structured_content=None, meta=meta)
    arrived = Arrived(
        content_blocks=CONTENT, structured=None, stripped=0, is_error=False, acted=False
    )
    with patch("time.time", return_value=1_000_030):
        return _federated_trust(
            profile, profile.backends["fed"], "fed", arrived, call,
            mode=mode, policy=None, stripped=0, ok=Outcome.OK,
        )


# --- the trust decision (no pipeline, no model) ---


def test_a_valid_verdict_is_trusted_and_delivered() -> None:
    priv, pub = _keypair()
    assembled = _decide(_downstream(pub), {vsa.VSA_KEY: _envelope(priv)})
    assert assembled is not None  # trusted: delivered without re-judging
    assert assembled.result["content"] == CONTENT


@pytest.mark.parametrize(
    "meta_of",
    [
        pytest.param(lambda priv: {}, id="absent"),
        pytest.param(lambda priv: {vsa.VSA_KEY: _envelope(priv, digest="x")}, id="hash"),
        pytest.param(lambda priv: {vsa.VSA_KEY: _envelope(priv, stamp="other")}, id="stamp"),
        pytest.param(lambda priv: {vsa.VSA_KEY: _envelope(priv, judge="weaker-l3")}, id="judge"),
        pytest.param(lambda priv: {vsa.VSA_KEY: _envelope(priv, mode="block")}, id="mode"),
    ],
)
def test_a_mismatched_verdict_re_judges(meta_of: Any) -> None:
    priv, pub = _keypair()
    assert _decide(_downstream(pub), meta_of(priv)) is None  # fall through to the pipeline


def test_a_forged_signature_re_judges() -> None:
    priv, _ = _keypair()
    _, other_pub = _keypair()
    assert _decide(_downstream(other_pub), {vsa.VSA_KEY: _envelope(priv)}) is None


def test_no_trust_verdict_never_trusts() -> None:
    priv, pub = _keypair()
    profile = _downstream(pub)
    federated = profile.backends["fed"].federated
    assert federated is not None
    federated.trust_verdict = None
    assert _decide(profile, {vsa.VSA_KEY: _envelope(priv)}) is None


def test_a_flagged_verdict_under_block_refuses() -> None:
    priv, pub = _keypair()
    flagged = {**vsa.verdict_summary(None, "block"), "flagged_by": "l2", "risk_level": "high"}
    env = _envelope(priv, verdict=flagged)
    assembled = _decide(_downstream(pub, enforcement="block"), {vsa.VSA_KEY: env}, mode=Mode.BLOCK)
    assert assembled is not None
    assert assembled.outcome is Outcome.BLOCKED_DEFENSE  # the peer's flag, applied under block
    assert assembled.result["content"] != CONTENT  # the body was withheld


def test_a_flagged_verdict_under_flag_delivers_with_a_warning() -> None:
    priv, pub = _keypair()
    flagged = {**vsa.verdict_summary(None, "flag"), "flagged_by": "l2", "risk_level": "high"}
    env = _envelope(priv, verdict=flagged)
    assembled = _decide(_downstream(pub), {vsa.VSA_KEY: env}, mode=Mode.FLAG)
    assert assembled is not None
    assert CONTENT[0] in assembled.result["content"]  # the body is delivered under flag
    assert assembled.result[WARNING_KEY]["flagged_by"] == "l2"  # downstream-authored warning


def test_trust_verdict_rejects_a_bad_public_key() -> None:
    with pytest.raises(ValueError, match="not a valid Ed25519"):
        TrustVerdict(public_key="not a pem", perimeter_stamp="v1", judge=JUDGE)


def test_trust_verdict_requires_a_stamp_and_a_judge() -> None:
    _, pub = _keypair()
    with pytest.raises(ValueError, match="perimeter_stamp"):
        TrustVerdict(public_key=pub, perimeter_stamp="", judge=JUDGE)
    with pytest.raises(ValueError, match="judge"):
        TrustVerdict(public_key=pub, perimeter_stamp="v1", judge="")


# --- through the transport: a trusted response is delivered without the scan ---


@pytest.mark.asyncio
async def test_the_transport_trusts_without_re_scanning() -> None:
    priv, pub = _keypair()

    async def fake_call(_b: str, _be: Any, _t: str, _a: dict[str, Any]) -> BackendCall:
        return BackendCall(
            content=CONTENT, is_error=False, structured_content=None,
            meta={vsa.VSA_KEY: _envelope(priv)},
        )

    scan = AsyncMock(return_value=IngressDecision(warning=None))
    with (
        patch("trentina.transports.mcp.call_backend_tool", side_effect=fake_call),
        patch("trentina.gateway.parts.scan_tool_response", scan),
        patch("trentina.orchestrator.scan_tool_response", scan),
        patch("trentina.transports.mcp.transform_response",
              AsyncMock(side_effect=AssertionError("transform ran on a trusted response"))),
        patch("trentina.gateway.audit._audit"),
        patch("time.time", return_value=1_000_030),
    ):
        resp = await route_jsonrpc(
            _downstream(pub),
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": f"fed{NAMESPACE_SEP}echo", "arguments": {}},
            },
        )
    scan.assert_not_called()  # the layers did not re-run
    assert resp["result"]["content"] == CONTENT  # delivered as it arrived


@pytest.mark.asyncio
async def test_the_transport_re_judges_an_untrusted_response() -> None:
    # No assertion → fall through to the local pipeline: the scan runs. The
    # transform is stubbed to a passthrough and the pager off, so the re-judge
    # reaches the (mocked) scan without needing the L2 model.
    from trentina.defense import Provenance

    pub = _keypair()[1]

    async def fake_call(_b: str, _be: Any, _t: str, _a: dict[str, Any]) -> BackendCall:
        return BackendCall(content=CONTENT, is_error=False, structured_content=None, meta={})

    scan = AsyncMock(return_value=IngressDecision(warning=None))
    reduced = SimpleNamespace(
        failed=None, content_blocks=CONTENT, provenance=Provenance.EXTERNAL,
        hidden=None, briefing=None, sidecar=None,
    )
    with (
        patch("trentina.transports.mcp.call_backend_tool", side_effect=fake_call),
        patch("trentina.transports.mcp.transform_response", AsyncMock(return_value=reduced)),
        patch("trentina.gateway.parts._hold_paged", AsyncMock(return_value=None)),
        patch("trentina.gateway.parts.scan_tool_response", scan),
        patch("trentina.orchestrator.scan_tool_response", scan),
        patch("trentina.gateway.audit._audit"),
        patch("time.time", return_value=1_000_030),
    ):
        await route_jsonrpc(
            _downstream(pub),
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": f"fed{NAMESPACE_SEP}echo", "arguments": {}},
            },
        )
    scan.assert_called()  # fell through to the local pipeline, fail-closed


@pytest.mark.parametrize(
    "warning",
    [
        pytest.param({"binary_unread": True}, id="gap"),
        pytest.param({"oversize": True}, id="oversize"),
        pytest.param({"unread_kinds": ["image/png"]}, id="unread"),
    ],
)
def test_an_incomplete_verdict_re_judges(warning: dict[str, Any]) -> None:
    # A valid, bound assertion whose verdict carries a gap/oversize/unread is
    # NOT trust-delivered (#592): the downstream re-judges so its own policy
    # (REQUIRE_L2/L3, the mode) decides, instead of inheriting the peer's
    # weaker gap handling. check_trust still passes; the gap bail returns None.
    priv, pub = _keypair()
    verdict = vsa.verdict_summary(warning, "flag")
    assert _decide(_downstream(pub), {vsa.VSA_KEY: _envelope(priv, verdict=verdict)}) is None
