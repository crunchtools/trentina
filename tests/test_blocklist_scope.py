"""The blocklist is keyed on (profile, source), and a refusal is constant (#263).

It was keyed on the source alone and its refusal said ``on the blocklist
since {detected_at}``. Profile A getting ``?slot=N`` flagged was then a bit
profile B could read, with A's timestamp, before any network I/O. These run
the real fetch producer, ``scope``/``internal_edge`` and the SQLite blocklist, with only the
page and the model calls faked.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

import pytest
from pydantic import SecretStr

from trentina import database
from trentina.errors import BlockedSourceError
from trentina.gateway.context import profile_context
from trentina.gateway.errors import ScopeError
from trentina.gateway.loader import load_profiles, register_active_config
from trentina.gateway.profile import AuthConfig, DefenseConfig, Profile
from trentina.modes import Mode
from trentina.tools.fetch import fetch_page

from .judge_key import with_judge_key
from .mode_harness import BENIGN, MALICIOUS, layers

pytestmark = pytest.mark.asyncio

URL = "https://example.com/page?slot=7"


def _agent(name: str) -> Profile:
    p = Profile(
        name=name,
        auth=AuthConfig(bearer_token_env="TEST"),
        defense=DefenseConfig(enforcement="block", modes=["block", "flag", "redact"]),
        backends={},
    )
    assert p.auth is not None
    p.auth.bearer_token = SecretStr("x")
    return with_judge_key(p)


ALPHA = _agent("alpha")
BETA = _agent("beta")


@contextmanager
def _as(profile: Profile) -> Iterator[None]:
    with profile_context(profile):
        yield


async def _fetch(env: Path, profile: Profile, mode: Mode, *, hostile: bool) -> Any:
    """One fetch as *profile*: the refusal's exact bytes, or the delivered response."""
    with layers(env, classification=MALICIOUS if hostile else BENIGN), _as(profile):
        try:
            return await fetch_page(URL, mode)
        except BlockedSourceError as exc:
            return json.dumps({"message": str(exc), "refusal": exc.refusal}, sort_keys=True)


async def test_nothing_alpha_does_changes_a_byte_of_betas_refusal(env: Path) -> None:
    # beta's own history: flagged once, then refused from the blocklist.
    await _fetch(env, BETA, Mode.BLOCK, hostile=True)
    before = await _fetch(env, BETA, Mode.BLOCK, hostile=False)
    assert "on the blocklist" in before

    for mode in (Mode.BLOCK, Mode.FLAG, Mode.REDACT):
        await _fetch(env, ALPHA, mode, hostile=True)
        await _fetch(env, ALPHA, mode, hostile=False)
    after = await _fetch(env, BETA, Mode.BLOCK, hostile=False)

    assert after == before


async def test_alphas_block_does_not_blocklist_the_url_for_beta(env: Path) -> None:
    await _fetch(env, ALPHA, Mode.BLOCK, hostile=True)
    assert "on the blocklist" in await _fetch(env, ALPHA, Mode.BLOCK, hostile=False)

    delivered = await _fetch(env, BETA, Mode.BLOCK, hostile=False)
    assert isinstance(delivered, dict)
    assert "_trentina_warning" not in delivered


async def test_the_refusal_carries_no_timestamp(env: Path) -> None:
    await _fetch(env, BETA, Mode.BLOCK, hostile=True)
    refusal = await _fetch(env, BETA, Mode.BLOCK, hostile=False)
    detected_at = database.get_db().execute("SELECT detected_at FROM detections").fetchone()[0]
    assert detected_at[:10] not in refusal
    assert json.loads(refusal)["refusal"]["reason"] == "on the blocklist"


async def test_the_row_is_written_under_the_calling_profile(env: Path) -> None:
    await _fetch(env, BETA, Mode.BLOCK, hostile=True)
    rows = database.get_db().execute("SELECT profile, source FROM detections").fetchall()
    assert [(r["profile"], r["source"]) for r in rows] == [("beta", URL)]


async def test_redact_on_betas_own_blocklist_says_so(env: Path) -> None:
    await _fetch(env, BETA, Mode.BLOCK, hostile=True)
    with layers(env), _as(BETA):
        result = await fetch_page(URL, Mode.REDACT, "the date")
    assert result["_trentina_warning"]["blocklisted"] is True


async def _fetch_standalone(env: Path, *, hostile: bool) -> Any:
    with layers(env, classification=MALICIOUS if hostile else BENIGN):
        try:
            return await fetch_page(URL, Mode.BLOCK)
        except BlockedSourceError as exc:
            return exc.refusal["reason"]


async def test_standalone_reads_its_own_null_profile_rows(env: Path) -> None:
    """No gateway registered: ``current_scope`` is the standalone operator profile."""
    await _fetch_standalone(env, hostile=True)
    row = database.get_db().execute("SELECT profile FROM detections").fetchone()
    assert row["profile"] == "standalone"
    assert await _fetch_standalone(env, hostile=False) == "on the blocklist"


async def test_the_operator_reads_every_profiles_rows(env: Path) -> None:
    await _fetch(env, ALPHA, Mode.BLOCK, hostile=True)
    operator = _agent("root")
    operator.role = "operator"
    assert "on the blocklist" in await _fetch(env, operator, Mode.BLOCK, hostile=False)


async def test_an_unbound_caller_on_a_live_gateway_is_refused(
    env: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A path nobody designed is refused outright (fail closed), not served.

    Before 3.0.0 an unbound caller under a live gateway read nothing and wrote a
    NULL-profile row; now ``current_scope`` refuses it, so it never reaches the
    blocklist at all — a stronger answer to "whose is this?".
    """
    await _fetch(env, ALPHA, Mode.BLOCK, hostile=True)
    monkeypatch.setenv("TEST_ALPHA_TOKEN", "x")
    config = env / "profiles.yaml"
    config.write_text(
        "profiles:\n  alpha:\n    auth:\n      bearer_token_env: TEST_ALPHA_TOKEN\n"
        "    backends: {}\n",
        encoding="utf-8",
    )
    register_active_config(config, load_profiles(config), {})

    with (
        layers(env, classification=BENIGN),
        pytest.raises(ScopeError, match="no calling profile bound"),
    ):
        await fetch_page(URL, Mode.BLOCK)
