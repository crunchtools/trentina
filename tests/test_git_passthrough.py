"""A git grant that does not opt in is 6.30.1's pass-through (spec 027, ``enforcement: none``).

Real ``git`` and real ``git http-backend`` through the real route, with a
recording wrapper around the forge. A grant that never set ``enforcement`` must
get from the gateway exactly what 6.30.1 gave: the request the forge receives is
the request the client sent (no ``thin-pack`` stripping), and the bytes the
client receives are the bytes the forge sent (no capability, side-band or pkt-line
rewriting, no tail hold).

6.30.1 did transform one thing on this path: a ref listing went through
``RefFilter``, which drops hidden refs. The test repository has none, so that
filter is the identity here and "byte-identical to 6.30.1" is "byte-identical to
the forge". Nothing was judged: no layer call, no detection row, no lane.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

import pytest

from trentina.gateway import git_judge, git_transport
from trentina.gateway.profile import GitGrant

from . import git_harness as harness
from . import test_git_transport as route
from .git_harness import DELIMITER, FLUSH, pkt
from .test_git_transport import UPLOAD_REQUEST, _settled, _stack, needs_git

if TYPE_CHECKING:
    from collections.abc import AsyncIterator
    from pathlib import Path

    from starlette.requests import Request
    from starlette.responses import Response

pytestmark = needs_git

audit_db = route.audit_db
no_slot_is_left_held = route.no_slot_is_left_held

BASE = "/acme/widgets"
V2 = "version=2"


@dataclass
class Recording(harness.Forge):
    """The forge, and every byte it answered with."""

    responses: list[bytes] = field(default_factory=list)

    async def handle(self, request: Request) -> Response:
        response = await super().handle(request)
        self.responses.append(bytes(response.body))
        return response


@dataclass
class Touched:
    """Everything the judging path would touch, counted."""

    layers: list[str] = field(default_factory=list)
    lanes: list[str] = field(default_factory=list)
    relays: list[str] = field(default_factory=list)


@pytest.fixture
def touched(monkeypatch: pytest.MonkeyPatch) -> Touched:
    seen = Touched()
    real_screen, real_l3 = git_judge.screen, git_judge.judge_l3
    real_lane = git_transport.enter_lane

    async def screen(*args: Any, **kwargs: Any) -> Any:
        seen.layers.append("screen")
        return await real_screen(*args, **kwargs)

    async def judge_l3(*args: Any, **kwargs: Any) -> Any:
        seen.layers.append("l3")
        return await real_l3(*args, **kwargs)

    async def enter_lane(*args: Any, **kwargs: Any) -> Any:
        seen.lanes.append("lane")
        return await real_lane(*args, **kwargs)

    monkeypatch.setattr(git_judge, "screen", screen)
    monkeypatch.setattr(git_judge, "judge_l3", judge_l3)
    monkeypatch.setattr(git_transport, "enter_lane", enter_lane)
    for name in ("relay_fetch", "relay_listing", "relay_push"):
        real = getattr(git_transport, name)

        def spy(*args: Any, _name: str = name, _real: Any = real, **kwargs: Any) -> Any:
            seen.relays.append(_name)
            return _real(*args, **kwargs)

        monkeypatch.setattr(git_transport, name, spy)
    return seen


class Served:
    """A running gateway over a real repository, and the forge's record."""

    def __init__(self, stack: Any, forge: Recording, home: Path, bare: Path, work: Path) -> None:
        self.stack, self.forge, self.home, self.bare, self.work = stack, forge, home, bare, work

    @property
    def head(self) -> str:
        return harness.git_sync(self.home, "rev-parse", "HEAD", cwd=self.bare)

    async def post(self, version: str | None, body: bytes) -> bytes:
        headers = {"Content-Type": UPLOAD_REQUEST}
        if version:
            headers["Git-Protocol"] = version
        answer = await self.stack.client.post(
            f"{self.stack.url}{BASE}/git-upload-pack", content=body, headers=headers
        )
        assert answer.status_code == 200, answer.text
        return answer.content

    async def listing(self, version: str | None) -> bytes:
        headers = {"Git-Protocol": version} if version else {}
        answer = await self.stack.client.get(
            f"{self.stack.url}{BASE}/info/refs?service=git-upload-pack", headers=headers
        )
        assert answer.status_code == 200, answer.text
        return answer.content


async def _serve(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, enforcement: str | None
) -> AsyncIterator[Served]:
    backend = harness.http_backend()
    assert backend is not None
    home = tmp_path / "home"
    home.mkdir()
    bare = tmp_path / "forge" / "acme" / "widgets.git"
    bare.parent.mkdir(parents=True)
    harness.git_sync(home, "init", "--bare", "-b", "main", str(bare))
    harness.git_sync(home, "config", "transfer.advertiseSID", "true", cwd=bare)
    seed = tmp_path / "seed"
    harness.git_sync(home, "init", "-b", "main", str(seed))
    (seed / "README.md").write_text("A small library.\n")
    harness.git_sync(home, "add", "-A", cwd=seed)
    harness.git_sync(home, "commit", "-m", "first", cwd=seed)
    harness.git_sync(home, "push", str(bare), "main", cwd=seed)
    forge = Recording(bare.parent.parent, backend)
    async for running in _stack(monkeypatch, forge, enforcement=enforcement):
        yield Served(running, forge, home, bare, tmp_path / "clone")


@pytest.fixture
async def none(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> AsyncIterator[Served]:
    """A grant that never mentions ``enforcement``."""
    async for served in _serve(monkeypatch, tmp_path, None):
        yield served


@pytest.fixture
async def flagged(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> AsyncIterator[Served]:
    async for served in _serve(monkeypatch, tmp_path, "flag"):
        yield served


def _ls_refs() -> bytes:
    head = [pkt(b"command=ls-refs\n"), pkt(b"agent=test\n"), DELIMITER]
    args = [b"peel\n", b"symrefs\n", b"ref-prefix refs/heads/\n"]
    return b"".join(head + [pkt(line) for line in args]) + FLUSH


def _v2_fetch(oid: str) -> bytes:
    head = [pkt(b"command=fetch\n"), pkt(b"agent=test\n"), DELIMITER]
    args = [b"thin-pack\n", b"ofs-delta\n", f"want {oid}\n".encode(), b"done\n"]
    return b"".join(head + [pkt(line) for line in args]) + FLUSH


def _v0_fetch(oid: str) -> bytes:
    caps = "multi_ack_detailed side-band-64k thin-pack ofs-delta agent=test"
    return pkt(f"want {oid} {caps}\n".encode()) + FLUSH + pkt(b"done\n")


def _nothing_was_judged(touched: Touched, db: Path) -> None:
    assert touched.layers == []
    assert touched.lanes == []
    assert touched.relays == []
    conn = sqlite3.connect(db)
    try:
        assert conn.execute("SELECT count(*) FROM detections").fetchone()[0] == 0
        calls = conn.execute("SELECT call_ref, normalized FROM gateway_calls").fetchall()
    finally:
        conn.close()
    assert all(call_ref is None and normalized is None for call_ref, normalized in calls)


class TestDefault:
    def test_a_grant_that_never_says_is_not_judging(self) -> None:
        grant = GitGrant(token_env="FORGE_TOKEN", fetch=["acme/*"])
        assert grant.enforcement == "none"
        assert not grant.judges

    @pytest.mark.parametrize("version", [None, "version=1", V2])
    async def test_an_advertisement_is_the_forges_bytes(
        self, none: Served, touched: Touched, audit_db: Path, version: str | None
    ) -> None:
        arrived = await none.listing(version)
        assert arrived == none.forge.responses[-1]
        if version == V2:
            assert b"agent=git/" in arrived, "the forge's own agent, not the gateway's"
        await _settled(audit_db)
        _nothing_was_judged(touched, audit_db)

    async def test_a_v2_ls_refs_is_the_forges_bytes_for_the_clients_request(
        self, none: Served, touched: Touched, audit_db: Path
    ) -> None:
        request = _ls_refs()
        arrived = await none.post(V2, request)
        assert none.forge.payloads[-1] == request
        assert arrived == none.forge.responses[-1]
        assert none.head.encode() in arrived
        await _settled(audit_db)
        _nothing_was_judged(touched, audit_db)

    async def test_a_v2_fetch_is_the_forges_bytes_for_the_clients_request(
        self, none: Served, touched: Touched, audit_db: Path
    ) -> None:
        request = _v2_fetch(none.head)
        arrived = await none.post(V2, request)
        assert none.forge.payloads[-1] == request, "thin-pack is not stripped"
        assert arrived == none.forge.responses[-1]
        assert b"packfile\n" in arrived
        assert b"Trentina" not in arrived
        await _settled(audit_db)
        _nothing_was_judged(touched, audit_db)

    @pytest.mark.parametrize("version", [None, "version=1"])
    async def test_a_v0_or_v1_fetch_is_the_forges_bytes_for_the_clients_request(
        self, none: Served, touched: Touched, audit_db: Path, version: str | None
    ) -> None:
        request = _v0_fetch(none.head)
        arrived = await none.post(version, request)
        assert none.forge.payloads[-1] == request, "thin-pack is not stripped"
        assert arrived == none.forge.responses[-1]
        assert b"PACK" in arrived
        await _settled(audit_db)
        _nothing_was_judged(touched, audit_db)

    @pytest.mark.parametrize("version", ["0", "1", "2"])
    async def test_a_real_clone_is_whole_and_says_nothing(
        self, none: Served, touched: Touched, audit_db: Path, version: str
    ) -> None:
        code, output = await harness.git(
            none.home,
            none.stack.port,
            "-c",
            f"protocol.version={version}",
            "clone",
            "GATEWAY/acme/widgets",
            str(none.work),
        )
        assert code == 0, output
        assert "Trentina" not in output
        harness.git_sync(none.home, "fsck", "--strict", cwd=none.work)
        await _settled(audit_db, 2)
        _nothing_was_judged(touched, audit_db)


class TestFlagIsDifferent:
    """The control: the same requests under ``flag`` are not the forge's bytes."""

    async def test_flag_strips_the_request_and_rewrites_the_answer(
        self, flagged: Served, touched: Touched
    ) -> None:
        request = _v2_fetch(flagged.head)
        arrived = await flagged.post(V2, request)
        assert flagged.forge.payloads[-1] != request
        assert b"thin-pack" not in flagged.forge.payloads[-1]
        assert arrived != flagged.forge.responses[-1]
        assert touched.lanes == ["lane"]
        assert "relay_fetch" in touched.relays

        listing = await flagged.listing(V2)
        assert listing != flagged.forge.responses[-1]
