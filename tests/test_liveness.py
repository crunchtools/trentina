"""Liveness: what one agent can do to the event loop every profile shares (#295).

Each test here failed before #295. L1 over a JSON payload, a selection or
redact's turn-2 output ran on the loop; ``quarantine_stats`` ran its SQLite
aggregates there; the audit table was never pruned and the blocklist sweep
deleted everything expired in one statement; a fetch had a per-read timeout
and no wall clock; and the webhooks read a reply of any size.
"""

from __future__ import annotations

import asyncio
import json
import sqlite3
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any
from unittest.mock import AsyncMock, patch

import httpx
import pytest

from tests.egress_harness import PUBLIC_ADDRESS
from tests.office_files import b64
from tests.pdf_files import pdf, show
from tests.test_egress_encoding import _Loopback as Loopback
from tests.test_unpack import _defend
from trentina import client as client_mod
from trentina import config as config_mod
from trentina import database, defense
from trentina.errors import FetchError
from trentina.gateway import collect
from trentina.gateway.context import get_current_profile, profile_context
from trentina.gateway.profile import AuthConfig, Profile
from trentina.httpbody import EncodedBodyError, TooLargeError, request_capped
from trentina.l1.pipeline import run_l1
from trentina.quarantine import agent as agent_mod
from trentina.reach import egress
from trentina.transforms import Selection, TransformContext
from trentina.transforms.pdf import PdfProcessor
from trentina.transforms.select import SelectProcessor
from trentina.transforms.structured import StructuredProcessor
from trentina.transforms.view import SelectionContext
from trentina.unpack import child
from trentina.unpack import pdf as pdf_reader
from trentina.unpack.scan import unpack

_PDF = b64(pdf(show("Quarterly report for the storage team.")))


async def _defended(token: str) -> None:
    await _defend(f"report: {token}")


async def _output_checked(token: str) -> None:
    with patch(
        "trentina.quarantine.classifier.classify_async",
        new_callable=AsyncMock,
        return_value=None,
    ):
        await agent_mod._output_flagged(token)


async def _reduced(token: str) -> None:
    await PdfProcessor().run(token, TransformContext("test"))


async def _reduced_in_json(token: str) -> None:
    await StructuredProcessor().run(json.dumps({"file": token}), TransformContext("test"))


async def _arrived_as_a_block(token: str) -> None:
    block = {"type": "resource", "resource": {"mimeType": "application/pdf", "blob": token}}
    await collect._read_response([block], None, None)


class TestWaitingForAWorker:
    """#383: a PDF or an image is read by a child process, and the thread that
    waits for it used to be one of the pool L1 and the tokenizer share."""

    @pytest.mark.parametrize(
        "reach",
        [_defended, _output_checked, _reduced, _reduced_in_json, _arrived_as_a_block],
    )
    async def test_every_way_to_a_worker_is_through_the_unpack_threads(
        self, reach: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        asked_from: list[str] = []

        def run(argv: list[str], **_kwargs: object) -> subprocess.CompletedProcess:
            asked_from.append(threading.current_thread().name)
            return subprocess.CompletedProcess(argv, 1, stdout=b"", stderr=b"")

        monkeypatch.setattr(child.subprocess, "run", run)
        await reach(_PDF)
        assert asked_from
        assert all(name.startswith("unpack") for name in asked_from)

    async def test_a_burst_of_pdfs_leaves_the_shared_pool_free(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        released = threading.Event()

        def stalls(argv: list[str], **_kwargs: object) -> subprocess.CompletedProcess:
            released.wait(10)
            return subprocess.CompletedProcess(argv, 1, stdout=b"", stderr=b"")

        monkeypatch.setattr(child.subprocess, "run", stalls)
        monkeypatch.setattr(child, "SLOT_WAIT", 0.5)
        shared = ThreadPoolExecutor(max_workers=1)
        asyncio.get_running_loop().set_default_executor(shared)
        burst = [
            asyncio.ensure_future(child.run_unpacking(unpack, _PDF))
            for _ in range(pdf_reader.CONCURRENCY + 2)
        ]
        try:
            await asyncio.sleep(0.05)
            assert not any(read.done() for read in burst), "every reader is waiting"
            result = await asyncio.wait_for(asyncio.to_thread(run_l1, "plain words"), 0.4)
            assert result.stats.total_detections() == 0
        finally:
            released.set()
            await asyncio.gather(*burst)

    async def test_the_callers_context_goes_with_it(self) -> None:
        profile = Profile(name="alpha", auth=AuthConfig(bearer_token_env="X"))
        with profile_context(profile):
            seen = await child.run_unpacking(get_current_profile)
        assert seen is profile


def _recording_run_l1(threads: list[int]) -> Any:
    def wrapped(text: str) -> Any:
        threads.append(threading.get_ident())
        return run_l1(text)

    return wrapped


class TestL1OffTheLoop:
    async def test_defend_json_runs_l1_in_a_worker(self) -> None:
        threads: list[int] = []
        with (
            patch.object(defense, "run_l1", _recording_run_l1(threads)),
            patch.object(defense, "defend", new_callable=AsyncMock),
        ):
            await defense.defend_json({"a": "one", "b": ["two"]}, source="s", source_type="t")
        assert threads
        assert threading.get_ident() not in threads

    async def test_defend_selection_runs_l1_in_a_worker(self) -> None:
        threads: list[int] = []
        view = Selection(extractor="x", segments=("one", "two"), chars_total=6, chars_scanned=6)
        with (
            patch.object(defense, "run_l1", _recording_run_l1(threads)),
            patch.object(defense, "defend", new_callable=AsyncMock),
        ):
            await defense.defend_selection(view, source="s", source_type="t")
        assert len(threads) == 2
        assert threading.get_ident() not in threads

    async def test_redacts_output_check_runs_l1_in_a_worker(self) -> None:
        threads: list[int] = []
        with (
            patch.object(agent_mod, "run_l1", _recording_run_l1(threads)),
            patch(
                "trentina.quarantine.classifier.classify_async",
                new_callable=AsyncMock,
                return_value=None,
            ),
        ):
            await agent_mod._output_flagged("body")
        assert threads
        assert threading.get_ident() not in threads

    async def test_the_select_processor_runs_in_a_worker(self) -> None:
        threads: list[int] = []
        original = SelectProcessor.select

        def recording(self: SelectProcessor, *args: Any, **kwargs: Any) -> Selection:
            threads.append(threading.get_ident())
            return original(self, *args, **kwargs)

        with patch.object(SelectProcessor, "select", recording):
            await SelectProcessor().extract({"body": "hello"}, SelectionContext())
        assert threads
        assert threading.get_ident() not in threads

    async def test_a_whitespace_flood_does_not_stall_the_loop(self) -> None:
        """60k tabs stalled every profile for ~20 s under defend_json.

        Measured as the longest the loop went without running a 10 ms
        heartbeat, end of the call included. Counting ticks instead failed
        on a call that simply finished before the first one was due. That
        the work runs off the loop at all is pinned by
        ``test_defend_json_runs_l1_in_a_worker``; this bounds its cost."""
        last = time.perf_counter()
        longest = 0.0

        async def heartbeat() -> None:
            nonlocal last, longest
            while True:
                await asyncio.sleep(0.01)
                now = time.perf_counter()
                longest, last = max(longest, now - last), now

        beat = asyncio.create_task(heartbeat())
        try:
            with patch.object(defense, "defend", new_callable=AsyncMock):
                start = time.perf_counter()
                await defense.defend_json({"body": "\t" * 60_000}, source="s", source_type="t")
                end = time.perf_counter()
        finally:
            beat.cancel()
        assert end - start < 2.0
        assert max(longest, end - last) < 0.5


@pytest.fixture
def audit_db(tmp_path: Any, monkeypatch: pytest.MonkeyPatch) -> Any:
    monkeypatch.setenv("QUARANTINE_DB", str(tmp_path / "trentina.db"))
    config_mod._config = None
    database._db = None
    database._last_sweep = None
    yield database.get_db()
    database._db = None
    config_mod._config = None


def _audit_rows(db: Any, n: int, age_days: float) -> None:
    then = time.time() - age_days * 86400
    db.executemany(
        "INSERT INTO gateway_calls (timestamp, profile, backend, tool, success, duration_ms, "
        "outcome) VALUES (?, 'alpha', 'b', 't', 0, 0, 'denied_guard')",
        [(then,)] * n,
    )
    db.commit()


def _count(db: Any) -> int:
    return int(db.execute("SELECT COUNT(*) FROM gateway_calls").fetchone()[0])


class TestStatsOffTheLoop:
    async def test_stats_read_in_a_worker_on_their_own_connection(self, audit_db: Any) -> None:
        from trentina.tools import stats as stats_mod

        seen: list[tuple[int, Any]] = []
        original = database.get_gateway_call_stats

        def recording(*args: Any, **kwargs: Any) -> dict[str, Any]:
            seen.append((threading.get_ident(), database._read_db()))
            return original(*args, **kwargs)

        _audit_rows(audit_db, 3, 0)
        with patch.object(stats_mod, "get_gateway_call_stats", recording):
            result = await stats_mod.get_trentina_stats()
        assert result["gateway_audit"]["total_calls"] == 3
        ((thread, conn),) = seen
        assert thread != threading.get_ident()
        assert conn is not audit_db

    def test_a_reader_cannot_write(self, audit_db: Any) -> None:
        with (
            database.snapshot_reader(database.opened_path()),
            pytest.raises(sqlite3.OperationalError),
        ):
            database._read_db().execute("DELETE FROM gateway_calls")


class TestRetention:
    def test_old_audit_rows_are_swept_and_recent_ones_kept(
        self, audit_db: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("TRENTINA_AUDIT_RETENTION_DAYS", "7")
        config_mod._config = None
        _audit_rows(audit_db, 3, 8)
        _audit_rows(audit_db, 2, 6)
        assert database.sweep_old_gateway_calls(audit_db) == 3
        assert _count(audit_db) == 2

    def test_zero_keeps_every_row(self, audit_db: Any, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("TRENTINA_AUDIT_RETENTION_DAYS", "0")
        config_mod._config = None
        _audit_rows(audit_db, 3, 10_000)
        assert database.sweep_old_gateway_calls(audit_db) == 0
        assert _count(audit_db) == 3

    def test_the_default_is_ninety_days(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("TRENTINA_AUDIT_RETENTION_DAYS", raising=False)
        assert database.audit_retention_days() == 90

    def test_a_pass_is_one_batch_and_the_sweep_stays_due(self, audit_db: Any) -> None:
        _audit_rows(audit_db, database.SWEEP_BATCH + 5, 400)
        database.record_gateway_call("alpha", "b", "t", "ok", 0)
        assert _count(audit_db) == 6  # one batch gone, five old rows and the new one left
        assert database._last_sweep is None  # a full batch leaves it due
        database.record_gateway_call("alpha", "b", "t", "ok", 0)
        assert _count(audit_db) == 2
        assert database._last_sweep is not None

    def test_a_failing_sweep_does_not_cost_the_row_being_written(
        self, audit_db: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Housekeeping runs inside the write; it must never take it down.

        The sweep deletes expired rows and the call is writing a new one. A
        locked table or a full disk met while pruning used to propagate out of
        ``record_gateway_call``, and ``gateway/audit.py`` logged the row as
        lost — the audit losing a row in order to delete one.
        """

        def boom(_db: Any) -> int:
            raise sqlite3.OperationalError("database is locked")

        monkeypatch.setattr(database, "sweep_expired_blocks", boom)
        database.record_gateway_call("alpha", "b", "t", "ok", 0)
        assert _count(audit_db) == 1
        assert database._last_sweep is None  # still due, so the next call retries

    def test_a_failing_sweep_does_not_fail_the_blocklist_answer(
        self, audit_db: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The other caller: the perimeter is waiting on this answer."""

        def boom(_db: Any) -> int:
            raise sqlite3.OperationalError("database is locked")

        monkeypatch.setattr(database, "sweep_old_gateway_calls", boom)
        assert database.is_blocked("https://example.com/x", "alpha") is False

    def test_the_first_call_sweeps_on_a_host_up_under_an_hour(
        self, audit_db: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """`time.monotonic()` counts from boot; a 0.0 sentinel never came due."""
        monkeypatch.setattr(database.time, "monotonic", lambda: 10.0)
        _audit_rows(audit_db, 3, 400)
        database.record_gateway_call("alpha", "b", "t", "ok", 0)
        assert _count(audit_db) == 1
        assert database._last_sweep == 10.0
        _audit_rows(audit_db, 2, 400)  # inside the hour: not swept again
        database.record_gateway_call("alpha", "b", "t", "ok", 0)
        assert _count(audit_db) == 4

    def test_the_blocklist_sweep_is_batched_too(self, audit_db: Any) -> None:
        then = "2000-01-01T00:00:00+00:00"
        audit_db.executemany(
            "INSERT INTO detections (source_type, source, detected_at, layer1_stats, "
            "risk_level, blocked, profile) VALUES ('url', ?, ?, '{}', 'high', 1, 'alpha')",
            [(f"https://x.test/{i}", then) for i in range(database.SWEEP_BATCH + 1)],
        )
        audit_db.commit()
        assert database.sweep_expired_blocks(audit_db) == database.SWEEP_BATCH
        assert database.sweep_expired_blocks(audit_db) == 1


class TestFetchDeadline:
    async def test_a_dripping_server_is_cut_off_at_the_deadline(self) -> None:
        """A byte every 50 ms never trips the per-read timeout; the wall clock does."""

        async def drip(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            await reader.readuntil(b"\r\n\r\n")
            writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 100000\r\n\r\n")
            for _ in range(200):
                if writer.is_closing():
                    break
                writer.write(b"x")
                await asyncio.sleep(0.05)
            writer.close()

        server = await asyncio.start_server(drip, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]

        async def read_all() -> None:
            async with egress.open_guarded(
                "GET", "http://drip.example/", timeout=5, deadline=0.5
            ) as resp:
                async for _chunk in resp.aiter_bytes():
                    pass

        start = time.perf_counter()
        try:
            with (
                patch.object(egress, "_lookup", lambda _h, _p: [PUBLIC_ADDRESS]),
                patch.object(egress, "_socket_backend", lambda: Loopback(port)),
                pytest.raises(TimeoutError),
            ):
                await read_all()
        finally:
            server.close()
        assert time.perf_counter() - start < 3.0

    async def test_fetch_url_reports_the_deadline_as_a_timeout(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        async def forever(_url: str) -> client_mod.Fetched:
            await asyncio.sleep(60)
            raise AssertionError("unreachable")

        monkeypatch.setattr(client_mod, "_fetch", forever)
        monkeypatch.setattr(client_mod, "FETCH_DEADLINE", 0.1)
        with pytest.raises(FetchError, match="timed out"):
            await client_mod.fetch_url("https://slow.example/")

    async def test_one_profile_holding_its_slots_does_not_queue_another(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("TRENTINA_FETCH_CONCURRENCY", "1")
        monkeypatch.setattr(client_mod, "_slots", None)
        release = asyncio.Event()

        async def held(url: str) -> client_mod.Fetched:
            if url.endswith("/hold"):
                await release.wait()
            return client_mod.Fetched("ok", "text/plain", (url,))

        monkeypatch.setattr(client_mod, "_fetch", held)

        async def fetch_as(name: str, url: str) -> str:
            with profile_context(Profile(name=name, auth=AuthConfig(bearer_token_env="X"))):
                return (await client_mod.fetch_url(url)).content

        holder = asyncio.create_task(fetch_as("alpha", "https://a.example/hold"))
        await asyncio.sleep(0.01)
        queued = asyncio.create_task(fetch_as("alpha", "https://a.example/second"))
        assert await fetch_as("beta", "https://b.example/") == "ok"
        await asyncio.sleep(0.05)
        assert not queued.done()  # alpha's second fetch waits for alpha's slot
        release.set()
        assert await holder == await queued == "ok"


def _client(handler: Any) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


class TestRequestCapped:
    async def test_a_reply_under_the_cap_is_read(self) -> None:
        async with _client(lambda _r: httpx.Response(200, content=b"hello")) as c:
            resp, body = await request_capped(c, "POST", "http://x/", deadline=5, limit=10)
        assert (resp.status_code, body) == (200, b"hello")

    async def test_a_chunked_reply_over_the_cap_is_refused(self) -> None:
        async def chunks() -> Any:
            for _ in range(100):
                yield b"x" * 1024

        async with _client(lambda _r: httpx.Response(200, content=chunks())) as c:
            with pytest.raises(TooLargeError):
                await request_capped(c, "POST", "http://x/", deadline=5, limit=4096)

    async def test_a_declared_length_over_the_cap_is_refused_unread(self) -> None:
        async with _client(
            lambda _r: httpx.Response(200, headers={"content-length": "99999999"}, content=b"")
        ) as c:
            with pytest.raises(TooLargeError):
                await request_capped(c, "POST", "http://x/", deadline=5, limit=4096)

    async def test_an_encoded_reply_is_refused(self) -> None:
        seen: list[str] = []

        def handler(request: httpx.Request) -> httpx.Response:
            seen.append(request.headers["accept-encoding"])
            return httpx.Response(200, headers={"content-encoding": "gzip"}, content=b"\x1f\x8b")

        async with _client(handler) as c:
            with pytest.raises(EncodedBodyError):
                await request_capped(c, "POST", "http://x/", deadline=5)
        assert seen == ["identity"]

    async def test_the_deadline_is_wall_clock(self) -> None:
        async def slow() -> Any:
            while True:
                await asyncio.sleep(0.05)
                yield b"x"

        async with _client(lambda _r: httpx.Response(200, content=slow())) as c:
            with pytest.raises(TimeoutError):
                await request_capped(c, "POST", "http://x/", deadline=0.2)
