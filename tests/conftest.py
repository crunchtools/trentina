"""Shared fixtures for gateway tests."""

from __future__ import annotations

import contextlib
import pathlib
from collections.abc import Iterator

import pytest

from trentina import config as config_mod
from trentina import database as database_mod
from trentina import logsafe
from trentina import perimeter_db as perimeter_db_mod
from trentina.gateway.backend import reset_tool_list_cache
from trentina.gateway.circuit import breaker
from trentina.gateway.ingress_defense import reset_verdict_cache
from trentina.gateway.loader import reset_active_config
from trentina.gateway.matrix_proxy import reset_extractors
from trentina.gateway.router import reset_profile_tools_cache
from trentina.quarantine.limiter import reset_limiters
from trentina.quarantine.providers import reset_provider


@pytest.fixture(autouse=True)
def _reset_singletons() -> None:
    """Reset global singletons before every test."""
    breaker.reset()
    reset_provider()
    reset_limiters()
    # A test that boots the gateway (test_logging_config) leaves an
    # ActiveConfig registered for the rest of the session. Admin tools read
    # that singleton to tell a multi-tenant gateway from a standalone server,
    # so a leftover turns later tests into a different scope than they wrote.
    reset_active_config()
    reset_extractors()
    reset_tool_list_cache()
    reset_profile_tools_cache()
    reset_verdict_cache()
    # The sqlite connection is bound to the thread that created it, and
    # Starlette's TestClient runs apps on a worker thread — a connection one
    # test created on the main thread poisons the next test's defend()
    # audit write with sqlite3.ProgrammingError. Fresh connection per test.
    if database_mod._db is not None:
        with contextlib.suppress(Exception):
            # close() is itself thread-bound; dropping the reference is the
            # part that matters.
            database_mod._db.close()
        database_mod._db = None
    # Same for the perimeter store, which is a second connection with the
    # same thread affinity.
    if perimeter_db_mod._db is not None:
        with contextlib.suppress(Exception):
            perimeter_db_mod._db.close()
        perimeter_db_mod._db = None


@pytest.fixture(autouse=True)
def _isolated_perimeter_store(tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Never let a test write the developer's real perimeter store.

    ``scan_tool_list`` persists every verdict it reaches, so without this a
    unit test leaves rows in ~/.local/share/trentina/perimeter.db — and
    a verdict cached from a mocked pipeline is exactly the kind of row that
    should not outlive the test that invented it.
    """
    # In a subdirectory, not tmp_path itself: read_tool refuses Trentina's own
    # state directories (#261), and tests read files they wrote to tmp_path.
    monkeypatch.setenv("TRENTINA_PERIMETER_DB", str(tmp_path / "state" / "perimeter.db"))
    config_mod._config = None


@pytest.fixture(autouse=True)
def _nothing_held() -> Iterator[None]:
    """No test inherits another's secrets (#341). ``logsafe`` holds every
    secret the loader reads for the life of the process, and a fake token
    that is also a word ("kage", "slack") would be cut from a later test's
    log lines."""
    logsafe._forget_all()
    yield
    logsafe._forget_all()


@pytest.fixture(autouse=True)
def _no_startup_scrub(monkeypatch: pytest.MonkeyPatch) -> None:
    """A test that boots the gateway must not pop the test process's own env (#268).

    ``_run_with_gateway`` ends by removing startup-only secrets from
    ``os.environ``. Under pytest that is the developer's shell environment,
    for every test after it. ``tests/test_envscrub.py`` imports the real
    function directly and exercises it under ``monkeypatch``.
    """
    from trentina.gateway import envscrub

    monkeypatch.setattr(envscrub, "scrub_startup_secrets", lambda _extra=(): [])


@pytest.fixture(autouse=True)
def _no_ambient_gemini_key(request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch) -> None:
    """Unit tests must not inherit the shell's GEMINI_API_KEY.

    The defense pipeline gates L3 on ``get_config().has_api_key``. With a key
    in the environment, a test that forgot to patch ``defense.get_config``
    passes on one machine and fails on another — and worse, one that forgot to
    mock ``quarantine_detect`` makes a live Gemini call from a unit test.
    Tests that need a key patch ``defense.get_config`` and say so.

    The provider integration suite is the one deliberate exception: it exists
    to make live calls and reads the key from the environment at call time.
    """
    if "integration" in request.node.path.name:
        yield
        return
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    config_mod._config = None
    yield
    config_mod._config = None


@pytest.fixture
def env(tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[pathlib.Path]:
    """For tests/mode_harness.py: an L3 key, a private blocklist, fresh config."""
    monkeypatch.setenv("GEMINI_API_KEY", "test-key")
    monkeypatch.setenv("QUARANTINE_DB", str(tmp_path / "state" / "trentina.db"))
    monkeypatch.delenv("QUARANTINE_FALLBACK", raising=False)
    monkeypatch.delenv("TRENTINA_REQUIRE_L2", raising=False)
    monkeypatch.delenv("TRENTINA_REQUIRE_L3", raising=False)
    monkeypatch.setenv("QUARANTINE_TRUST_CONFIG", str(tmp_path / "state" / "no-such-trust.json"))
    config_mod._config = None
    database_mod._db = None
    yield tmp_path
    config_mod._config = None
    database_mod._db = None


@pytest.fixture(autouse=True)
def _no_ocr_process(request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch) -> None:
    """Images are left unread unless a test asks for OCR (``@pytest.mark.ocr``).

    OCR is a child process that loads three models: about a second before the
    first image is read. Hundreds of tests pass a few bytes with a PNG
    signature through the unpack stage to see them counted unread, and none
    of them should start it.
    """
    if "ocr" in request.keywords:
        return
    from trentina.unpack import scan

    monkeypatch.setattr(scan, "read_images", lambda images: [None] * len(images))


@pytest.fixture
def read_only_tools(monkeypatch: pytest.MonkeyPatch) -> None:
    """Every remote tool is one its backend annotated ``readOnlyHint``.

    A test whose backend never listed its tools gets an unannotated one, and
    the router treats that as a tool that may write (#425).
    """
    monkeypatch.setattr("trentina.gateway.router.cached_tool_read_only", lambda _url, _tool: True)
