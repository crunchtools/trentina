"""A real browser against the real approval pages (RT#1609).

The unit suite drives these routes with Starlette's TestClient, which sends
whatever headers the test writes. A browser decides some of them itself --
``Origin`` above all -- and that is exactly where RT#1609 hid: every form and
passkey POST from a real browser carried ``Origin: null`` and was refused,
while every TestClient and curl replay passed. So these tests put Chrome in
front of the routes over real HTTP, with nothing in between.

Kept out of the default run (``pyproject.toml`` ignores ``tests/browser``)
because the image that runs the default suite has no browser. CI runs it as
its own job and passes ``--browser-path``, which turns a missing browser into
a failure instead of a skip.
"""

from __future__ import annotations

import shutil
import socket
import threading
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

playwright_api = pytest.importorskip("playwright.sync_api")

_DEFAULT_BROWSERS = ("google-chrome", "google-chrome-stable", "chromium", "chromium-browser")


def pytest_addoption(parser: pytest.Parser) -> None:
    parser.addoption(
        "--browser-path",
        default=None,
        help="Chrome/Chromium to drive. Given: it must exist. Omitted: one on PATH, or skip.",
    )


@pytest.fixture(scope="session")
def browser_path(pytestconfig: pytest.Config) -> str:
    given = pytestconfig.getoption("--browser-path")
    if given:
        if not Path(given).is_file():
            pytest.fail(f"--browser-path {given} does not exist")
        return str(given)
    for name in _DEFAULT_BROWSERS:
        found = shutil.which(name)
        if found:
            return found
    pytest.skip("no Chrome or Chromium on PATH and no --browser-path given")


@pytest.fixture(scope="session")
def browser(browser_path: str) -> Iterator[Any]:
    with playwright_api.sync_playwright() as p:
        launched = p.chromium.launch(executable_path=browser_path, headless=True)
        yield launched
        launched.close()


@pytest.fixture
def tab(browser: Any) -> Iterator[Any]:
    """A fresh profile per test: no cookies, no storage, no cache."""
    context = browser.new_context()
    page = context.new_page()
    yield page
    context.close()


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


@pytest.fixture(scope="module")
def server() -> Iterator[str]:
    """The approval routes on a real uvicorn server; yields its base URL.

    ``localhost`` rather than ``127.0.0.1``: it is a secure context, so the
    passkey ceremony runs, and it is the name WebAuthn accepts as an rpId.
    """
    import uvicorn
    from fastmcp import FastMCP
    from starlette.applications import Starlette

    from trentina.gateway import approval_routes

    mcp = FastMCP("browser")
    approval_routes.register_approval_routes(mcp)
    port = _free_port()
    config = uvicorn.Config(
        Starlette(routes=mcp._additional_http_routes),
        host="127.0.0.1",
        port=port,
        log_level="warning",
    )
    running = uvicorn.Server(config)
    thread = threading.Thread(target=running.run, daemon=True)
    thread.start()
    deadline = time.monotonic() + 10
    while not running.started:
        if time.monotonic() > deadline:
            pytest.fail("the approval server did not start")
        time.sleep(0.05)
    yield f"http://localhost:{port}"
    running.should_exit = True
    thread.join(timeout=10)


@pytest.fixture
def fresh(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Iterator[None]:
    """A gateway with no approver, no window and its own data directory."""
    from trentina import config as config_mod
    from trentina.gateway import approval_session, approver, pending

    monkeypatch.delenv("TRENTINA_APPROVAL_PASSWORD_HASH", raising=False)
    monkeypatch.setenv("QUARANTINE_DB", str(tmp_path / "state" / "trentina.db"))
    config_mod._config = None
    approver.close_enrolment()
    pending.clear()
    approval_session.clear()
    yield
    approver.close_enrolment()
    pending.clear()
    approval_session.clear()
    config_mod._config = None
