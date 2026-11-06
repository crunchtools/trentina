"""``auth.callback_url`` (#725): a per-backend redirect_uri and its extra route."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from trentina.gateway import backend_oauth
from trentina.gateway.profile import Backend, BackendAuth


def _auth(url: str | None) -> BackendAuth:
    return BackendAuth(type="oauth", client_id="c", callback_url=url)


@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1:8787/oauth/callback",
        "http://[::1]:8787/cb",
        "https://example.com/oauth/callback",
    ],
)
def test_valid_callback_urls(url: str) -> None:
    assert _auth(url).callback_url == url


@pytest.mark.parametrize(
    "url",
    [
        "/oauth/callback",
        "http://example.com/cb",
        "http://localhost:8787/cb",
        "https://u:p@example.com/cb",
        "https://example.com/cb?x=1",
        "https://example.com/cb#f",
        "https://example.com/a/../cb",
        "https://example.com/a//cb",
        "https://example.com/",
        "https://example.com/oauth/backend/start",
        "https://example.com/authorize",
        "ftp://example.com/cb",
    ],
)
def test_invalid_callback_urls(url: str) -> None:
    with pytest.raises(ValidationError):
        _auth(url)


def test_callback_url_prefers_backend_override() -> None:
    backend = Backend(
        url="https://hub.example.com/mcp",
        auth=_auth("http://127.0.0.1:8787/oauth/callback"),
    )
    assert backend_oauth.callback_url(backend) == "http://127.0.0.1:8787/oauth/callback"
    assert backend_oauth.callback_url().endswith(backend_oauth.CALLBACK_PATH)
