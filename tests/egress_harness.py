"""Route guarded fetches through a MockTransport with a fixed resolver.

Every gateway-side fetch resolves its host before it connects (#260), so a
test that hands httpx a MockTransport must also say what the name resolves
to. Nothing here touches the network.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import httpx

from trentina.reach import egress

if TYPE_CHECKING:
    from collections.abc import Callable

    import pytest

PUBLIC_ADDRESS = "93.184.215.14"


def route(
    monkeypatch: pytest.MonkeyPatch,
    handler: Callable[[httpx.Request], httpx.Response],
    answers: dict[str, list[str]] | None = None,
) -> None:
    """Serve every request from ``handler``; resolve names from ``answers``.

    A name missing from ``answers`` resolves to one public address.
    """
    resolved = answers or {}
    monkeypatch.setattr(egress, "PinnedTransport", lambda _backend: httpx.MockTransport(handler))
    monkeypatch.setattr(egress, "_lookup", lambda host, _port: resolved.get(host, [PUBLIC_ADDRESS]))
