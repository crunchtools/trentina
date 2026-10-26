"""What a policy refusal looks like on the wire (router ``_refused``).

An ordinary tool result: not a JSON-RPC error, ``isError`` false, the line an
agent reads first in ``content``, the structured refusal under
``_trentina_refusal``. Stock agent clients count an error of either kind as a
strike against the server, and every tool behind the gateway is one server.
"""

from __future__ import annotations

from typing import Any

from trentina.reserved import REFUSAL_KEY


def refused(response: dict[str, Any]) -> dict[str, Any]:
    """The structured refusal of ``response``, after checking it was delivered as one."""
    assert "error" not in response, response
    result = response["result"]
    assert result["isError"] is False, result
    assert result["content"][0]["text"].startswith("[TRENTINA]"), result
    return result[REFUSAL_KEY]


def refused_text(response: dict[str, Any]) -> str:
    """The line an agent reads for a refused call."""
    refused(response)
    return response["result"]["content"][0]["text"]
