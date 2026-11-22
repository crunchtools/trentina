"""A tool reply as L2 reads it behind the gateway, for corpora built outside it.

The path ``benchmarks/l2_benign.as_read`` takes for a benign case, for any
payload: the reply arrives as a JSON text block and the same object as
``structuredContent``; the router drops a structured copy that repeats the
text, the default pre-processors rewrite the text block, the perimeter
collects what is left and the unpack stage builds what the layers read. The
envelope gate (``benchmarks/l2_envelopes.py``) and the L2 training set
(``scripts/l2_train_data.py``) both render through it, so a model is trained
on exactly the text it is gated on and judged on in production.

``as_request`` is the other read path (#869): a JSON body an agent sends out
through an ``egress_http`` upstream (``body: json``), read as the route reads
it before anything is sent. The request line, the forwarded headers and the
body unescaped become one document (``egress_policy.request_document``), every
escaping is decoded and every credential shape cut (``outbound.judge_input``),
and the unpack stage builds what the layers read from that.
"""

from __future__ import annotations

import json
from typing import Any

from trentina.gateway.collect import _collect_response_texts
from trentina.gateway.egress_policy import forward_request_headers, request_document
from trentina.gateway.outbound import body_text, judge_input
from trentina.gateway.profile import AuthConfig, Backend, Profile
from trentina.gateway.results import _drop_duplicate_structured
from trentina.gateway.transform import transform_response
from trentina.unpack.scan import unpack

_BACKEND = Backend(url="http://ops.invalid/mcp", tools_allow=["*"])
_PROFILE = Profile(
    name="gateway-read",
    auth=AuthConfig(bearer_token_env="GATEWAY_READ_TOKEN"),
    backends={"ops": _BACKEND},
)
"""A profile with every default: the pre-processing an operator who
configured nothing gets."""

_ARRIVED = [
    ("accept", "*/*"),
    ("accept-encoding", "gzip, deflate"),
    ("connection", "keep-alive"),
    ("user-agent", "python-httpx/0.28.1"),
    ("content-type", "application/json"),
    ("x-title", "gatehouse"),
]
"""The headers an HTTP client sends with a JSON POST; the route forwards, and
judges, only those its allowlist names."""


async def as_read(payload: Any, tool: str) -> str:
    """``payload`` (a reply object, or a document's text) as L2 reads it from ``tool``."""
    structured = not isinstance(payload, str)
    text = json.dumps(payload, separators=(",", ":")) if structured else payload
    blocks: list[Any] = [{"type": "text", "text": text}]
    kept = _drop_duplicate_structured(payload if structured else None, blocks)
    outcome = await transform_response(
        profile=_PROFILE,
        backend=_BACKEND,
        backend_name="ops",
        tool_name=tool,
        content_blocks=blocks,
    )
    texts, _, _, _ = _collect_response_texts(outcome.content_blocks, kept)
    return unpack("\n".join(texts)).text


def as_request(payload: Any, path: str = "/v1/chat/completions") -> str:
    """``payload``, a JSON body POSTed to ``path`` on an egress upstream, as L2 reads it."""
    body = body_text(json.dumps(payload).encode())
    headers = forward_request_headers(_ARRIVED, ())
    document = request_document("POST", path, "", headers, body)
    return unpack(judge_input(document)).text
