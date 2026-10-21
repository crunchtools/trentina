"""Alert webhook ingress for agent profiles.

Receives POST requests at ``/alert`` with ``Authorization: Bearer
<token>``, validates the token against profile ``alert_ingress``
configurations (constant-time), and forwards the JSON payload to the
profile's ``forward_url``. Designed for monitoring systems such as Nagios
that need to page an agent (e.g. a Hermes agent) through Trentina.

Until 0.52.0 the token was the last path segment, ``/alert/{token}``. Every
web server and reverse proxy between the sender and the gateway writes the
request line to its access log, so the credential sat in every one of them
(#333, the same shape as the Matrix proxy's #330). A request to the old
shape now gets 404 and the token is not echoed.

Before forwarding, the payload runs through the same three-layer
defense used elsewhere: string leaves in the JSON go through L1,
the L1 input is classified by L2, and — when
a Gemini API key is configured — the Q-Agent reviews it (Layer 3).
This closes the injection vector in Hermes's own webhook adapter,
which interpolates payload values into a live agent prompt with no
detection of its own.

What a flagged payload becomes is ``alert_ingress.enforcement``, and it
defaults to ``flag``: forwarded with a ``_trentina_warning`` field attached
rather than dropped. For paging that is the right default — silently
dropping a real incident on a classifier false positive is worse than
forwarding a flagged one, and the warning lands in context ahead of the
payload, so the receiving agent reads the caution before the content.

Until 0.25.0 that behaviour was HARDCODED here and the setting did not
exist. `defense.enforcement` was read only on the tool path, so the one
path with an agent to ask was the only path that was ever configurable,
while the paths with nobody to ask could not be configured at all. An
operator who wants a stricter ingress can now say so.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

import httpx
from starlette.responses import Response

from ..defense import defend, defend_json
from ..httpbody import (
    STATUS_TOO_LARGE,
    EncodedBodyError,
    TooLargeError,
    max_request_bytes,
    read_capped,
    request_capped,
)
from ..l1.pipeline import risk_level_for_count
from ..logsafe import exc_kind, redact_source, safe_url
from ..modes import gaps_of
from ..reserved import WARNING_KEY, strip_reserved, with_stripped
from .context import profile_context

if TYPE_CHECKING:
    from starlette.requests import Request

    from .profile import AlertIngressConfig, Profile

logger = logging.getLogger(__name__)

_TIMEOUT = httpx.Timeout(connect=10.0, read=30.0, write=10.0, pool=5.0)
# Wall clock for one forward, the reply included (#295).
_FORWARD_DEADLINE = 60.0
_alert_client: httpx.AsyncClient | None = None


@dataclass
class _L1Counts:
    """Aggregate L1 detection counts across every string leaf in a JSON payload."""

    detections: int = field(default=0)
    suspicious: int = field(default=0)


def _get_alert_client() -> httpx.AsyncClient:
    global _alert_client
    if _alert_client is None:
        # nosemgrep: trentina-httpx-client-outside-egress -- operator forward_url
        _alert_client = httpx.AsyncClient(timeout=_TIMEOUT)
    return _alert_client


async def close_alert_client() -> None:
    """Shut down the httpx client.  Called on application shutdown."""
    global _alert_client
    if _alert_client is not None:
        await _alert_client.aclose()
        _alert_client = None


def _resolve_profile_by_alert_token(
    token: str,
    profiles: dict[str, Profile],
) -> Profile | None:
    token_bytes = token.encode("utf-8")
    match: Profile | None = None
    for profile in profiles.values():
        if profile.alert_ingress is None or profile.alert_ingress.token is None:
            continue
        expected = profile.alert_ingress.token.get_secret_value().encode("utf-8")
        if hmac.compare_digest(token_bytes, expected) and match is None:
            match = profile
    return match


def register_alert_routes(
    mcp_server: Any,
    profiles: dict[str, Profile],
) -> None:
    """Wire ``POST /alert`` onto the FastMCP server."""
    alert_profiles = [name for name, p in profiles.items() if p.alert_ingress is not None]
    if not alert_profiles:
        logger.info("alert_ingress: no profiles configured, skipping")
        return

    async def alert_endpoint(request: Request) -> Response:
        return await _handle_alert(request, profiles)

    mcp_server.custom_route("/alert", methods=["POST"])(alert_endpoint)

    logger.info(
        "alert_ingress: registered /alert for %d profile(s): %s",
        len(alert_profiles),
        ", ".join(alert_profiles),
    )


async def _handle_alert(
    request: Request,
    profiles: dict[str, Profile],
) -> Response:
    header = request.headers.get("authorization", "")
    token = header[7:].strip() if header.lower().startswith("bearer ") else ""
    if not token:
        return Response(
            content="missing token",
            status_code=400,
            media_type="text/plain",
        )

    profile = _resolve_profile_by_alert_token(token, profiles)
    if profile is None:
        return Response(
            content="unauthorized",
            status_code=401,
            media_type="text/plain",
        )

    if profile.alert_ingress is None:
        # _resolve_profile_by_alert_token() only ever returns a profile whose
        # alert_ingress is set -- this branch means that invariant broke.
        logger.error("alert_ingress: resolved profile has no alert_ingress config")
        return Response(
            content="internal error",
            status_code=500,
            media_type="text/plain",
        )

    try:
        body = await read_capped(request, max_request_bytes())
    except TooLargeError:
        logger.warning("alert_ingress: refused a body over %d bytes", max_request_bytes())
        return Response(
            content="request body too large",
            status_code=STATUS_TOO_LARGE,
            media_type="text/plain",
        )
    except Exception as exc:
        # Client disconnect mid-read, malformed chunked encoding, and a body
        # exceeding the server limit all land here. 400 is the right answer to
        # all three, but the reason is the only signal distinguishing a flaky
        # client from an attack, so it is logged rather than discarded: its
        # kind, since a parser's message can quote the bytes it choked on.
        logger.warning("alert_ingress: could not read request body: %s", exc_kind(exc))
        return Response(
            content="bad request body",
            status_code=400,
            media_type="text/plain",
        )

    # Judged on this profile's provider and key (RT #1505).
    with profile_context(profile):
        forward_body, risk_level, flagged, counts = await _defend_alert(body, profile)

    client_host = request.client.host if request.client is not None else "unknown"
    log_fn = logger.warning if flagged else logger.info
    # The payload's fingerprint, never its text (#292): whoever shapes a
    # monitored check's output chooses these bytes, and the journal is
    # readable by agents through other backends.
    log_fn(
        "alert_ingress: profile=%s source_ip=%s risk=%s l1_detections=%d payload=%s",
        profile.name,
        client_host,
        risk_level,
        counts.detections,
        redact_source(forward_body),
    )

    enforcement = profile.alert_ingress.enforcement
    if flagged and enforcement != "flag":
        # `redact` has no extraction contract on this path yet, so it refuses
        # rather than forwarding the bytes it exists to replace — the same
        # reading the tool path takes.
        logger.warning(
            "alert_ingress: refusing flagged payload for profile=%s (enforcement=%s risk=%s)",
            profile.name,
            enforcement,
            risk_level,
        )
        return Response(
            content=json.dumps({"error": "payload refused by trentina", "risk_level": risk_level}),
            status_code=403,
            media_type="application/json",
        )

    return await _forward(profile, profile.alert_ingress, forward_body)


async def _forward(profile: Profile, cfg: AlertIngressConfig, forward_body: bytes) -> Response:
    """POST the judged body on, and relay the target's reply under the #267 cap."""
    fwd_headers: dict[str, str] = {"Content-Type": "application/json"}
    forward_url = cfg.forward_url
    if cfg.forward_secret is not None:
        secret = cfg.forward_secret.get_secret_value()
        sig = hmac.new(
            secret.encode("utf-8"),
            forward_body,
            hashlib.sha256,
        ).hexdigest()
        fwd_headers["X-Hub-Signature-256"] = f"sha256={sig}"

    client = _get_alert_client()
    try:
        resp, reply = await request_capped(
            client,
            "POST",
            forward_url,
            deadline=_FORWARD_DEADLINE,
            content=forward_body,
            headers=fwd_headers,
        )
    except (httpx.TimeoutException, TimeoutError):
        logger.warning("alert_ingress: timeout forwarding for profile %s", profile.name)
        return Response(
            content="forward timeout",
            status_code=504,
            media_type="text/plain",
        )
    except httpx.ConnectError as exc:
        logger.warning(
            "alert_ingress: connect error forwarding for profile %s: %s",
            profile.name,
            exc_kind(exc),
        )
        return Response(
            content="forward unreachable",
            status_code=502,
            media_type="text/plain",
        )
    except (TooLargeError, EncodedBodyError, httpx.HTTPError) as exc:
        # The forward target's reply is relayed to the sender; over the cap
        # or encoded, it is refused rather than buffered (#295).
        logger.warning(
            "alert_ingress: unreadable reply forwarding for profile %s: %s",
            profile.name,
            exc_kind(exc),
        )
        return Response(
            content="forward reply refused",
            status_code=502,
            media_type="text/plain",
        )

    logger.info(
        "alert_ingress: forwarded to %s for profile %s (status=%d)",
        safe_url(forward_url),
        profile.name,
        resp.status_code,
    )

    return Response(
        content=reply,
        status_code=resp.status_code,
        media_type=resp.headers.get("content-type", "application/json"),
    )


async def _defend_alert(
    body: bytes,
    profile: Profile,
) -> tuple[bytes, str, bool, _L1Counts]:
    """Run the three-layer defense over an alert payload.

    Returns the bytes to forward — the payload's content intact, with a
    ``_trentina_warning`` field attached when flagged (JSON payloads only;
    plain text has nowhere to carry an annotation, so its warning lives in
    the log line and the D-Bus event) — plus the L1 risk level, whether any
    layer flagged, and the raw L1 detection counts. Content is never
    modified on the way through: L1 detects and the sidecar warns. The one
    exception is gateway-reserved keys (``reserved.py``, #265), which the
    sender may not write: they are removed before the scan and counted in
    the warning as ``reserved_stripped``.

    This function does not decide disposition and never did — an earlier
    revision claimed "the enforcement mode (not this function) decides
    disposition", which was false in the only way that matters: no
    enforcement mode was consulted anywhere on this path. `_handle_alert`
    reads `alert_ingress.enforcement` and decides.

    Two things changed when this moved onto the shared pipeline, both
    deliberate:

    1. It now honours ``profile.defense``. This was the only place in the
       codebase where the pipeline actually ran, and it was the one place that
       ignored the per-profile toggles DefenseConfig exists to hold.

    2. A truncated L2 scan now flags. Previously the classifier was handed the
       whole payload, and a payload past CLASSIFIER_MAX_TOKENS was scanned only
       in part while ``ClassifierResult.truncated`` was discarded — so an
       oversized alert forwarded looking clean. "We could not finish reading
       this" is not the same as "this is fine", and it should never again be
       reported as though it were.
    """
    try:
        payload = json.loads(body)
    except (json.JSONDecodeError, UnicodeDecodeError):
        payload = None

    defense = profile.defense
    source = f"alert:{profile.name}"

    # The sender does not get to write the gateway's markers (#265): stripped
    # before the scan, so what is judged is what is forwarded, and before the
    # gateway adds its own below.
    stripped = await asyncio.to_thread(strip_reserved, payload) if payload is not None else 0
    if stripped:
        logger.info(
            "alert_ingress: stripped %d reserved key(s) from an alert for profile=%s",
            stripped,
            profile.name,
        )

    if payload is not None:
        # L1 per leaf so the JSON survives; L2/L3 read the joined document, so
        # an instruction split across two fields is still visible.
        verdict = await defend_json(
            payload,
            source=source,
            source_type="alert",
            defense=defense,
        )
        counts = _L1Counts(
            detections=verdict.verdict.pipeline.stats.total_detections(),
            suspicious=verdict.verdict.pipeline.stats.suspicious_detections(),
        )
        forward_payload: Any = verdict.payload
        joined_text = verdict.joined_text
        final = verdict.verdict
    else:
        text = body.decode("utf-8", errors="replace")
        first = await defend(
            text,
            source=source,
            source_type="alert",
            defense=defense,
            record=False,
        )
        counts = _L1Counts(
            detections=first.pipeline.stats.total_detections(),
            suspicious=first.pipeline.stats.suspicious_detections(),
        )
        final = first
        forward_payload = None
        joined_text = first.content

    risk_level = risk_level_for_count(counts.suspicious)
    classification = final.classification
    l2_truncated = bool(classification is not None and classification.truncated)

    # Under anything but flag, a layer that could not give a verdict is held
    # to the same rule as every other path (modes.Gaps.blocking): unjudged
    # is refused, not forwarded. flag delivers, so it is not flagged for it.
    cfg = profile.alert_ingress
    unjudged = (cfg is None or cfg.enforcement != "flag") and gaps_of(final).blocking()

    flagged = risk_level != "low" or final.flagged or l2_truncated or unjudged

    # NOTE: this warning is still built by hand rather than via
    # warning.build_warning, because this path derives risk_level from
    # its own suspicious-detection counts rather than from the verdict. Folding
    # it in means reconciling those two risk models, which is a behaviour
    # change to the alert path and does not belong in the commit that fixes
    # the Matrix one. Tracked separately.
    warning: dict[str, Any] | None = None
    if flagged:
        warning = {
            "risk_level": risk_level,
            "l1_detections": counts.detections,
            "l2_label": classification.label if classification is not None else None,
            "l2_score": classification.score if classification is not None else None,
            "l2_truncated": l2_truncated,
            "l3_injection_detected": (
                final.l3_assessment.get("injection_detected")
                if final.l3_assessment is not None
                else None
            ),
        }
    warning = with_stripped(warning, stripped)
    if warning is not None and isinstance(forward_payload, dict):
        forward_payload[WARNING_KEY] = warning

    forward_body = (
        json.dumps(forward_payload).encode("utf-8")
        if forward_payload is not None
        else joined_text.encode("utf-8")
    )

    return forward_body, risk_level, flagged, counts
