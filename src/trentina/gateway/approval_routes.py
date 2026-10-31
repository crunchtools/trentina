"""The page a person approves a staged action on (#637).

``pending`` holds what is staged, ``approver`` decides who may approve, and
this is the only way a human reaches either. Two steps, both POSTs after the
first GET:

1. GET shows a password field and nothing else — not even whether anything is
   pending, so an unauthenticated visitor learns nothing about this gateway.
2. POST with the password shows what is staged and an Approve/Decline button
   per action.
3. POST with the password, a kind and a decision applies it.

The password is re-sent on the last step rather than held in a cookie or a
server-side session. That keeps the route stateless, keeps the secret out of
the URL and so out of every access log, and makes the password itself the CSRF
defence: a page on another origin cannot supply it.

There is no capability token anywhere, and that is the point. The first cut of
this handed the staging agent a link that approved; the agent reads its own
tool result, and an operator with any code-execution backend can POST. The
only thing that may stand between a staged action and its application is
something the agent cannot read.

Modelled on ``backend_oauth``'s pages, down to the headers and the limiter, so
a person meets one idiom on this gateway rather than three. No script, no
external reference, and no form action but its own path.
"""

from __future__ import annotations

import html
import logging
from http import HTTPStatus
from typing import TYPE_CHECKING, Any

from starlette.responses import HTMLResponse, Response

from ..logsafe import exc_kind
from . import approver, pending

if TYPE_CHECKING:
    from starlette.requests import Request

logger = logging.getLogger(__name__)

PATH = "/approve"

#: Tighter than the OAuth pages'. A person approves a handful of things ever,
#: and this route gates who holds root, so the limit is also what bounds a
#: guess at the password.
PAGE_LIMIT = (10, 30)

#: Nothing here needs a body: a password and two short fields.
MAX_BODY_BYTES = 4096

_HEADERS = {
    "Cache-Control": "no-store",
    "Referrer-Policy": "no-referrer",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    # Nothing on this page runs, and nothing it shows is fetched.
    "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'",
}

#: One wording for a wrong password and for a right one with nothing staged. A
#: visitor who guesses learns neither whether the password was right nor
#: whether this gateway has anything pending.
_NOTHING = (
    "Nothing to approve. If you were expecting something, check with the agent "
    "that proposed it and try again."
)

_STYLE = "font:16px/1.5 system-ui,sans-serif;max-width:40rem;margin:3rem auto;padding:0 1rem"
_BUTTON = "font:inherit;padding:.5rem 1rem"


def _page(title: str, body: str, status: int = 200) -> Response:
    """A small fixed page. ``body`` is HTML built from escaped values."""
    document = (
        '<!doctype html><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        f"<title>{html.escape(title)}</title>"
        f'<body style="{_STYLE}">{body}</body>'
    )
    return HTMLResponse(document, status_code=status, headers=_HEADERS)


def _facts_table(facts: dict[str, str]) -> str:
    rows = "".join(
        "<tr>"
        "<th style='text-align:left;padding:.25rem 1rem .25rem 0;vertical-align:top'>"
        f"{html.escape(label)}</th>"
        f"<td style='padding:.25rem 0'><code>{html.escape(value)}</code></td>"
        "</tr>"
        for label, value in facts.items()
    )
    return f"<table style='border-collapse:collapse;margin:1rem 0'>{rows}</table>"


def _review(password: str, staged: dict[pending.Kind, dict[str, str]]) -> Response:
    """What is staged, with the password carried forward for the decision."""
    sections = "".join(
        f"<h2>{html.escape(kind.value)}</h2>"
        f"{_facts_table(facts)}"
        f'<form method="post" action="{html.escape(PATH)}">'
        f'<input type="hidden" name="password" value="{html.escape(password)}">'
        f'<input type="hidden" name="kind" value="{html.escape(kind.value)}">'
        f'<button name="decision" value="approve" style="{_BUTTON}">Approve</button> '
        f'<button name="decision" value="decline" style="{_BUTTON}">Decline</button>'
        "</form>"
        for kind, facts in staged.items()
    )
    return _page(
        "Approve a change",
        f"<h1>Approve this change?</h1><p>Nothing has changed yet.</p>{sections}"
        "<p style='color:#555'>Each of these expires on its own if you do nothing. "
        "If you did not expect it, decline it.</p>",
    )


async def _show(_request: Request) -> Response:
    """The first page: a password field, and no statement about what is staged.

    It does not say whether anything is pending, so an unauthenticated visitor
    learns nothing about this gateway — not even that it has an agent asking
    for something.
    """
    return _page(
        "Approve a change",
        "<h1>Approve a change</h1>"
        "<p>An agent on this gateway may be asking to change something only a "
        "person should agree to. Enter the approval password to see it.</p>"
        f'<form method="post" action="{html.escape(PATH)}">'
        "<p><label>Approval password<br>"
        '<input type="password" name="password" autocomplete="current-password" '
        'style="font:inherit;padding:.4rem;width:20rem"></label></p>'
        f'<button style="{_BUTTON}">Continue</button>'
        "</form>",
    )


def _nothing() -> Response:
    return _page("Nothing to approve", f"<p>{_NOTHING}</p>", HTTPStatus.NOT_FOUND)


async def _act(kind: pending.Kind, decision: str) -> Response:
    """Carry out a decision a verified person made."""
    if decision == "decline":
        return (
            _page("Declined", "<p>Declined. Nothing was changed.</p>")
            if pending.decline(kind)
            else _nothing()
        )
    try:
        await pending.approve(kind)
    except pending.PendingError:
        return _nothing()
    except Exception as exc:
        # The action's own failure. It reports the detail to the agent that
        # staged it; a person is told it did not happen, never the exception
        # (#262).
        logger.warning("approval: applying refused err=%s", exc_kind(exc))
        return _page(
            "Not applied",
            "<p>Approved, but the change could not be applied, so nothing was "
            "changed. The agent that proposed it has the reason.</p>",
            HTTPStatus.INTERNAL_SERVER_ERROR,
        )
    return _page("Approved", "<p>Approved and applied. You can close this tab.</p>")


async def _decide(request: Request) -> Response:
    form = await request.form()
    password = str(form.get("password") or "")
    if not approver.verify(password):
        # A wrong password and a right one with nothing staged answer the same.
        logger.info("approval: a visitor did not present a valid approval password")
        return _nothing()

    staged = pending.outstanding()
    kind = pending.kind_named(str(form.get("kind") or ""))
    decision = str(form.get("decision") or "")
    if kind is None or decision not in ("approve", "decline"):
        return _review(password, staged) if staged else _nothing()
    return await _act(kind, decision)


def register_approval_routes(mcp_server: Any) -> None:
    """Mount the approval page, but only where someone can actually approve.

    With no approver configured the route does not exist and nothing may be
    staged, so the two guarded writes are refused exactly as they were before
    this feature. The absence of a password is the absence of the feature.
    """
    if not approver.configured():
        logger.info(
            "gateway: no approval password configured, so %s is not mounted and the "
            "operator seat and federation trust stay unwritable",
            PATH,
        )
        return

    from starlette.routing import request_response

    from .ratelimit import RateLimiter, UnauthenticatedWriteGuard, enabled

    limiter = RateLimiter(*PAGE_LIMIT, name=PATH)
    for methods, handler in ((["GET"], _show), (["POST"], _decide)):
        app: Any = handler
        if enabled():
            app = UnauthenticatedWriteGuard(
                request_response(handler), limiter=limiter, max_body_bytes=MAX_BODY_BYTES
            )
        mcp_server.custom_route(PATH, methods=methods)(app)
    logger.info("gateway: the approval page is mounted at %s", PATH)
