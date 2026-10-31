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

import asyncio
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

#: Defined in ``pending``, so a tool can name the page without importing a
#: route module. Re-exported under the names this module reads best with.
PATH = pending.PAGE_PATH
ENROL_PATH = pending.ENROL_PATH

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
    # scrypt is deliberately expensive — ~16 MiB and tens of milliseconds — so
    # it runs in a worker. On the loop it would stall every other profile's
    # request for the duration of a stranger's password guess.
    if not await asyncio.to_thread(approver.verify, password):
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
        logger.warning(
            "gateway: no approval password is set, so the operator seat and federation "
            "trust stay unwritable. An operator agent can ask for one with "
            "approval_enrol, which opens %s for a person to set it. Until it is set, an "
            "operator profile holding a backend that can make arbitrary HTTP requests "
            "could enrol itself — set it promptly, and keep such a backend off the "
            "operator seat (docs/deployment-hardening.md)",
            ENROL_PATH,
        )

    from starlette.routing import request_response

    from .ratelimit import RateLimiter, UnauthenticatedWriteGuard, enabled

    # The body cap holds whether or not limiting does: a form parser must never
    # be handed an unbounded body, and the limiter is an incident escape hatch.
    limiter = RateLimiter(*PAGE_LIMIT, name=PATH) if enabled() else None
    routes = (
        (PATH, ["GET"], _show),
        (PATH, ["POST"], _decide),
        (ENROL_PATH, ["GET"], _password_page),
        (ENROL_PATH, ["POST"], _set_password),
    )
    for path, methods, handler in routes:
        app: Any = UnauthenticatedWriteGuard(
            request_response(handler),
            limiter=limiter,
            max_body_bytes=MAX_BODY_BYTES,
            name=path,
        )
        mcp_server.custom_route(path, methods=methods)(app)
    logger.info("gateway: the approval pages are mounted at %s", PATH)


_CODE_FIELD = (
    "<p><label>Enrolment code<br>"
    '<input name="code" autocomplete="off" '
    'style="font:inherit;padding:.4rem;width:20rem"></label></p>'
)

_SET_FORM = (
    '<p><label>New approval password<br>'
    '<input type="password" name="new" autocomplete="new-password" '
    'style="font:inherit;padding:.4rem;width:20rem"></label></p>'
    '<p><label>Again<br>'
    '<input type="password" name="again" autocomplete="new-password" '
    'style="font:inherit;padding:.4rem;width:20rem"></label></p>'
)


async def _password_page(_request: Request) -> Response:
    """Where a person sets or changes the approval password.

    An operator agent cannot set it — that is the whole point — but it CAN ask
    for this page to be worth opening, which is what `approval_enrol` does.
    Three states, and the page says which one it is in rather than offering
    something that will be refused.
    """
    if approver.pinned_by_deployment():
        return _page(
            "Approval password",
            "<h1>Approval password</h1><p>This gateway's approval password is pinned "
            "by its deployment, so it cannot be changed from here. Change it where "
            "the configuration is kept.</p>",
        )
    if approver.enrolling():
        return _page(
            "Set the approval password",
            "<h1>Set the approval password</h1>"
            "<p>This gateway has no approval password yet, and an agent has asked for "
            "one to be set. Choose it here. Afterwards it is what you will be asked "
            f"for whenever an agent proposes a change only a person should agree to.</p>"
            f'<form method="post" action="{html.escape(ENROL_PATH)}">'
            f"{_CODE_FIELD}{_SET_FORM}"
            f'<button style="{_BUTTON}">Set password</button></form>'
            f"<p style='color:#555'>The code came back to the agent that asked for this "
            f"page. At least {approver.MIN_PASSWORD_CHARS} characters. Nothing else can "
            "be approved on this gateway until it is set.</p>",
        )
    return _page(
        "Change the approval password",
        "<h1>Change the approval password</h1>"
        "<p>Enter the current password to change it.</p>"
        f'<form method="post" action="{html.escape(ENROL_PATH)}">'
        "<p><label>Current password<br>"
        '<input type="password" name="password" autocomplete="current-password" '
        'style="font:inherit;padding:.4rem;width:20rem"></label></p>'
        f"{_SET_FORM}"
        f'<button style="{_BUTTON}">Change password</button></form>',
    )


async def _set_password(request: Request) -> Response:
    """Set or change it. Fail-closed on every path that is not clearly allowed."""
    form = await request.form()
    new = str(form.get("new") or "")
    if new != str(form.get("again") or ""):
        return _page("Not set", "<p>Those did not match. Nothing was changed.</p>", 400)

    if approver.pinned_by_deployment():
        return _page("Not set", f"<p>{_NOTHING}</p>", HTTPStatus.NOT_FOUND)
    # Enrolling needs the code from the window the operator opened; changing an
    # existing password needs the current one. A wrong code, a wrong current
    # password and a closed window all answer the same: none says which it was.
    enrolling = approver.enrolling(str(form.get("code") or ""))
    if not enrolling and not await asyncio.to_thread(
        approver.verify, str(form.get("password") or "")
    ):
        logger.info("approval: a password change was not authorised")
        return _page("Not set", f"<p>{_NOTHING}</p>", HTTPStatus.NOT_FOUND)
    try:
        # Deriving the verifier is the same cost as checking one, plus a write.
        await asyncio.to_thread(approver.set_password, new)
    except ValueError as exc:
        # Its own message names the rule, never the password.
        return _page("Not set", f"<p>{html.escape(str(exc))}</p>", 400)
    except OSError as exc:
        logger.warning("approval: the password could not be stored err=%s", exc_kind(exc))
        return _page("Not set", "<p>It could not be stored. Nothing was changed.</p>", 500)
    approver.close_enrolment()
    return _page(
        "Password set",
        "<p>Set. This is what you will be asked for when an agent proposes a change "
        "only a person should agree to.</p>",
    )
