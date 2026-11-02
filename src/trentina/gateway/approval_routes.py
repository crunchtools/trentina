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
a person meets one idiom on this gateway rather than three. ``page`` is that
idiom: the sheet, the mark, and the host this was reached on, which is what
tells two gateways' passwords apart. No script, no external reference, and no
form action but its own path.
"""

from __future__ import annotations

import asyncio
import html
import logging
from http import HTTPStatus
from typing import TYPE_CHECKING, Any

from starlette.responses import HTMLResponse, Response

from ..logsafe import exc_kind
from . import approver, page, pending

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

#: One password operation at a time, refusing rather than queueing. A KDF is
#: expensive by design, so a queue of them is the attack and not the defence —
#: and the pool it queues on is the default executor, which L1 and the
#: tokenizer share. Holding it across the whole check-then-set also makes
#: enrolment atomic (see ``_authorised_set``).
_PASSWORD_WORK = asyncio.Semaphore(1)

# Nothing on this page runs, nothing it shows is fetched, and the one form on
# it posts to this gateway or nowhere.
_HEADERS = {**page.headers("form-action 'self'"), "X-Frame-Options": "DENY"}

#: One wording for a wrong password and for a right one with nothing staged. A
#: visitor who guesses learns neither whether the password was right nor
#: whether this gateway has anything pending.
_NOTHING = (
    "Nothing to approve. If you were expecting something, check with the agent "
    "that proposed it and try again."
)


def _page(request: Request, title: str, body: str, status: int = 200) -> Response:
    """A small fixed page. ``body`` is HTML built from escaped values."""
    document = page.render(title, body, host=page.served_as(request))
    return HTMLResponse(document, status_code=status, headers=_HEADERS)


def _facts_table(facts: dict[str, str]) -> str:
    rows = "".join(
        f"<tr><th>{html.escape(label)}</th><td><code>{html.escape(value)}</code></td></tr>"
        for label, value in facts.items()
    )
    return f"<table>{rows}</table>"


def _review(
    request: Request,
    password: str,
    staged: dict[pending.Kind, dict[str, str]],
    *,
    swapped: bool = False,
) -> Response:
    """What is staged, with the password carried forward for the decision.

    Each form also carries a fingerprint of the facts rendered above it, so the
    decision that comes back names the PROPOSAL and not merely its kind. The
    agent stages when it likes and staging replaces silently; without this, it
    could let a person read one proposal and have their click apply the next
    one (see ``pending.approve``).
    """
    sections = "".join(
        f"<h2>{html.escape(kind.value)}</h2>"
        f"{_facts_table(facts)}"
        f'<form method="post" action="{html.escape(PATH)}">'
        f'<input type="hidden" name="password" value="{html.escape(password)}">'
        f'<input type="hidden" name="kind" value="{html.escape(kind.value)}">'
        f'<input type="hidden" name="facts" value="{html.escape(pending.digest_of(facts))}">'
        '<button name="decision" value="approve">Approve</button> '
        '<button name="decision" value="decline">Decline</button>'
        "</form>"
        for kind, facts in staged.items()
    )
    warning = (
        "<p class='note'><strong>Nothing was applied.</strong> What you agreed to is "
        "not what is staged now — the agent replaced its proposal after this page "
        "was drawn. Read what is below before deciding again, and if you did not "
        "expect it to change, decline it.</p>"
        if swapped
        else ""
    )
    return _page(
        request,
        "Approve a change",
        f"<h1>Approve this change?</h1><p>Nothing has changed yet.</p>{warning}{sections}"
        "<p class='note'>Each of these expires on its own if you do nothing. "
        "If you did not expect it, decline it.</p>",
    )


async def _show(request: Request) -> Response:
    """The first page: a password field, and no statement about what is staged.

    It does not say whether anything is pending, so an unauthenticated visitor
    learns nothing about this gateway — not even that it has an agent asking
    for something.
    """
    return _page(
        request,
        "Approve a change",
        "<h1>Approve a change</h1>"
        "<p>An agent on this gateway may be asking to change something only a "
        "person should agree to. Enter the approval password to see it.</p>"
        f'<form method="post" action="{html.escape(PATH)}">'
        "<label>Approval password"
        '<input type="password" name="password" autocomplete="current-password"></label>'
        "<button>Continue</button>"
        "</form>",
    )


#: Spread into `_page` at every site that refuses, so the five of them are one
#: answer rather than five that could drift apart. That they are identical is
#: the property: a wrong password, a guessed kind and an idle gateway must be
#: indistinguishable.
_NOTHING_PAGE = ("Nothing to approve", f"<p>{_NOTHING}</p>", HTTPStatus.NOT_FOUND)

#: Someone else's password operation is in flight. Said rather than queued: a
#: KDF is expensive by design, so a queue of them starves the gateway instead
#: of being fair to anyone.
_BUSY_PAGE = (
    "Busy",
    "<p>Another password attempt is in flight. Try again in a moment.</p>",
    HTTPStatus.SERVICE_UNAVAILABLE,
)


async def _act(
    request: Request, kind: pending.Kind, decision: str, facts_digest: str, password: str
) -> Response:
    """Carry out a decision a verified person made.

    ``facts_digest`` is what the review page showed them. A decline needs none:
    dropping whatever is staged of that kind is what a person who did not
    expect it wants, whichever proposal is sitting there now.
    """
    if decision == "decline":
        return (
            _page(request, "Declined", "<p>Declined. Nothing was changed.</p>")
            if pending.decline(kind)
            else _page(request, *_NOTHING_PAGE)
        )
    try:
        await pending.approve(kind, facts_digest)
    except pending.PendingError:
        # This person has already proved they hold the password, so the
        # "learn nothing" rule has done its job and showing them the current
        # proposal tells an attacker nothing new. Answering _NOTHING_PAGE here
        # hid the one thing they most need to know: what they agreed to is not
        # what is staged. Re-render, and let them read it and decide again.
        staged = pending.outstanding()
        return (
            _review(request, password, staged, swapped=True)
            if staged
            else _page(request, *_NOTHING_PAGE)
        )
    except Exception as exc:
        # The action's own failure. It reports the detail to the agent that
        # staged it; a person is told it did not happen, never the exception
        # (#262).
        logger.warning("approval: applying refused err=%s", exc_kind(exc))
        return _page(
            request,
            "Not applied",
            "<p>Approved, but the change could not be applied, so nothing was "
            "changed. The agent that proposed it has the reason.</p>",
            HTTPStatus.INTERNAL_SERVER_ERROR,
        )
    return _page(request, "Approved", "<p>Approved and applied. You can close this tab.</p>")


async def _decide(request: Request) -> Response:
    form = await request.form()
    password = str(form.get("password") or "")
    if _PASSWORD_WORK.locked():
        return _page(request, *_BUSY_PAGE)
    # scrypt is deliberately expensive — ~16 MiB and tens of milliseconds — so
    # it runs in a worker, bounded. On the loop it would stall every other
    # profile's request for the duration of a stranger's password guess.
    async with _PASSWORD_WORK:
        verified = await asyncio.to_thread(approver.verify, password)
    if not verified:
        # A wrong password and a right one with nothing staged answer the same.
        logger.info("approval: a visitor did not present a valid approval password")
        return _page(request, *_NOTHING_PAGE)

    staged = pending.outstanding()
    kind = pending.kind_named(str(form.get("kind") or ""))
    decision = str(form.get("decision") or "")
    if kind is None or decision not in ("approve", "decline"):
        return _review(request, password, staged) if staged else _page(request, *_NOTHING_PAGE)
    return await _act(request, kind, decision, str(form.get("facts") or ""), password)


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


_CODE_FIELD = '<label>Enrolment code<input name="code" autocomplete="off"></label>'

_CURRENT_FIELD = (
    "<label>Current approval password"
    '<input type="password" name="password" autocomplete="current-password"></label>'
)

_SET_FORM = (
    "<label>New approval password"
    '<input type="password" name="new" autocomplete="new-password"></label>'
    '<label>Again<input type="password" name="again" autocomplete="new-password"></label>'
)


async def _password_page(request: Request) -> Response:
    """Where a person sets or changes the approval password.

    An operator agent cannot set it — that is the whole point — but it CAN ask
    for this page to be worth opening, which is what `approval_enrol` does.
    Three states, and the page says which one it is in rather than offering
    something that will be refused.
    """
    if approver.pinned_by_deployment():
        return _page(
            request,
            "Approval password",
            "<h1>Approval password</h1><p>This gateway's approval password is pinned "
            "by its deployment, so it cannot be changed from here. Change it where "
            "the configuration is kept.</p>",
        )
    if approver.enrolling():
        return _page(
            request,
            "Set the approval password",
            "<h1>Set the approval password</h1>"
            "<p>This gateway has no approval password yet, and an agent has asked for "
            "one to be set. Choose it here. Afterwards it is what you will be asked "
            "for whenever an agent proposes a change only a person should agree to.</p>"
            f'<form method="post" action="{html.escape(ENROL_PATH)}">'
            f"{_CODE_FIELD}{_SET_FORM}"
            "<button>Set password</button></form>"
            f"<p class='note'>The code came back to the agent that asked for this "
            f"page. At least {approver.MIN_PASSWORD_CHARS} characters. Nothing else can "
            "be approved on this gateway until it is set.</p>",
        )
    # Both fields, because this is also what a person meets when the window
    # has CLOSED behind them. Offering only the current password there is a
    # trap: a gateway with no password has none to enter, the refusal is
    # deliberately silent, and they are left retyping a field that cannot
    # work. With the code field present the agent can open a fresh window
    # while they sit on the page. It discloses nothing: which field was
    # accepted, which was wrong, and which state this gateway is in all
    # answer identically.
    return _page(
        request,
        "Set the approval password",
        "<h1>Set the approval password</h1>"
        "<p>Enter the current approval password, if this gateway has one. If an "
        "agent gave you an enrolment code instead, enter that.</p>"
        f'<form method="post" action="{html.escape(ENROL_PATH)}">'
        f"{_CURRENT_FIELD}{_CODE_FIELD}{_SET_FORM}"
        "<button>Set password</button></form>"
        f"<p class='note'>At least {approver.MIN_PASSWORD_CHARS} characters. An "
        "enrolment code only works while the window the agent opened is still "
        "open; ask it to open another if this is refused.</p>",
    )


async def _authorised_set(request: Request, code: str, current: str, new: str) -> Response | None:
    """Authorise and perform a password change, or return the refusal.

    One critical section, held across the authorisation AND the write, so two
    requests that both saw an open enrolment window cannot both set a password
    with the later silently replacing the first. Enrolling needs the code from
    the window the operator opened; changing an existing password needs the
    current one. A wrong code, a wrong current password and a closed window all
    answer the same: none says which it was.

    Returns None when the password was set.
    """
    async with _PASSWORD_WORK:
        if not approver.enrolling(code) and not await asyncio.to_thread(approver.verify, current):
            logger.info("approval: a password change was not authorised")
            return _page(request, "Not set", f"<p>{_NOTHING}</p>", HTTPStatus.NOT_FOUND)
        # Deriving the verifier is the same cost as checking one, plus a write.
        await asyncio.to_thread(approver.set_password, new)
        approver.close_enrolment()
    return None


async def _set_password(request: Request) -> Response:
    """Set or change it. Fail-closed on every path that is not clearly allowed."""
    form = await request.form()
    new = str(form.get("new") or "")
    if new != str(form.get("again") or ""):
        return _page(request, "Not set", "<p>Those did not match. Nothing was changed.</p>", 400)
    if approver.pinned_by_deployment():
        return _page(request, "Not set", f"<p>{_NOTHING}</p>", HTTPStatus.NOT_FOUND)
    if _PASSWORD_WORK.locked():
        return _page(request, *_BUSY_PAGE)
    try:
        refused = await _authorised_set(
            request, str(form.get("code") or ""), str(form.get("password") or ""), new
        )
    except ValueError as exc:
        # Its own message names the rule, never the password.
        return _page(request, "Not set", f"<p>{html.escape(str(exc))}</p>", 400)
    except OSError as exc:
        logger.warning("approval: the password could not be stored err=%s", exc_kind(exc))
        return _page(request, "Not set", "<p>It could not be stored. Nothing changed.</p>", 500)
    return refused or _page(
        request,
        "Password set",
        "<p>Set. This is what you will be asked for when an agent proposes a change "
        "only a person should agree to.</p>",
    )
