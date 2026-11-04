"""The pages a person approves a staged action on (#637), and signs in to (#639).

``pending`` holds what is staged, ``approver`` decides who may approve, and
this is the only way a human reaches either.

1. ``/approve`` signed out asks a person to sign in — a passkey, or the
   password — and says nothing else: not even whether anything is pending, so
   an unauthenticated visitor learns nothing about this gateway.
2. Signed in, it shows what is staged and an Approve/Decline per action.
3. ``/approve/setup`` is where a person enrols the first passkey or password
   (with the code the operator's ``approval_enrol`` returned), and later adds a
   passkey, changes or drops the password, or removes a passkey.

**A session, not a reflected password (#639).** Until 6.5.0 the decision POST
carried the password, so the review page wrote it back into a hidden field —
into the DOM, form history and any shared screen. Now a sign-in issues a short
server-side session (``approval_session``); the secret is presented once and
never written into a page. Every form carries the session's CSRF token, the
cookie is SameSite=Strict, and a POST from another origin is refused.

**Every unauthenticated failure is one answer.** A wrong password, an unknown
passkey, a bad signature, a spent challenge, a missing session: one status, one
body, one set of headers, and no cookie. Once a person HAS signed in, the page
may tell them nothing is waiting — they are who it is for.

There is no capability token anywhere, and that is the point. The first cut of
#637 handed the staging agent a link that approved; the agent reads its own
tool result. The only thing that may stand between a staged action and its
application is something the agent cannot read or answer: a password a person
holds, or a passkey a person unlocks.

Modelled on ``backend_oauth``'s pages, so a person meets one idiom on this
gateway. One fixed script runs here, for the passkey ceremony, allowed by its
hash; without it the password path still works.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import html
import json
import logging
import secrets
import time
from http import HTTPStatus
from pathlib import Path
from typing import TYPE_CHECKING, Any, NamedTuple
from urllib.parse import urlsplit

from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse, Response

from ..logsafe import exc_kind
from . import approval_session, approver, page, pending, webauthn

if TYPE_CHECKING:
    from starlette.requests import Request

logger = logging.getLogger(__name__)

#: Defined in ``pending``, so a tool can name the page without importing a
#: route module. Re-exported under the names this module reads best with.
PATH = pending.PAGE_PATH
SETUP_PATH = pending.ENROL_PATH
#: Where the password page lived through 6.4; a bookmark to it still lands.
OLD_ENROL_PATH = "/approve/password"
SIGN_OUT_PATH = "/approve/signout"
BEGIN_PATH = "/approve/webauthn/begin"
FINISH_PATH = "/approve/webauthn/finish"

#: Tighter than the OAuth pages'. A person approves a handful of things ever,
#: and this route gates who holds root, so the limit is also what bounds a
#: guess at the password. It covers only the requests that TEST something — a
#: password, a passkey assertion, an enrolment code — and the decisions posted
#: beside them.
PAGE_LIMIT = (10, 30)

#: Everything else: drawing a page, asking for a challenge, signing out. A
#: passkey sign-in and one decision is five requests, so one bucket for both
#: would leave a person locked out of their own page for minutes after an
#: ordinary visit. Looser, still per address, still bounded. A challenge is
#: worth nothing without a passkey to answer it, and the pool evicts its oldest.
BROWSE_LIMIT = (60, 600)

#: Nothing on the forms needs a body: a password and a few short fields. The
#: passkey JSON carries client data, authenticator data and a key or a
#: signature, base64url, all bounded in ``webauthn``.
MAX_BODY_BYTES = 4096
MAX_CEREMONY_BYTES = 16384

#: One password operation at a time, refusing rather than queueing. A KDF is
#: expensive by design, so a queue of them is the attack and not the defence —
#: and the pool it queues on is the default executor, which L1 and the
#: tokenizer share. Holding it across the whole check-then-set also makes
#: enrolment atomic (see ``_enrol_password``).
_PASSWORD_WORK = asyncio.Semaphore(1)

#: Where a sign-in may send a person on. A closed set, so a crafted ``next``
#: is never a redirect anywhere else.
_NEXT = (PATH, SETUP_PATH)

#: What a finished change says at the top of the setup page. Keyed by a
#: closed set of names in the query string, never echoed.
_DONE = {
    "passkey_added": "Passkey added. You can use it to approve from now on.",
    "passkey_removed": "Passkey removed. Anyone signed in with it has been signed out.",
    "password_set": "Password set.",
    "password_removed": "Password removed. Approving now takes a passkey.",
}

# approval_page.js, the ceremony: base64url helpers, the code from the link's fragment (which
# never reaches the server, and is cleared from the address bar), the session
# countdown, and navigator.credentials. Every value it needs arrives through
# escaped data- attributes; nothing in it is built per request, so its hash is
# fixed and the policy allows exactly it.
_SCRIPT = (Path(__file__).parent / "approval_page.js").read_text(encoding="utf-8")

_SCRIPT_HASH = base64.b64encode(hashlib.sha256(_SCRIPT.encode("utf-8")).digest()).decode()

# Nothing on this page is fetched, the one script that runs is the one above,
# it talks only to this origin, and the forms post here or nowhere.
_HEADERS = {
    **page.headers(
        "form-action 'self'", f"script-src 'sha256-{_SCRIPT_HASH}'", "connect-src 'self'"
    ),
    "X-Frame-Options": "DENY",
}

#: One wording for every unauthenticated failure. A visitor who guesses learns
#: neither whether the password was right nor whether this gateway has anything
#: pending.
_NOTHING = (
    "Nothing to approve. If you were expecting something, check with the agent "
    "that proposed it and try again."
)

#: Spread into `_page` at every site that refuses an unauthenticated visitor,
#: so they are one answer rather than several that could drift apart.
_NOTHING_PAGE = ("Nothing to approve", f"<p>{_NOTHING}</p>", HTTPStatus.NOT_FOUND)

#: The JSON routes' one answer to the same visitor.
_NOTHING_JSON = {"ok": False, "message": "That did not work. Try again."}

#: Someone else's password operation is in flight. Said rather than queued: a
#: KDF is expensive by design, so a queue of them starves the gateway instead
#: of being fair to anyone.
_BUSY_PAGE = (
    "Busy",
    "<p>Another password attempt is in flight. Try again in a moment.</p>",
    HTTPStatus.SERVICE_UNAVAILABLE,
)


def _footer(session: approval_session.Session | None) -> str:
    if session is None:
        return ""
    seconds = approval_session.remaining(session)
    return (
        '<footer><span class="who">Signed in · '
        f'<span id="ttl" data-seconds="{seconds}">{seconds // 60}:{seconds % 60:02d}</span>'
        " left</span>"
        f'<a href="{PATH}">Approvals</a>'
        f'<a href="{SETUP_PATH}">Manage sign-in</a>'
        f'<form method="post" action="{SIGN_OUT_PATH}">'
        f'<input type="hidden" name="csrf" value="{html.escape(session.csrf)}">'
        "<button>Sign out</button></form></footer>"
    )


def _page(
    request: Request,
    title: str,
    body: str,
    status: int = 200,
    *,
    session: approval_session.Session | None = None,
) -> Response:
    """A small fixed page. ``body`` is HTML built from escaped values."""
    document = page.render(
        title, body + _footer(session), host=page.served_as(request), script=_SCRIPT
    )
    return HTMLResponse(document, status_code=status, headers=_HEADERS)


def _next(value: object, default: str = PATH) -> str:
    return value if isinstance(value, str) and value in _NEXT else default


def _same_origin(request: Request, *, required: bool) -> bool:
    """Whether a POST came from a page this gateway served.

    The cookie is SameSite=Strict and every form carries a CSRF token; this is
    the third leg. A form POST from a browser old enough to send no Origin
    passes on the other two; the JSON routes are reached only by ``fetch``,
    which always sends one, so there it is required.
    """
    origin = request.headers.get("origin")
    if origin is None:
        return not required
    try:
        parts = urlsplit(origin)
    except ValueError:
        # e.g. "https://[": malformed, so not ours.
        return False
    host = (request.headers.get("host") or "").lower()
    return bool(host) and parts.scheme in ("http", "https") and parts.netloc.lower() == host


def _audit_change(what: str) -> None:
    """One audit row per change to who may approve, like an approved apply.

    ``what`` is fixed text plus at most a credential digest: never an id, an
    rpId or an origin, which are strings a browser chose.
    """
    from ..outcomes import Outcome
    from .audit import _audit
    from .service import service_profile

    _audit(service_profile().name, "internal://approval", "approver", Outcome.OK, 0, what)


def _signin_body(next_path: str, *, confirm: bool) -> str:
    """Sign in with a passkey first, the password tucked underneath."""
    lead = (
        "<p class='lead'>Confirm it is you before changing how approval works.</p>"
        if confirm
        else "<p class='lead'>An agent on this gateway may be asking to change something "
        "only a person should agree to. Sign in to see it.</p>"
    )
    return (
        f"{lead}"
        f'<div id="pk" data-ceremony="signin" data-next="{html.escape(next_path)}" '
        f'data-begin="{BEGIN_PATH}" data-finish="{FINISH_PATH}">'
        '<div class="actions"><button id="pk-go" class="wide" type="button">'
        "Sign in with a passkey</button></div>"
        '<p id="pk-status" class="status" role="status"></p></div>'
        "<details><summary>Use the approval password instead</summary>"
        f'<form method="post" action="{PATH}">'
        f'<input type="hidden" name="next" value="{html.escape(next_path)}">'
        "<label>Approval password"
        '<input type="password" name="password" autocomplete="current-password"></label>'
        '<div class="actions"><button>Sign in</button></div></form></details>'
    )


def _facts_table(facts: dict[str, str]) -> str:
    rows = "".join(
        f"<tr><th>{html.escape(label)}</th><td><code>{html.escape(value)}</code></td></tr>"
        for label, value in facts.items()
    )
    return f"<table>{rows}</table>"


def _review(
    request: Request,
    session: approval_session.Session,
    staged: dict[pending.Kind, dict[str, str]],
    *,
    swapped: bool = False,
) -> Response:
    """What is staged, each with its decision form.

    Each form carries a fingerprint of the facts rendered above it, so the
    decision that comes back names the PROPOSAL and not merely its kind. The
    agent stages when it likes and staging replaces silently; without this, it
    could let a person read one proposal and have their click apply the next
    one (see ``pending.approve``).
    """
    csrf = html.escape(session.csrf)
    sections = "".join(
        f"<h2>{html.escape(kind.value.capitalize())}</h2>"
        f"{_facts_table(facts)}"
        f'<form method="post" action="{html.escape(PATH)}">'
        f'<input type="hidden" name="csrf" value="{csrf}">'
        f'<input type="hidden" name="kind" value="{html.escape(kind.value)}">'
        f'<input type="hidden" name="facts" value="{html.escape(pending.digest_of(facts))}">'
        '<div class="actions"><button name="decision" value="approve">Approve</button>'
        '<button name="decision" value="decline">Decline</button></div>'
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
        session=session,
    )


#: What a signed-in person sees when no agent is asking for anything.
_IDLE_PAGE = (
    "Nothing waiting",
    (
        "<h1>Nothing is waiting</h1><p>No agent on this gateway is asking for anything "
        "right now. When one does, it will give you this link again.</p>"
    ),
)


async def _show(request: Request) -> Response:
    """Signed out: sign in, and no statement about what is staged."""
    session = approval_session.current(request)
    if session is None:
        return _page(
            request,
            "Approve a change",
            "<h1>Approve a change</h1>" + _signin_body(PATH, confirm=False),
        )
    staged = pending.outstanding()
    return (
        _review(request, session, staged)
        if staged
        else _page(request, *_IDLE_PAGE, session=session)
    )


def _signed_in(request: Request, method: str, target: str, *, as_json: bool) -> Response:
    """Start a session, ending whatever this browser held before."""
    approval_session.end(approval_session.token_of(request))
    token = approval_session.start(method)
    response = (
        JSONResponse({"ok": True, "next": target}, headers=_HEADERS)
        if as_json
        else RedirectResponse(target, HTTPStatus.SEE_OTHER, headers=_HEADERS)
    )
    approval_session.set_cookie(response, request, token)
    return response


async def _password_sign_in(request: Request, form: Any) -> Response:
    if _PASSWORD_WORK.locked():
        return _page(request, *_BUSY_PAGE)
    # scrypt is deliberately expensive — ~16 MiB and tens of milliseconds — so
    # it runs in a worker, bounded. On the loop it would stall every other
    # profile's request for the duration of a stranger's password guess.
    async with _PASSWORD_WORK:
        verified = await asyncio.to_thread(approver.verify, str(form.get("password") or ""))
    if not verified:
        logger.info("approval: a visitor did not present a valid approval password")
        return _page(request, *_NOTHING_PAGE)
    return _signed_in(request, "password", _next(form.get("next")), as_json=False)


async def _act(
    request: Request,
    session: approval_session.Session,
    kind: pending.Kind,
    decision: str,
    facts_digest: str,
) -> Response:
    """Carry out a decision a signed-in person made.

    ``facts_digest`` is what the review page showed them. A decline needs none:
    dropping whatever is staged of that kind is what a person who did not
    expect it wants, whichever proposal is sitting there now.
    """
    if decision == "decline":
        if pending.decline(kind):
            return _page(
                request, "Declined", "<p>Declined. Nothing was changed.</p>", session=session
            )
        return _page(request, *_IDLE_PAGE, session=session)
    try:
        await pending.approve(kind, facts_digest)
    except pending.PendingError:
        # They are signed in, so showing the current proposal tells nobody
        # anything new, and it is the one thing they most need: what they
        # agreed to is not what is staged. Re-render, and let them decide again.
        staged = pending.outstanding()
        return (
            _review(request, session, staged, swapped=True)
            if staged
            else _page(request, *_IDLE_PAGE, session=session)
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
            session=session,
        )
    return _page(
        request,
        "Approved",
        "<p>Approved and applied. You can close this tab.</p>",
        session=session,
    )


async def _decide(request: Request) -> Response:
    if not _same_origin(request, required=False):
        return _page(request, *_NOTHING_PAGE)
    form = await request.form()
    if "password" in form:
        return await _password_sign_in(request, form)
    session = approval_session.current(request)
    if session is None or not approval_session.csrf_ok(session, form.get("csrf")):
        return _page(request, *_NOTHING_PAGE)
    staged = pending.outstanding()
    kind = pending.kind_named(str(form.get("kind") or ""))
    decision = str(form.get("decision") or "")
    if kind is None or decision not in ("approve", "decline"):
        return (
            _review(request, session, staged)
            if staged
            else _page(request, *_IDLE_PAGE, session=session)
        )
    return await _act(request, session, kind, decision, str(form.get("facts") or ""))


async def _sign_out(request: Request) -> Response:
    """Sign out. Needs no token: ending a session is never what an attacker wants."""
    approval_session.end(approval_session.token_of(request))
    response = RedirectResponse(PATH, HTTPStatus.SEE_OTHER, headers=_HEADERS)
    approval_session.clear_cookie(response, request)
    return response


async def _legacy(_request: Request) -> Response:
    return RedirectResponse(SETUP_PATH, HTTPStatus.SEE_OTHER, headers=_HEADERS)


# --- /approve/setup ---------------------------------------------------------

_NEW_FIELDS = (
    "<label>New password"
    f'<span class="hint">At least {approver.MIN_PASSWORD_CHARS} characters</span>'
    '<input type="password" name="new" autocomplete="new-password"></label>'
    "<label>Type it again"
    '<input type="password" name="again" autocomplete="new-password"></label>'
)


def _register_box(*, csrf: str = "", with_code: bool = False, label: str) -> str:
    """The passkey ceremony's markup: a name beside the button that starts it."""
    code = (
        '<label for="pk-code">Enrolment code'
        '<span class="hint">Filled in for you when you came from your agent\'s link</span>'
        '<input id="pk-code" name="code" autocomplete="off" spellcheck="false"></label>'
        if with_code
        else ""
    )
    return (
        f'<div id="pk" data-ceremony="register" data-csrf="{html.escape(csrf)}" '
        f'data-begin="{BEGIN_PATH}" data-finish="{FINISH_PATH}">'
        f"{code}"
        '<label for="pk-name">Name this passkey'
        '<span class="hint">So you can tell your devices apart later</span></label>'
        '<div class="row"><input id="pk-name" maxlength="40" placeholder="Laptop" '
        'autocomplete="off">'
        f'<button id="pk-go" type="button">{html.escape(label)}</button></div>'
        '<p id="pk-status" class="status" role="status"></p></div>'
    )


def _enrol_body() -> str:
    return (
        "<h1>Set up approval</h1>"
        "<p class='lead'>An agent on this gateway asked for a way for you to approve its "
        "changes. Create a passkey: your device keeps the secret, and this gateway "
        "keeps only a public key.</p>"
        f"{_register_box(with_code=True, label='Create passkey')}"
        "<details><summary>Set a password instead</summary>"
        f'<form method="post" action="{SETUP_PATH}">'
        '<input type="hidden" name="action" value="enrol_password">'
        '<label>Enrolment code<input name="code" autocomplete="off" spellcheck="false"></label>'
        f'{_NEW_FIELDS}<div class="actions"><button>Set password</button></div></form>'
        "</details>"
        "<p class='note'>This page works only while the window your agent opened is "
        "still open. Nothing can be approved on this gateway until it is done.</p>"
    )


def _unconfigured_body() -> str:
    return (
        "<h1>Set up approval</h1>"
        "<p>No one can approve changes on this gateway yet. Ask its agent:</p>"
        "<p class='lead'><em>“Let me set my passkey in Trentina.”</em></p>"
        "<p class='note'>It opens a short window and gives you a link back here with the "
        "code filled in.</p>"
    )


def _when(stamp: object) -> str:
    if not isinstance(stamp, int) or stamp <= 0:
        return ""
    moment = time.gmtime(stamp)
    return f"{moment.tm_mday} {time.strftime('%b %Y', moment)}"


def _passkey_list(keys: list[dict[str, Any]], csrf: str) -> str:
    items = []
    for key in keys:
        used = _when(key["last_used"])
        meta = f"Added {_when(key['created'])} · " + (
            f"last used {used}" if used else "not used yet"
        )
        items.append(
            f"<li><div><strong>{html.escape(str(key['name']))}</strong>"
            f'<span class="meta">{html.escape(meta)}</span></div>'
            f'<form method="post" action="{SETUP_PATH}">'
            f'<input type="hidden" name="csrf" value="{csrf}">'
            '<input type="hidden" name="action" value="remove_passkey">'
            f'<input type="hidden" name="id" value="{html.escape(str(key["id"]))}">'
            '<button class="quiet">Remove</button></form></li>'
        )
    return f'<ul class="keys">{"".join(items)}</ul>'


_PINNED_NOTE = (
    "<p class='note'>The password is pinned by this gateway's deployment, so it "
    "is changed where the configuration is kept, not here.</p>"
)


def _password_section(csrf: str, *, has_keys: bool) -> str:
    has = approver.has_password()
    lead = (
        "<p class='note'>A fallback for a browser that cannot use your passkey.</p>"
        if not has
        else ""
    )
    remove = (
        f'<form method="post" action="{SETUP_PATH}">'
        f'<input type="hidden" name="csrf" value="{csrf}">'
        '<input type="hidden" name="action" value="remove_password">'
        '<div class="actions"><button class="quiet">'
        "Remove the password and use passkeys only</button></div></form>"
        if has and has_keys
        else ""
    )
    return (
        f"{lead}"
        f'<form method="post" action="{SETUP_PATH}">'
        f'<input type="hidden" name="csrf" value="{csrf}">'
        '<input type="hidden" name="action" value="set_password">'
        f"{_NEW_FIELDS}"
        f'<div class="actions"><button>{"Change password" if has else "Set password"}'
        f"</button></div></form>{remove}"
    )


def _manage_body(session: approval_session.Session, done: str | None) -> str:
    csrf = html.escape(session.csrf)
    keys = approver.passkeys()
    notice = f"<p class='done' role='status'>{html.escape(_DONE[done])}</p>" if done else ""
    listing = _passkey_list(keys, csrf) if keys else "<p class='note'>None yet.</p>"
    password_part = (
        _PINNED_NOTE
        if approver.pinned_by_deployment()
        else _password_section(csrf, has_keys=bool(keys))
    )
    return (
        f"<h1>Sign-in for approvals</h1>{notice}"
        "<p class='note'>How you prove it is you when an agent asks for a change.</p>"
        f"<section><h2>Passkeys</h2>{listing}"
        f"{_register_box(csrf=session.csrf, label='Add passkey')}</section>"
        f"<section><h2>Password</h2>{password_part}</section>"
    )


async def _setup(request: Request) -> Response:
    """Enrol, sign in to manage, or manage — whichever this gateway is ready for."""
    title = "Set up approval"
    if approver.enrolling():
        return _page(request, title, _enrol_body())
    if not approver.configured():
        return _page(request, title, _unconfigured_body())
    session = approval_session.current(request)
    if session is None or not approval_session.fresh(session):
        return _page(
            request,
            "Sign in",
            "<h1>Sign-in for approvals</h1>" + _signin_body(SETUP_PATH, confirm=True),
            session=session,
        )
    done = request.query_params.get("done")
    return _page(
        request,
        "Sign-in for approvals",
        _manage_body(session, done if done in _DONE else None),
        session=session,
    )


async def _enrol_password(request: Request, form: Any) -> Response:
    """The first password, through the window the operator opened.

    One critical section held across the authorisation AND the write, so two
    requests that both saw an open window cannot both set a password with the
    later silently replacing the first. A wrong code and a closed window answer
    the same.
    """
    new = str(form.get("new") or "")
    if new != str(form.get("again") or ""):
        return _page(request, "Not set", "<p>Those did not match. Nothing was changed.</p>", 400)
    if _PASSWORD_WORK.locked():
        return _page(request, *_BUSY_PAGE)
    async with _PASSWORD_WORK:
        if not approver.enrolling(str(form.get("code") or "")):
            logger.info("approval: an enrolment was not authorised")
            return _page(request, *_NOTHING_PAGE)
        try:
            await asyncio.to_thread(approver.set_password, new)
        except ValueError as exc:
            return _page(request, "Not set", f"<p>{html.escape(str(exc))}</p>", 400)
        approver.close_enrolment()
    _audit_change("approval password enrolled")
    return _signed_in(request, "password", f"{SETUP_PATH}?done=password_set", as_json=False)


class _BusyError(Exception):
    """Another password operation holds ``_PASSWORD_WORK``."""


async def _apply_change(form: Any, action: str) -> tuple[str, str]:
    """Make one change; returns its audit wording and its ``_DONE`` key.

    Raises ``ApproverError``/``ValueError`` with text a person may read, never
    the input, and ``LookupError`` for an action that does not exist.
    """
    if action == "set_password":
        new = str(form.get("new") or "")
        if new != str(form.get("again") or ""):
            raise ValueError("Those did not match. Nothing was changed.")
        if _PASSWORD_WORK.locked():
            raise _BusyError
        async with _PASSWORD_WORK:
            await asyncio.to_thread(approver.set_password, new)
        return "approval password changed", "password_set"
    if action == "remove_password":
        await asyncio.to_thread(approver.remove_password)
        return "approval password removed", "password_removed"
    if action == "remove_passkey":
        cred_id = str(form.get("id") or "")
        await asyncio.to_thread(approver.remove_passkey, cred_id)
        return f"passkey removed {approver.credential_digest(cred_id)}", "passkey_removed"
    raise LookupError(action)


async def _change(request: Request, form: Any, action: str) -> Response:
    """A change to how approval works, by someone signed in recently."""
    token = approval_session.token_of(request)
    session = approval_session.current(request)
    if (
        session is None
        or not approval_session.fresh(session)
        or not approval_session.csrf_ok(session, form.get("csrf"))
    ):
        return _page(request, *_NOTHING_PAGE)
    try:
        what, done = await _apply_change(form, action)
    except LookupError:
        return _page(request, *_NOTHING_PAGE)
    except _BusyError:
        return _page(request, *_BUSY_PAGE)
    except (approver.ApproverError, ValueError) as exc:
        # Fixed text, or the password rule's own message: never the input.
        return _page(
            request, "Not changed", f"<p>{html.escape(str(exc))}</p>", 400, session=session
        )
    except OSError as exc:
        logger.warning("approval: a credential change could not be stored err=%s", exc_kind(exc))
        return _page(
            request,
            "Not changed",
            "<p>It could not be stored. Nothing changed.</p>",
            500,
            session=session,
        )
    # Whoever signed in with what just changed must not still be in.
    approval_session.end_others(token)
    _audit_change(what)
    return RedirectResponse(f"{SETUP_PATH}?done={done}", HTTPStatus.SEE_OTHER, headers=_HEADERS)


async def _setup_post(request: Request) -> Response:
    if not _same_origin(request, required=False):
        return _page(request, *_NOTHING_PAGE)
    form = await request.form()
    action = str(form.get("action") or "")
    if action == "enrol_password":
        return await _enrol_password(request, form)
    return await _change(request, form, action)


# --- the passkey ceremony ----------------------------------------------------


async def _body(request: Request) -> dict[str, Any] | None:
    try:
        parsed = json.loads(await request.body())
    except (ValueError, UnicodeDecodeError, RecursionError):
        # RecursionError: a body of nested brackets inside the size cap.
        return None
    return parsed if isinstance(parsed, dict) else None


class _Registrant(NamedTuple):
    """Who may register a passkey: the challenge binding, and whether it came
    from the enrolment window (the first approver) rather than a session."""

    binding: str
    enrolling: bool


def _registration_binding(request: Request, body: dict[str, Any]) -> _Registrant | None:
    """Who is allowed to register a passkey right now.

    A fresh session with its CSRF token, or the enrolment window's code. Asked
    at BEGIN too, so nobody unauthorised can even spend a challenge.
    """
    token = approval_session.token_of(request)
    session = approval_session.current(request)
    if (
        token
        and session is not None
        and approval_session.fresh(session)
        and approval_session.csrf_ok(session, body.get("csrf"))
    ):
        return _Registrant(approval_session.binding_for_session(token), enrolling=False)
    code = body.get("code")
    if isinstance(code, str) and code and approver.enrolling(code):
        return _Registrant(approval_session.binding_for_code(code), enrolling=True)
    return None


async def _begin(request: Request) -> Response:
    if not _same_origin(request, required=True):
        return JSONResponse(_NOTHING_JSON, HTTPStatus.BAD_REQUEST, headers=_HEADERS)
    body = await _body(request)
    served = page.served_as(request)
    if body is None or served is None:
        return JSONResponse(_NOTHING_JSON, HTTPStatus.BAD_REQUEST, headers=_HEADERS)
    ceremony = body.get("ceremony")
    options: dict[str, Any] = {"rpId": served, "algorithms": list(webauthn.ALGORITHMS)}
    if ceremony == webauthn.SIGN_IN:
        # Issued whether or not any passkey exists: the empty store and the
        # full one look the same from here.
        challenge = approval_session.issue_challenge(webauthn.SIGN_IN)
    elif ceremony == webauthn.REGISTER:
        registrant = _registration_binding(request, body)
        if registrant is None:
            return JSONResponse(_NOTHING_JSON, HTTPStatus.BAD_REQUEST, headers=_HEADERS)
        challenge = approval_session.issue_challenge(webauthn.REGISTER, registrant.binding)
        options["userId"] = webauthn.b64url(secrets.token_bytes(16))
        options["userName"] = f"Trentina approver ({served})"
    else:
        return JSONResponse(_NOTHING_JSON, HTTPStatus.BAD_REQUEST, headers=_HEADERS)
    options["challenge"] = webauthn.b64url(challenge)
    return JSONResponse(options, headers=_HEADERS)


def _field(body: dict[str, Any], name: str, limit: int) -> bytes:
    return webauthn.from_b64url(body.get(name), limit=limit)


async def _finish_sign_in(request: Request, body: dict[str, Any]) -> Response:
    try:
        challenge = _field(body, "challenge", 64)
        if not approval_session.take_challenge(challenge, webauthn.SIGN_IN):
            return JSONResponse(_NOTHING_JSON, HTTPStatus.BAD_REQUEST, headers=_HEADERS)
        _field(body, "id", webauthn.MAX_CREDENTIAL_ID)
        verified = await asyncio.to_thread(
            approver.verify_passkey,
            str(body.get("id")),
            client_data=_field(body, "clientDataJSON", webauthn.MAX_CLIENT_DATA),
            auth_data=_field(body, "authenticatorData", webauthn.MAX_AUTH_DATA),
            signature=_field(body, "signature", webauthn.MAX_SIGNATURE),
            challenge=challenge,
        )
    except webauthn.WebAuthnError:
        return JSONResponse(_NOTHING_JSON, HTTPStatus.BAD_REQUEST, headers=_HEADERS)
    if not verified:
        return JSONResponse(_NOTHING_JSON, HTTPStatus.BAD_REQUEST, headers=_HEADERS)
    return _signed_in(request, "passkey", _next(body.get("next")), as_json=True)


def _registration_challenge(body: dict[str, Any], binding: str) -> bytes:
    """The registration challenge this caller was issued, consumed, or raise."""
    challenge = _field(body, "challenge", 64)
    if not approval_session.take_challenge(challenge, webauthn.REGISTER, binding):
        raise webauthn.WebAuthnError("challenge")
    return challenge


async def _finish_register(request: Request, body: dict[str, Any]) -> Response:
    registrant = _registration_binding(request, body)
    if registrant is None:
        return JSONResponse(_NOTHING_JSON, HTTPStatus.BAD_REQUEST, headers=_HEADERS)
    try:
        challenge = _registration_challenge(body, registrant.binding)
        alg = body.get("publicKeyAlgorithm")
        credential = webauthn.verify_registration(
            raw_id=_field(body, "id", webauthn.MAX_CREDENTIAL_ID),
            client_data=_field(body, "clientDataJSON", webauthn.MAX_CLIENT_DATA),
            auth_data=_field(body, "authenticatorData", webauthn.MAX_AUTH_DATA),
            spki=_field(body, "publicKey", webauthn.MAX_SPKI),
            alg=alg if isinstance(alg, int) and not isinstance(alg, bool) else 0,
            challenge=challenge,
            served_as=page.served_as(request),
        )
    except webauthn.WebAuthnError as exc:
        logger.info("approval: a passkey registration did not verify: %s", exc.reason)
        return JSONResponse(
            {"ok": False, "message": "That passkey could not be verified. Try again."},
            HTTPStatus.BAD_REQUEST,
            headers=_HEADERS,
        )
    try:
        cred_id = await asyncio.to_thread(approver.add_passkey, credential, body.get("name"))
    except approver.ApproverError as exc:
        return JSONResponse(
            {"ok": False, "message": str(exc)}, HTTPStatus.BAD_REQUEST, headers=_HEADERS
        )
    except OSError as exc:
        logger.warning("approval: a passkey could not be stored err=%s", exc_kind(exc))
        return JSONResponse(
            {"ok": False, "message": "It could not be stored."}, 500, headers=_HEADERS
        )
    _audit_change(f"passkey enrolled {approver.credential_digest(cred_id)} alg={credential.alg}")
    target = f"{SETUP_PATH}?done=passkey_added"
    if registrant.enrolling:
        # The first approver: shut the window and sign them straight in.
        approver.close_enrolment()
        return _signed_in(request, "passkey", target, as_json=True)
    return JSONResponse({"ok": True, "next": target}, headers=_HEADERS)


async def _finish(request: Request) -> Response:
    if not _same_origin(request, required=True):
        return JSONResponse(_NOTHING_JSON, HTTPStatus.BAD_REQUEST, headers=_HEADERS)
    body = await _body(request)
    if body is None:
        return JSONResponse(_NOTHING_JSON, HTTPStatus.BAD_REQUEST, headers=_HEADERS)
    ceremony = body.get("ceremony")
    if ceremony == webauthn.SIGN_IN:
        return await _finish_sign_in(request, body)
    if ceremony == webauthn.REGISTER:
        return await _finish_register(request, body)
    return JSONResponse(_NOTHING_JSON, HTTPStatus.BAD_REQUEST, headers=_HEADERS)


def register_approval_routes(mcp_server: Any) -> None:
    """Mount the approval pages.

    With no approver configured nothing may be staged, so the guarded writes
    are refused exactly as they were before #637; the pages still mount,
    because they are where the first approver is set.
    """
    if not approver.configured():
        logger.warning(
            "gateway: no approval passkey or password is set, so the operator profile and "
            "federation trust stay unwritable. An operator agent can ask for one with "
            "approval_enrol, which opens %s for a person to set it. Until it is set, an "
            "operator profile holding a backend that can make arbitrary HTTP requests "
            "could enrol itself — set it promptly, and keep such a backend off the "
            "operator profile (docs/deployment-hardening.md)",
            SETUP_PATH,
        )

    from starlette.routing import request_response

    from .ratelimit import RateLimiter, UnauthenticatedWriteGuard, enabled

    # The body cap holds whether or not limiting does: a parser must never be
    # handed an unbounded body, and the limiter is an incident escape hatch.
    attempts = RateLimiter(*PAGE_LIMIT, name=PATH) if enabled() else None
    browsing = RateLimiter(*BROWSE_LIMIT, name=f"{PATH} pages") if enabled() else None
    routes = (
        (PATH, ["GET"], _show, MAX_BODY_BYTES, browsing),
        (PATH, ["POST"], _decide, MAX_BODY_BYTES, attempts),
        (SIGN_OUT_PATH, ["POST"], _sign_out, MAX_BODY_BYTES, browsing),
        (SETUP_PATH, ["GET"], _setup, MAX_BODY_BYTES, browsing),
        (SETUP_PATH, ["POST"], _setup_post, MAX_BODY_BYTES, attempts),
        (OLD_ENROL_PATH, ["GET", "POST"], _legacy, MAX_BODY_BYTES, browsing),
        (BEGIN_PATH, ["POST"], _begin, MAX_CEREMONY_BYTES, browsing),
        (FINISH_PATH, ["POST"], _finish, MAX_CEREMONY_BYTES, attempts),
    )
    for path, methods, handler, cap, limiter in routes:
        app: Any = UnauthenticatedWriteGuard(
            request_response(handler),
            limiter=limiter,
            max_body_bytes=cap,
            name=path,
        )
        mcp_server.custom_route(path, methods=methods)(app)
    logger.info("gateway: the approval pages are mounted at %s", PATH)
