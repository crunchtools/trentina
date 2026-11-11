"""Bringing up the page where a person sets how they approve (#637, #639).

The operator profile can bring a gateway up on its own, and approving a staged
change needs a person: a passkey they unlock, or a password they hold. So the
operator asks, exactly as ``backend_auth`` asks for a backend sign-in: it
returns a link, a person opens it, and they choose. What the operator cannot do
is answer — making a passkey needs a person's device, and setting a password is
a form submission none of Trentina's own tools makes. That asymmetry is the
whole security property, and it is why asking is safe to give away.

It is what a person reaches for by saying "let me set my passkey in Trentina"
or "let me change my password in Trentina":

- **Nothing set yet.** ``open`` starts a short window and hands back a link
  carrying a one-time code as a query parameter. A query, not a fragment, so a
  freshly opened link always reloads and the server renders the code into the
  form: a fragment-only change does not reload an already-open tab, which
  stranded people on a stale, empty form. The code reaches the server now, where
  a fragment did not; it is single-use, lives only as long as the window, and
  ``Referrer-Policy: no-referrer`` keeps it from leaking onward. The window
  closes when a passkey or password is set, when it runs out, or on ``close``.
- **Already set.** ``open`` hands back the same page with no code: the person
  signs in with what they have and adds a passkey, changes the password or
  removes either there. Nothing here can replace a working approver.
"""

from __future__ import annotations

import logging
from typing import Any
from urllib.parse import urlsplit

from ..gateway import approver, backend_oauth, pending
from ..gateway.context import current_origin
from ..gateway.errors import ScopeError
from ..gateway.scope import require_caller, require_operator
from ..logsafe import exc_kind

logger = logging.getLogger(__name__)

ACTIONS = ("open", "close")


def _link(code: str | None = None) -> dict[str, str]:
    """The setup page's path, and its absolute address when one is known.

    The deployment's ``TRENTINA_OAUTH_BASE_URL`` when it set one, since that is
    the public address it already hands out; otherwise the origin this very
    call arrived on. Never ``public_base_url()``'s fallback, which is one
    particular deployment's address and would send a person elsewhere.
    """
    configured = backend_oauth.configured_base_url()
    parts = urlsplit(configured or "")
    base = (
        f"{parts.scheme}://{parts.netloc}"
        if parts.scheme in ("http", "https") and parts.hostname
        else current_origin.get()
    )
    path = pending.ENROL_PATH + (f"?code={code}" if code else "")
    answer = {"url": path}
    if base:
        answer["open_url"] = base + path
    return answer


_OPEN_IT = (
    "Open open_url in the person's browser for them, or give it to them to open. "
    "You cannot complete this page yourself: a passkey needs their device, and a "
    "password is a form submission none of your tools makes. If there is no "
    "open_url, they open url on this gateway's own address. Passkeys need https, or "
    "a gateway reached as localhost."
)


async def approval_enrol(action: str = "open") -> dict[str, Any]:
    """Bring up the approval sign-in page for a person, or shut its window."""
    try:
        require_operator(require_caller("approval_enrol"), "approval_enrol")
    except ScopeError as exc:
        logger.warning("approval_enrol refused: %s", exc_kind(exc))
        return {"error": str(exc)}

    if action not in ACTIONS:
        return {"error": "action is 'open' or 'close'"}

    if action == "close":
        open_now = approver.enrolling()
        approver.close_enrolment()
        return {"closed": True, "was_open": open_now}

    if approver.configured():
        return {
            **_link(),
            "already_set": True,
            "note": (
                "A passkey or password is already set. On that page the person signs in "
                "with what they have, then adds a passkey, changes or removes the "
                "password, or removes a passkey. " + _OPEN_IT
            ),
        }

    seconds, code = approver.open_enrolment()
    return {
        **_link(code),
        "opened": True,
        "code": code,
        "open_for_seconds": seconds,
        "note": (
            "The link carries a one-time code; the person creates a passkey (or sets a "
            "password) there before the window closes. The code is what stops anyone "
            "else who can reach the page claiming this gateway's approver meanwhile. "
            "Until it is done, a change to the operator profile or to federation trust "
            "cannot be approved, so both stay refused. Call again with action='close' "
            "to shut the window early. " + _OPEN_IT
        ),
    }
