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

- **Nothing set yet.** ``open`` starts a window and hands back a link carrying a
  one-time code in its #fragment, so the code never reaches the server and never
  lands in a request or proxy log; the same code also prints as ``xxxx-xxxx-xxxx``
  for a person to type if the link does not fill the field. Re-opening keeps that
  code (and so the link already in the chat stays valid) and only restarts the
  clock. The result names the gateway it is for, so a link to one gateway is not
  opened against another. The window closes when a passkey or password is set,
  when it runs out, or on ``close``.
- **Already set.** ``open`` hands back the same page with no code: the person
  signs in with what they have and adds a passkey, changes the password or
  removes either there. Nothing here can replace a working approver.
- **Checking.** ``status`` says, without touching the window, whether an approver
  is set, whether a window is open and how long it has left.
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

ACTIONS = ("open", "close", "status")

#: Hosts a passkey is allowed to register against over plain http; everything
#: else needs https. Used only to WORD the hand-off ("it will not open from a
#: phone"), never to decide security.
_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "::1", "localhost"})


def _base() -> str:
    """The absolute address this gateway hands out, or ``""`` when none is known.

    The deployment's ``TRENTINA_OAUTH_BASE_URL`` when it set one, since that is
    the public address it already hands out; otherwise the origin this very call
    arrived on. Never ``public_base_url()``'s fallback, which is one particular
    deployment's address and would send a person elsewhere.
    """
    configured = backend_oauth.configured_base_url()
    parts = urlsplit(configured or "")
    if parts.scheme in ("http", "https") and parts.hostname:
        return f"{parts.scheme}://{parts.netloc}"
    return current_origin.get() or ""


def _link(code: str | None = None) -> dict[str, str]:
    """The setup page's path, and its absolute address when one is known."""
    base = _base()
    path = pending.ENROL_PATH + (f"#code={code}" if code else "")
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
    """Bring up the approval sign-in page for a person, shut its window, or report."""
    try:
        require_operator(require_caller("approval_enrol"), "approval_enrol")
    except ScopeError as exc:
        logger.warning("approval_enrol refused: %s", exc_kind(exc))
        return {"error": str(exc)}

    if action not in ACTIONS:
        return {"error": "action is 'open', 'close' or 'status'"}

    base = _base()
    host = urlsplit(base).hostname or ""
    local = host in _LOOPBACK_HOSTS
    named = host or "this gateway"

    if action == "status":
        return {
            "gateway": named,
            "local_only": local,
            "approver_set": approver.configured(),
            "window_open": approver.enrolling(),
            "seconds_left": approver.enrol_seconds_left(),
        }

    if action == "close":
        open_now = approver.enrolling()
        approver.close_enrolment()
        return {"gateway": named, "closed": True, "was_open": open_now}

    if approver.configured():
        link = _link()
        where = link.get("open_url", link["url"])
        return {
            "gateway": named,
            "local_only": local,
            **link,
            "already_set": True,
            "message": (
                f"Approval is already set up for {named}. Open this link to add a "
                f"passkey, change the password or sign out: {where}"
            ),
            "note": (
                f"A passkey or password is already set for {named}. On that page the "
                "person signs in with what they have, then manages it. " + _OPEN_IT
            ),
        }

    reopened = approver.enrolling()
    seconds, code = approver.open_enrolment()
    minutes = max(1, round(seconds / 60))
    link = _link(code)
    where = link.get("open_url", link["url"])
    device = (
        "in a browser on the computer running this gateway; it will not open from a phone"
        if local
        else "on the device that will hold your passkey"
    )
    message = (
        f"Set up approval for {named}. Open this link within {minutes} minutes {device}: "
        f"{where} If the page asks for a code: {code}"
    )
    return {
        "gateway": named,
        "local_only": local,
        "reopened": reopened,
        **link,
        "opened": True,
        "code": code,
        "open_for_seconds": seconds,
        "message": message,
        "note": (
            f"This sets the approver for {named} only — a link to one gateway will not "
            "set up another. Relay `message` to the person unchanged. To check whether "
            "it worked, call this tool with action='status'; do not call 'open' again "
            "to check, which the person does not need and only restarts the clock. "
            + _OPEN_IT
        ),
    }
