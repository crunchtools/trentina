"""Asking a person to set the approval password (#637): operator only.

The operator seat can bring a gateway up on its own, and this is the last
thing that was not true of. Approving a staged change needs a password a
person holds; setting that password needed a script and a config edit, which
is a shell, which is the thing this product exists to remove.

So the operator asks, exactly as ``backend_auth`` asks for a backend sign-in:
it opens a window and hands back a URL, a person opens it and chooses the
password. What the operator cannot do is answer the prompt — setting the
password is a POST, and none of Trentina's own tools makes one. That asymmetry
is the whole security property, and it is why asking is safe to give away.

The window exists so that a gateway sitting with no password is not a standing
offer to whoever reaches the page first. It is short, it is opened only on
request, and it closes the moment a password is set.
"""

from __future__ import annotations

import logging
from typing import Any

from ..gateway import approver, pending
from ..gateway.errors import ScopeError
from ..gateway.scope import require_caller, require_operator
from ..logsafe import exc_kind

logger = logging.getLogger(__name__)


async def approval_enrol() -> dict[str, Any]:
    """Open the window for a person to set this gateway's approval password."""
    try:
        require_operator(require_caller("approval_enrol"), "approval_enrol")
    except ScopeError as exc:
        logger.warning("approval_enrol refused: %s", exc_kind(exc))
        return {"error": str(exc)}

    if approver.pinned_by_deployment():
        return {
            "error": (
                "this gateway's approval password is pinned by its deployment, so it "
                "cannot be set from here; change it where the configuration is kept"
            )
        }
    if approver.configured():
        return {
            "already_set": True,
            "url": pending.ENROL_PATH,
            "note": (
                "An approval password is already set. A person can change it at that "
                "URL by entering the current one; nothing here can replace it."
            ),
        }

    seconds, code = approver.open_enrolment()
    return {
        "opened": True,
        "url": pending.ENROL_PATH,
        "code": code,
        "open_for_seconds": seconds,
        "note": (
            "Give a person that URL and code. They choose the password; you cannot, "
            "because setting it is a form submission and none of your tools makes one. "
            "The code is what stops anyone else who can reach the page claiming this "
            "gateway's approver while the window is open. Until a password is set, a "
            "change to the operator seat or to federation trust cannot be approved, so "
            "both stay refused."
        ),
    }
