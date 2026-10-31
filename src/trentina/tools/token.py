"""Minting a profile's bearer token (#635): operator only.

The last step of provisioning an agent that still needed a person and a
restart. A profile's token could only be named as an environment variable, and
a profile naming one that is not set does not merely need a restart — it fails
validation, so ``config_tool`` refuses the write and restores the file. There
was no way to add an agent profile to a running gateway.

This returns the token, ONCE, which nothing else in Trentina does. That is a
deliberate exception and worth stating plainly: ``federation_keygen`` hands
back only the public half, and every other credential is named rather than
carried. Two things make it acceptable here. The caller is the operator, which
already writes ``llm_keys.*.api_key`` into the config with its own hands, so
its context already holds credentials of exactly this kind and this adds no new
class of exposure. And there is nowhere else for the value to go: the agent
being provisioned has to be told its own token by someone, and the alternative
is a person copying it, which is the step this removes.

What is NOT returned is a second read. The token is written once under a name
and never handed out again, so a lost one is rotated by minting a new name and
pointing the profile at it — the same shape as ``federation_keygen``.
"""

from __future__ import annotations

import logging
from typing import Any

from ..gateway import key_store, token_store
from ..gateway.errors import ScopeError
from ..gateway.scope import require_caller, require_operator
from ..logsafe import exc_kind

logger = logging.getLogger(__name__)


async def profile_token(name: str) -> dict[str, Any]:
    """Mint a bearer token under ``name`` and return it once.

    Args:
        name: Lower-case letters, digits and hyphens. It becomes a filename in
            the gateway's own token store, which is why the shape is held.
    """
    try:
        require_operator(require_caller("profile_token"), "profile_token")
    except ScopeError as exc:
        logger.warning("profile_token refused: %s", exc_kind(exc))
        return {"error": str(exc)}

    # Never echoed: a rejected name is caller-chosen text, and it becomes a
    # filename (#262, #633).
    if not key_store.KEY_NAME_RE.match(name):
        return {"error": "token name must be lowercase letters, digits and hyphens"}

    try:
        token = token_store.mint(name)
    except FileExistsError:
        return {"error": "a token of that name already exists; rotate to a new name"}
    except OSError as exc:
        logger.warning("profile_token failed: %s", exc_kind(exc))
        return {"error": "could not write the token"}

    logger.info("profile_token: minted a token")
    return {
        "token_name": name,
        "token": token,
        "note": (
            "This is the only time the token is returned. Put the NAME in the "
            "profile's auth.bearer_token_name and give the token to the agent that "
            "will use it. To rotate, mint a new name and point the profile at it."
        ),
    }
