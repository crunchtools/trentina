"""Federation keypair generation (#633): operator only.

A federated edge needs an Ed25519 keypair on each side. Until now the only way
to get one was ``openssl`` on the host, which is the manual step the operator
seat exists to remove: ``docs/operator.md`` promises a loop where "none of this
needs a shell", and generating a key was one of the places that was not true.

The store itself is ``gateway/key_store.py``, which the profile loader also
reads — this module is only the operator's door to it. The private half stays
inside the gateway, where ``tools/confine.py`` refuses it to every file tool,
and is never returned. Only the PUBLIC half comes back: that is the half a peer
pins, and a public key is not a secret, which is why
``FederationPeer.public_key`` is inline in ``profiles.yaml`` to begin with.
"""

from __future__ import annotations

import logging
from typing import Any

from ..gateway import key_store
from ..gateway.errors import ScopeError
from ..gateway.scope import require_caller, require_operator
from ..logsafe import exc_kind

logger = logging.getLogger(__name__)


async def federation_keygen(name: str) -> dict[str, Any]:
    """Mint an Ed25519 keypair under ``name`` and return only the public half.

    Args:
        name: What to call the key, lowercase letters, digits and hyphens. It
            is what a profile's ``primary_key_name`` or ``secondary_key_name`` refers
            to later, and it is written once.
    """
    try:
        require_operator(require_caller("federation_keygen"), "federation_keygen")
    except ScopeError as exc:
        logger.warning("federation_keygen refused: %s", exc_kind(exc))
        return {"error": str(exc)}

    if not key_store.KEY_NAME_RE.match(name):
        # The name is the caller's, so the refusal describes the shape and never
        # echoes what arrived (#262).
        return {"error": "key name must be lowercase letters, digits and hyphens"}

    try:
        public_pem = key_store.mint(name)
    except FileExistsError:
        return {"error": "a key of that name already exists; rotate to a new name"}
    except OSError as exc:
        logger.warning("federation_keygen failed: %s", exc_kind(exc))
        return {"error": "could not write the key"}

    logger.info("federation_keygen: minted a key")
    return {"key": name, "public_key": public_pem}
