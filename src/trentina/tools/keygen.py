"""Federation keypair generation (#633): operator only.

A federated edge needs an Ed25519 keypair on each side. Until now the only way
to get one was ``openssl`` on the host, which is the manual step the operator
seat exists to remove: ``docs/operator.md`` promises a loop where "none of this
needs a shell", and generating a key was one of the places that was not true.

This mints the pair inside the gateway. The private half is written under the
gateway's own data directory, which ``tools/confine.py`` already refuses to
every file tool, and is never returned or logged. Only the PUBLIC half comes
back: that is the half a peer pins, and a public key is not a secret, which is
why ``FederationPeer.public_key`` is inline in ``profiles.yaml`` to begin with.

Two deliberate choices:

- ``O_EXCL`` on the final path, so a name is written exactly once. Rotation is
  a new name, and a key in use can never be replaced under a running edge.
- The private PEM is NOT passed to ``logsafe.hold``. Holding it would keep the
  key in process memory for the lifetime of the gateway, where otherwise
  nothing retains it after the write. Log safety for private keys is already
  pattern-based and needs no registration: ``credential_shapes.PEM_KEY``
  matches any ``BEGIN ... PRIVATE KEY`` block in any record.
"""

from __future__ import annotations

import logging
import os
import re
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ..config import get_config
from ..gateway.errors import ScopeError
from ..gateway.scope import require_caller, require_operator
from ..logsafe import exc_kind

logger = logging.getLogger(__name__)

#: A key name, shaped like a backend or profile name. It becomes a filename, so
#: the shape is what keeps it one: no dot, no slash, no traversal.
KEY_NAME_RE = re.compile(r"^[a-z][a-z0-9-]{0,62}$")

KEY_DIR_MODE = 0o700
KEY_FILE_MODE = 0o600

KEY_SUFFIX = ".pem"


def keys_dir() -> Path:
    """The gateway's own federation key directory, beside the audit database.

    The same derivation ``backend_tokens`` uses for its grant store, so every
    piece of gateway-owned secret material sits under one data directory —
    ``/data`` in the container, which ``confine.HARD_DENIED`` refuses outright.
    """
    return Path(get_config().db_path).parent / "keys"


def key_path(name: str) -> Path:
    """The file a key name resolves to. Call only with a name that matched
    ``KEY_NAME_RE``; the shape is what makes this safe to join."""
    return keys_dir() / f"{name}{KEY_SUFFIX}"


def _ensure_keys_dir() -> Path:
    """Create the key directory 0700, and hold it there.

    ``mkdir(mode=)`` is masked by the umask and does nothing at all to a
    directory that already exists, so the explicit ``chmod`` is the one that
    decides the mode — the same reason ``backend_tokens.open_backend_token_store``
    does both.
    """
    directory = keys_dir()
    directory.mkdir(mode=KEY_DIR_MODE, parents=True, exist_ok=True)
    os.chmod(directory, KEY_DIR_MODE)
    return directory


def _mint(path: Path) -> str:
    """Write a new Ed25519 private key to ``path``; return its public PEM.

    ``O_EXCL`` refuses an existing file, a planted file and a symlink in one
    move. A write that fails part way leaves nothing behind, so the name stays
    free rather than becoming permanently unusable by a half-written key.
    """
    key = Ed25519PrivateKey.generate()
    private_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, KEY_FILE_MODE)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(private_pem)
    except BaseException:
        path.unlink(missing_ok=True)
        raise
    return (
        key.public_key()
        .public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode()
    )


async def federation_keygen(name: str) -> dict[str, Any]:
    """Mint an Ed25519 keypair under ``name`` and return only the public half.

    Args:
        name: What to call the key, lowercase letters, digits and hyphens. It
            is what a profile's ``edge_key_name`` or ``signing_key_name`` refers
            to later, and it is written once.
    """
    try:
        require_operator(require_caller("federation_keygen"), "federation_keygen")
    except ScopeError as exc:
        logger.warning("federation_keygen refused: %s", exc_kind(exc))
        return {"error": str(exc)}

    if not KEY_NAME_RE.match(name):
        # The name is the caller's, so the refusal describes the shape and never
        # echoes what arrived (#262).
        return {"error": "key name must be lowercase letters, digits and hyphens"}

    try:
        _ensure_keys_dir()
        public_pem = _mint(key_path(name))
    except FileExistsError:
        return {"error": "a key of that name already exists; rotate to a new name"}
    except OSError as exc:
        logger.warning("federation_keygen failed: %s", exc_kind(exc))
        return {"error": "could not write the key"}

    logger.info("federation_keygen: minted a key")
    return {"key": name, "public_key": public_pem}
