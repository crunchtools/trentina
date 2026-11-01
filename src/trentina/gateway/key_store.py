"""The gateway's own federation keypairs, by name (#633).

A federated link needs an Ed25519 private key on each side. Until 3.3.0 a
profile could only name an environment variable holding one, which means a new
key needs a new variable in the container's environment, which means a restart
— the one step an operator agent cannot take. Referring to a key by NAME
instead removes that: ``reload_profiles`` re-runs ``load_profiles``, which
re-reads the keys, so a key minted after startup is live on the next reload.

A name, not a path. The operator passes back the name ``federation_keygen``
returned, and the store joins it to its own directory, so there is no path to
validate, no traversal to defend and no way to point a profile at a file
outside the store. The name's shape is what makes the join safe.

The store lives beside the audit database — ``/data`` in the container — which
is the same directory ``backend_tokens`` keeps its grants in and which
``tools/confine.py`` refuses to every file tool.
"""

from __future__ import annotations

import re
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ..config import get_config
from . import secret_file

#: A key name, shaped like a backend or profile name. It becomes a filename, so
#: the shape is what keeps it one: no dot, no slash, no traversal.
KEY_NAME_RE = re.compile(r"^[a-z][a-z0-9-]{0,62}\Z")

#: Re-exported so the tests that check the mode bits, and token_store, have
#: one spelling of them.
KEY_DIR_MODE = secret_file.DIR_MODE
KEY_FILE_MODE = secret_file.FILE_MODE

KEY_SUFFIX = ".pem"


def keys_dir() -> Path:
    """The key directory, beside the audit database."""
    return Path(get_config().db_path).parent / "keys"


def key_path(name: str) -> Path:
    """The file a key name resolves to.

    Call only with a name that matched ``KEY_NAME_RE``; that shape is what
    makes this join safe, and every caller checks it first.
    """
    return keys_dir() / f"{name}{KEY_SUFFIX}"


def ensure_keys_dir() -> Path:
    """Create the key directory 0700, and hold it there."""
    return secret_file.private_dir("keys")


def mint(name: str) -> str:
    """Write a new Ed25519 private key under ``name``; return its public PEM.

    ``secret_file.write_once`` is what refuses an existing name, so a key in
    use is never replaced underneath a live link; rotation is a new name.

    The private PEM is deliberately not passed to ``logsafe.hold``: that would
    keep it in process memory for the gateway's lifetime, where nothing
    otherwise retains it after the write, and a private key is already held out
    of every log record by pattern (``credential_shapes.PEM_KEY``).
    """
    ensure_keys_dir()
    path = key_path(name)
    key = Ed25519PrivateKey.generate()
    private_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    secret_file.write_once(path, private_pem)
    return (
        key.public_key()
        .public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode()
    )


def read_key(name: str) -> str:
    """The stored private PEM for ``name``, or raise ``OSError``.

    Read on every load and every reload, which is what makes a key minted after
    startup take effect without one.
    """
    return key_path(name).read_text(encoding="utf-8")
