"""The bearer tokens the gateway minted for its own profiles, by name (#635).

A profile authenticates its agent with a bearer token, and until now the only
way to name one was an environment variable. That means a new profile needs a
new variable in the container's environment, which means a restart — and it is
worse than a restart, because the candidate config fails validation before it
is ever written: ``loader._require_env`` refuses a profile whose token variable
is not set, so ``config_tool`` restores the file and the write is refused
outright. There was no way to add an agent profile to a running gateway at all.

Naming a token instead removes that, exactly as ``key_store`` did for
federation keys: ``reload_profiles`` re-runs ``load_profiles``, which re-reads
the store, so a token minted after startup is live on the next reload.

A name, not a path, for the same reason as a key: the operator passes back the
name ``profile_token`` returned, the store joins it to its own directory, and
there is no path to validate and no traversal to defend. The name's shape is
what makes the join safe, so this reuses ``key_store``'s shape rather than
inventing a second one.

The store lives beside the key store and the audit database — ``/data`` in the
container — which ``tools/confine.py`` refuses to every file tool.
"""

from __future__ import annotations

import os
import secrets
from pathlib import Path

from ..config import get_config
from ..logsafe import hold
from .key_store import KEY_DIR_MODE, KEY_FILE_MODE

#: The lead-in every minted token carries. An opaque random string has no shape
#: a scrubber could recognise, unlike a PEM; this is what gives it one, so
#: ``credential_shapes`` can hold it out of a log record even somewhere nobody
#: thought to hold it by hand.
MINTED_PREFIX = "trt_"

#: 32 bytes, url-safe. The token is the whole credential for a profile.
_TOKEN_BYTES = 32


def tokens_dir() -> Path:
    """The token directory, beside the key store."""
    return Path(get_config().db_path).parent / "tokens"


def token_path(name: str) -> Path:
    """The file a token name resolves to.

    Call only with a name that matched ``key_store.KEY_NAME_RE``; that shape is
    what makes this join safe, and every caller checks it first.
    """
    return tokens_dir() / name


def ensure_tokens_dir() -> Path:
    """Create the token directory 0700, and hold it there.

    ``mkdir(mode=)`` is masked by the umask and does nothing at all to a
    directory that already exists, so the explicit ``chmod`` is the one that
    decides the mode — the same reason ``key_store.ensure_keys_dir`` does both.
    """
    directory = tokens_dir()
    directory.mkdir(mode=KEY_DIR_MODE, parents=True, exist_ok=True)
    os.chmod(directory, KEY_DIR_MODE)
    return directory


def mint(name: str) -> str:
    """Write a new bearer token under ``name``; return it.

    ``O_EXCL`` refuses an existing file, a planted file and a symlink in one
    move, so a name is written exactly once and a token in use is never
    replaced underneath a live profile. A write that fails part way leaves
    nothing behind, so the name stays free rather than becoming permanently
    unusable. Rotation is a new name.

    Unlike ``key_store.mint``, the value IS passed to ``logsafe.hold``. A
    private key is held out of every record by pattern and nothing retains it
    after the write; a bearer token is retained in memory for the gateway's
    lifetime anyway — ``auth.verify_bearer`` compares against it on every
    request — so holding it costs nothing and covers the one place a shape
    might not.
    """
    ensure_tokens_dir()
    path = token_path(name)
    token = MINTED_PREFIX + secrets.token_urlsafe(_TOKEN_BYTES)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, KEY_FILE_MODE)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(token)
    except BaseException:
        path.unlink(missing_ok=True)
        raise
    hold(token, "PROFILE_TOKEN")
    return token


def read_token(name: str) -> str:
    """The stored token for ``name``, or raise ``OSError``.

    Read on every load and every reload, which is what makes a token minted
    after startup take effect without one. Held on the way out for the same
    reason ``mint`` holds it.
    """
    token = token_path(name).read_text(encoding="utf-8").strip()
    hold(token, "PROFILE_TOKEN")
    return token
