"""The inbound OAuth proxy's encrypted store, strict about plaintext (#495).

FastMCP wraps its ``FileTreeStore`` in py-key-value's
``FernetEncryptionWrapper``, whose ``_decrypt_value`` returns any record
lacking ``__encrypted_data__`` unchanged. Fernet then authenticates nothing a
writer plants: a plaintext ``{"profile": "<operator>"}`` under a binding key,
dropped into ``$FASTMCP_HOME/oauth-proxy/<fp>/``, is accepted without the key.
``StrictFernetEncryptionWrapper`` treats such a record as a miss.

``harden_client_storage`` makes the store the provider built for itself strict
in place, rather than rebuilding it: a rebuild has to copy FastMCP's key
derivation and directory layout, and drifts from them on an upgrade, which
strands every record already on disk. ``tests/test_oauth_storage.py`` pins
that records FastMCP writes stay readable.

This module is the one place that touches FastMCP's internals for it:
``harden_provider_storage`` reads the provider's private ``_client_storage``
(FastMCP offers no hook to wrap its store), and ``harden_client_storage``
relies on that object being exactly ``FernetEncryptionWrapper``. Both fail
startup, never open, when an upgrade changes either, and
``tests/test_oauth_storage.py`` runs them against the installed FastMCP.
"""

from __future__ import annotations

import logging
from typing import Any, cast

from key_value.aio.wrappers.encryption import FernetEncryptionWrapper

from .. import logsafe

logger = logging.getLogger(__name__)

_ENCRYPTED_DATA_KEY = "__encrypted_data__"


class StrictFernetEncryptionWrapper(FernetEncryptionWrapper):
    """A record that is not ciphertext is a miss, never a value."""

    def _decrypt_value(self, value: dict[str, Any] | None) -> dict[str, Any] | None:
        if value is None:
            return None
        if _ENCRYPTED_DATA_KEY not in value:
            # The fingerprint of the stored text, never the text itself.
            logger.warning(
                "OAuth store: unencrypted record refused (%s)",
                logsafe.redact_source(repr(sorted(value))),
            )
            return None
        return super()._decrypt_value(value)


def harden_client_storage(storage: Any) -> StrictFernetEncryptionWrapper:
    """Make the provider's own encrypted store refuse plaintext records.

    The subclass adds no state, so swapping the class keeps the key, the
    directory and every adapter FastMCP already built over this object.
    Anything but a plain ``FernetEncryptionWrapper`` is refused: the gateway
    does not start on a store it cannot make strict.
    """
    if type(storage) is not FernetEncryptionWrapper:
        raise RuntimeError("OAuth store: not a FernetEncryptionWrapper; cannot refuse plaintext")
    storage.__class__ = StrictFernetEncryptionWrapper
    return cast("StrictFernetEncryptionWrapper", storage)


def harden_provider_storage(provider: Any, *, persistent: bool) -> None:
    """Make the store an OAuth proxy ``provider`` built for itself strict.

    ``persistent`` is false when the provider has no signing key: FastMCP's
    store is then its ephemeral default, and nothing on disk is read.
    """
    if not persistent:
        return
    storage = getattr(provider, "_client_storage", None)
    if storage is None:
        raise RuntimeError("OAuth store: provider has no _client_storage; cannot refuse plaintext")
    harden_client_storage(storage)
