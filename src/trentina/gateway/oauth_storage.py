"""The inbound OAuth proxy's encrypted store, strict about plaintext (#495).

FastMCP wraps its ``FileTreeStore`` in py-key-value's
``FernetEncryptionWrapper``, whose ``_decrypt_value`` returns any record
lacking ``__encrypted_data__`` unchanged. Fernet then authenticates nothing a
writer plants: a plaintext ``{"profile": "<operator>"}`` under a binding key,
dropped into ``$FASTMCP_HOME/oauth-proxy/<fp>/``, is accepted without the key.
``StrictFernetEncryptionWrapper`` treats such a record as a miss.

``build_client_storage`` rebuilds the store the way FastMCP does (same derived
key, same directory, same sanitization strategies) so records already on disk
stay readable. ``tests/test_oauth_storage.py`` pins that parity.
"""

from __future__ import annotations

import base64
import hashlib
import logging
from typing import Any

from key_value.aio.wrappers.encryption import FernetEncryptionWrapper

from .. import logsafe

logger = logging.getLogger(__name__)

_ENCRYPTED_DATA_KEY = "__encrypted_data__"
_STORAGE_SALT = "fastmcp-storage-encryption-key"


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


def client_storage_kwargs(signing_key: str | None) -> dict[str, Any]:
    """The provider's ``client_storage`` argument; none without a signing key,
    where FastMCP keeps its ephemeral default."""
    if not signing_key:
        return {}
    return {"client_storage": build_client_storage(signing_key)}


def build_client_storage(signing_key: str) -> StrictFernetEncryptionWrapper:
    """The store ``OAuthProxy`` builds by default, with the strict wrapper."""
    from cryptography.fernet import Fernet
    from fastmcp import settings
    from fastmcp.server.auth.jwt_issuer import derive_jwt_key
    from key_value.aio.stores.filetree import (
        FileTreeStore,
        FileTreeV1CollectionSanitizationStrategy,
        FileTreeV1KeySanitizationStrategy,
    )

    encryption_key = base64.urlsafe_b64encode(
        derive_jwt_key(high_entropy_material=signing_key, salt=_STORAGE_SALT)
    )
    fingerprint = hashlib.sha256(encryption_key).hexdigest()[:12]
    cache_dir = settings.home / "oauth-proxy" / fingerprint
    cache_dir.mkdir(parents=True, exist_ok=True)
    file_store = FileTreeStore(
        data_directory=cache_dir,
        key_sanitization_strategy=FileTreeV1KeySanitizationStrategy(cache_dir),
        collection_sanitization_strategy=FileTreeV1CollectionSanitizationStrategy(cache_dir),
    )
    return StrictFernetEncryptionWrapper(
        key_value=file_store,
        fernet=Fernet(key=encryption_key),
        raise_on_decryption_error=False,
    )
