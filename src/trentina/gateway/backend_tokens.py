"""Grants the gateway holds to backends, each owned by one profile (#479).

When a backend authenticates with MCP OAuth, the gateway is the OAuth client,
and what it obtains belongs to the (profile, backend) pair that authorized
it: the *slot*. A grant josui obtained for Era is never sent for kagetora,
even when both profiles list the same Era URL.

Records live on the data volume, encrypted with a key derived from
``TRENTINA_BACKEND_TOKEN_KEY`` (preferably its ``_FILE`` form). Without that
key there is no store, and every OAuth backend reports "needs auth": nothing
is ever written in plaintext.

The disk is not trusted, which is the point of encrypting it, so the
envelope is ours rather than py-key-value's ``FernetEncryptionWrapper``:
that wrapper hands back any record without ciphertext as-is, so a planted
plaintext file would read as a grant (#495). Here a record is
``{"v": 1, "ct": <Fernet token>}``, and the plaintext inside names the slot
and the backend origin it was written for. A file copied into another
profile's slot, or a grant whose backend URL has since moved to another
host, reads as absent.

Refresh is a read-modify-write that two concurrent calls must not both do,
or the same refresh token is spent twice and a rotating authorization server
revokes the lineage. ``locked(profile, backend)`` serializes one slot, and
``put_grant`` takes the generation the caller read, so a write based on a
stale read is refused rather than lost.

Dynamic client registrations live in their own collection: revoking a grant
keeps the client, so re-authorizing does not register another one.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import logging
import os
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal, TypeVar
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, SecretStr, ValidationError

from ..config import get_config
from ..logsafe import exc_kind, exc_where
from .errors import ProfileConfigError
from .loader import read_secret_env
from .profile import BACKEND_NAME_RE, PROFILE_NAME_RE

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Mapping

    from cryptography.fernet import Fernet

    from .profile import Backend, Profile

logger = logging.getLogger(__name__)

KEY_ENV = "TRENTINA_BACKEND_TOKEN_KEY"
#: Characters. Length is not entropy, but a key this short was typed, not
#: generated; the docs say ``openssl rand -base64 48``.
MIN_KEY_CHARS = 32
#: How long a slot's records outlive their last write. A grant is re-written
#: on every refresh, so only one idle this long is dropped.
RECORD_TTL = timedelta(days=365)

_ENVELOPE_VERSION = 1
_GRANTS = "backend-grants"
_CLIENTS = "backend-clients"
_FLOWS = "backend-flows"
_HKDF_SALT = b"trentina-backend-tokens"


#: How a client authenticates at the token endpoint (RFC 7591).
AuthMethod = Literal["client_secret_basic", "client_secret_post", "none"]


class GrantConflictError(Exception):
    """A grant write was based on a read that is no longer current."""


def _now() -> datetime:
    """The clock every expiry here is read against. Tests move it."""
    return datetime.now(UTC)


class BackendGrant(BaseModel):
    """A token set one profile holds for one backend. Tokens never print."""

    model_config = ConfigDict(extra="forbid", frozen=True, hide_input_in_errors=True)

    access_token: SecretStr
    refresh_token: SecretStr | None = None
    token_type: str = Field(default="Bearer", description="The RFC 6750 scheme name")
    expires_at: datetime | None = None
    scopes: tuple[str, ...] = ()
    #: The authorization server that issued it, and where it is refreshed.
    #: Pinned at issue: a refresh never rediscovers, so a backend whose
    #: metadata later names another server cannot redirect the refresh
    #: token (or the client secret sent with it) there.
    issuer: str
    token_endpoint: str
    #: The RFC 8707 resource it was issued for, sent again on refresh.
    resource: str | None = None
    #: The client it was issued to, and how that client authenticates.
    client_id: str
    auth_method: AuthMethod = "none"
    obtained_at: datetime
    #: Set by the store: what ``put_grant`` must be handed back to replace it.
    generation: int = 0


class BackendClient(BaseModel):
    """The OAuth client a profile registered (or was given) for one backend."""

    model_config = ConfigDict(extra="forbid", frozen=True, hide_input_in_errors=True)

    client_id: str
    client_secret: SecretStr | None = None
    #: How the client authenticates at the token endpoint (RFC 7591).
    auth_method: AuthMethod = "none"
    issuer: str
    token_endpoint: str


class BackendFlow(BaseModel):
    """One authorization in progress: what the callback needs to finish it.

    Keyed by a hash of its ``state``; the state itself is never stored. The
    verifier is the PKCE secret, so this is as sensitive as a grant.
    """

    model_config = ConfigDict(extra="forbid", frozen=True, hide_input_in_errors=True)

    profile: str
    backend: str
    origin: str
    issuer: str
    #: Whether the callback must carry ``iss`` (RFC 9207).
    iss_required: bool
    token_endpoint: str
    authorize_url: str
    client_id: str
    auth_method: AuthMethod
    verifier: SecretStr
    redirect_uri: str
    resource: str | None
    scopes: tuple[str, ...]
    #: Where the confirmation page finds this flow; dropped with it.
    page_key: str
    expires_at: datetime


class _Sealed(BaseModel):
    """What is inside the ciphertext: the record, and where it belongs."""

    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)

    slot: str
    origin: str
    stored_until: datetime


class _SealedGrant(_Sealed):
    access_token: str = Field(repr=False)
    refresh_token: str | None = Field(default=None, repr=False)
    token_type: str
    expires_at: datetime | None
    scopes: list[str]
    issuer: str
    token_endpoint: str
    resource: str | None
    client_id: str
    auth_method: AuthMethod
    obtained_at: datetime
    generation: int


class _SealedClient(_Sealed):
    client_id: str
    client_secret: str | None = Field(default=None, repr=False)
    auth_method: AuthMethod
    issuer: str
    token_endpoint: str


class _SealedFlow(_Sealed):
    key: str
    profile: str
    backend: str
    issuer: str
    iss_required: bool
    token_endpoint: str
    authorize_url: str
    client_id: str
    auth_method: AuthMethod
    verifier: str = Field(repr=False)
    redirect_uri: str
    resource: str | None
    scopes: list[str]
    page_key: str


_S = TypeVar("_S", bound=_Sealed)


def backend_origin(url: str) -> str:
    """``scheme://host[:port]`` of a backend URL, lowercased: what a grant is bound to.

    The path is left out, since a backend may move it without changing who
    it is; the host is not, since that is who receives the token.
    """
    parts = urlsplit(url)
    return f"{parts.scheme}://{parts.netloc}".lower()


def slot_key(profile: str, backend: str) -> str:
    """The record key for one (profile, backend). ``:`` is in neither name's alphabet."""
    if not PROFILE_NAME_RE.match(profile) or not BACKEND_NAME_RE.match(backend):
        raise ValueError("profile and backend must be configured names")
    return f"{profile}:{backend}"


def flow_key(secret: str) -> str:
    """The record key for a flow: a hash, so the state is never on disk."""
    return hashlib.sha256(secret.encode()).hexdigest()


def _reveal(value: SecretStr | None) -> str | None:
    return None if value is None else value.get_secret_value()


def _hide(value: str | None) -> SecretStr | None:
    return None if value is None else SecretStr(value)


class BackendTokenStore:
    """Encrypted grants, client registrations and flows, one slot per (profile, backend).

    There is no listing: nothing reads a slot without naming its profile.
    """

    def __init__(self, records: Any, fernet: Fernet) -> None:
        self._records = records
        self._fernet = fernet
        self._locks: dict[str, asyncio.Lock] = {}
        self._holders: dict[str, asyncio.Task[Any] | None] = {}
        self._flow_lock = asyncio.Lock()

    @asynccontextmanager
    async def locked(self, profile: str, backend: str) -> AsyncIterator[None]:
        """Hold one slot for a read-modify-write: ``async with store.locked(p, b):``.

        The holder is the task that entered, and only it may ``put_grant``:
        ``Lock.locked()`` alone says the slot is held, not by whom.
        """
        slot = slot_key(profile, backend)
        lock = self._locks.get(slot)
        if lock is None:
            lock = self._locks[slot] = asyncio.Lock()
        async with lock:
            self._holders[slot] = asyncio.current_task()
            try:
                yield
            finally:
                del self._holders[slot]

    # ---------------------------------------------------------------- grants

    async def get_grant(self, profile: str, name: str, backend: Backend) -> BackendGrant | None:
        """The slot's grant, or None: absent, unreadable, expired, or for another host."""
        sealed = await self._open(_GRANTS, profile, name, backend, _SealedGrant)
        if sealed is None:
            return None
        return BackendGrant(
            access_token=SecretStr(sealed.access_token),
            refresh_token=_hide(sealed.refresh_token),
            token_type=sealed.token_type,
            expires_at=sealed.expires_at,
            scopes=tuple(sealed.scopes),
            issuer=sealed.issuer,
            token_endpoint=sealed.token_endpoint,
            resource=sealed.resource,
            client_id=sealed.client_id,
            auth_method=sealed.auth_method,
            obtained_at=sealed.obtained_at,
            generation=sealed.generation,
        )

    async def put_grant(
        self,
        profile: str,
        name: str,
        backend: Backend,
        grant: BackendGrant,
        *,
        expected_generation: int,
    ) -> BackendGrant:
        """Replace the slot's grant, if it is still the one the caller read.

        ``expected_generation`` is the ``generation`` of the grant the caller
        read, or 0 when there was none. Call under ``locked()``. Returns the
        grant as stored, carrying its new generation.
        """
        slot = slot_key(profile, name)
        if slot not in self._holders or self._holders[slot] is not asyncio.current_task():
            raise RuntimeError(
                "put_grant must be called by the task holding locked(profile, backend)"
            )
        current = await self.get_grant(profile, name, backend)
        if (current.generation if current else 0) != expected_generation:
            raise GrantConflictError(slot)
        stored = grant.model_copy(update={"generation": expected_generation + 1})
        await self._seal(
            _GRANTS,
            slot,
            _SealedGrant(
                slot=slot,
                origin=backend_origin(backend.url),
                stored_until=_now() + RECORD_TTL,
                access_token=stored.access_token.get_secret_value(),
                refresh_token=_reveal(stored.refresh_token),
                token_type=stored.token_type,
                expires_at=stored.expires_at,
                scopes=list(stored.scopes),
                issuer=stored.issuer,
                token_endpoint=stored.token_endpoint,
                resource=stored.resource,
                client_id=stored.client_id,
                auth_method=stored.auth_method,
                obtained_at=stored.obtained_at,
                generation=stored.generation,
            ),
        )
        return stored

    async def delete_grant(self, profile: str, name: str) -> bool:
        """Drop the slot's grant; its client registration stays."""
        return bool(await self._records.delete(slot_key(profile, name), collection=_GRANTS))

    # --------------------------------------------------------------- clients

    async def get_client(self, profile: str, name: str, backend: Backend) -> BackendClient | None:
        """The slot's client registration, or None."""
        sealed = await self._open(_CLIENTS, profile, name, backend, _SealedClient)
        if sealed is None:
            return None
        return BackendClient(
            client_id=sealed.client_id,
            client_secret=_hide(sealed.client_secret),
            auth_method=sealed.auth_method,
            issuer=sealed.issuer,
            token_endpoint=sealed.token_endpoint,
        )

    async def put_client(
        self, profile: str, name: str, backend: Backend, client: BackendClient
    ) -> None:
        """Record the slot's client registration."""
        slot = slot_key(profile, name)
        await self._seal(
            _CLIENTS,
            slot,
            _SealedClient(
                slot=slot,
                origin=backend_origin(backend.url),
                stored_until=_now() + RECORD_TTL,
                client_id=client.client_id,
                client_secret=_reveal(client.client_secret),
                auth_method=client.auth_method,
                issuer=client.issuer,
                token_endpoint=client.token_endpoint,
            ),
        )

    async def delete_client(self, profile: str, name: str) -> bool:
        """Drop the slot's client registration."""
        return bool(await self._records.delete(slot_key(profile, name), collection=_CLIENTS))

    # ----------------------------------------------------------------- flows

    async def put_flow(self, key: str, flow: BackendFlow) -> None:
        """Record a flow under ``key`` (a ``flow_key``) until it expires or is taken."""
        await self._seal(
            _FLOWS,
            key,
            _SealedFlow(
                slot=slot_key(flow.profile, flow.backend),
                origin=flow.origin,
                stored_until=flow.expires_at,
                key=key,
                profile=flow.profile,
                backend=flow.backend,
                issuer=flow.issuer,
                iss_required=flow.iss_required,
                token_endpoint=flow.token_endpoint,
                authorize_url=flow.authorize_url,
                client_id=flow.client_id,
                auth_method=flow.auth_method,
                verifier=flow.verifier.get_secret_value(),
                redirect_uri=flow.redirect_uri,
                resource=flow.resource,
                scopes=list(flow.scopes),
                page_key=flow.page_key,
            ),
            ttl=max(1.0, (flow.expires_at - _now()).total_seconds()),
        )

    async def peek_flow(self, key: str) -> BackendFlow | None:
        """The live flow under ``key``, left in place; None if absent or expired."""
        sealed = await self._unseal(_FLOWS, key, _SealedFlow)
        if sealed is None or sealed.key != key or sealed.stored_until <= _now():
            return None
        return BackendFlow(
            profile=sealed.profile,
            backend=sealed.backend,
            origin=sealed.origin,
            issuer=sealed.issuer,
            iss_required=sealed.iss_required,
            token_endpoint=sealed.token_endpoint,
            authorize_url=sealed.authorize_url,
            client_id=sealed.client_id,
            auth_method=sealed.auth_method,
            verifier=SecretStr(sealed.verifier),
            redirect_uri=sealed.redirect_uri,
            resource=sealed.resource,
            scopes=tuple(sealed.scopes),
            page_key=sealed.page_key,
            expires_at=sealed.stored_until,
        )

    async def take_flow(self, key: str) -> BackendFlow | None:
        """The flow under ``key``, removed before it is returned: a state is spent once.

        Serialized, so two callbacks racing on one state cannot both read it.
        """
        async with self._flow_lock:
            flow = await self.peek_flow(key)
            await self._records.delete(key, collection=_FLOWS)
        return flow

    async def drop_flow(self, key: str) -> None:
        """Forget a flow without finishing it."""
        await self._records.delete(key, collection=_FLOWS)

    # --------------------------------------------------------------- envelope

    async def _seal(
        self, collection: str, key: str, record: _Sealed, *, ttl: float | None = None
    ) -> None:
        token = self._fernet.encrypt(record.model_dump_json().encode())
        await self._records.put(
            key,
            {"v": _ENVELOPE_VERSION, "ct": token.decode("ascii")},
            collection=collection,
            ttl=RECORD_TTL.total_seconds() if ttl is None else ttl,
        )

    async def _unseal(self, collection: str, key: str, model: type[_S]) -> _S | None:
        """Read and decrypt one record; None for anything that is not a good one.

        Every refusal is logged by key (operator names, or a hash) and
        exception class, never by content: a record that fails to parse may
        hold a token.
        """
        from cryptography.fernet import InvalidToken

        try:
            envelope = await self._records.get(key, collection=collection)
        except Exception as exc:
            logger.warning(
                "backend-tokens: %s %s unreadable (%s at %s)",
                collection,
                key,
                exc_kind(exc),
                exc_where(exc),
            )
            return None
        if envelope is None:
            return None
        # TRUST: a record read back from the data volume
        #   untrusted: the file's contents; anything with write access to /data wrote it
        #   judged-by: Fernet (authenticated encryption) under the derived key, then
        #     the sealed slot, key and origin compared to what was asked for
        #   on-failure: fail-closed; the record reads as absent and the backend needs auth
        #   owner: backend_tokens.BackendTokenStore._unseal
        #   evidence: T2 test_backend_tokens planted-plaintext, copied-slot and moved-host cases
        ciphertext = envelope.get("ct") if isinstance(envelope, dict) else None
        if not isinstance(ciphertext, str) or envelope.get("v") != _ENVELOPE_VERSION:
            logger.warning("backend-tokens: %s %s is not a sealed record; ignored", collection, key)
            return None
        try:
            return model.model_validate_json(self._fernet.decrypt(ciphertext.encode("ascii")))
        except (InvalidToken, ValidationError, ValueError) as exc:
            logger.warning(
                "backend-tokens: %s %s did not open (%s); ignored", collection, key, exc_kind(exc)
            )
            return None

    async def _open(
        self, collection: str, profile: str, name: str, backend: Backend, model: type[_S]
    ) -> _S | None:
        """One slot's record, if it is that slot's, for the backend's current host, and live."""
        slot = slot_key(profile, name)
        sealed = await self._unseal(collection, slot, model)
        if sealed is None:
            return None
        if sealed.slot != slot:
            logger.warning(
                "backend-tokens: %s %s holds another slot's record; ignored", collection, slot
            )
        elif sealed.origin != backend_origin(backend.url):
            logger.info(
                "backend-tokens: %s %s was for another host; needs auth again", collection, slot
            )
        elif sealed.stored_until > _now():
            return sealed
        return None


def _derive(secret: str, purpose: bytes) -> bytes:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF

    return HKDF(algorithm=hashes.SHA256(), length=32, salt=_HKDF_SALT, info=purpose).derive(
        secret.encode()
    )


def open_backend_token_store(root: Path | None = None) -> BackendTokenStore | None:
    """The store under ``root`` (default: beside the audit DB), or None without a key.

    The directory is named for a fingerprint of a key derived for that
    purpose alone, so a rotated key starts empty and every slot authorizes
    again, and the name says nothing about the encryption key.
    """
    secret = read_secret_env(KEY_ENV, record=False)
    if not secret:
        return None
    if len(secret) < MIN_KEY_CHARS:
        raise ProfileConfigError(
            f"{KEY_ENV} is under {MIN_KEY_CHARS} characters; generate one with "
            "`openssl rand -base64 48`"
        )
    from cryptography.fernet import Fernet
    from key_value.aio.stores import filetree

    base = root if root is not None else Path(get_config().db_path).parent / "backend-oauth"
    directory = base / hashlib.sha256(_derive(secret, b"directory")).hexdigest()[:12]
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    for path in (base, directory):
        os.chmod(path, 0o700)
    return BackendTokenStore(
        filetree.FileTreeStore(
            data_directory=directory,
            key_sanitization_strategy=filetree.FileTreeV1KeySanitizationStrategy(directory),
            collection_sanitization_strategy=(
                filetree.FileTreeV1CollectionSanitizationStrategy(directory)
            ),
        ),
        Fernet(base64.urlsafe_b64encode(_derive(secret, b"fernet"))),
    )


_store: BackendTokenStore | None = None


def configure_backend_tokens(profiles: Mapping[str, Profile]) -> BackendTokenStore | None:
    """Open the store once, at startup, before the env scrub drops the key.

    Warns when a profile has an OAuth backend and there is no key: those
    backends will report "needs auth" until one is set and the gateway
    restarts. A warning, not a refusal, so a missing key costs those backends
    and nothing else.
    """
    global _store
    _store = open_backend_token_store()
    wanting = sum(
        1 for profile in profiles.values() for b in profile.backends.values() if b.auth is not None
    )
    if _store is None and wanting:
        logger.warning(
            "gateway: backend OAuth configured for %d backend(s) but %s_FILE is unset; "
            'they will report "needs auth"',
            wanting,
            KEY_ENV,
        )
    return _store


def backend_token_store() -> BackendTokenStore | None:
    """The store opened at startup, or None when there is no key."""
    return _store
