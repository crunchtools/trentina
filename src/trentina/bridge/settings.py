"""The bridge process's configuration, from its own environment.

Deliberately NOT profiles.yaml. The bridge holds the upstream Matrix identity
and nothing else; the gateway holds the agent's homeserver and nothing of the
upstream one. Two processes, two environments, and neither can read the
other's (spec 015). Every secret accepts the ``_FILE`` form.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING
from urllib.parse import urlparse

from ..gateway.errors import ProfileConfigError
from ..gateway.loader import read_env_or_file, read_secret_env
from ..gateway.profile import is_matrix_user_id, private_url

if TYPE_CHECKING:
    from collections.abc import Callable

DEFAULT_HOMESERVER = "https://matrix-client.matrix.org"
DEFAULT_PORT = 8471


class SettingsError(RuntimeError):
    """A required setting is missing. Fatal at startup."""


def read_setting(name: str, reader: Callable[[str], str] = read_secret_env) -> str:
    """A value from ``NAME`` or ``NAME_FILE``, with one error type for every
    way it can be unusable. The profile name, which every log line carries
    on purpose, passes ``read_env_or_file`` so it is not held out of the log
    (#344). The Matrix IDs and the gateway URL stay held: the #262 rule keeps
    them out of the log anyway, and holding them backs that up."""
    try:
        return reader(name)
    except ProfileConfigError as exc:
        raise SettingsError(str(exc)) from exc


def _http_url(name: str, value: str) -> str:
    """An http(s) URL with a host, trailing slash dropped."""
    parsed = urlparse(value)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise SettingsError(f"{name} must be an http(s) URL with a host, got {value!r}")
    return value.rstrip("/")


_MAX_PORT = 65535


def parse_port(value: str) -> int:
    if not value.isdigit() or not 0 < int(value) <= _MAX_PORT:
        raise SettingsError(f"BRIDGE_LISTEN_PORT must be a port number, got {value!r}")
    return int(value)


def private_gateway_url(value: str) -> str:
    """The gateway receives decrypted events and the ingress token, so it
    must be on a private host, by the same rule as the gateway's own bridge
    URLs; no userinfo or fragment either."""
    parsed = urlparse(value)
    if parsed.username or parsed.password or parsed.fragment:
        raise SettingsError("BRIDGE_GATEWAY_URL must not carry credentials or a fragment")
    try:
        return private_url(value)
    except ValueError as exc:
        raise SettingsError(f"BRIDGE_GATEWAY_URL: {exc}") from exc


def required_setting(name: str, reader: Callable[[str], str] = read_secret_env) -> str:
    value = read_setting(name, reader)
    if not value:
        raise SettingsError(f"{name} (or {name}_FILE) is required")
    return value


def _inviters() -> frozenset[str]:
    """``BRIDGE_ALLOWED_INVITERS``: comma-separated Matrix user IDs whose
    invites the bridge accepts (#264). Not a secret, but it takes the
    ``_FILE`` form like one so a unit can mount it. Empty is legal and means
    no invite is accepted; a malformed entry is fatal rather than skipped,
    because a typo would otherwise shut out the one person meant to get in."""
    raw = read_setting("BRIDGE_ALLOWED_INVITERS")
    ids = {part.strip() for part in raw.split(",") if part.strip()}
    bad = sum(1 for user in ids if not is_matrix_user_id(user, historical=True))
    if bad:
        raise SettingsError(f"BRIDGE_ALLOWED_INVITERS: {bad} entries are not Matrix user IDs")
    return frozenset(ids)


@dataclass(frozen=True)
class BridgeSettings:
    """Everything the bridge needs to run."""

    profile: str
    homeserver: str
    user_id: str
    store_dir: Path
    pickle_key: str
    gateway_url: str
    ingress_token: str
    bridge_token: str
    listen_host: str
    listen_port: int
    device_name: str
    # Exactly one way in: a saved session, an adopted device, or a password.
    device_id: str
    access_token: str
    password: str
    # Whose invites are accepted; empty accepts none (#264).
    allowed_inviters: frozenset[str] = frozenset()

    @classmethod
    def from_env(cls) -> BridgeSettings:
        return cls(
            profile=required_setting("BRIDGE_PROFILE", read_env_or_file),
            homeserver=_http_url(
                "BRIDGE_HOMESERVER", os.environ.get("BRIDGE_HOMESERVER", DEFAULT_HOMESERVER)
            ),
            user_id=required_setting("BRIDGE_USER_ID"),
            store_dir=Path(os.environ.get("BRIDGE_STORE_DIR", "/data")),
            pickle_key=required_setting("BRIDGE_PICKLE_KEY"),
            gateway_url=private_gateway_url(required_setting("BRIDGE_GATEWAY_URL")),
            ingress_token=required_setting("BRIDGE_INGRESS_TOKEN"),
            bridge_token=required_setting("BRIDGE_TOKEN"),
            listen_host=os.environ.get("BRIDGE_LISTEN_HOST", "127.0.0.1"),
            listen_port=parse_port(os.environ.get("BRIDGE_LISTEN_PORT", str(DEFAULT_PORT))),
            device_name=os.environ.get("BRIDGE_DEVICE_NAME", "Trentina bridge"),
            device_id=os.environ.get("BRIDGE_DEVICE_ID", ""),
            access_token=read_setting("BRIDGE_ACCESS_TOKEN"),
            password=read_setting("BRIDGE_PASSWORD"),
            allowed_inviters=_inviters(),
        )
