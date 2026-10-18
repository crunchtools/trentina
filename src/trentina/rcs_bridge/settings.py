"""The RCS bridge's configuration, from its own environment.

Like the Matrix bridge's (``bridge/settings.py``), deliberately not
profiles.yaml: this process holds the RCS provider's credentials and the
gateway does not. Every secret accepts the ``_FILE`` form.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

from ..bridge.settings import (
    SettingsError,
    parse_port,
    private_gateway_url,
    read_setting,
    required_setting,
)
from ..gateway.loader import read_env_or_file, read_secret_env
from ..gateway.profile import is_matrix_user_id

DEFAULT_API_PORT = 8472
DEFAULT_WEBHOOK_PORT = 8473
DEFAULT_TWILIO_API = "https://api.twilio.com"
# The synthetic server the owner's and the room's IDs live under. Reserved by
# RFC 2606, so no real homeserver can ever be named this.
DEFAULT_SERVER = "rcs.invalid"
DEFAULT_ROOM_TOPIC = "Text messages with the owner's phone over RCS"

_E164_RE = re.compile(r"^\+[1-9][0-9]{6,14}$")
_ACCOUNT_SID_RE = re.compile(r"^AC[0-9a-f]{32}$")
_SENDER_ID_RE = re.compile(r"^[A-Za-z0-9_]{1,128}$")


def _e164(name: str, value: str) -> str:
    if not _E164_RE.match(value):
        raise SettingsError(f"{name} must be an E.164 number like +15551234567")
    return value


def _account_sid(value: str) -> str:
    if not _ACCOUNT_SID_RE.match(value):
        raise SettingsError("RCS_TWILIO_ACCOUNT_SID is not a Twilio account SID")
    return value


def _sender_id(value: str) -> str:
    """The RCS sender's ID from its Settings page, with or without `rcs:`.
    Sending from it directly needs no Messaging Service, which Twilio only
    allows an RCS sender into after carrier approval, and can never fall
    back to SMS."""
    sender = value.removeprefix("rcs:")
    if not _SENDER_ID_RE.match(sender):
        raise SettingsError("RCS_TWILIO_SENDER_ID is not an RCS sender ID")
    return sender


def _https_url(name: str, value: str) -> str:
    """The public URL Twilio calls. It is half of what the signature covers,
    so it must be exactly what is configured in the console."""
    parsed = urlparse(value)
    if parsed.scheme != "https" or not parsed.hostname or parsed.fragment:
        raise SettingsError(f"{name} must be the https URL Twilio calls")
    return value


def _api_url(value: str) -> str:
    """Where the auth token goes, as Basic auth: TLS only, whatever the host."""
    parsed = urlparse(value)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        raise SettingsError("RCS_TWILIO_API must be an https URL with no credentials")
    return value.rstrip("/")


@dataclass(frozen=True)
class RcsSettings:
    """Everything the RCS bridge needs to run."""

    profile: str
    channel: str
    gateway_url: str
    ingress_token: str
    bridge_token: str
    # The agent's upstream identity: the gateway profile's public_user_id.
    agent_user_id: str
    owner_number: str
    owner_name: str
    room_topic: str
    server: str
    store_dir: Path
    listen_host: str
    listen_port: int
    webhook_host: str
    webhook_port: int
    webhook_url: str
    account_sid: str
    auth_token: str
    sender_id: str
    twilio_api: str

    @property
    def owner_user_id(self) -> str:
        """The owner as the gateway sees them: a stand-in named by number."""
        return f"@tel{self.owner_number[1:]}:{self.server}"

    @property
    def room_id(self) -> str:
        """The one room: the agent's DM with the owner."""
        localpart = self.agent_user_id[1:].partition(":")[0]
        return f"!{localpart}-owner:{self.server}"

    @classmethod
    def from_env(cls) -> RcsSettings:
        agent = required_setting("RCS_AGENT_USER_ID", read_env_or_file)
        if not is_matrix_user_id(agent):
            raise SettingsError("RCS_AGENT_USER_ID must be a Matrix user ID")
        server = os.environ.get("RCS_SERVER", DEFAULT_SERVER)
        if not is_matrix_user_id(f"@x:{server}"):
            raise SettingsError("RCS_SERVER must be a Matrix server name")
        return cls(
            profile=required_setting("BRIDGE_PROFILE", read_env_or_file),
            channel=os.environ.get("BRIDGE_CHANNEL", "rcs"),
            gateway_url=private_gateway_url(required_setting("BRIDGE_GATEWAY_URL")),
            ingress_token=required_setting("BRIDGE_INGRESS_TOKEN"),
            bridge_token=required_setting("BRIDGE_TOKEN"),
            agent_user_id=agent,
            owner_number=_e164("RCS_OWNER_NUMBER", required_setting("RCS_OWNER_NUMBER")),
            owner_name=os.environ.get("RCS_OWNER_NAME", "Owner (phone)"),
            # The gateway judges the topic with every message, so it must
            # describe, never instruct: the old "confirm destructive actions
            # in Matrix" scored as an injection and withheld every text.
            room_topic=os.environ.get("RCS_ROOM_TOPIC", DEFAULT_ROOM_TOPIC),
            server=server,
            store_dir=Path(os.environ.get("BRIDGE_STORE_DIR", "/data")),
            listen_host=os.environ.get("BRIDGE_LISTEN_HOST", "127.0.0.1"),
            listen_port=parse_port(
                "BRIDGE_LISTEN_PORT", os.environ.get("BRIDGE_LISTEN_PORT", str(DEFAULT_API_PORT))
            ),
            webhook_host=os.environ.get("RCS_WEBHOOK_HOST", "127.0.0.1"),
            webhook_port=parse_port(
                "RCS_WEBHOOK_PORT", os.environ.get("RCS_WEBHOOK_PORT", str(DEFAULT_WEBHOOK_PORT))
            ),
            webhook_url=_https_url("RCS_WEBHOOK_URL", required_setting("RCS_WEBHOOK_URL")),
            account_sid=_account_sid(required_setting("RCS_TWILIO_ACCOUNT_SID")),
            auth_token=required_setting("RCS_TWILIO_AUTH_TOKEN", read_secret_env),
            sender_id=_sender_id(required_setting("RCS_TWILIO_SENDER_ID")),
            twilio_api=_api_url(read_setting("RCS_TWILIO_API") or DEFAULT_TWILIO_API),
        )
