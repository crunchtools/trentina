"""HTTP surface of the bridge on the gateway.

* ``POST /bridge/{profile}/event`` — the bridge process hands over one
  decrypted upstream event. Bearer ``ingress_token``. Answers 200 only once
  the event is in the agent's Conduit (or deliberately withheld or skipped),
  so the bridge advances its sync position only past what landed.
* ``/bridge/as/{profile}/...`` — the appservice API Conduit calls. Bearer
  ``hs_token``. Transactions carry the agent's events outbound.
* ``/bridge/{profile}/{channel}/event`` and
  ``/bridge/as/{profile}/{channel}/_matrix/app/v1/...`` — the same two, for
  a channel in the profile's ``bridges`` (#483). The paths above are the
  ``matrix`` channel's, which ``matrix_bridge`` configures.

Tokens are accepted in the ``Authorization`` header only. Conduit sends
the ``hs_token`` both ways (``conduit/src/api/appservice_server.rs``: ruma's
``SendAccessToken::IfRequired`` sets the header, and the query string is
appended after); the query copy is ignored rather than honoured, so nothing
here depends on a credential that access logs record.
"""

from __future__ import annotations

import hmac
import logging
from http import HTTPStatus
from typing import TYPE_CHECKING, Any

from pydantic import BaseModel, ConfigDict, Field, ValidationError
from starlette.responses import JSONResponse, Response

from ...httpbody import TooLargeError, read_capped, where_invalid
from ...logsafe import exc_kind
from ..profile import MATRIX_CHANNEL
from .appservice import AppService, ConduitError
from .core import BridgeUnavailableError, ProfileBridge
from .mapping import BridgeMapping

if TYPE_CHECKING:
    from pathlib import Path

    from pydantic import SecretStr
    from starlette.requests import Request

    from ..profile import Profile

logger = logging.getLogger(__name__)


class RoomInfo(BaseModel):
    """What the bridge knows about the room an event arrived in."""

    model_config = ConfigDict(extra="forbid", strict=True)

    name: str = ""
    topic: str = ""
    is_direct: bool = False
    # In a direct message, the other member, so the local DM can be theirs.
    peer: str = ""
    peer_displayname: str = ""
    # On a room announcement only: every member but the bridge's own user,
    # joined or invited (#264). None from a bridge that reports none.
    members: list[str] | None = None


class BridgeEvent(BaseModel):
    """One upstream event, as the bridge process hands it over. Our own wire
    format, so anything unexpected in it is refused."""

    model_config = ConfigDict(extra="forbid", strict=True)

    room_id: str = Field(min_length=1)
    event_id: str = Field(min_length=1)
    sender: str = Field(min_length=1)
    sender_displayname: str = ""
    type: str = Field(min_length=1)
    content: dict[str, Any] = Field(default_factory=dict)
    redacts: str | None = None
    room: RoomInfo = Field(default_factory=RoomInfo)


class AgentEvent(BaseModel):
    """A client-format event as Conduit pushes it: every field the spec
    defines (plus the two legacy ones homeservers still send), so an event
    carrying anything else is refused. Only the first six are read."""

    model_config = ConfigDict(extra="forbid", strict=True)

    event_id: str
    room_id: str
    sender: str
    type: str
    content: dict[str, Any] = Field(default_factory=dict)
    redacts: str | None = None
    origin_server_ts: int | None = None
    state_key: str | None = None
    unsigned: dict[str, Any] | None = None
    age: int | None = None
    user_id: str | None = None


class Transaction(BaseModel):
    """An appservice transaction: the spec's sections, stable and MSC2409's
    unstable spelling. Only ``events`` is carried; the bridge moves timeline
    events, not presence, receipts or to-device traffic."""

    model_config = ConfigDict(extra="forbid", strict=True, populate_by_name=True)

    events: list[AgentEvent] = Field(default_factory=list)
    ephemeral: list[dict[str, Any]] | None = None
    to_device: list[dict[str, Any]] | None = None
    unstable_ephemeral: list[dict[str, Any]] | None = Field(
        default=None, alias="de.sorunome.msc2409.ephemeral"
    )
    unstable_to_device: list[dict[str, Any]] | None = Field(
        default=None, alias="de.sorunome.msc2409.to_device"
    )


def bridged_agents(profiles: dict[str, Profile]) -> frozenset[str]:
    """The upstream user of every bridge on every profile (#264, #483).

    Enabled or not: a block that is switched off still names an agent's
    upstream identity, and another bridge talking to it is the same channel.
    ``public_user_id`` is the only upstream ID a bridge carries; the bridge
    process speaks as it (``BRIDGE_USER_ID``).
    """
    return frozenset(
        cfg.public_user_id for p in profiles.values() for cfg in p.channel_bridges().values()
    )


def _store_name(profile: str, channel: str) -> str:
    """The mapping store's file name. The matrix channel keeps the name it
    had before #483, so its rooms are not mirrored a second time."""
    return f"bridge-{profile}.db" if channel == MATRIX_CHANNEL else f"bridge-{profile}-{channel}.db"


def build_bridges(
    profiles: dict[str, Profile], data_dir: Path, other_agents: frozenset[str] = frozenset()
) -> dict[tuple[str, str], ProfileBridge]:
    """Build the gateway half of every enabled bridge, on every channel.

    Args:
        profiles: the loaded profiles; each enabled bridge (and so one with
            resolved tokens) in ``matrix_bridge`` or ``bridges`` gets one.
        data_dir: where each mapping store goes (``_store_name``). Created
            if absent.
        other_agents: agents' Matrix IDs that no profile bridges
            (``matrix.other_agent_user_ids``), refused like a bridged one.

    Returns:
        ``{(profile, channel): ProfileBridge}``, empty when no bridge is
        enabled. Each owns HTTP clients and a SQLite store;
        ``close_bridges`` closes the ones registered at startup.
    """
    out: dict[tuple[str, str], ProfileBridge] = {}
    agents = bridged_agents(profiles) | other_agents
    for name, profile in profiles.items():
        for channel, cfg in profile.channel_bridges().items():
            if not cfg.enabled or cfg.local.as_token is None:
                continue
            mapping = BridgeMapping(data_dir / _store_name(name, channel))
            appservice = AppService(
                homeserver=cfg.local.homeserver,
                server_name=cfg.local.server_name,
                as_token=cfg.local.as_token.get_secret_value(),
                sender_localpart=cfg.local.sender_localpart,
                user_prefix=cfg.local.user_prefix,
                agent_localpart=cfg.local.agent_localpart,
                mapping=mapping,
            )
            out[(name, channel)] = ProfileBridge(
                profile,
                mapping=mapping,
                appservice=appservice,
                other_agents=agents,
                channel=channel,
            )
    return out


def _presented(request: Request) -> str:
    header = request.headers.get("authorization", "")
    return header[7:].strip() if header.lower().startswith("bearer ") else ""


def _matches(presented: str, expected: SecretStr | None) -> bool:
    if expected is None or not presented:
        return False
    return hmac.compare_digest(
        presented.encode("utf-8"), expected.get_secret_value().encode("utf-8")
    )


def _refused(status: int, errcode: str, error: str) -> JSONResponse:
    return JSONResponse({"errcode": errcode, "error": error}, status_code=status)


# The bridges registered at startup, so the gateway's lifespan can close them.
_registered: list[ProfileBridge] = []


def outbound_refused() -> int | None:
    """The agents' events refused outbound since start, every bridge summed;
    None when no bridge is running. For /health, so a monitoring check can
    alert on a paging path that stopped delivering (#317)."""
    if not _registered:
        return None
    return sum(b.outbound_refused for b in _registered)


async def close_bridges() -> None:
    """Close every registered bridge's clients and store. Called on shutdown."""
    while _registered:
        await _registered.pop().aclose()


class BridgeRoutes:
    """The endpoints, bound to the bridges built at startup."""

    def __init__(self, bridges: dict[tuple[str, str], ProfileBridge]) -> None:
        self._bridges = bridges

    def _bridge(self, request: Request) -> ProfileBridge | None:
        """The bridge a path names. No ``channel`` in it is the matrix one."""
        params = request.path_params
        key = (str(params.get("profile", "")), str(params.get("channel", MATRIX_CHANNEL)))
        return self._bridges.get(key)

    def _for_ingress(self, request: Request) -> ProfileBridge | None:
        bridge = self._bridge(request)
        if bridge is None or not _matches(_presented(request), bridge.cfg.ingress_token):
            return None
        return bridge

    def _for_homeserver(self, request: Request) -> ProfileBridge | None:
        bridge = self._bridge(request)
        if bridge is None or not _matches(_presented(request), bridge.cfg.local.hs_token):
            return None
        return bridge

    async def event(self, request: Request) -> Response:
        bridge = self._for_ingress(request)
        if bridge is None:
            return _refused(401, "M_UNKNOWN_TOKEN", "unauthorized")
        try:
            event = BridgeEvent.model_validate_json(await read_capped(request))
        except TooLargeError:
            return _refused(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, "M_TOO_LARGE", "event too large")
        except ValidationError as exc:
            logger.warning(
                "matrix_bridge: malformed event for %s at %s",
                bridge.label,
                where_invalid(exc),
            )
            return _refused(400, "M_BAD_JSON", "malformed event")
        try:
            outcome = await bridge.inbound(event.model_dump())
        except (KeyError, TypeError, ValueError) as exc:
            logger.warning(
                "matrix_bridge: event for %s refused by the bridge core: %s",
                bridge.label,
                exc_kind(exc),
            )
            return _refused(400, "M_BAD_JSON", "malformed event")
        except (ConduitError, OSError) as exc:
            logger.warning(
                "matrix_bridge: could not deliver for %s: %s", bridge.label, exc_kind(exc)
            )
            return _refused(503, "M_UNKNOWN", "delivery failed, retry")
        return JSONResponse({"outcome": outcome})

    async def transaction(self, request: Request) -> Response:
        bridge = self._for_homeserver(request)
        if bridge is None:
            return _refused(403, "M_FORBIDDEN", "bad hs_token")
        try:
            txn = Transaction.model_validate_json(await read_capped(request))
        except TooLargeError:
            return _refused(
                HTTPStatus.REQUEST_ENTITY_TOO_LARGE, "M_TOO_LARGE", "transaction too large"
            )
        except ValidationError as exc:
            logger.warning(
                "matrix_bridge: malformed transaction for %s at %s",
                bridge.label,
                where_invalid(exc),
            )
            return _refused(400, "M_BAD_JSON", "malformed transaction")
        try:
            await bridge.outbound(
                str(request.path_params["txn"]), [e.model_dump() for e in txn.events]
            )
        except (BridgeUnavailableError, ConduitError, OSError) as exc:
            logger.warning("matrix_bridge: outbound failed for %s: %s", bridge.label, exc_kind(exc))
            return _refused(503, "M_UNKNOWN", "bridge unavailable, retry")
        return JSONResponse({})

    async def query(self, request: Request) -> Response:
        """User and alias queries: nothing is created on demand."""
        if self._for_homeserver(request) is None:
            return _refused(403, "M_FORBIDDEN", "bad hs_token")
        return _refused(404, "M_NOT_FOUND", "not provisioned on demand")

    async def ping(self, request: Request) -> Response:
        if self._for_homeserver(request) is None:
            return _refused(403, "M_FORBIDDEN", "bad hs_token")
        return JSONResponse({})


def register_bridge_routes(
    mcp_server: Any,
    profiles: dict[str, Profile],
    data_dir: Path,
    *,
    other_agents: frozenset[str] = frozenset(),
) -> BridgeRoutes | None:
    """Wire the bridge endpoints for every enabled bridge. Bound at startup.

    Args:
        mcp_server: the FastMCP server; routes go on via ``custom_route``.
        profiles: the loaded profiles (see ``build_bridges``).
        data_dir: where the mapping stores live.
        other_agents: see ``build_bridges``.

    Returns:
        The bound handlers, or None when no profile has an enabled bridge,
        in which case no route is registered at all.
    """
    bridges = build_bridges(profiles, data_dir, other_agents)
    if not bridges:
        return None
    _registered.extend(bridges.values())
    handlers = BridgeRoutes(bridges)
    route = mcp_server.custom_route
    route("/bridge/{profile}/event", methods=["POST"])(handlers.event)
    # The spec's prefixed paths, and the unprefixed ones older homeservers use.
    for prefix in ("/bridge/as/{profile}/_matrix/app/v1", "/bridge/as/{profile}"):
        _appservice_routes(route, prefix, handlers)
    route("/bridge/as/{profile}/_matrix/app/v1/ping", methods=["POST"])(handlers.ping)
    # Further channels (#483): prefixed paths only, since each is a new
    # registration and every homeserver we register with sends those.
    if any(channel != MATRIX_CHANNEL for _, channel in bridges):
        route("/bridge/{profile}/{channel}/event", methods=["POST"])(handlers.event)
        prefix = "/bridge/as/{profile}/{channel}/_matrix/app/v1"
        _appservice_routes(route, prefix, handlers)
        route(f"{prefix}/ping", methods=["POST"])(handlers.ping)
    logger.warning(
        "matrix_bridge: serving %s", ", ".join(sorted(b.label for b in bridges.values()))
    )
    return handlers


def _appservice_routes(route: Any, prefix: str, handlers: BridgeRoutes) -> None:
    """The transaction and query endpoints Conduit calls, under ``prefix``."""
    route("/".join((prefix, "transactions", "{txn}")), methods=["PUT"])(handlers.transaction)
    for kind, param in (("users", "{user}"), ("rooms", "{alias}")):
        route("/".join((prefix, kind, param)), methods=["GET"])(handlers.query)
