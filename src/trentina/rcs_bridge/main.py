"""``python -m trentina.rcs_bridge.main run``: one agent's RCS bridge.

Three tasks, and any one ending ends the bridge: the delivery loop, the
private API the gateway calls, and the public webhook Twilio calls. A bridge
that can take messages but not deliver them, or deliver but not take them,
is worse than one that is plainly down and restarted by systemd.
"""

from __future__ import annotations

import argparse
import asyncio
import logging
from typing import TYPE_CHECKING

import uvicorn

from .. import logsafe
from ..bridge.settings import SettingsError
from .api import build_private_app, build_public_app
from .bridge import RcsBridge
from .settings import RcsSettings
from .store import RcsStore
from .twilio import TwilioBackend

if TYPE_CHECKING:
    from starlette.applications import Starlette

logger = logging.getLogger("trentina.rcs_bridge")


def _server(app: Starlette, host: str, port: int) -> uvicorn.Server:
    return uvicorn.Server(uvicorn.Config(app, host=host, port=port, log_level="warning"))


async def _run(settings: RcsSettings) -> None:
    backend = TwilioBackend(
        account_sid=settings.account_sid,
        auth_token=settings.auth_token,
        messaging_service_sid=settings.messaging_service_sid,
        api=settings.twilio_api,
    )
    bridge = RcsBridge(settings, backend, RcsStore(settings.store_dir / "rcs.db"))
    try:
        tasks = [
            asyncio.create_task(bridge.run(), name="deliver"),
            asyncio.create_task(
                _server(
                    build_private_app(bridge), settings.listen_host, settings.listen_port
                ).serve(),
                name="api",
            ),
            asyncio.create_task(
                _server(
                    build_public_app(bridge), settings.webhook_host, settings.webhook_port
                ).serve(),
                name="webhook",
            ),
        ]
        try:
            done, _ = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
            for task in done:
                task.result()
        finally:
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
    finally:
        await bridge.aclose()


def main(argv: list[str] | None = None) -> None:
    logsafe.configure("BRIDGE_LOG_LEVEL", default="WARNING")
    parser = argparse.ArgumentParser(prog="trentina-rcs-bridge")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("run", help="run the bridge")
    parser.parse_args(argv)

    from ..gateway.loader import secret_env_names
    from ..posture import check_secret_sources, check_startup_posture

    check_startup_posture()
    try:
        settings = RcsSettings.from_env()
    except SettingsError as exc:
        raise SystemExit(f"rcs bridge: {exc}") from exc
    check_secret_sources(secret_env_names())
    logger.warning("rcs bridge[%s/%s]: starting", settings.profile, settings.channel)
    asyncio.run(_run(settings))


if __name__ == "__main__":
    main()
