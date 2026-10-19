"""What an RCS provider has to do for the bridge, and nothing more.

Twilio is the first provider (``twilio.py``). Another one (a toll-free SMS
fallback, say) only has to verify its own webhooks, read its own form, and
send one text; the bridge, the queue and the gateway contract stay the same.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol


class BackendError(RuntimeError):
    """The provider did not take a message. ``permanent`` when retrying
    cannot help (a body it refuses, a number it cannot reach)."""

    def __init__(self, reason: str, *, permanent: bool = False) -> None:
        super().__init__(reason)
        # Ours: a status and the provider's error number, never its text.
        self.reason = reason
        self.permanent = permanent


@dataclass(frozen=True)
class Inbound:
    """One message from the owner, as the provider's webhook carried it."""

    message_id: str
    sender: str  # E.164
    body: str
    # ``(url, declared content type)`` of each attachment, fetched only at
    # delivery (#493): the webhook answers before any bytes move.
    media: tuple[tuple[str, str], ...] = ()


class Backend(Protocol):
    """One provider account, one agent's sender."""

    def verify(self, url: str, form: list[tuple[str, str]], signature: str) -> bool:
        """Whether a webhook request was signed by the provider."""
        ...

    def parse(self, form: list[tuple[str, str]]) -> Inbound | None:
        """The message a verified webhook carries, or None for a request
        that carries none (a status callback, an account it is not for)."""
        ...

    async def send_text(self, to: str, body: str) -> str:
        """Send one text to an E.164 number; the provider's message ID."""
        ...

    async def send_media(self, to: str, media_url: str, body: str) -> str:
        """Send media the provider fetches from ``media_url``, with an
        optional caption; the provider's message ID."""
        ...

    async def fetch_media(self, url: str) -> dict[str, Any]:
        """One inbound attachment as the gateway's ``media`` item: ``status``
        ok with ``content_type`` and ``base64``, or too_large/unavailable.
        Never raises."""
        ...

    async def send_typing(self, to: str) -> None:
        """Show the agent typing on an E.164 number's phone, briefly."""
        ...

    async def aclose(self) -> None: ...
