"""Drive every family in every mode with the layers replaced by fakes.

Only the edges are faked: the producers' I/O (HTTP, L0 search), and the three
layers' model calls (L2's classifier, L3's detect/extract/verify). Everything
between — L1, defend(), modes.py, internal_edge.py, warning.py, report.py, the
blocklist database — is the real code, so a test that passes here is
exercising the path production runs.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import ExitStack, contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any
from unittest.mock import AsyncMock, patch

from trentina import config as config_mod
from trentina.modes import Mode
from trentina.quarantine.classifier import ClassifierResult
from trentina.tools import (
    block_content,
    block_dir,
    block_fetch,
    block_read,
    block_search,
    flag_content,
    flag_dir,
    flag_fetch,
    flag_read,
    flag_search,
    redact_content,
    redact_dir,
    redact_fetch,
    redact_read,
    redact_search,
)

if TYPE_CHECKING:
    import pytest

BENIGN = ClassifierResult(label="BENIGN", score=0.02, latency_ms=1.0)
MALICIOUS = ClassifierResult(label="MALICIOUS", score=0.97, latency_ms=1.0)
CLEAN_DETECT: dict[str, Any] = {
    "injection_detected": False,
    "risk_level": "low",
    "summary": "nothing found",
}
EXTRACTION: dict[str, Any] = {
    "content": {
        "extracted_text": "The maintenance window is Tuesday.",
        "title": "Maintenance",
        "confidence": "high",
        "injection_detected": False,
        "injection_details": "L3 PROSE THAT MUST NOT BE DELIVERED",
    },
    "usage": {"input_tokens": 10, "output_tokens": 5},
}

FAMILIES = ("fetch", "read", "dir", "content", "search")
MODES = (Mode.BLOCK, Mode.FLAG, Mode.REDACT)

_TOOLS = {
    ("fetch", Mode.BLOCK): block_fetch,
    ("fetch", Mode.FLAG): flag_fetch,
    ("fetch", Mode.REDACT): redact_fetch,
    ("read", Mode.BLOCK): block_read,
    ("read", Mode.FLAG): flag_read,
    ("read", Mode.REDACT): redact_read,
    ("dir", Mode.BLOCK): block_dir,
    ("dir", Mode.FLAG): flag_dir,
    ("dir", Mode.REDACT): redact_dir,
    ("content", Mode.BLOCK): block_content,
    ("content", Mode.FLAG): flag_content,
    ("content", Mode.REDACT): redact_content,
    ("search", Mode.BLOCK): block_search,
    ("search", Mode.FLAG): flag_search,
    ("search", Mode.REDACT): redact_search,
}


@dataclass
class Layers:
    """The fakes, and what each saw."""

    classify: AsyncMock
    detect: AsyncMock
    extract: AsyncMock
    verify: AsyncMock
    output_classify: AsyncMock
    fetch_url: AsyncMock
    search_grounded: AsyncMock
    payload: str
    workdir: Path
    calls: dict[str, int] = field(default_factory=dict)


def allowlist(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Allowlist every source the harness produces, then reload config."""
    trust = tmp_path / "state" / "trust.json"
    trust.parent.mkdir(exist_ok=True)
    trust.write_text(
        '{"trusted_domains": ["example.com"], "trusted_paths": ["*"]}',
        encoding="utf-8",
    )
    monkeypatch.setenv("QUARANTINE_TRUST_CONFIG", str(trust))
    config_mod._config = None


@contextmanager
def layers(
    workdir: Path,
    *,
    payload: str = (
        "The maintenance window is Tuesday at 02:00 UTC. The gateway restarts once during it."
    ),
    classification: ClassifierResult | None = BENIGN,
    detection: dict[str, Any] | None = None,
    extraction: dict[str, Any] | Exception | None = None,
    verification: dict[str, Any] | None = None,
    output_classification: ClassifierResult | None = BENIGN,
) -> Iterator[Layers]:
    """Fake the model calls and the producers' I/O for one call."""
    (workdir / "doc.txt").write_text(payload, encoding="utf-8")
    listing_dir = workdir / "listing"
    listing_dir.mkdir(exist_ok=True)
    (listing_dir / payload[:60].replace("/", "_")).write_text("x", encoding="utf-8")

    with ExitStack() as stack:

        def p(target: str, **kw: Any) -> Any:
            return stack.enter_context(patch(target, **kw))

        extract_kw: dict[str, Any] = (
            {"side_effect": extraction}
            if isinstance(extraction, Exception)
            else {"return_value": extraction or EXTRACTION}
        )
        fakes = Layers(
            classify=p(
                "trentina.defense.classify_async",
                new_callable=AsyncMock,
                return_value=classification,
            ),
            detect=p(
                "trentina.defense.quarantine_detect",
                new_callable=AsyncMock,
                return_value=detection or CLEAN_DETECT,
            ),
            extract=p(
                "trentina.quarantine.agent.quarantine_extract",
                new_callable=AsyncMock,
                **extract_kw,
            ),
            verify=p(
                "trentina.quarantine.agent.quarantine_verify",
                new_callable=AsyncMock,
                return_value=verification or CLEAN_DETECT,
            ),
            output_classify=p(
                "trentina.quarantine.classifier.classify_async",
                new_callable=AsyncMock,
                return_value=output_classification,
            ),
            fetch_url=p(
                "trentina.tools.fetch.fetch_url",
                new_callable=AsyncMock,
                return_value=(payload, "text/plain", ()),
            ),
            search_grounded=p(
                "trentina.tools.search.search_grounded",
                new_callable=AsyncMock,
                return_value={
                    "text": payload,
                    "sources": [{"uri": "https://example.com/a", "title": "A"}],
                    "usage": {},
                },
            ),
            payload=payload,
            workdir=workdir,
        )
        p(
            "trentina.tools.search.resolve_grounding_urls",
            new_callable=AsyncMock,
            side_effect=lambda sources: sources,
        )
        yield fakes


async def call(family: str, mode: Mode, fakes: Layers) -> dict[str, Any]:
    """Invoke the real tool for (family, mode) against the fakes' payload."""
    tool = _TOOLS[(family, mode)]
    arg: str = {
        "fetch": "https://example.com/page",
        "read": str(fakes.workdir / "doc.txt"),
        "dir": str(fakes.workdir / "listing"),
        "content": fakes.payload,
        "search": "maintenance window",
    }[family]
    if mode is Mode.REDACT:
        return await tool(arg, "Extract the facts.")
    return await tool(arg)
