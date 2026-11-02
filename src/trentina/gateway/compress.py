"""Tool and parameter description compression for the gateway.

The call site of the ``summarize`` transform on
``Channel.TOOL_DESCRIPTION`` (#176): which descriptions to compress, the
cache, retries, and applying the results. The model call itself is
``transforms.summarize.summarize_descriptions``. A backend opts in with
``preprocess_tool_descriptions: {processors: [summarize]}``.

Triggered lazily on the first tools/list request; results are cached in
SQLite and looked up synchronously on subsequent calls. Best-effort: failures
at any level are logged and skipped, and an uncompressed description is
served as the backend wrote it.

Parameter descriptions (0.38.0) were ~100 KB of a 376-tool profile's 400 KB tool list and
were never compressed: the tool prompt says to leave them to the schema.
Each is first trimmed of boilerplate the schema already states (``_trim``),
then, past ``PARAM_MODEL_MIN_CHARS``, rewritten by the model with the tool
and parameter name as context. They are cached like descriptions, under a
``param:`` key that includes the schema default the trim compared against.

Nothing compressed is served until the next aggregate build, so a deploy's
first tools/list matches the verdict cache and answers fast. When a run banks
anything, ``on_compressed`` rebuilds the aggregates in the background and the
new text is judged there, while clients keep the list they have.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import re
from typing import TYPE_CHECKING, Any, Literal

from ..database import get_all_compressions, save_compression
from ..errors import QuarantineAgentError
from ..logsafe import exc_kind
from ..quarantine.agent import resolve_profile_llm
from ..quarantine.limiter import THROTTLE_STATUS
from ..quarantine.providers import get_provider
from ..transforms.summarize import summarize_descriptions

if TYPE_CHECKING:
    from collections.abc import Callable

    from ..quarantine.providers.base import Provider
    from .profile import Backend, Profile

logger = logging.getLogger(__name__)

BATCH_SIZE = 5
# Parameter descriptions are short, so more fit one call.
PARAM_BATCH_SIZE = 20
# Below this a parameter description is only trimmed: a model call cannot
# make "Page size." shorter by enough to pay for itself.
PARAM_MODEL_MIN_CHARS = 80
DELAY_BETWEEN_BACKENDS = 2
DELAY_BETWEEN_BATCHES = 3
MAX_RETRIES = 3
RETRY_BASE_DELAY = 2.0
_RETRYABLE_STATUS_CODES = {429, 503}

# grant owner -> {description hash: compressed text}. Per owner since 6.1.0: a
# compressed description is a model rewrite one tenant's key paid for, and
# serving it to another both spends across tenants and tells the second that
# the first holds the same backend.
_cache: dict[str, dict[str, str]] = {}
_profiles: dict[str, Profile] | None = None
_compress_triggered: bool = False
_compress_task: asyncio.Task[dict[str, int]] | None = None
# Called when a run banked anything; the router rebuilds aggregates.
_on_compressed: Callable[[], None] | None = None

# What a parameter description repeats from its own schema. Anchored and
# bounded, so each is linear.
_OPTIONAL_LEAD = re.compile(r"^\s*(?:\(optional\)|optional)[\s.:,-]+", re.IGNORECASE)
_OPTIONAL_TAIL = re.compile(r"\s*\(optional\)\s*\.?\s*$", re.IGNORECASE)
_DEFAULT_TAIL = re.compile(
    r"[\s.;,]*\(?\s*defaults?(?:\s+(?:to|is))?\s*[:=]?\s*[`'\"]?([^\s`'\".,;)]{1,40})[`'\"]?\s*\)?\.?\s*$",
    re.IGNORECASE,
)


def _hash_description(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def _param_key(description: str, default: Any) -> str:
    """The cache key of a parameter description, with the default the trim read."""
    marker = json.dumps(default, sort_keys=True) if default is not ... else ""
    return _hash_description(f"param:{description}\0{marker}")


def _trim(description: str, *, required: bool, default: Any) -> str:
    """The description without what its schema already says: optional, and its default."""
    text = description.strip()
    if not required:
        text = _OPTIONAL_TAIL.sub("", _OPTIONAL_LEAD.sub("", text))
    match = _DEFAULT_TAIL.search(text)
    if (
        match
        and default is not ...
        and match.group(1).lower()
        in {
            str(default).lower(),
            json.dumps(default).lower(),
        }
    ):
        text = text[: match.start()].rstrip(" ,;")
        text = text if not text or text.endswith((".", "!", "?")) else f"{text}."
    return text or description


def set_on_compressed(callback: Callable[[], None] | None) -> None:
    """Register what runs when a compression pass banked new text."""
    global _on_compressed
    _on_compressed = callback


def load_compression_cache() -> int:
    """Populate the in-memory cache from SQLite. Returns count loaded."""
    global _cache
    _cache = get_all_compressions()
    total = sum(len(owned) for owned in _cache.values())
    logger.info(
        "compress: loaded %d cached compression(s) for %d owner(s) from database",
        total,
        len(_cache),
    )
    return total


def set_profiles(profiles: dict[str, Profile]) -> None:
    """Store the profile registry for lazy compression."""
    global _profiles
    _profiles = profiles


def get_profiles() -> dict[str, Profile] | None:
    """Return the loaded profile registry, or None if the gateway is not up."""
    return _profiles


def retrigger_compression() -> None:
    """Re-arm the one-shot trigger so the next tools/list compresses again.

    Called after a profile reload adds or changes a backend. Without it the
    trigger stays spent for the life of the process and a newly added
    ``compress_descriptions`` backend would serve full-length descriptions
    until a restart. Re-running is cheap: ``_find_uncached`` skips every
    description already in the cache, so an unchanged backend costs one
    tools/list and no model calls.
    """
    global _compress_triggered
    _compress_triggered = False


async def maybe_trigger_compression() -> None:
    """Trigger background compression on the first call, retrying on failure.

    On success, subsequent calls return immediately. If the previous task
    failed, allows re-triggering so transient errors don't permanently
    disable compression.
    """
    global _compress_triggered, _compress_task
    if _profiles is None:
        return
    failed = (
        _compress_task.exception() if _compress_task is not None and _compress_task.done() else None
    )
    if failed is not None:
        logger.warning("compress: previous task failed: %s — allowing retry", exc_kind(failed))
        _compress_triggered = False
    if _compress_triggered:
        return
    _compress_triggered = True
    _compress_task = asyncio.create_task(precompress_all(_profiles))
    logger.info("compress: background compression triggered by first tools/list")


def compress_tools(profile: Profile, tools: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Replace tool and parameter descriptions from cache. Sync-only, no model calls.

    Reads only the calling profile's own owner partition (6.1.0), so a
    description another tenant's key paid to shorten is never swapped in here.
    Cache miss = passthrough (original description kept).
    """
    owned = _cache.get(profile.grant_owner)
    if not owned:
        return tools
    return [_compressed_tool(owned, tool) for tool in tools]


def _compressed_tool(owned: dict[str, str], tool: dict[str, Any]) -> dict[str, Any]:
    out = dict(tool)
    desc = tool.get("description", "")
    if desc:
        out["description"] = owned.get(_hash_description(desc), desc)
    schema = tool.get("inputSchema")
    if isinstance(schema, dict):
        out["inputSchema"] = _compressed_schema(owned, schema)
    return out


def _compressed_schema(owned: dict[str, str], schema: dict[str, Any]) -> dict[str, Any]:
    """The schema with each cached parameter description swapped in, top level and $defs."""
    out = dict(schema)
    out["properties"] = _compressed_properties(owned, schema)
    defs = schema.get("$defs")
    if isinstance(defs, dict):
        out["$defs"] = {
            name: {**sub, "properties": _compressed_properties(owned, sub)}
            if isinstance(sub, dict) and isinstance(sub.get("properties"), dict)
            else sub
            for name, sub in defs.items()
        }
    return out


def _compressed_properties(owned: dict[str, str], schema: dict[str, Any]) -> Any:
    props = schema.get("properties")
    if not isinstance(props, dict):
        return props
    out: dict[str, Any] = {}
    for name, prop, desc in _described(props):
        cached = owned.get(_param_key(desc, prop.get("default", ...))) if desc else None
        out[name] = {**prop, "description": cached} if cached is not None else prop
    return out


def _described(props: dict[str, Any]) -> list[tuple[str, Any, str]]:
    """(name, property, description or "") for every property."""
    out: list[tuple[str, Any, str]] = []
    for name, prop in props.items():
        desc = prop.get("description") if isinstance(prop, dict) else None
        out.append((name, prop, desc if isinstance(desc, str) else ""))
    return out


async def precompress_all(
    profiles: dict[str, Profile],
) -> dict[str, int]:
    """Pre-compress descriptions for all compression-enabled backends.

    Best-effort: each backend is independent. A failure in one backend does not
    affect others. Deduplicates by ``(grant_owner, url)``: every holder of a
    shared backend fills its own partition, because since 6.1.0 the cache is
    per owner and deduping by URL alone would leave every holder but the first
    compressing on first use instead.

    The model call runs as the holder, on its key. It ran as the service
    identity (``service.py``, #138) through 6.0.0 — one provider, one model,
    one bill — which made one tenant's key pay to shorten another's tool list.

    The list is fetched with that same profile's credential, and the tool-list
    cache is partitioned the same way (6.1.0), so no holder reads a list
    another holder's credential earned.
    """
    seen_urls: set[tuple[str, str]] = set()
    stats: dict[str, int] = {}

    for profile in profiles.values():
        for backend_name, backend in profile.backends.items():
            if not backend.compresses_descriptions:
                continue
            if not backend.is_remote:
                continue
            # Per (owner, url) since 6.1.0. Deduping by URL alone filled only
            # the first holder's partition, and every other holder of a shared
            # backend compressed on first use instead — the pre-compression
            # pass silently stopped covering them.
            if (profile.grant_owner, backend.url) in seen_urls:
                continue
            seen_urls.add((profile.grant_owner, backend.url))

            try:
                count = await _precompress_backend(backend_name, backend, profile)
                stats[backend_name] = count
            except Exception as exc:
                logger.warning(
                    "compress: backend %s failed, skipping: %s",
                    backend_name,
                    exc_kind(exc),
                )
            await asyncio.sleep(DELAY_BETWEEN_BACKENDS)

    total = sum(stats.values())
    if total:
        logger.info("compress: finished — %d descriptions across %d backends", total, len(stats))
        if _on_compressed is not None:
            _on_compressed()
    return stats


def _find_uncached(owner: str, tools: list[dict[str, Any]]) -> list[tuple[str, str]]:
    """Return (hash, description) pairs for tools not already in this owner's cache."""
    owned = _cache.get(owner, {})
    uncached: list[tuple[str, str]] = []
    for tool in tools:
        desc = tool.get("description", "")
        if not desc:
            continue
        h = _hash_description(desc)
        if h not in owned:
            uncached.append((h, desc))
    return uncached


def _store_result(
    owner: str,
    batch: list[tuple[str, str]],
    h: str,
    compressed_text: str,
    *,
    model: str = "provider",
) -> bool:
    """Store a compression result if it's actually shorter. Returns True if stored."""
    original = next((desc for bh, desc in batch if bh == h), None)
    if original is None or not compressed_text or len(compressed_text) >= len(original):
        return False
    _cache.setdefault(owner, {})[h] = compressed_text
    save_compression(owner, h, original, compressed_text, model)
    return True


async def _precompress_backend(backend_name: str, backend: Backend, profile: Profile) -> int:
    """Fetch tools from one backend, compress this profile's uncached descriptions.

    ``profile`` is the holder whose partition is being filled. It is no longer
    optional: since 6.1.0 both the model call and the cache belong to that
    profile, and the tool list it reads is fetched under that profile's own
    credential. A federated backend also needs it to mint its primary JWT —
    without one the list fetch goes out unauthenticated and the secondary
    rejects it (#592, F4).
    """
    from .backend import list_backend_tools

    try:
        tools = await list_backend_tools(backend_name, backend, profile)
    except Exception:
        logger.warning("compress: %s — could not list tools, skipping", backend_name)
        return 0

    owner = profile.grant_owner
    uncached = _find_uncached(owner, tools)
    compressed_count = 0
    if uncached:
        logger.info("compress: %s — %d descriptions to compress", backend_name, len(uncached))
    for i in range(0, len(uncached), BATCH_SIZE):
        if i > 0:
            await asyncio.sleep(DELAY_BETWEEN_BATCHES)
        batch = uncached[i : i + BATCH_SIZE]
        results = await _compress_batch_with_fallback(batch, profile)
        for h, text in results:
            if _store_result(owner, batch, h, text):
                compressed_count += 1
    compressed_count += await _precompress_params(backend_name, profile, tools)

    if compressed_count:
        logger.info("compress: %s — compressed %d descriptions", backend_name, compressed_count)
    return compressed_count


def _uncached_params(
    owner: str, tools: list[dict[str, Any]]
) -> list[tuple[str, str, str, dict[str, str]]]:
    """(key, original, trimmed, model context) for each parameter description not cached."""
    owned = _cache.get(owner, {})
    out: list[tuple[str, str, str, dict[str, str]]] = []
    for tool in tools:
        schema = tool.get("inputSchema")
        if not isinstance(schema, dict):
            continue
        defs = schema.get("$defs")
        for sub in [schema, *(defs.values() if isinstance(defs, dict) else ())]:
            props = sub.get("properties") if isinstance(sub, dict) else None
            if not isinstance(props, dict):
                continue
            required = set(sub.get("required") or [])
            for name, prop, desc in _described(props):
                if not desc:
                    continue
                default = prop.get("default", ...)
                key = _param_key(desc, default)
                if key in owned:
                    continue
                trimmed = _trim(desc, required=name in required, default=default)
                context = {"tool": str(tool.get("name", "")), "parameter": name}
                out.append((key, desc, trimmed, context))
    return out


async def _precompress_params(
    backend_name: str, profile: Profile, tools: list[dict[str, Any]]
) -> int:
    """Trim every uncached parameter description; send the long ones to the model."""
    owner = profile.grant_owner
    stored = 0
    for_model: list[tuple[str, str, str, dict[str, str]]] = []
    for item in _uncached_params(owner, tools):
        key, original, trimmed, _ = item
        if len(trimmed) >= PARAM_MODEL_MIN_CHARS:
            for_model.append(item)
        elif _store_result(owner, [(key, original)], key, trimmed, model="trim"):
            stored += 1
    if for_model:
        logger.info(
            "compress: %s — %d parameter descriptions to compress", backend_name, len(for_model)
        )
    for i in range(0, len(for_model), PARAM_BATCH_SIZE):
        await asyncio.sleep(DELAY_BETWEEN_BATCHES)
        batch = for_model[i : i + PARAM_BATCH_SIZE]
        results = dict(
            await _call_compress_model(
                [(key, trimmed) for key, _, trimmed, _ in batch],
                profile,
                kind="parameter",
                context={key: ctx for key, _, _, ctx in batch},
            )
        )
        originals = [(key, original) for key, original, _, _ in batch]
        for key, _, trimmed, _ in batch:
            # The model's text if it came back shorter; the trim otherwise.
            text = results.get(key, trimmed)
            if _store_result(owner, originals, key, text) or _store_result(
                owner, originals, key, trimmed, model="trim"
            ):
                stored += 1
    return stored


async def _compress_batch_with_fallback(
    batch: list[tuple[str, str]],
    profile: Profile,
) -> list[tuple[str, str]]:
    """Try batch compression, fall back to one-at-a-time on failure."""
    results = await _call_compress_model(batch, profile)
    if results:
        return results

    if len(batch) == 1:
        return []

    logger.info("compress: batch of %d failed, falling back to one-at-a-time", len(batch))
    all_results: list[tuple[str, str]] = []
    for item in batch:
        await asyncio.sleep(1)
        single = await _call_compress_model([item], profile)
        all_results.extend(single)
    return all_results


def _provider_for(profile: Profile) -> Provider:
    """The provider a profile's own compression runs on.

    Since 6.1.0 compression is the LISTING profile's work, on its key, not the
    service identity's: shortening a description is a model rewrite of that
    profile's own tool list, and the result is cached in that profile's
    partition. ``resolve_profile_llm`` refuses to bill any key but the
    profile's own, so there is no fallback to anyone else's.
    """
    name, api_key, model = resolve_profile_llm(profile)
    return get_provider(name, api_key=api_key, model=model)


async def _call_compress_model(
    items: list[tuple[str, str]],
    profile: Profile,
    *,
    kind: Literal["tool", "parameter"] = "tool",
    context: dict[str, dict[str, str]] | None = None,
) -> list[tuple[str, str]]:
    """Compress a batch as ``profile``, via ``summarize_descriptions``.

    Retries up to MAX_RETRIES times on transient errors with exponential
    backoff. Returns [(hash, compressed_text)] for successful compressions,
    or empty list on permanent failure. ``context`` adds per-item keys the
    model reads (a parameter's tool and name).
    """
    payload = [{"id": h, "text": desc, **(context or {}).get(h, {})} for h, desc in items]

    for attempt in range(MAX_RETRIES):
        try:
            return await summarize_descriptions(_provider_for(profile), payload, kind)
        except Exception as exc:
            status = exc.status_code if isinstance(exc, QuarantineAgentError) else None
            if status in _RETRYABLE_STATUS_CODES and attempt < MAX_RETRIES - 1:
                # A 429's wait is the limiter's pause, which the next
                # acquire already honours; only an outage needs our own.
                delay = 0.0 if status == THROTTLE_STATUS else RETRY_BASE_DELAY * (2**attempt)
                logger.info(
                    "compress: provider error, retry %d/%d in %.0fs: %s",
                    attempt + 1,
                    MAX_RETRIES,
                    delay,
                    exc_kind(exc),
                )
                await asyncio.sleep(delay)
                continue
            logger.warning(
                "compress: provider call failed for %d items: %s", len(items), exc_kind(exc)
            )
            return []

    return []
