"""Reading and writing the gateway's own configuration (#633): operator only.

``docs/operator.md`` describes an Operator agent's loop as "it edits
profiles.yaml, applies the edit with reload_profiles, and reads back what
applied and what needs a restart. None of this needs a shell." Until now the
first clause was not true: nothing in Trentina could edit the file, so the only
way an operator agent did it was with a shell it was not supposed to need.

The file stays the source of truth. It is not a view over a database and it is
not generated: a human maintains it, reviews it in a diff and keeps it in git,
and a hand edit still wins. ``expect_hash`` is what keeps the two writers
honest.

The order below is the point of the module. The candidate is validated by
LOADING it — from a real file, through ``loader.load_profiles``, the one schema
authority — before anything replaces anything, so a refusal has touched
nothing. The previous text is kept before the replace, so even a crash between
the two leaves it recoverable. And the reload is the existing
``reload_profiles``, not a second applier, so there stays one path by which a
profile change reaches the running gateway.

The rules live in ``gateway/config_guard.py``; this module is the sequence.
"""

from __future__ import annotations

import asyncio
import logging
import os
import tempfile
import time
from pathlib import Path
from typing import TYPE_CHECKING, Any

import yaml

from ..gateway import config_guard, config_patch, config_store
from ..gateway.config_guard import ConfigWriteError
from ..gateway.errors import ProfileConfigError, ScopeError
from ..gateway.llm_proxy import validate_profile_llm_keys
from ..gateway.loader import get_active_config, load_profiles
from ..gateway.scope import require_caller, require_operator
from ..logsafe import exc_kind
from .reload import reload_profiles

if TYPE_CHECKING:
    from ..gateway.loader import ActiveConfig
    from ..gateway.profile import Profile

logger = logging.getLogger(__name__)

#: One write at a time. Two writes that each validated against the same text
#: would both satisfy their own ``expect_hash``, and the second would land on a
#: file it never read.
_WRITE_LOCK = asyncio.Lock()

_CANDIDATE_PREFIX = ".profiles-candidate-"


def _live_config() -> tuple[ActiveConfig, Path, str]:
    """The running config, the file behind it, and that file's current text."""
    active = get_active_config()
    if active is None:
        raise ConfigWriteError({"error": "no gateway configuration is loaded"})
    live = Path(active.path)
    try:
        return active, live, live.read_text(encoding="utf-8")
    except OSError as exc:
        logger.warning("config could not read the live file: %s", exc_kind(exc))
        raise ConfigWriteError({"error": "could not read the configuration"}) from exc


def _read_at(text: str, keys: tuple[str, ...]) -> Any:
    """The value at ``keys``, as plain Python.

    Reading is pyyaml's job and writing is ruamel's (``config_patch``). Reading
    here keeps ruamel's round-trip types — comment-carrying maps, quote-
    preserving strings — out of a tool result that has to serialize to JSON.
    """
    node = yaml.safe_load(text)
    try:
        checked = config_patch.checked_path(keys) if keys else ()
    except config_patch.ConfigPatchError as exc:
        raise ConfigWriteError({"error": str(exc)}) from None
    for key in checked:
        if not isinstance(node, dict) or key not in node:
            raise ConfigWriteError({"error": f"{key!r} is not set"})
        node = node[key]
    return node


def _read(keys: tuple[str, ...]) -> dict[str, Any]:
    """A ``get``: the file's hash, and the masked value at ``keys``."""
    _, _, current = _live_config()
    return {
        "hash": config_store.config_hash(current),
        "value": _read_at(config_guard.mask_inline_secrets(current), keys),
    }


def _candidate_loads(live: Path, text: str, providers: dict[str, Any]) -> dict[str, Profile]:
    """Load ``text`` as a configuration, or refuse. Nothing live is touched.

    Written to a real file beside the live one and loaded by path, because that
    is exactly what ``reload_profiles`` does moments later: validating the way
    the applier reads it leaves no gap between "it validated" and "it loaded".
    The staged file is random-named and 0600 from creation, and is removed
    whatever happens.
    """
    fd, staged_name = tempfile.mkstemp(dir=live.parent, prefix=_CANDIDATE_PREFIX, suffix=".yaml")
    staged = Path(staged_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
        config = load_profiles(staged)
        validate_profile_llm_keys(providers, config.profiles)
    except ProfileConfigError as exc:
        # Its message names the file it read, which is this temporary one. The
        # operator needs the reason, not our scratch path.
        reason = str(exc).replace(str(staged), str(live))
        raise ConfigWriteError({"error": f"the change does not validate: {reason}"}) from None
    else:
        return config.profiles
    finally:
        staged.unlink(missing_ok=True)


def _prepared(
    active: ActiveConfig,
    live: Path,
    current: str,
    action: str,
    keys: tuple[str, ...],
    value: Any,
) -> tuple[str, Path]:
    """Render, validate, guard, keep and replace. Returns (candidate, backup).

    Every step here is blocking — parsing YAML, loading a candidate from disk,
    fsync, rename — so it runs in a worker rather than on the event loop, the
    same rule the rest of the gateway follows for L1 and for SQLite. The reload
    is the caller's, because that belongs on the loop.
    """
    current_hash = config_store.config_hash(current)
    try:
        candidate_text = (
            config_patch.set_at(current, keys, value)
            if action == "set"
            else config_patch.unset_at(current, keys)
        )
    except config_patch.ConfigPatchError as exc:
        raise ConfigWriteError({"error": str(exc)}) from None

    if candidate_text == current:
        raise ConfigWriteError(
            {"error": "that change is already in the configuration", "hash": current_hash}
        )
    if config_guard.echoes_redaction(value):
        raise ConfigWriteError(
            {
                "error": (
                    f"that value contains {config_guard.REDACTED}, which is what a read "
                    "puts in place of a credential — send the real value, or leave the "
                    "field out of the write"
                )
            }
        )
    if not config_guard.trust_stays_human(action, keys, value):
        raise ConfigWriteError(
            {
                "error": (
                    "trust_verdict makes this gateway serve another gateway's response "
                    "without scanning it, so it is not writable through this tool; it "
                    "stays an edit a person makes to the file"
                )
            }
        )

    after = _candidate_loads(live, candidate_text, active.llm_providers)
    if config_guard.operator_seat(after) != config_guard.operator_seat(active.config.profiles):
        raise ConfigWriteError(
            {
                "error": (
                    "a write may not create, move or remove the operator seat, or change "
                    "how a caller becomes it; that stays a human edit of the file"
                )
            }
        )

    # Validating read and wrote a file, so look once more before replacing:
    # nothing else may have moved while this write was being checked.
    if live.read_text(encoding="utf-8") != current:
        raise ConfigWriteError(
            {"error": "the configuration changed while this write was checked; read it again"}
        )

    kept = config_store.back_up(
        current, after_hash=config_store.config_hash(candidate_text), now=time.time()
    )
    config_store.replace_config(live, candidate_text)
    return candidate_text, kept


async def _write(
    active: ActiveConfig,
    live: Path,
    current: str,
    action: str,
    keys: tuple[str, ...],
    value: Any,
) -> dict[str, Any]:
    """Apply a change: the blocking part off the loop, the reload on it."""
    current_hash = config_store.config_hash(current)
    candidate_text, kept = await asyncio.to_thread(
        _prepared, active, live, current, action, keys, value
    )
    after_hash = config_store.config_hash(candidate_text)

    applied = await reload_profiles()
    if applied.get("reloaded") is not True:
        # The file must never be ahead of the running gateway: a later reader —
        # a human, a drift check, the next write's expect_hash — would be told
        # the change is live when it is not. Put back what was there.
        await asyncio.to_thread(config_store.replace_config, live, current)
        logger.warning("config: reload refused the validated change; the file was restored")
        raise ConfigWriteError(
            {"error": "the change validated but the reload refused it", "reload": applied}
        )

    logger.info("config: applied a change and reloaded")
    return {
        "applied": True,
        "hash_before": current_hash,
        "hash_after": after_hash,
        "backup": str(kept),
        "reload": applied,
    }


async def manage_config(
    action: str,
    path: str | None = None,
    value: Any = None,
    expect_hash: str | None = None,
) -> dict[str, Any]:
    """Read or change the gateway's configuration.

    Args:
        action: ``get``, ``set`` or ``unset``.
        path: A dotted path of config keys, e.g.
            ``profiles.myagent.backends.lotor.federated.edge_key_name``. For
            ``get`` it may be omitted, which returns the whole file.
        value: What to set, for ``set``. A scalar, a list or a mapping.
        expect_hash: The ``hash`` a previous ``get`` or write returned.
            Required for ``set`` and ``unset``.
    """
    keys = tuple(path.split(".")) if path else ()
    try:
        require_operator(require_caller("config"), "config")
        if action == "get":
            # Reading the file and parsing it twice is blocking too, so it goes
            # to a worker like the write does.
            return await asyncio.to_thread(_read, keys)
        async with _WRITE_LOCK:
            active, live, current = await asyncio.to_thread(_live_config)
            config_guard.check_write_request(
                action, keys, expect_hash, config_store.config_hash(current)
            )
            return await _write(active, live, current, action, keys, value)
    except ScopeError as exc:
        logger.warning("config refused: %s", exc_kind(exc))
        return {"error": str(exc)}
    except ConfigWriteError as exc:
        return exc.payload
    except config_patch.ConfigPatchError as exc:
        # The live file can be invalid YAML: a person edits it by hand while the
        # gateway runs. A read has to say so rather than raise.
        return {"error": str(exc)}
    except OSError as exc:
        logger.warning("config failed: %s", exc_kind(exc))
        return {"error": "the configuration could not be written"}
