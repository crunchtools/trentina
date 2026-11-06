"""The gateway's service identity: the operator profile (#138).

Work that belongs to no tenant runs as the ``role: operator`` profile rather
than as whoever happened to be nearby. Until #138 it ran as the latter:
compression took the FIRST profile's provider for a shared backend URL, so
reordering ``profiles.yaml`` changed the model, and the ``tools/list`` path had
no profile bound at all, so L3 fell through to the env-global key. Neither was
a decision; both were fall-through.

**Since 6.1.0 no MODEL call runs here.** Judging and compressing a tool
description were the two, and they are the listing profile's own work now, on
its key (``tool_list_edge``, ``compress``) — one tenant's key never pays to
read another's tool list. What is left binding the operator is the
approved-config-write apply (``tools/config.py``), which spends nothing: an
approval arrives from a browser with no bound caller, and ``reload_profiles``
applies a whole file only for an operator, so without the binding an approved
change would be written and then refused by the reload.

Binding into ``context._current_profile`` remains the mechanism, and it is why
no model call can leak across a tenant if one is added back here: the Q-Agent
resolves provider, model, key and fallback chain from the bound profile, and
refuses to fall back to anyone else's key (``resolve_profile_llm``).

No operator declared keeps the env-global path — logged at startup so the
fallback is a stated fact rather than an inherited one.

**More than one profile may hold the role since 6.4.0 (#661).** Two agents
administer one gateway without sharing a login, and which of them the gateway
binds and reports as ITSELF is named in the file — ``gateway.service_identity``
— rather than taken from whichever came first in the mapping. A file with two
operators and no such name is refused: the thing #138 removed was order
deciding an identity, and defaulting to the first one would put it back under a
new spelling. One operator needs no setting, so no file written before 6.4.0
changes meaning.

``load_profiles`` still refuses an operator with no key for its own judge, and
that reason is per-profile rather than per-gateway: the admin tools it would
lose are the ones that repair the gateway, so EVERY written operator is held to
it, not only the one the setting names.
"""

from __future__ import annotations

import logging
from contextlib import contextmanager
from enum import Enum
from typing import TYPE_CHECKING

from ..config import get_config
from ..quarantine.packs import SUPPORTED, pack_for, supported_judges
from ..quarantine.providers import openrouter_model
from .context import _current_profile

if TYPE_CHECKING:
    from collections.abc import Iterator, Mapping

    from .profile import Profile

logger = logging.getLogger(__name__)


def written_operators(profiles: Mapping[str, Profile]) -> list[Profile]:
    """Every WRITTEN ``role: operator`` profile in ``profiles``, in file order.

    Derived ingresses are skipped, and that is load-bearing rather than tidy.
    Since 6.0.0 a derived ingress carries its source's role, so a shared
    operator profile and its derivation both match the role test — and counting
    the derivation would make every such file look like two operators, while
    BINDING it would let dict order decide which identity the gateway reports as
    its own. That is exactly the defect #138 removed when it made the operator
    an explicit profile instead of a search. The service identity is a profile
    somebody wrote, never one this code derived from it.

    The one predicate, read by ``find_operator``, by the loader's
    ``_check_operator`` and by the approval rule, so "which profiles are
    operators" cannot come out differently in the three places that ask.
    """
    return [p for p in profiles.values() if p.role == "operator" and p.federation_of is None]


def find_operator(
    profiles: Mapping[str, Profile], service_identity: str | None = None
) -> Profile | None:
    """The profile the gateway binds and reports as its own identity, or None.

    ``service_identity`` is ``gateway.service_identity`` from the file (#661):
    when it is set it decides, and ``load_profiles`` has already proved it names
    a written operator. When it is unset there is at most one written operator
    to find, because the loader refuses a file where there would be more — so
    the answer is never the first of several.

    A name that resolves to nothing falls through to the scan rather than
    raising. It cannot happen through ``load_profiles``, and the caller here is
    the gateway reporting who it is: answering with the operator it does have
    beats answering None on a mapping somebody built by hand in a test.
    """
    operators = written_operators(profiles)
    if service_identity is not None:
        named = next((p for p in operators if p.name == service_identity), None)
        if named is not None:
            return named
    return operators[0] if operators else None


def service_profile() -> Profile:
    """The identity the gateway binds for its own work. Never None.

    The profile ``gateway.service_identity`` names when the file names one and
    more than one profile holds the role (#661); the single declared
    ``role: operator`` profile when there is one; otherwise the
    environment operator (``standalone.standalone_profile``) — the whole identity
    for a standalone server, and the env-global fallback for a live gateway that
    declares no operator. The gateway's own work always has a profile, so nothing
    is ever bound as None and ``get_current_profile`` never has to answer
    "unknown" on a gateway's own call.

    Read from the active config on every call rather than cached: a reload
    refills that dict in place, and a promoted or demoted operator has to take
    effect on the next such call, not the next restart.
    """
    from .loader import get_active_config
    from .standalone import environment_operator

    active = get_active_config()
    if active is not None:
        operator = find_operator(active.config.profiles, active.config.service_identity)
        if operator is not None:
            return operator
    return environment_operator()


class _Unresolved(Enum):
    """``service_context``'s default: "resolve the operator yourself"."""

    TOKEN = 0


@contextmanager
def service_context(
    operator: Profile | _Unresolved = _Unresolved.TOKEN,
) -> Iterator[Profile]:
    """Run the enclosed model calls as the service identity.

    Binds the operator profile for the block and yields it. ``service_profile``
    is never None — a declared operator, else the environment operator — so a
    tenant bound further up the stack cannot leak into the gateway's own work:
    the operator always replaces it for the block.

    A caller that already resolved the operator passes it in. That caller has
    usually keyed something on ``judge_of(operator)``, and resolving again here
    would let a reload between the two file a verdict under one judge that
    another one reached.
    """
    if isinstance(operator, _Unresolved):
        operator = service_profile()
    token = _current_profile.set(operator)
    try:
        yield operator
    finally:
        _current_profile.reset(token)


def judge_of(profile: Profile | None) -> tuple[str, str]:
    """The (provider, model) that L3 runs on for ``profile``.

    The same resolution the Q-Agent applies: the profile's override, else the
    env default. None is the env default itself.
    """
    config = get_config()
    if profile is None:
        return config.provider, config.model
    return (
        profile.defense.provider or config.provider,
        profile.defense.model or config.model,
    )


def judge_stamp(profile: Profile | None) -> str:
    """The L3 judge identity ``profile`` scans under: ``provider/model/pack``.

    A federated verdict pins this separately from the ``perimeter_stamp``,
    because that one covers L2 and the perimeter version but not L3 — a peer
    that swapped to a weaker judge is caught here or nowhere. It is the same
    (provider, model) and pack the verdict cache keys on.

    Not a secret: it names a model and a prompt pack. An operator reads it to
    tell a peer what to pin, and to compare a peer's against its own.
    """
    judge = judge_of(profile)
    pack = pack_for(judge, profile.defense.l3_prompt_pack if profile is not None else None)
    return f"{judge[0]}/{judge[1]}/{pack.stamp}"


def log_service_identity(
    profiles: Mapping[str, Profile], service_identity: str | None = None
) -> None:
    """Say, once, which profile the gateway binds for its own work.

    WARNING for the same reason as the startup cache line: production logs at
    WARNING, and this is the line that answers "who holds the admin role".

    It no longer answers "who pays for compression" — since 6.1.0 that is each
    listing profile, on its own key, so the judge named here is the operator's
    OWN and says nothing about anyone else's bill.

    Since 6.4.0 it also has to answer "who ELSE holds the role" (#661): with two
    operators, the one line saying which is bound reads as though it were the
    only one. The count goes in the same record rather than a second line,
    because a reader scanning startup for the admin seat finds one line and not
    the half of a pair that scrolled past.
    """
    operator = find_operator(profiles, service_identity)
    bound = operator.name if operator is not None else None
    others = [p.name for p in written_operators(profiles) if p.name != bound]
    if others:
        logger.warning(
            "service identity: %d profile(s) also hold role: operator (%s). Each administers "
            "this gateway on its own credential; the one named below is what the gateway "
            "reports as itself",
            len(others),
            ", ".join(sorted(others)),
        )
    if operator is None:
        provider, model = judge_of(None)
        logger.warning(
            "service identity: no operator profile declared — an approved config write "
            "binds the env-global identity, provider=%s model=%s. No model call runs as "
            "the service identity: each profile judges its own tool descriptions on its "
            "own key",
            provider,
            model,
        )
        log_judge_support(profiles)
        return
    provider, model = judge_of(operator)
    logger.warning(
        "service identity: operator profile=%s, its own judge provider=%s model=%s. It "
        "binds the approved-config apply; no model call runs as it",
        operator.name,
        provider,
        model,
    )
    log_judge_support(profiles)


def judge_support(profiles: Mapping[str, Profile]) -> dict[tuple[str, str], str]:
    """Every judge these profiles name that is not a supported one, with its pack's status.

    A judge is supported when the pack it is prompted with passed the pack
    gate as production runs it (``packs.SUPPORTED``, #397). The env default
    counts as named: it is what a call with no profile is judged by.
    """
    found: dict[tuple[str, str], str] = {}
    for profile in (None, *profiles.values()):
        provider, model = judge_of(profile)
        if provider == "openrouter":
            model = openrouter_model(model)
        own = getattr(getattr(profile, "defense", None), "l3_prompt_pack", None)
        status = pack_for((provider, model), own).status
        if status != SUPPORTED:
            found[(provider, model)] = status
    return found


def log_judge_support(profiles: Mapping[str, Profile]) -> None:
    """Name, once each, a judge in use whose pack has not passed the gate."""
    listed = ", ".join(f"{provider}/{model}" for provider, model in supported_judges())
    for (provider, model), status in sorted(judge_support(profiles).items()):
        logger.warning(
            "judge: provider=%s model=%s is %s on the L3 pack gate; supported: %s. "
            "See docs/configuration.md#supported-judges.",
            provider,
            model,
            status,
            listed or "none",
        )
