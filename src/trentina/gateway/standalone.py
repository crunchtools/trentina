"""The standalone server as a synthesized operator profile.

Running ``trentina`` with no gateway bound is not a second code path any more:
it is one operator profile, built from the environment, that every scope and
every model call reads exactly as it reads a profile from ``profiles.yaml``.
Before Trentina 3.0 "standalone" was a web of ``scope is None`` / ``profile is
None`` branches and a ``standalone_policy`` beside the gateway one — the single-
tenant case defended through its own set of fall-throughs. This collapses them:
``context.get_current_profile`` and ``service.service_profile`` return this
profile when nothing is bound and no gateway config is registered, so standalone
takes the operator path end to end.

The profile is built with ``model_construct`` for one reason: a profile with no
``auth`` and no ``oauth`` is refused by ``profile_has_an_authentication_method``,
and standalone has neither — there is no network edge to authenticate. Nothing
else is skipped: ``DefenseConfig`` is built normally, so its validators run, and
the mode policy it carries is the same ``_mode_policy_env`` a standalone server
has always read (``TRENTINA_MODE`` / ``TRENTINA_MODES``). ``llm_keys`` mirrors
every provider key the environment holds, so ``judge_of`` and the Q-Agent
resolve the same (provider, model, key) they resolved on the old env-global
path. ``role`` is operator because standalone is single-tenant: there is nothing
to insulate it from.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, cast
from weakref import WeakKeyDictionary

from pydantic import SecretStr

from .profile import (
    DefenseConfig,
    EnforcementMode,
    LlmKeyOverride,
    ModeName,
    PreProcessConfig,
    Profile,
)

if TYPE_CHECKING:
    from ..config import Config

STANDALONE = "standalone"
"""The synthesized profile's name — operator-visible in audit rows and
``quarantine_stats``. A ``profiles.yaml`` profile may not reuse it."""

#: One provider list: every provider the key table knows. A key present in the
#: environment becomes an ``llm_keys`` entry, so the synthesized profile resolves
#: its judge and fallbacks off its own keys, as a bound profile does.
_PROVIDERS = ("gemini", "openai", "anthropic", "openrouter")

# Cached per Config instance: standalone_profile is read on every internal call,
# and the profile is a pure function of the Config. A new Config (reset_config)
# is a new key, so the cache rebuilds without an explicit flush.
_cache: WeakKeyDictionary[Config, Profile] = WeakKeyDictionary()


def standalone_profile(config: Config) -> Profile:
    """The operator profile a standalone server runs as, built from ``config``."""
    cached = _cache.get(config)
    if cached is not None:
        return cached
    llm_keys = {
        provider: LlmKeyOverride(api_key=SecretStr(key))
        for provider in _PROVIDERS
        if (key := config.provider_key(provider))
    }
    profile = Profile.model_construct(
        name=STANDALONE,
        auth=None,
        role="operator",
        honeypot=False,
        backends={},
        llm_keys=llm_keys,
        defense=DefenseConfig(
            # default_mode / allowed_modes are already validated mode strings
            # (``_mode_policy_env``); the cast is the Literal narrowing only.
            enforcement=cast("EnforcementMode", config.default_mode),
            modes=[cast("ModeName", m) for m in config.allowed_modes],
            provider=config.provider,
            model=config.model,
        ),
        preprocess=PreProcessConfig(),
    )
    _cache[config] = profile
    return profile


def environment_operator() -> Profile:
    """The operator synthesized from the running process's environment config.

    The one synthesis path the two unbound call sites share —
    ``context.get_current_profile`` (standalone) and ``service.service_profile``
    (a gateway that declares no operator) — so neither repeats the
    ``get_config`` → ``standalone_profile`` step. Imported lazily by both to
    stay clear of the loader import cycle ``context`` already documents.
    """
    from ..config import get_config

    return standalone_profile(get_config())
