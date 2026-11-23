"""Pluggable LLM provider drivers for the Q-Agent and compression."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from ...config import get_config
from ...errors import QuarantineAgentError
from .base import Provider, ProviderResult

if TYPE_CHECKING:
    from pydantic import SecretStr

    from ...gateway.profile import Profile, VertexTarget

logger = logging.getLogger(__name__)

#: (provider, key, model, project, region); the last two are empty except for vertex.
_provider_cache: dict[tuple[str, str, str, str, str], Provider] = {}

__all__ = [
    "Provider",
    "ProviderResult",
    "driver_model",
    "get_fallback_providers",
    "get_provider",
]

_DEFAULT_GEMINI_MODEL = "gemini-3.5-flash-lite"

#: OpenRouter aliases the gateway asks for by their dated build (a1061,
#: constitution 2.20.0 condition 1). An alias is repointed when the vendor ships
#: a new build, and a verdict keyed on the alias would then be served for a
#: model that never reached it. The build is the one the shipped pack was
#: measured on: the only build of 3.5 Flash-Lite there has been, and older
#: than the pack's ``measured`` header. Google's own API has no dated id
#: for it, so the ``gemini`` provider stays on the alias and the TTL (#817) is
#: what bounds its drift.
PINNED = {"google/gemini-3.5-flash-lite": "google/gemini-3.5-flash-lite-20260721"}


def openrouter_model(model: str) -> str:
    """``model`` as OpenRouter names it: the bare default is given its vendor,
    and an alias in ``PINNED`` its dated build."""
    model = f"google/{model}" if model == _DEFAULT_GEMINI_MODEL else model
    return PINNED.get(model, model)


def driver_model(provider: str, model: str) -> str:
    """``model`` as ``provider``'s driver sends it, and so as ``Provider.judge`` names it.

    The one place the per-provider defaults are resolved (#922): the Gemini
    default is not a model anthropic, openai or ollama serve, so each gives it
    its own default, and OpenRouter gives it a vendor and a dated build.
    ``get_provider`` builds on this and ``judge_of`` reports it, so a verdict
    key and a federation pin name the model that reached the verdict.
    """
    if provider == "openrouter":
        return openrouter_model(model)
    if model != _DEFAULT_GEMINI_MODEL:
        return model
    from .anthropic import DEFAULT_MODEL as ANTHROPIC_DEFAULT
    from .openai import DEFAULT_MODEL as OPENAI_DEFAULT

    defaults = {
        "anthropic": ANTHROPIC_DEFAULT,
        "openai": OPENAI_DEFAULT,
        "ollama": get_config().ollama_model,
    }
    return defaults.get(provider, model)


def _openrouter(key_value: str, model: str, reasoning_effort: str | None) -> Provider:
    """The OpenAI driver pointed at OpenRouter, where model ids carry a vendor."""
    from .openai import OPENROUTER_API_BASE, OPENROUTER_ROUTING, OpenAIProvider

    if not key_value:
        raise QuarantineAgentError("OPENROUTER_API_KEY not configured")
    return OpenAIProvider(
        api_key=key_value,
        model=driver_model("openrouter", model),
        base_url=OPENROUTER_API_BASE,
        routing=OPENROUTER_ROUTING,
        reasoning_effort=reasoning_effort,
    )


def _vertex(api_key: SecretStr | None, target: VertexTarget | None, model: str) -> Provider:
    """The Vertex driver. No global env key: the credential is llm_keys.vertex."""
    if api_key is None or not api_key.get_secret_value():
        raise QuarantineAgentError("vertex needs llm_keys.vertex")
    if target is None:
        raise QuarantineAgentError("vertex needs defense.vertex (project, region)")
    from .vertex import VertexProvider

    return VertexProvider(
        credentials=api_key.get_secret_value(),
        model=model,
        project=target.project,
        region=target.region,
    )


def _cache_key(
    provider: str, key: str, model: str, vertex: VertexTarget | None
) -> tuple[str, str, str, str, str]:
    """The cache key; project and region are empty for all but vertex."""
    target = vertex if provider == "vertex" else None
    return (provider, key, model, target.project if target else "", target.region if target else "")


def _key_ordinal(key_value: str) -> str:
    """The limiter's name for a key: the one an instance on it already has.

    Read off the cache, which holds the key already, so no second copy is
    kept and nothing is derived from it. A key not yet seen takes the next
    ``key<n>``; the env key (``global``) keeps its own name.
    """
    if key_value == "global":
        return key_value
    for (_name, cached_key, *_rest), provider in _provider_cache.items():
        if cached_key == key_value:
            return provider.key_ordinal
    return f"key{len({entry[1] for entry in _provider_cache if entry[1] != 'global'}) + 1}"


def _anthropic(api_key: SecretStr | None, model: str) -> Provider:
    """The Anthropic driver, on the profile's key or the global one."""
    from .anthropic import ANTHROPIC_API_BASE, AnthropicProvider

    config = get_config()
    key_value = api_key.get_secret_value() if api_key else config.anthropic_api_key
    if not key_value:
        raise QuarantineAgentError("ANTHROPIC_API_KEY not configured")
    # TRENTINA_ANTHROPIC_BASE_URL is the host, as Anthropic's own clients read
    # it: the driver's base carries the API version segment.
    return AnthropicProvider(
        api_key=key_value,
        model=driver_model("anthropic", model),
        base_url=(
            f"{config.anthropic_base_url}/v1" if config.anthropic_base_url else ANTHROPIC_API_BASE
        ),
    )


def _register(
    provider: Provider, cache_key: tuple[str, str, str, str, str], own_key: bool
) -> Provider:
    """Stamp the judge and limiter key, cache the instance, and return it."""
    resolved_provider, _key, resolved_model = cache_key[:3]
    provider.judge = (resolved_provider, provider.model)
    provider.key_ordinal = _key_ordinal(cache_key[1])
    _provider_cache[cache_key] = provider
    logger.info(
        "provider: initialized %s (model=%s, key=%s)",
        resolved_provider,
        resolved_model,
        "override" if own_key else "global",
    )
    return provider


def get_provider(
    provider_name: str | None = None,
    api_key: SecretStr | None = None,
    model: str | None = None,
    vertex: VertexTarget | None = None,
) -> Provider:
    """Return a provider instance, cached per (provider, api_key, model, project, region).

    The cache key uses the full secret value rather than a prefix so two
    profiles whose keys share a prefix cannot collide onto one instance.

    Args:
        provider_name: Explicit provider to use. When None, falls back
            to TRENTINA_MODEL_PROVIDER from config (the global default).
        api_key: API key override for this provider. When None, falls back
            to the global config key for the provider.
        model: Model override for this provider. When None, falls back
            to QUARANTINE_MODEL from config.
        vertex: Project and region for the ``vertex`` provider (the profile's
            ``defense.vertex``); ignored by every other provider.
    """
    config = get_config()
    resolved_provider = provider_name or config.provider
    resolved_model = model or config.model

    key_value = api_key.get_secret_value() if api_key else "global"
    cache_key = _cache_key(resolved_provider, key_value, resolved_model, vertex)

    if cache_key in _provider_cache:
        return _provider_cache[cache_key]

    match resolved_provider:
        case "gemini":
            from .gemini import GeminiProvider

            key_value = api_key.get_secret_value() if api_key else config.api_key.get_secret_value()
            if not key_value:
                raise QuarantineAgentError("GEMINI_API_KEY not configured")
            provider: Provider = GeminiProvider(
                api_key=key_value,
                model=resolved_model,
            )

        case "openai":
            from .openai import OPENAI_API_BASE, OpenAIProvider

            key_value = api_key.get_secret_value() if api_key else config.openai_api_key
            if not key_value:
                raise QuarantineAgentError("OPENAI_API_KEY not configured")
            provider = OpenAIProvider(
                api_key=key_value,
                model=driver_model("openai", resolved_model),
                base_url=config.openai_base_url or OPENAI_API_BASE,
            )

        case "openrouter":
            provider = _openrouter(
                (api_key or config.openrouter_api_key).get_secret_value(),
                resolved_model,
                config.reasoning_effort,
            )

        case "anthropic":
            provider = _anthropic(api_key, resolved_model)

        case "ollama":
            from .ollama import OllamaProvider

            provider = OllamaProvider(
                model=driver_model("ollama", resolved_model),
                base_url=config.ollama_base_url,
            )

        case "vertex":
            provider = _vertex(api_key, vertex, resolved_model)

        case _:
            raise QuarantineAgentError(
                f"Unknown provider {resolved_provider!r}. "
                "Supported: gemini, openai, anthropic, ollama, openrouter, vertex"
            )

    return _register(provider, cache_key, api_key is not None)


def get_fallback_providers(profile: Profile) -> list[tuple[str, SecretStr | None]]:
    """Resolve the configured fallback chain to (provider_name, api_key) pairs.

    Skips a provider the calling profile has no key for — a warning says the
    chain is shorter than configured — except ollama, which is keyless; and
    vertex when the profile has no ``defense.vertex`` to send it to.
    Standalone the profile is the synthesized operator, whose ``llm_keys``
    mirror the environment, so the chain is the global one it always was.

    Args:
        profile: The calling profile (its ``llm_keys`` dict holds the keys).

    Returns:
        List of (provider_name, api_key_or_none) tuples ready for _call_gemini().
    """
    config = get_config()
    chain: list[tuple[str, SecretStr | None]] = []

    for name in config.provider_fallback:
        if name == "ollama":
            chain.append((name, None))
            continue
        if name not in profile.llm_keys:
            logger.warning(
                "provider fallback: skipping %r — no key in profile %r",
                name,
                profile.name,
            )
            continue
        if name == "vertex" and profile.defense.vertex is None:
            # Built, it would raise the non-retryable "needs defense.vertex"
            # and end the chain on a primary's 429 instead of passing it on.
            logger.warning(
                "provider fallback: skipping 'vertex' — profile %r has no defense.vertex",
                profile.name,
            )
            continue
        chain.append((name, profile.llm_keys[name].api_key))

    return chain


def reset_provider() -> None:
    """Clear the cached providers (for testing)."""
    _provider_cache.clear()
