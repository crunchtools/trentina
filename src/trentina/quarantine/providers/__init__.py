"""Pluggable LLM provider drivers for the Q-Agent and compression."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from ...config import get_config
from ...errors import QuarantineAgentError
from .base import Provider, ProviderResult

if TYPE_CHECKING:
    from pydantic import SecretStr

    from ...gateway.profile import Profile

logger = logging.getLogger(__name__)

_provider_cache: dict[tuple[str, str, str], Provider] = {}

__all__ = ["Provider", "ProviderResult", "get_fallback_providers", "get_provider"]

_DEFAULT_GEMINI_MODEL = "gemini-3.5-flash-lite"


def openrouter_model(model: str) -> str:
    """``model`` as OpenRouter names it: the bare default is given its vendor."""
    return f"google/{model}" if model == _DEFAULT_GEMINI_MODEL else model


def _openrouter(key_value: str, model: str, reasoning_effort: str | None) -> Provider:
    """The OpenAI driver pointed at OpenRouter, where model ids carry a vendor."""
    from .openai import OPENROUTER_API_BASE, OPENROUTER_ROUTING, OpenAIProvider

    if not key_value:
        raise QuarantineAgentError("OPENROUTER_API_KEY not configured")
    return OpenAIProvider(
        api_key=key_value,
        model=openrouter_model(model),
        base_url=OPENROUTER_API_BASE,
        routing=OPENROUTER_ROUTING,
        reasoning_effort=reasoning_effort,
    )


def _key_ordinal(key_value: str) -> str:
    """The limiter's name for a key: the one an instance on it already has.

    Read off the cache, which holds the key already, so no second copy is
    kept and nothing is derived from it. A key not yet seen takes the next
    ``key<n>``; the env key (``global``) keeps its own name.
    """
    if key_value == "global":
        return key_value
    for (_name, cached_key, _model), provider in _provider_cache.items():
        if cached_key == key_value:
            return provider.key_ordinal
    return f"key{len({k for _n, k, _m in _provider_cache if k != 'global'}) + 1}"


def get_provider(
    provider_name: str | None = None,
    api_key: SecretStr | None = None,
    model: str | None = None,
) -> Provider:
    """Return a provider instance, cached per (provider, api_key, model) tuple.

    The cache key uses the full secret value rather than a prefix so two
    profiles whose keys share a prefix cannot collide onto one instance.

    Args:
        provider_name: Explicit provider to use. When None, falls back
            to TRENTINA_MODEL_PROVIDER from config (the global default).
        api_key: API key override for this provider. When None, falls back
            to the global config key for the provider.
        model: Model override for this provider. When None, falls back
            to QUARANTINE_MODEL from config.
    """
    config = get_config()
    resolved_provider = provider_name or config.provider
    resolved_model = model or config.model

    key_value = api_key.get_secret_value() if api_key else "global"
    cache_key = (resolved_provider, key_value, resolved_model)

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
            from .openai import OpenAIProvider

            key_value = api_key.get_secret_value() if api_key else config.openai_api_key
            if not key_value:
                raise QuarantineAgentError("OPENAI_API_KEY not configured")
            default_model = (
                resolved_model if resolved_model != _DEFAULT_GEMINI_MODEL else "gpt-4o-mini"
            )
            provider = OpenAIProvider(api_key=key_value, model=default_model)

        case "openrouter":
            provider = _openrouter(
                (api_key or config.openrouter_api_key).get_secret_value(),
                resolved_model,
                config.reasoning_effort,
            )

        case "anthropic":
            from .anthropic import AnthropicProvider

            key_value = api_key.get_secret_value() if api_key else config.anthropic_api_key
            if not key_value:
                raise QuarantineAgentError("ANTHROPIC_API_KEY not configured")
            default_model = (
                resolved_model
                if resolved_model != _DEFAULT_GEMINI_MODEL
                else "claude-haiku-4-5-20251001"
            )
            provider = AnthropicProvider(api_key=key_value, model=default_model)

        case "ollama":
            from .ollama import OllamaProvider

            default_model = (
                resolved_model if resolved_model != _DEFAULT_GEMINI_MODEL else config.ollama_model
            )
            provider = OllamaProvider(
                model=default_model,
                base_url=config.ollama_base_url,
            )

        case _:
            raise QuarantineAgentError(
                f"Unknown provider {resolved_provider!r}. "
                "Supported: gemini, openai, anthropic, ollama, openrouter"
            )

    provider.judge = (resolved_provider, provider.model)
    provider.key_ordinal = _key_ordinal(cache_key[1])
    _provider_cache[cache_key] = provider
    logger.info(
        "provider: initialized %s (model=%s, key=%s)",
        resolved_provider,
        resolved_model,
        "override" if api_key else "global",
    )
    return provider


def get_fallback_providers(profile: Profile) -> list[tuple[str, SecretStr | None]]:
    """Resolve the configured fallback chain to (provider_name, api_key) pairs.

    Skips a provider the calling profile has no key for — a warning says the
    chain is shorter than configured — except ollama, which is keyless.
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
        chain.append((name, profile.llm_keys[name].api_key))

    return chain


def reset_provider() -> None:
    """Clear the cached providers (for testing)."""
    _provider_cache.clear()
