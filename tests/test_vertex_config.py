"""Config wiring for the ``vertex`` L3 provider (no network)."""

from __future__ import annotations

import json

import pytest
from pydantic import SecretStr, ValidationError

from trentina.errors import QuarantineAgentError
from trentina.gateway.errors import ProfileConfigError
from trentina.gateway.llm_proxy import load_llm_providers, validate_profile_llm_keys
from trentina.gateway.profile import (
    AuthConfig,
    DefenseConfig,
    LlmKeyOverride,
    Profile,
    VertexTarget,
)
from trentina.quarantine.providers import _provider_cache, get_provider, reset_provider

ADC = json.dumps(
    {
        "type": "authorized_user",
        "client_id": "id",
        "client_secret": "secret",
        "refresh_token": "refresh",
    }
)
TARGET = VertexTarget(project="my-project-1", region="us-central1")


@pytest.fixture(autouse=True)
def _fresh_cache():
    reset_provider()
    yield
    reset_provider()


def test_defense_accepts_vertex_target():
    d = DefenseConfig(provider="vertex", model="gemini-3.5-flash-lite", vertex=TARGET.model_dump())
    assert d.vertex == TARGET


@pytest.mark.parametrize(
    "bad",
    [
        {"project": "Bad_Project", "region": "global"},
        {"project": "x", "region": "global"},
        {"project": "my-project-1", "region": "us central"},
        {"project": "my-project-1", "region": "../x"},
        {"project": "my-project-1"},
        {"project": "my-project-1", "region": "global", "extra": 1},
    ],
)
def test_defense_refuses_bad_target(bad):
    with pytest.raises(ValidationError):
        DefenseConfig(vertex=bad)


def test_global_region_ok():
    assert VertexTarget(project="my-project-1", region="global").region == "global"


def test_provider_vertex_requires_target():
    with pytest.raises(ValidationError, match=r"defense\.vertex"):
        DefenseConfig(provider="vertex")


def test_target_without_provider_vertex_allowed():
    assert DefenseConfig(provider="gemini", vertex=TARGET.model_dump()).vertex == TARGET


def _profile() -> Profile:
    return Profile(
        name="p",
        auth=AuthConfig(bearer_token_env="T"),
        defense=DefenseConfig(provider="vertex", vertex=TARGET.model_dump()),
        llm_keys={"vertex": LlmKeyOverride(api_key=SecretStr(ADC))},
    )


def test_llm_key_needs_no_llm_provider():
    validate_profile_llm_keys({}, {"p": _profile()})


def test_other_llm_key_still_needs_llm_provider():
    prof = _profile()
    prof.llm_keys["gemini"] = LlmKeyOverride(api_key=SecretStr("k"))
    with pytest.raises(ProfileConfigError):
        validate_profile_llm_keys({}, {"p": prof})


def test_vertex_cannot_be_a_reverse_proxy_provider():
    with pytest.raises(ProfileConfigError, match="L3-only"):
        load_llm_providers(
            {"vertex": {"upstream": "https://example.com", "api": "openai", "enabled": True}}
        )


def test_get_provider_builds_vertex():
    from trentina.quarantine.providers.vertex import VertexProvider

    p = get_provider("vertex", api_key=SecretStr(ADC), model="gemini-3.5-flash-lite", vertex=TARGET)
    assert isinstance(p, VertexProvider)
    assert p.judge == ("vertex", "gemini-3.5-flash-lite")


def test_get_provider_vertex_needs_key():
    with pytest.raises(QuarantineAgentError, match=r"llm_keys\.vertex"):
        get_provider("vertex", model="m", vertex=TARGET)


def test_get_provider_vertex_needs_target():
    with pytest.raises(QuarantineAgentError, match=r"defense\.vertex"):
        get_provider("vertex", api_key=SecretStr(ADC), model="m")


def test_cache_distinguishes_projects_and_regions():
    a = get_provider("vertex", api_key=SecretStr(ADC), model="m", vertex=TARGET)
    b = get_provider(
        "vertex",
        api_key=SecretStr(ADC),
        model="m",
        vertex=VertexTarget(project="other-project-2", region="us-central1"),
    )
    c = get_provider(
        "vertex",
        api_key=SecretStr(ADC),
        model="m",
        vertex=VertexTarget(project="my-project-1", region="global"),
    )
    assert len({id(a), id(b), id(c)}) == 3
    assert get_provider("vertex", api_key=SecretStr(ADC), model="m", vertex=TARGET) is a
    assert all(len(k) == 5 for k in _provider_cache)


def test_loader_refuses_unusable_vertex_credential_at_load():
    from trentina.gateway.loader import _check_vertex_credentials

    profile = _profile()
    _check_vertex_credentials("p", profile)  # a well-formed ADC file loads

    profile.llm_keys["vertex"] = LlmKeyOverride(
        api_key=SecretStr('{"type": "authorized_user", "client_id": "id"}')
    )
    with pytest.raises(ProfileConfigError, match=r"llm_keys\.vertex") as exc:
        _check_vertex_credentials("p", profile)
    assert "client_secret" in str(exc.value)

    profile.llm_keys["vertex"] = LlmKeyOverride(api_key=SecretStr("hunter2-not-json"))
    with pytest.raises(ProfileConfigError) as exc:
        _check_vertex_credentials("p", profile)
    assert "hunter2" not in str(exc.value)


def _env_judged(monkeypatch, provider: str, fallback: str = "") -> None:
    """TRENTINA_MODEL_PROVIDER / TRENTINA_PROVIDER_FALLBACK, on a fresh config."""
    import trentina.config as cfg_mod

    monkeypatch.setenv("TRENTINA_MODEL_PROVIDER", provider)
    monkeypatch.setenv("TRENTINA_PROVIDER_FALLBACK", fallback)
    monkeypatch.setattr(cfg_mod, "_config", None)


def _bare_profile(**defense) -> Profile:
    return Profile(
        name="p",
        auth=AuthConfig(bearer_token_env="T"),
        defense=DefenseConfig(**defense),
        llm_keys={
            "vertex": LlmKeyOverride(api_key=SecretStr(ADC)),
            "gemini": LlmKeyOverride(api_key=SecretStr("k")),
        },
    )


def test_loader_refuses_inherited_vertex_judge_without_target(monkeypatch):
    from trentina.gateway.loader import _check_vertex_judges

    _env_judged(monkeypatch, "vertex")
    with pytest.raises(ProfileConfigError, match=r"TRENTINA_MODEL_PROVIDER.*defense\.vertex"):
        _check_vertex_judges({"p": _bare_profile()})
    _check_vertex_judges({"p": _bare_profile(vertex=TARGET.model_dump())})
    _check_vertex_judges({"p": _bare_profile(provider="gemini")})


def test_loader_ignores_vertex_target_when_env_judge_is_not_vertex(monkeypatch):
    from trentina.gateway.loader import _check_vertex_judges

    _env_judged(monkeypatch, "gemini")
    _check_vertex_judges({"p": _bare_profile()})


def test_fallback_skips_vertex_without_target(monkeypatch, caplog):
    from trentina.quarantine.providers import get_fallback_providers

    _env_judged(monkeypatch, "gemini", "vertex,gemini")
    chain = get_fallback_providers(_bare_profile())
    assert [name for name, _key in chain] == ["gemini"]
    assert "defense.vertex" in caplog.text


def test_fallback_keeps_vertex_with_target(monkeypatch):
    from trentina.quarantine.providers import get_fallback_providers

    _env_judged(monkeypatch, "gemini", "vertex")
    chain = get_fallback_providers(_bare_profile(vertex=TARGET.model_dump()))
    assert [name for name, _key in chain] == ["vertex"]
