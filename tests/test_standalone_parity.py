"""Standalone is the synthesized operator, byte for byte (#579, P7.3 commit 8).

Before Trentina 3.0 the single-tenant standalone server defended through its
own set of fall-throughs — ``scope is None``, ``scope.profile is None``,
``standalone_policy``. Now it is one operator profile synthesized from the
environment, read the same way a declared operator is. These tests hold that
identity three ways:

* **Parity.** The delivery a standalone server produces is identical to the one
  the same tool produces bound to a file-declared operator with the same
  defense — across every family and mode, benign and hostile — differing only
  where it must: the profile NAME that lands on an audit row.
* **L3 keys.** The synthesized operator resolves each provider's judge off the
  environment key for that provider, exactly as a bound profile resolves its
  own ``llm_keys``.
* **No regression.** A static guard keeps the retired ``None`` branches and
  ``standalone_policy`` from coming back into ``src/``.
"""

from __future__ import annotations

import ast
import json
import subprocess
import sys
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest
from pydantic import SecretStr

from trentina import database
from trentina.config import get_config
from trentina.errors import BlockedSourceError
from trentina.gateway.context import profile_context
from trentina.gateway.profile import AuthConfig, DefenseConfig, Profile
from trentina.gateway.standalone import STANDALONE, environment_operator, standalone_profile

from .mode_harness import BENIGN, FAMILIES, MALICIOUS, MODES, call, layers

if TYPE_CHECKING:
    from trentina.modes import Mode

# Audit identity is the ONE field that may differ between the two operators:
# the synthesized one is named "standalone", the declared one "ops". Everything
# else in a delivery must match. ``profile`` names appear nowhere a benign or
# flag delivery carries, but a refusal body never carries one either, so the
# set is empty today and the drop is defensive against a future field.
_IDENTITY_FIELDS: tuple[str, ...] = ()


def _file_operator() -> Profile:
    """A declared operator whose defense mirrors the synthesized one.

    Built the validated way — real ``auth`` — so it is a genuine
    ``profiles.yaml`` operator, not a second ``model_construct``. Its defense is
    copied from the synthesized profile so the only differences the parity test
    can surface are the ones it is meant to: the name and the auth edge.
    """
    syn = standalone_profile(get_config())
    operator = Profile(
        name="ops",
        auth=AuthConfig(bearer_token_env="TEST"),
        role="operator",
        defense=DefenseConfig(
            enforcement=syn.defense.enforcement,
            modes=list(syn.defense.modes),
            provider=syn.defense.provider,
            model=syn.defense.model,
        ),
        llm_keys=dict(syn.llm_keys),
        backends={},
    )
    assert operator.auth is not None
    operator.auth.bearer_token = SecretStr("x")
    return operator


async def _deliver(family: str, mode: Mode, fakes: Any) -> dict[str, Any]:
    """One (family, mode) call's delivery, with a refusal reduced to its body."""
    try:
        return await call(family, mode, fakes)
    except BlockedSourceError as exc:
        return {"_refusal": exc.refusal}


def _clear_blocklist() -> None:
    """Both operators must start from the same (empty) blocklist.

    The blocklist is cumulative state, not delivery logic: a first hostile call
    flags the source, and because an operator reads gateway-wide a second call
    would then see ``on the blocklist`` instead of a fresh flag. Clearing it
    between the two deliveries is what keeps the comparison about the delivery
    path and not about who ran first.
    """
    db = database.get_db()
    db.execute("DELETE FROM detections")
    db.commit()


def _comparable(result: dict[str, Any]) -> str:
    """The delivery as stable JSON, minus the fields that carry profile identity."""
    return json.dumps(
        {k: v for k, v in result.items() if k not in _IDENTITY_FIELDS}, sort_keys=True
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("family", FAMILIES)
@pytest.mark.parametrize("mode", MODES, ids=lambda m: m.value)
@pytest.mark.parametrize("hostile", [False, True], ids=["benign", "hostile"])
async def test_standalone_delivers_what_a_file_operator_delivers(
    env: Path, family: str, mode: Mode, hostile: bool
) -> None:
    classification = MALICIOUS if hostile else BENIGN
    detection = (
        {"injection_detected": True, "risk_level": "high", "summary": "x", "findings": []}
        if hostile
        else None
    )

    # Standalone: nothing bound, so current_scope synthesizes the operator.
    _clear_blocklist()
    with layers(env, classification=classification, detection=detection) as fakes:
        standalone = await _deliver(family, mode, fakes)

    # The same call bound to a declared operator with the same defense, from the
    # same empty blocklist.
    _clear_blocklist()
    with (
        layers(env, classification=classification, detection=detection) as fakes,
        profile_context(_file_operator()),
    ):
        declared = await _deliver(family, mode, fakes)

    assert _comparable(standalone) == _comparable(declared)


def test_the_synthesized_operator_is_an_operator_named_standalone() -> None:
    operator = environment_operator()
    assert operator.name == STANDALONE
    assert operator.role == "operator"
    assert operator.auth is None


@pytest.mark.usefixtures("env")
@pytest.mark.parametrize("provider", ["gemini", "openai", "anthropic", "openrouter"])
def test_each_providers_env_key_becomes_the_operators_own(
    monkeypatch: pytest.MonkeyPatch, provider: str
) -> None:
    """The synthesized operator judges off its own ``llm_keys``, one per provider.

    This is the whole reason judge resolution is identical to the retired
    env-global path: ``llm_keys`` mirrors every provider key the environment
    holds, so ``resolve_profile_llm`` finds the same key for that provider that
    the old global read would have.
    """
    import trentina.config as config_mod
    from trentina.quarantine.agent import resolve_profile_llm

    env_var = {
        "gemini": "GEMINI_API_KEY",
        "openai": "OPENAI_API_KEY",
        "anthropic": "ANTHROPIC_API_KEY",
        "openrouter": "OPENROUTER_API_KEY",
    }[provider]
    monkeypatch.setenv(env_var, f"{provider}-secret")
    config_mod._config = None

    operator = standalone_profile(get_config())
    name, key, _model = resolve_profile_llm(operator, provider)
    assert name == provider
    assert key is not None
    assert key.get_secret_value() == f"{provider}-secret"


def test_no_standalone_none_branches_in_src() -> None:
    """The retired branches do not come back (#579).

    An AST walk, not a text grep: ``standalone.py``'s own module docstring names
    the old branches to explain what it replaced, and a grep would flag the
    prose. Only real code — a ``scope is None`` / ``scope.profile is None``
    comparison, or a ``standalone_policy`` reference — fails here.
    """
    src = Path(__file__).resolve().parent.parent / "src" / "trentina"
    offenders: list[str] = []

    for path in sorted(src.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        rel = path.relative_to(src)
        for node in ast.walk(tree):
            if isinstance(node, ast.Name) and node.id == "standalone_policy":
                offenders.append(f"{rel}:{node.lineno} standalone_policy")
            if isinstance(node, ast.Attribute) and node.attr == "standalone_policy":
                offenders.append(f"{rel}:{node.lineno} .standalone_policy")
            if isinstance(node, ast.Compare) and _is_scope_is_none(node):
                offenders.append(f"{rel}:{node.lineno} {_dump_compare(node)}")

    assert not offenders, "retired standalone/None branches are back:\n" + "\n".join(offenders)


def _is_scope_is_none(node: ast.Compare) -> bool:
    """``scope is None`` or ``scope.profile is None`` — the two the model retired.

    A bare ``profile is None`` stays legal: request-path handlers resolve a
    profile from a bearer token and None there is an unauthenticated caller,
    a live fail-closed guard.
    """
    if len(node.ops) != 1 or not isinstance(node.ops[0], ast.Is):
        return False
    if not (len(node.comparators) == 1 and _is_none(node.comparators[0])):
        return False
    left = node.left
    if isinstance(left, ast.Name) and left.id == "scope":
        return True
    return (
        isinstance(left, ast.Attribute)
        and left.attr == "profile"
        and isinstance(left.value, ast.Name)
        and left.value.id == "scope"
    )


def _is_none(node: ast.expr) -> bool:
    return isinstance(node, ast.Constant) and node.value is None


def _dump_compare(node: ast.Compare) -> str:
    return ast.unparse(node)


def test_agent_first_import_order_has_no_cycle() -> None:
    """The isolated-plugin subprocess imports ``agent`` first (#579 commit 7).

    ``get_current_profile`` is imported lazily inside ``bound_profile`` precisely
    so this order loads. Proven in a clean interpreter, not this one, where the
    package is already imported.
    """
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            "import trentina.quarantine.agent; import trentina.client; import trentina.server",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
