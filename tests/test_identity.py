"""The one Posture factory: honeypot resolved from scope, everything else passed.

``identity.posture`` is sealed (``test_seal``) as the only place a ``Posture`` is
built; this exercises what it DOES — read the honeypot flag from the ambient
request scope, and carry the rest through untouched. The honeypot resolution is
the factory's reason to exist (it is why it is not a thin wrapper), so every
scope shape it must survive is pinned here.
"""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import patch

from trentina.core.identity import posture
from trentina.modes import Mode, ModePolicy

POLICY = ModePolicy((Mode.BLOCK, Mode.FLAG, Mode.REDACT), Mode.BLOCK)
# posture() does ``from ..gateway.scope import current_scope`` at call time, so
# the module attribute is what it resolves — patch it there.
_SCOPE = "trentina.gateway.scope.current_scope"


def _scope(profile: object) -> SimpleNamespace:
    return SimpleNamespace(profile=profile)


class TestHoneypotFromScope:
    def test_a_non_honeypot_profile_is_not_a_honeypot(self) -> None:
        with patch(_SCOPE, return_value=_scope(SimpleNamespace(honeypot=False))):
            assert posture(Mode.FLAG, POLICY).honeypot is False

    def test_a_honeypot_profile_is_a_honeypot(self) -> None:
        with patch(_SCOPE, return_value=_scope(SimpleNamespace(honeypot=True))):
            assert posture(Mode.FLAG, POLICY).honeypot is True


class TestEverythingElseIsPassedThrough:
    def test_mode_policy_allowlisted_and_prompt_are_preserved(self) -> None:
        with patch(_SCOPE, return_value=_scope(SimpleNamespace(honeypot=False))):
            p = posture(Mode.REDACT, POLICY, allowlisted=True, prompt="just the title")
        assert p.mode is Mode.REDACT
        assert p.policy is POLICY
        assert p.allowlisted is True
        assert p.prompt == "just the title"

    def test_allowlisted_and_prompt_default_off(self) -> None:
        with patch(_SCOPE, return_value=_scope(SimpleNamespace(honeypot=False))):
            p = posture(Mode.BLOCK, POLICY)
        assert p.allowlisted is False
        assert p.prompt is None
