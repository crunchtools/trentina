"""The fail-closed disposition rule is derived in one place, never re-copied.

Phase 1 of Trentina 3.0 moved the decision "a flagged or incompletely-judged
payload is refused unless the mode is flag" into ``core.dispose`` / ``Posture``,
after the hand-rolled copies had drifted: ``gateway/outbound.py`` derived
``stop_on_partial`` from ``mode is Mode.BLOCK`` (fail-OPEN for any future
non-BLOCK mode) where the tools and the ingress used ``mode is not Mode.FLAG``
(fail-closed). They agreed only because ``redact`` cannot be an enforcement mode
on the proxy paths.

This test fences that drift structurally. Outside ``core/``, the two booleans
that encode the rule — the ``stop_on_partial`` argument to ``defend()`` and the
``"blocked"`` attribution — may never again be written as a ``Mode`` comparison.
They come from ``Posture.stop_on_partial`` / ``Posture.records_block()``, or they
are a plain constant (a path that is always strict, like the gatekeeper). If a
fourth mode is ever added, there is one place that decides what it does, and it
fails closed there (``dispose``'s ``assert_never``) rather than fanning out into
a dozen ``mode is X`` branches that each guess.
"""

from __future__ import annotations

import ast
from pathlib import Path

SRC = Path(__file__).resolve().parent.parent / "src" / "trentina"
CORE = SRC / "core"


def _mentions_mode(node: ast.AST) -> bool:
    """Whether an expression references the ``Mode`` enum (``Mode.X`` or ``Mode(...)``)."""
    for sub in ast.walk(node):
        if isinstance(sub, ast.Name) and sub.id == "Mode":
            return True
        if (
            isinstance(sub, ast.Attribute)
            and isinstance(sub.value, ast.Name)
            and sub.value.id == "Mode"
        ):
            return True
    return False


def test_disposition_rule_is_not_rederived_outside_core() -> None:
    violations: list[str] = []
    for path in SRC.rglob("*.py"):
        if CORE in path.parents:
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        rel = path.relative_to(SRC)
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                for kw in node.keywords:
                    if kw.arg == "stop_on_partial" and _mentions_mode(kw.value):
                        violations.append(
                            f"{rel}:{kw.value.lineno}: stop_on_partial is a Mode comparison"
                        )
            if isinstance(node, ast.Dict):
                for key, value in zip(node.keys, node.values, strict=False):
                    if (
                        isinstance(key, ast.Constant)
                        and key.value == "blocked"
                        and _mentions_mode(value)
                    ):
                        violations.append(f'{rel}:{value.lineno}: "blocked" is a Mode comparison')
    assert not violations, (
        "The fail-closed disposition rule must come from core (Posture / dispose), "
        "not a Mode comparison at the call site:\n  " + "\n  ".join(violations)
    )
