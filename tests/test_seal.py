"""The trust types are constructed in one place each, never forged elsewhere.

Trentina 3.0's security rests on a handful of UNFORGEABLE types: holding a value
of the type is proof that a check ran. A ``ResolvedTarget`` is proof that an
address passed ``egress.check_url`` (#260) — so if other code built one around
an unchecked address, the egress guard would be a suggestion, not a boundary,
and ``egress.open_pinned`` / ``PinnedBackend.pin`` would dial wherever the
forged value pointed.

Python cannot make a dataclass genuinely unconstructable, so this test is the
fence: the only FUNCTION allowed to construct each sealed type is the one that
performs its check, and a construction anywhere else in ``src`` fails here —
including through an import alias (``from egress import ResolvedTarget as RT``)
and including elsewhere in the same module as the factory. This binds in-repo
code, which is every caller there is until out-of-tree plugins land; the Phase 6
runtime token is the stricter layer for untrusted authors. It is the same
structural shape as ``test_disposition_parity``: one rule in one place, no
enforcement spread across the codebase.

All four of Trentina 3.0's unforgeable trust types are now sealed, each to the
function that builds it: ``ResolvedTarget`` to ``egress.check_url``,
``ResolvedPath`` to the confined open, ``Posture`` to ``identity.posture``, and
``Judged`` to the orchestrator's ``judge_response`` (built only once the gate
has run).
"""

from __future__ import annotations

import ast
import os
from pathlib import Path

import pytest

from trentina.core.dispose import Posture
from trentina.core.stages import Judged
from trentina.modes import Mode, ModePolicy
from trentina.reach.egress import ResolvedTarget
from trentina.seal import Seal
from trentina.tools.confine import ResolvedPath

SRC = Path(__file__).resolve().parent.parent / "src" / "trentina"

# Each sealed trust type mapped to the ONE place that may construct it: the src
# module (path relative to ``src/trentina``) and the function within it whose
# check produces the value. A construction anywhere else — another module, or
# another function in the same module — is the forgery this seal forbids. Tests
# construct freely; only ``src`` runs inside the perimeter.
SEALED: dict[str, tuple[str, str]] = {
    # A ResolvedTarget is proof an address passed egress.check_url.
    "ResolvedTarget": ("reach/egress.py", "check_url"),
    # A ResolvedPath is proof a path passed confinement and was opened under
    # O_NOFOLLOW — so no code can hand read_tool/dir_tool a forged "confined" path.
    "ResolvedPath": ("tools/confine.py", "open_confined"),
    # A Posture is built from the bound request identity (honeypot read from the
    # ambient scope), never assembled ad hoc where a field could drift.
    "Posture": ("core/identity.py", "posture"),
    # A Judged binds a gate verdict to the exact transformed bytes it was reached
    # over — built only after scan_tool_response (the gate) has run, so holding
    # one is proof the gate ran on those bytes and no others.
    "Judged": ("orchestrator.py", "judge_response"),
}


def _constructs(node: ast.AST, names: set[str]) -> bool:
    """Whether ``node`` calls one of ``names`` as a constructor — bare
    (``RT(...)``, covering an import alias) or qualified (``egress.RT(...)``).
    A class definition or a type annotation is not a call, so neither is
    flagged."""
    if not isinstance(node, ast.Call):
        return False
    func = node.func
    if isinstance(func, ast.Name):
        return func.id in names
    return isinstance(func, ast.Attribute) and func.attr in names


def test_sealed_types_are_constructed_only_by_their_factory() -> None:
    violations: list[str] = []
    for path in SRC.rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        rel = str(path.relative_to(SRC))
        for type_name, (home, factory) in SEALED.items():
            # Local names that mean this type here, so an aliased import
            # (``import ResolvedTarget as RT``) cannot slip a construction past.
            names = {type_name} | {
                alias.asname or alias.name
                for node in ast.walk(tree)
                if isinstance(node, ast.ImportFrom)
                for alias in node.names
                if alias.name == type_name
            }
            # The constructions the seal allows: those lexically inside the
            # factory function, in its own module. Everything else is a forgery.
            allowed = {
                sub
                for node in ast.walk(tree)
                if rel == home
                and isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                and node.name == factory
                for sub in ast.walk(node)
                if _constructs(sub, names)
            }
            for node in ast.walk(tree):
                if _constructs(node, names) and node not in allowed:
                    where = f"{rel}:{node.lineno}"
                    violations.append(f"{where}: constructs {type_name} outside {home}:{factory}")
    assert not violations, (
        "A sealed trust type is constructed only by the function that checks it; "
        "elsewhere it would be a value no check stands behind:\n  " + "\n  ".join(violations)
    )


# The Phase 6 RUNTIME half: each sealed type carries a module-private Seal token
# its factory alone holds (``core.seal``), so a value of the type is proof the
# factory built it even for an out-of-tree author who never ran the AST test
# above. The token name is referenced only where it is defined (the type's
# module) and where it is passed (the factory's module); a reference anywhere
# else is a handle to forge the type at runtime, and is forbidden here.
SEAL_TOKENS: dict[str, frozenset[str]] = {
    "_TARGET_SEAL": frozenset({"reach/egress.py"}),
    "_PATH_SEAL": frozenset({"tools/confine.py"}),
    "_POSTURE_SEAL": frozenset({"core/dispose.py", "core/identity.py"}),
    "_JUDGED_SEAL": frozenset({"core/stages.py", "orchestrator.py"}),
}


def test_seal_tokens_live_only_with_their_type_and_factory() -> None:
    violations: list[str] = []
    for path in SRC.rglob("*.py"):
        rel = str(path.relative_to(SRC))
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Name):
                name = node.id
            elif isinstance(node, ast.Attribute):
                name = node.attr
            else:
                continue
            if name in SEAL_TOKENS and rel not in SEAL_TOKENS[name]:
                violations.append(f"{rel}:{node.lineno}: references seal token {name}")
    assert not violations, (
        "A seal token is a handle to forge its type at runtime; it belongs only "
        "with the type's definition and its factory:\n  " + "\n  ".join(violations)
    )


def _without_seal() -> dict[str, object]:
    """Each sealed type built with every field BUT the seal token — so what
    fails is the seal, not a missing argument. Values are placeholders: the
    seal's ``__post_init__`` runs before anything reads them."""
    policy = ModePolicy((Mode.FLAG,), Mode.FLAG)
    st = os.stat(__file__)
    return {
        "ResolvedTarget": lambda **k: ResolvedTarget(host="h", port=443, addresses=(), **k),
        "ResolvedPath": lambda **k: ResolvedPath(fd=0, st=st, path=Path("/"), **k),
        "Posture": lambda **k: Posture(mode=Mode.FLAG, policy=policy, **k),
        "Judged": lambda **k: Judged(transformed=object(), decision=object(), **k),
    }


@pytest.mark.parametrize("type_name", sorted(_without_seal()))
def test_sealed_type_refuses_a_missing_token(type_name: str) -> None:
    """Direct construction gets the ``UNSEALED`` default and is refused."""
    build = _without_seal()[type_name]
    with pytest.raises(TypeError, match="constructed only by"):
        build()


@pytest.mark.parametrize("type_name", sorted(_without_seal()))
def test_sealed_type_refuses_a_foreign_token(type_name: str) -> None:
    """A token the forger minted is not the factory's, so identity rejects it."""
    build = _without_seal()[type_name]
    with pytest.raises(TypeError, match="constructed only by"):
        build(_seal=Seal("forger"))
