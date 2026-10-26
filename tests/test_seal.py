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

As Trentina 3.0 lands its other trust types each joins ``SEALED`` with the
function that builds it: ``Posture`` and ``Judged`` when their factories arrive
with the orchestrator (``identity.posture`` / ``core.gate``, Phase 4), and
``ResolvedPath`` when the confined open returns one.
"""

from __future__ import annotations

import ast
from pathlib import Path

SRC = Path(__file__).resolve().parent.parent / "src" / "trentina"

# Each sealed trust type mapped to the ONE place that may construct it: the src
# module (path relative to ``src/trentina``) and the function within it whose
# check produces the value. A construction anywhere else — another module, or
# another function in the same module — is the forgery this seal forbids. Tests
# construct freely; only ``src`` runs inside the perimeter.
SEALED: dict[str, tuple[str, str]] = {
    # A ResolvedTarget is proof an address passed egress.check_url.
    "ResolvedTarget": ("reach/egress.py", "check_url"),
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
