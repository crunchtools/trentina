"""The ONE perimeter-call lifecycle guardrail (#511, extends the #260/#167 discipline).

``relay.Operation`` owns the slot, the outcome/reason settle and the single
``gateway_calls`` row for every terminating reverse proxy — ``/egress``, ``/git``,
``/llm``, the Matrix proxy and the CONNECT tunnel. The convergence collapsed the
hand-rolled copies of that bookkeeping that had drifted apart. This test keeps a
sixth path from quietly growing another: writing a ``gateway_calls`` row is
allowed only from the known audit lifecycles, so a new perimeter route must
finish a ``relay.Operation`` rather than call ``record_gateway_call`` itself.
"""

from __future__ import annotations

import ast
import pathlib

_SRC = pathlib.Path(__file__).resolve().parent.parent / "src" / "trentina"

#: The modules that may write a ``gateway_calls`` row, each a DISTINCT audit
#: lifecycle. Adding one here is a deliberate act: it means a genuinely new
#: lifecycle, NOT a perimeter reverse proxy (which must finish a
#: ``relay.Operation``). Today they are:
#:   gateway/relay.py              — the ONE perimeter-proxy lifecycle (Operation.finish)
#:   gateway/audit.py              — the MCP tool-call path (``_audit``, lifted from router in PR3a)
#:   gateway/matrix_bridge/core.py — the Matrix bridge appservice (bridged events, not the proxy)
#:   gateway/backend_oauth.py      — a backend OAuth token exchange
_ALLOWED = {
    "gateway/relay.py",
    "gateway/audit.py",
    "gateway/matrix_bridge/core.py",
    "gateway/backend_oauth.py",
}


def _modules_calling(func: str) -> set[str]:
    """Every module under ``src/trentina`` with a call to ``func`` by name."""
    found: set[str] = set()
    for path in _SRC.rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            target = node.func
            name = (
                target.attr
                if isinstance(target, ast.Attribute)
                else target.id
                if isinstance(target, ast.Name)
                else None
            )
            if name == func:
                found.add(path.relative_to(_SRC).as_posix())
    return found


def test_a_gateway_calls_row_is_written_only_by_the_known_lifecycles() -> None:
    """A new perimeter route must finish a ``relay.Operation``, never call
    ``record_gateway_call`` itself — else it spawns a parallel lifecycle (its own
    slot cap, outcome mapping, exactly-once row), the drift #511 removed. A new
    direct caller here is a deliberate choice and must be justified by adding it
    to ``_ALLOWED`` above (a genuinely different audit lifecycle)."""
    callers = _modules_calling("record_gateway_call")
    assert callers == _ALLOWED, (
        f"unexpected gateway_calls writer(s): {sorted(callers - _ALLOWED)}; "
        f"gone: {sorted(_ALLOWED - callers)}. A perimeter reverse proxy must write "
        "its row through relay.Operation, not record_gateway_call directly."
    )


# --- The spine is the only way onto the perimeter (#535 R5) ----------------------

#: Modules that mount a route that is NOT a perimeter path: content pushed in,
#: the approval page, OAuth callbacks, the gateway's own MCP surface.
_NOT_PERIMETER = {
    "__init__.py",
    "gateway/alert_ingress.py",
    "gateway/approval_routes.py",
    "gateway/backend_oauth.py",
    "gateway/app.py",
}

#: Perimeter paths not yet moved onto the spine: none, since #535 R10. A
#: perimeter path has one way in.
_NOT_YET_ON_THE_SPINE: frozenset[str] = frozenset()

_SPINE = "transports/perimeter.py"


def test_only_the_spine_mounts_a_perimeter_path() -> None:
    """A route served by hand skips the spine: its caller, its slot, its dial,
    its judging and its row. ``custom_route`` and ``start_server`` are the two
    ways to serve something; outside the spine only non-perimeter modules (and,
    until #535 R11, the routes still being ported) may call them."""
    allowed = _NOT_PERIMETER | _NOT_YET_ON_THE_SPINE | {_SPINE}
    callers = _modules_calling("custom_route") | _modules_calling("start_server")
    assert callers <= allowed, (
        f"serves a route outside the spine: {sorted(callers - allowed)}. A perimeter "
        "route is a transports.base.Route mounted by transports.registry."
    )


def _route_classes() -> set[str]:
    """Every class in ``src`` that subclasses ``Route`` or ``Listener``, by name."""
    found: set[str] = set()
    for path in _SRC.rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if not isinstance(node, ast.ClassDef):
                continue
            for base in node.bases:
                target = base.value if isinstance(base, ast.Subscript) else base
                name = target.id if isinstance(target, ast.Name) else getattr(target, "attr", "")
                if name in {"Route", "Listener"}:
                    found.add(node.name)
    return found


def test_every_route_in_the_source_is_seeded() -> None:
    """A Route class the registry does not seed is never mounted, so it is
    either dead or about to be served some other way."""
    from trentina.transports import registry

    seeded = {type(route).__name__ for route, _kind in registry._seed().values()} | {
        type(listener).__name__ for listener, _kind in registry._listener_seed().values()
    }
    assert _route_classes() == seeded
