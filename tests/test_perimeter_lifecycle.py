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
