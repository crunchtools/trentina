"""reach — the one place Trentina dials out from.

Every network leg the gateway makes to the world lands here, so the openers
that connect to an address and the check that clears one live beside each
other rather than scattered across the tree. Today that is the egress guard
(``reach.egress``): ``check_url`` resolves and refuses, ``ResolvedTarget`` is
the proof it passed, and ``open_guarded`` / ``open_pinned`` dial only what it
cleared. The operator-origin leg (``gateway/upstream.py``), the confined-path
open (``tools/confine.py``) and the CONNECT tunnel join this package as the
orchestrator carries their sealed results across module boundaries; until then
callers import from the submodule they need (``from ..reach.egress import …``).
"""
