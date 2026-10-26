"""transports — one package per wire protocol (Trentina 3.0 registry 2).

A transport speaks a protocol. It is two halves that the orchestrator runs in a
fixed order it alone knows: a ``Face`` (authenticate, parse the request, wrap
the response) and a ``Carrier`` (carry an outbound request to a resolved
destination and bring back the reply). Neither half constructs a sealed trust
type, and the order — request edge, carry, response edge — is the security
property, so a transport cannot skip the gate (plan §A/§C).

Phase 4 lands the first transport, the MCP server face + client carrier
(``transports.mcp``), as the in-tree extraction target for the hand-rolled
``gateway/router.py`` ``tools/call`` path. The remaining faces (alert, matrix,
llm, http-egress, git) follow in Phase 5, and the typed public contract — the
plugin surface — is drawn in Phase 6.
"""
