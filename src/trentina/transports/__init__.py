"""transports — one package per wire protocol (Trentina 3.0 registry 2).

A transport speaks a protocol. It is two halves that the orchestrator runs in a
fixed order it alone knows: a ``Face`` (authenticate, parse the request, wrap
the response) and a ``Dispatch`` (hand an outbound request to a resolved
destination and bring back the reply). Neither half constructs a sealed trust
type, and the order — request edge, dispatch, response edge — is the security
property, so a transport cannot skip the gate (plan §A/§C). Both are in-tree.

Under them, a backend's session rides a ``Carrier`` (#740): the frozen v1
plugin contract in ``base.py``, ``http`` built in (``http_carrier``). The
perimeter routes (``perimeter``, #535) are the third role.
"""
