# Gateway-to-Gateway Federation

Two Trentina gateways can be linked so that a **downstream** mounts an
**upstream**'s offered tools as if they were its own, over a directed,
profile-declared, authenticated edge — and **trusts the upstream's scan instead
of re-judging** what crosses it. That last part is the point: without it, every
federated response is judged by the upstream's three layers and then re-judged
by the downstream's (twice the L3 tokens and latency). With it, the upstream
scans once and signs a verdict the downstream verifies and serves.

Federation is additive and opt-in (3.1.0). A profile with no `federated:` or
`federation:` block behaves exactly as before.

## The shape of an edge

An edge is **directed**. The upstream *offers* a declared set of tools; the
downstream *consumes* them. The upstream can never enumerate or call the
downstream's local tools — a downstream's Red Hat stack stays local even when it
mounts a public upstream. A pair of gateways that each want the other's tools
declare **two** edges, one in each direction.

A gateway **consumes, it does not route**: a mounted tool is never re-exported
onward. That makes the mesh loop-free by construction, so there is no
spanning-tree or routing machinery — the single link is the primitive.

Two blocks declare the two ends, beside `auth:` on an ordinary agent-role
profile:

- **Downstream** — a backend with a `federated:` block instead of (or beside) a
  plain `url:`. Its presence marks the backend as a federated peer and carries
  the edge signing key and, once trust is turned on, the upstream's public key
  and perimeter stamp (below).
- **Upstream** — a `federation:` block naming the `peers:` whose edge JWTs it
  accepts, and optionally its own `signing_key_env` for verdict signing. A
  profile with `federation.peers` is a **federation ingress**; a downstream peer
  authenticates to it with an edge JWT, so it needs no shared static bearer.

Both blocks are held on an agent `reload_profiles` and refused on a honeypot,
like every other security-bearing field.

## Authentication: a stateless edge key

The link authenticates with a per-edge **Ed25519 key**, not a shared bearer.
The downstream signs a short-lived (60 s) JSON Web Token whose claims are an
actor chain in the shape of RFC 8693: `sub` is the real caller, `act.sub` is the
downstream itself, and `aud` is the federation profile being called. The
upstream verifies it against the peer's public key.

There is no `/token` round-trip and **no grant store** — there is no subject
token to exchange, because callers hold their own credentials upstream of the
downstream, and the JWT is minted fresh per request from the edge key. The key
is read once from its `_FILE`-capable env var at startup and scrubbed from the
environment.

Because the token carries the **real caller** (not just "the downstream"), the
upstream's audit, request guards and response guards all evaluate the actual
actor. The upstream's `gateway_calls` rows carry two columns: `caller_peer`,
the authenticated downstream, and `caller_sub`, the real caller the downstream
asserts. Both are written to the **audit database**; `caller_sub` is peer-chosen
rather than independently verified, so it is recorded there and nowhere else —
never emitted to the journal (the logging rule, #262, keeps caller-chosen text
out of the logs other agents can read). This is what the single shared static
bearer of the interim arrangement could not do — every call looked like one
identity.

## Provenance, not renaming

A federated tool keeps its short, token-cheap served name — there is no forced
`lotor_` prefix, because short-naming already strips a backend-name prefix, and
a rename would cost the agent tokens and break hooks that key on tool names. The
upstream origin is recorded **internally and in the audit**, and the
"why can't profile X see tool Y?" diagnostic reports it. An operator who wants
visible disambiguation can still set `name_tag` per backend.

## Scan-once at the trust boundary

This is the headline. When trust is configured, a federated response is
delivered **without re-running the downstream's L1/L2/L3**.

**The upstream signs.** A federation ingress with a `signing_key_env` emits a
verdict assertion beside each federated response, SLSA-VSA-shaped:
`{verifier, content_sha256, verdict, perimeter_stamp, judge, ts}`, signed with
its own key and carried in the response `_meta` (the channel the MCP SDK
preserves). It also signs its `tools/list` descriptions the same way. The
upstream signs with its **own** key — distinct from the downstream's edge key:
the edge key authenticates a caller, the signing key vouches for a response.

**The downstream trusts, or re-judges.** A `federated.trust_verdict` block pins
the upstream's `public_key`, the `perimeter_stamp` it expects, and the `judge`
(provider/model/pack). On each federated response the downstream checks, as a
pure fail-closed function, that the assertion's signature verifies **and** its
`content_sha256` matches the exact bytes delivered **and** its `perimeter_stamp`
equals the pinned stamp **and** its `judge` equals the pinned judge **and** the
resolved mode matches **and** it is fresh. Only when *all* hold is the response
served as the upstream judged it:

- a clean verdict is delivered as it arrived;
- a flagged verdict under `block` refuses, exactly as a local block would;
- a flagged verdict under `flag` is delivered with a **downstream-authored**
  warning built from the verdict's closed fields — the peer's text is never
  relayed.

Any failure — a missing, forged, stale, hash-mismatched, stamp-mismatched or
judge-mismatched assertion — **falls through to the full local pipeline**
(re-judge), logged by the kind of miss. An upstream that retunes its L2 model or
L3 prompt changes its stamp, which auto-invalidates the pin until an operator
updates it: a weaker judge cannot be swapped in under the same stamp.

Why the `judge` pin on top of the stamp: the `perimeter_stamp` covers L2 (the
model, revision, threshold, polarity, gates, window) and the perimeter version,
but **not** L3. Without a separate judge pin, an upstream could answer with a
weaker L3 model under an unchanged stamp and still be trusted.

The carve-out lives in the response edge's assembly, before the transform, never
in `defend()` — the layer contract is untouched. A trusted verdict is the same
"each layer reads once" the constitution already allows for a cached verdict,
carried over a signed channel. See the Coverage table and Known gap 33 in the
[defense pipeline](defense-pipeline.md) for exactly what the stamp binds and
what it does not (the peer's defense **policy** — its modes, thresholds and
allowlists — is accepted by declaring the edge, not re-derived downstream).

Production keeps `trust_verdict` **unset** until an operator pins a peer's key
and stamp; unset means re-judge, exactly as today.

## Paging is not repeated

A response the upstream already paged is not re-paged. The downstream recognises
the upstream's `_trentina_part` shape (carried in `_meta`) and forwards a
`read_part` call to the peer, rather than cutting the response again.

## Pinning across a federated edge

See [Tool Pinning](tool-pinning.md) for the mechanism; the federated specifics:

- **No first-connect storm.** A large upstream offers hundreds of tools. On the
  downstream's **first** connect to a federated backend, the whole offered set
  is approved as a unit rather than held tool by tool — declaring the edge
  accepts the peer's curation, and its set already passed the peer's own pin
  gate. "First" is a persisted marker, so an empty first list still records the
  connect; thereafter a newly added or changed upstream tool is held one at a
  time, as usual.
- **Held state travels downstream.** The upstream reports how many tools it is
  withholding in the caller's slice as a count in its `tools/list` `_meta`
  (`_trentina_pins.held`, no tool names), which the downstream surfaces per
  federated backend. And when the upstream's call gate refuses a held tool, the
  downstream maps the closed `tool_held` reason to its own words — "held
  upstream, awaiting approval" (`tool_held_upstream`) — never relaying the peer's
  refusal text.
- **A pending-pin count for monitoring.** The unauthenticated `/health` probe
  reports a gateway-wide count of tools pending approval, so Nagios can alarm on
  a federated upstream that has grown tools awaiting an operator.

## Finding each gateway's operator

Approving a held federated tool happens on the **upstream** that holds it, with
its operator's `tool_pins` tool — the downstream only reports that something is
held there. A pending count on the downstream's view points at work the upstream
operator must do.

## Out of scope

Egress (`:8021`) and git (`/proxy/git`) federation, a mesh fabric, and routing
are deliberately out of scope. Horizontal scaling to thousands of users is a
separate effort; federation's new state is built externalize-ready but is not
that effort.
