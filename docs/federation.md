# Gateway-to-gateway federation

Federation extends tool use to a second Trentina gateway. The primary Trentina provides its agent profiles with tools from MCP servers connected directly to it, as well as tools connected through a secondary Trentina. It creates a framework for trust tools and associated security scanning between gateways. This gives architectural flexibility for how tools flow between locations, data centers, or VPCs. It may also help with scaling resource usage.

Picture a gateway on your **laptop** and another on a **server**. The server fronts a set of tools; you want your laptop's agents to call them without re-plumbing every backend locally. Federation lets the laptop essentially *mount* the server's tools as if they were its own.

Two roles:

- **Primary** — the gateway that *uses* them (the laptop).
- **Secondary** — the gateway that *offers* tools (the server).

The link is **one-way**: the primary mounts the secondary's tools. The secondary can never see or call anything on the primary. The laptop's own tools stay private even while it consumes tools from the server.

## Why trust the other gateway's scan

Trentina scans untrusted content at its perimeter: deterministic checks, a local classifier, and a quarantined LLM with no tools. Instances of Trentinas can be connected together as if they're regular MCP servers, and it will work, but tool responses will be scanned **twice** — once by the secondary on the way in (from its MCP servers), once by the primary on the way in (from the other Trentinas). Same bytes, double the cost and latency.

**Scan-once** removes the second pass. The secondary scans a response and signs a short verdict — in effect, "I checked these exact bytes; here's the result." The primary verifies that signature and serves the response without scanning again. The primary stops re-scanning and relies on the secondary - the **trust boundary** extends to the secondary.

Trust is off by default. You turn it on per secondary.

## Two keys, two jobs

Federation uses two separate private/public keypairs to ensure trust both ways:

- A **primary key** proves *which primary is calling* — like a client certificate. The primary signs each request; the secondary cryptographically validates the caller. There is no shared bearer token, so every call carries the real caller's identity into audit logs instead of collapsing to one anonymous identity.
- A **secondary key** proves *what the secondary concluded about a response* — it's what the primary checks before it will trust a verdict.

## Setup

Three moves, and none of them needs a shell, a file edit or a restart. An operator agent makes the first two itself. The third it proposes and you agree to. The exact field names and formats live in the config schema and the code.

1. **Two keypairs exist** — a primary key for the primary, a secondary key for the secondary. Each gateway mints its own: ask it for a key and it keeps the private half somewhere no tool can read, and hands back the public half. A private key is never in a config file; the config refers to it by name. The public halves cross over and are pinned on the opposite side.
2. **Declare the link in two profiles** — an *ingress* profile on the secondary that lists the tools it offers and names its peers, and a *federated backend* on the primary pointing at that ingress. At this stage the link is authenticated but still double-scans. Prove it works here first.
3. **Turn on trust** — on the primary, pin the secondary's key plus a *fingerprint of its scanner*. Now the primary trusts verdicts that match and scans locally anything that doesn't. The agent proposes this one; it cannot apply it. Nothing moves until a person opens the approval page and agrees, and the page shows the key's fingerprint and both gateways' scanners side by side, so you are comparing them rather than taking a name on trust.

Trust is the only setting that decides whether a layer runs at all, which is why it is the one an agent can ask for and not take. [Approvals](approvals.md) is how that works, and what happens on a gateway where nobody can approve.

Pinning the scanner's fingerprint, not just the key, is what makes trust safe: a response is trusted only if the secondary scanned it with the exact model and settings you vetted. If the secondary quietly swaps in a weaker scanner, the fingerprint stops matching and the primary falls back to scanning for itself.

## Constraints, and why they exist

- **HTTPS required.** The per-request token is short-lived but has no replay nonce, so a plaintext link would let an on-path attacker replay it within its window. (A local-network override exists for trusted networks, and warns loudly.)
- **Clocks in sync.** The token is valid only for a narrow window of seconds, so NTP drift between the two gateways will reject otherwise-valid tokens. Clock sync is a requirement, not a nicety.
- **One role per profile.** A profile is either a secondary's ingress or a primary's consumer, never both — so a two-way pair of gateways is four profiles, and each operator owns exactly what their own side exposes.
- **A peer list, and a key each.** An ingress declares at least one peer, because the peer list *is* what authenticates a primary — a federation block without one is not an ingress and is refused. Two peers may not share a public key: the caller recorded in the audit is the peer whose key verified, so a shared key would make that a matter of which peer was written first.
- **No second way in.** An ingress profile may not also carry `auth` or `oauth`, and is refused at load if it does. The peer list is its authentication, and the gateway tries a static bearer *first* — so a bearer on an ingress would admit a caller through that instead, with no peer and no `sub`. Everything downstream then reads a null caller: the audit records no actor, the guarantee below that every request names its real caller is false for that profile, and held response parts — which belong to `(profile, peer, sub)` — would all share one owner. If you have an ingress with an `auth` block today, it loaded before 5.0.0; delete the block, since `peers` was already doing the work.
- **Adding a peer needs a person.** Since 5.0.0 a write that adds or changes a `federation.peers` entry is staged for a human rather than applied, because it hands another gateway a seat on your ingress. Removing one applies at once. See [approvals](approvals.md).
- **One primary key per secondary.** The per-request token is audience-pinned to the ingress *profile name*, and nothing in it says which gateway it was minted for. So one primary key used for two secondaries whose ingress profiles share a name mints tokens either secondary accepts, and one could replay the other's within the window. That configuration is refused at load. Give each secondary its own primary key, or give the ingress profiles different names — either is enough, and a key each is the better habit.
- **No routing.** A gateway uses federated tools but never re-exports them onward. There's no mesh fabric or routing to configure; a single directed link is the whole primitive, which keeps it loop-free by construction. An ingress profile that also mounts a federated secondary is refused at load, and so is the pre-3.1 way of reaching one — a backend pointing at a gateway's federation endpoint with no `federated:` block, over a shared bearer. That shape warned rather than refused until 5.0.0, and it was the hole in this promise: it let an ingress re-export the next gateway, A to B to C.

## Operating concepts

- **Fail-closed.** A missing, forged, stale, or mismatched verdict never means "trust it" — it means "scan it locally." Trust only ever *removes* a redundant scan; it never lets something through unscanned.
- **Staying fresh.** The primary re-checks the secondary's tool list on an interval, so a newly approved or changed tool shows up on its own, without a manual reconnect.
- **Approvals happen on the secondary — and then on the primary too.** A new or changed tool on the secondary is held for approval by the *secondary's* operator, because that's who owns the tool, and the primary reports a pending-approval count for monitoring. But once the link is past its first connect, the primary holds a newly added or changed tool as well, one at a time, exactly as it would for any remote backend. Only the *first* list is approved as a unit. Both sides, not just the secondary — see [tool pinning](tool-pinning.md).
- **Signing in across the link.** A grant belongs to one profile, and a federated call runs as the ingress profile, so an OAuth backend on the secondary needs its own sign-in for that ingress. List `backend_auth_tool` in the ingress's internal backend, approve it on the primary, and it is served there with the peer's tag, such as `lotor_backend_auth`. It acts only on that ingress's own backends, needs `auth.self_authorize` on each one, and returns a link on the secondary's public URL. A call with no grant is refused with the name of that tool, and doesn't count against the link's circuit breaker. **It is allowed only on an ingress with one peer.** A grant belongs to the profile and a federated call runs as the ingress, so on a shared ingress any peer could revoke another's sign-in — or start a fresh one and make its own human's account the account every peer's calls use. Two peers plus `backend_auth_tool` is refused at load.
- **A trusted response skips more than the scan.** Delivering on the secondary's verdict returns before the primary's own transform chain, so a trusted response is not minified, not converted to Markdown, and ignores the caller's `trentina_preprocess` switch — the bytes the secondary judged are the bytes delivered, which is what the layer contract requires. It is the right behaviour and it surprises people: a trusted backend's output looks different from the same backend's output when a pin stops matching.
- **Verifying it works.** The secondary's audit shows the real caller on every request; the primary's audit shows whether each response was trusted or re-scanned, and when it was re-scanned, why. Those are the signals to watch — and the second one is how you find out that a pin has quietly stopped matching and is buying nothing.
- **A refusal is not an outage.** If the secondary rejects the primary's token, the primary reports `federation_unauthorized` and leaves the peer's circuit closed. It is one of three things: the peer holds a different public key for you, the audience does not match the URL, or the clocks have drifted. Before 5.0.0 this counted as unreachability and opened a breaker keyed by URL, so one rotated key took the peer down for every profile federating to it.
- **Moving a peer's URL keeps its approvals.** Normalising a trailing slash or writing `:443` explicitly is the same endpoint, and the reload carries the backend's tool pins across and says it did (`federated_pins_migrated`). A URL naming a *different* host is a different peer: its pins do not move, and the first list there is a first connect — which approves that peer's whole offered set as a unit, loudly.

## Out of scope

Egress and git federation, a mesh fabric, and routing among more than two gateways are deliberately not part of this. Federation is the single directed link between two gateways; anything larger is a separate effort.
