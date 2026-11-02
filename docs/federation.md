# Gateway-to-gateway federation

> **Preview surface** (#592). Federation's configuration and wire shape are not
> frozen: a breaking change confined to them is a minor release. See
> [stability.md](stability.md).

Federation extends tool use to a second Trentina gateway. The primary Trentina provides its agent profiles with tools from MCP servers connected directly to it, as well as tools connected through a secondary Trentina. It creates a framework for trust tools and associated security scanning between gateways. This gives architectural flexibility for how tools flow between locations, data centers, or VPCs. It may also help with scaling resource usage.

Picture a gateway on your **laptop** and another on a **server**. The server fronts a set of tools; you want your laptop's agents to call them without re-plumbing every backend locally. Federation lets the laptop essentially *mount* the server's tools as if they were its own.

Two roles:

- **Primary** — the gateway that *uses* them (the laptop).
- **Secondary** — the gateway that *offers* tools (the server).

The link is **one-way**: the primary mounts the secondary's tools. The secondary can never see or call anything on the primary. The laptop's own tools stay private even while it consumes tools from the server.

## What you share is a seat

A federation link is a property of **the seat whose tools you are sharing**, not a separate thing you build beside it. You write a `federation` block on that seat — who may authenticate, and the key it signs verdicts with — and the gateway derives the ingress from it: a profile named `<seat>-federation`, offering that seat's own remote backends, with that seat's guards and defense posture.

So sharing Josui's tools on the server means writing one block on the `josui` profile. The primary then points at `/gateway/josui-federation/mcp`.

There is deliberately nothing else to write, because everything else used to be a way to get it wrong:

- The offered set is **derived**, not listed. A backend added to the seat is offered on the next reload with no second edit, and a hand-listed set that no longer matches the seat is not expressible.
- The name is **derived**, so it follows the seat rather than the machine at the other end. The profile name *is* the JWT audience, which makes it load-bearing on both sides; an invented name hides that.
- The defense posture is **inherited**, so a link can never be scanned less strictly than the seat whose tools it serves.
- The seat's OAuth sign-ins **serve the link**, so one human sign-in covers both sides.

What does *not* cross: the seat's internal tool surface (a peer gets the paging reader and nothing else), its decoys, its bridges and ingresses, its egress and git grants, and any backend that is itself federated.

## Why trust the other gateway's scan

Trentina scans untrusted content at its perimeter: deterministic checks, a local classifier, and a quarantined LLM with no tools. Instances of Trentinas can be connected together as if they're regular MCP servers, and it will work, but tool responses will be scanned **twice** — once by the secondary on the way in (from its MCP servers), once by the primary on the way in (from the other Trentinas). Same bytes, double the cost and latency.

**Scan-once** removes the second pass. The secondary scans a response and signs a short verdict — in effect, "I checked these exact bytes; here's the result." The primary verifies that signature and serves the response without scanning again. The primary stops re-scanning and relies on the secondary - the **trust boundary** extends to the secondary.

Trust is off by default. You turn it on per secondary.

## Two keys, two jobs

Federation uses two separate private/public keypairs to ensure trust both ways:

- A **primary key** proves *which primary is calling* — like a client certificate. The primary signs each request; the secondary cryptographically validates the caller. There is no shared bearer token, so every call carries the real caller's identity into audit logs instead of collapsing to one anonymous identity.
- A **secondary key** proves *what the secondary concluded about a response* — it's what the primary checks before it will trust a verdict.

## Setup

Three moves, and none of them needs a shell, a file edit or a restart. An operator agent makes the first itself, proposes the second, and makes the third once you have agreed to the second.

1. **Two keypairs exist** — a primary key for the primary, a secondary key for the secondary. Each gateway mints its own: ask it for a key and it keeps the private half somewhere no tool can read, and hands back the public half. A private key is never in a config file; the config refers to it by name. The public halves cross over and are pinned on the opposite side.
2. **Share the seat** — a `federation` block on the seat whose tools you are sharing, naming its peers and its secondary key. This one needs a person: admitting a peer hands another gateway a seat on your gateway, and since the link spends that seat's sign-ins, it hands over the accounts a person authorized there too. The approval page says which backends cross and which of them run on your sign-in. At this stage the link is authenticated but still double-scans. Prove it works here first.
3. **Turn on trust** — on the primary, pin the secondary's key plus a *fingerprint of its scanner*. Now the primary trusts verdicts that match and scans locally anything that doesn't. The agent proposes this one; it cannot apply it. Nothing moves until a person opens the approval page and agrees, and the page shows the key's fingerprint and both gateways' scanners side by side, so you are comparing them rather than taking a name on trust.

Trust is the only setting that decides whether a layer runs at all, which is why it is the one an agent can ask for and not take. [Approvals](approvals.md) is how that works, and what happens on a gateway where nobody can approve.

Pinning the scanner's fingerprint, not just the key, is what makes trust safe: a response is trusted only if the secondary scanned it with the exact model and settings you vetted. If the secondary quietly swaps in a weaker scanner, the fingerprint stops matching and the primary falls back to scanning for itself.

## Constraints, and why they exist

- **HTTPS required.** The per-request token is short-lived but has no replay nonce, so a plaintext link would let an on-path attacker replay it within its window. (A local-network override exists for trusted networks, and warns loudly.)
- **Clocks in sync.** The token is valid only for a narrow window of seconds, so NTP drift between the two gateways will reject otherwise-valid tokens. Clock sync is a requirement, not a nicety.
- **A shared seat is a seat.** It is `role: agent` — an operator seat shared with a peer would offer that peer the gateway's own admin tools — it carries `auth` or `oauth` of its own, since a profile no agent can reach has no tools to share, it has at least one non-federated remote backend to offer, and its name does not end in `-federation`, which is reserved for the ingress derived from it.
- **A peer list, and a key each.** A seat's `federation` block declares at least one peer, because the peer list *is* what authenticates a primary — a block without one is refused. Two peers may not share a public key: the caller recorded in the audit is the peer whose key verified, so a shared key would make that a matter of which peer was written first.
- **Several peers on one seat are fine.** Each authenticates with its own key and each is named in the audit. They do share one identity at the backends — a federated call runs as the ingress — so all of them spend the seat's sign-ins. That is the point when the peers are your own laptop and phone, and the reason the peer list needs a person's approval when they are not.
- **Adding a peer needs a person.** A write that adds or changes a `federation.peers` entry is staged for a human rather than applied. Removing one applies at once. See [approvals](approvals.md).
- **One primary key per secondary.** The per-request token is audience-pinned to the ingress *profile name*, and nothing in it says which gateway it was minted for. So one primary key used for two secondaries whose seats share a name mints tokens either secondary accepts, and one could replay the other's within the window. That configuration is refused at load. Give each secondary its own primary key — or name the seats differently, which per-seat naming makes natural.
- **No routing.** A gateway uses federated tools but never re-exports them onward. There's no mesh fabric or routing to configure; a single directed link is the whole primitive, and it is loop-free **by construction**: the derived offered set excludes every federated backend, so A to B to C is not refused, it is unsayable. One seat may therefore both consume a peer's tools and share its own. The pre-3.1 way of reaching a gateway — a backend pointing at its federation endpoint with no `federated:` block, over a shared bearer — is refused at load; that shape warned rather than refused until 5.0.0, and it was the hole in this promise.

## Operating concepts

- **Fail-closed.** A missing, forged, stale, or mismatched verdict never means "trust it" — it means "scan it locally." Trust only ever *removes* a redundant scan; it never lets something through unscanned.
- **Staying fresh.** The primary re-checks the secondary's tool list on an interval, so a newly approved or changed tool shows up on its own, without a manual reconnect.
- **Approvals happen on the secondary — and then on the primary too.** A new or changed tool on the secondary is held for approval by the *secondary's* operator, because that's who owns the tool, and the primary reports a pending-approval count for monitoring. But once the link is past its first connect, the primary holds a newly added or changed tool as well, one at a time, exactly as it would for any remote backend. Only the *first* list is approved as a unit. Both sides, not just the secondary — see [tool pinning](tool-pinning.md).
- **One sign-in, both sides.** A grant belongs to a profile and a federated call runs as the ingress, so the link uses the **seat's** OAuth grants. Sign in once, on the seat, and the link is signed in: the tool that does it is the seat's own `backend_auth`, which no peer can reach. Before 5.0.0 the ingress held its own grants, so the same person authorized the same account twice and `backend_auth_tool` had to be offered across the link to make that possible — which on a shared ingress let one peer revoke another's sign-in, or start one that repointed every peer's calls at its own human's account. Both are gone; the tool is no longer offerable to a peer.
- **A trusted response skips more than the scan.** Delivering on the secondary's verdict returns before the primary's own transform chain, so a trusted response is not minified, not converted to Markdown, and ignores the caller's `trentina_preprocess` switch — the bytes the secondary judged are the bytes delivered, which is what the layer contract requires. It is the right behaviour and it surprises people: a trusted backend's output looks different from the same backend's output when a pin stops matching.
- **Seeing the link.** `quarantine_stats` carries a `federation` section for an operator: per shared seat, the derived ingress, the peers by key fingerprint, which backends cross, which of those run on your sign-in, whether the link signs verdicts at all, and how many tools are held for approval. Per federated backend, the audience, whether trust is pinned, how its responses were handled, and the commonest reason one was re-judged. A `trusted` count of zero beside a climbing `hash_mismatch` is a pin that has quietly stopped matching and is buying nothing — which nothing else reports, because such a link keeps working and only costs twice.
- **A refusal is not an outage.** If the secondary rejects the primary's token, the primary reports `federation_unauthorized` and leaves the peer's circuit closed. It is one of three things: the peer holds a different public key for you, the audience does not match the URL, or the clocks have drifted. Before 5.0.0 this counted as unreachability and opened a breaker keyed by URL, so one rotated key took the peer down for every profile federating to it.
- **Moving a peer's URL keeps its approvals.** Normalising a trailing slash or writing `:443` explicitly is the same endpoint, and the reload carries the backend's tool pins across and says it did (`federated_pins_migrated`). A URL naming a *different* host is a different peer: its pins do not move, and the first list there is a first connect — which approves that peer's whole offered set as a unit, loudly. Renaming the seat changes the path, so it is a different endpoint too: expect one first connect on each side, once.

## Out of scope

Egress and git federation, a mesh fabric, and routing among more than two gateways are deliberately not part of this. Federation is the single directed link between two gateways; anything larger is a separate effort.
