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

Three moves. The first two an operator agent makes itself — no shell, no file editing, no restart. The third is deliberately a person's. The exact field names and formats live in the config schema and the code.

1. **Two keypairs exist** — a primary key for the primary, a secondary key for the secondary. Each gateway mints its own: ask it for a key and it keeps the private half somewhere no tool can read, and hands back the public half. A private key is never in a config file; the config refers to it by name. The public halves cross over and are pinned on the opposite side.
2. **Declare the link in two profiles** — an *ingress* profile on the secondary that lists the tools it offers and names its peers, and a *federated backend* on the primary pointing at that ingress. At this stage the link is authenticated but still double-scans. Prove it works here first.
3. **Turn on trust** — on the primary, pin the secondary's key plus a *fingerprint of its scanner*. Now the primary trusts verdicts that match and scans locally anything that doesn't. This one is a person editing the file: it is the only setting that decides whether a layer runs at all, so it is not something an agent can turn on, however convincingly it is asked.

Pinning the scanner's fingerprint, not just the key, is what makes trust safe: a response is trusted only if the secondary scanned it with the exact model and settings you vetted. If the secondary quietly swaps in a weaker scanner, the fingerprint stops matching and the primary falls back to scanning for itself.

## Constraints, and why they exist

- **HTTPS required.** The per-request token is short-lived but has no replay nonce, so a plaintext link would let an on-path attacker replay it within its window. (A local-network override exists for trusted networks, and warns loudly.)
- **Clocks in sync.** The token is valid only for a narrow window of seconds, so NTP drift between the two gateways will reject otherwise-valid tokens. Clock sync is a requirement, not a nicety.
- **One role per profile.** A profile is either a secondary's ingress or a primary's consumer, never both — so a two-way pair of gateways is four profiles, and each operator owns exactly what their own side exposes.
- **No routing.** A gateway uses federated tools but never re-exports them onward. There's no mesh fabric or routing to configure; a single directed link is the whole primitive, which keeps it loop-free by construction.

## Operating concepts

- **Fail-closed.** A missing, forged, stale, or mismatched verdict never means "trust it" — it means "scan it locally." Trust only ever *removes* a redundant scan; it never lets something through unscanned.
- **Staying fresh.** The primary re-checks the secondary's tool list on an interval, so a newly approved or changed tool shows up on its own, without a manual reconnect.
- **Approvals happen on the secondary.** A new or changed tool on the secondary is held for approval by the *secondary's* operator — that's who owns the tool. The primary only reports that something is held there, and exposes a pending-approval count for monitoring.
- **Verifying it works.** The secondary's audit shows the real caller on every request; the primary's audit shows whether each response was trusted or re-scanned, and when it was re-scanned, why. Those are the signals to watch — and the second one is how you find out that a pin has quietly stopped matching and is buying nothing.

## Out of scope

Egress and git federation, a mesh fabric, and routing among more than two gateways are deliberately not part of this. Federation is the single directed link between two gateways; anything larger is a separate effort.
