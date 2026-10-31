# Gateway-to-gateway federation

Federation links two Trentina gateways so one can use the other's tools — and, optionally, trust the other's security scan instead of repeating it.

Picture a gateway on your **laptop** and another on a **server**. The server fronts a set of tools; you want your laptop's agents to call them without re-plumbing every backend locally. Federation lets the laptop *mount* the server's tools as if they were its own.

Two roles:

- **Upstream** — the gateway that *offers* tools (the server).
- **Downstream** — the gateway that *uses* them (the laptop).

The link is **one-way**: the downstream reaches the upstream's tools; the upstream can never see or call anything on the downstream. The laptop's own tools stay private even while it borrows the server's. It's opt-in — a gateway with no federation config behaves exactly as before.

## Why trust the other gateway's scan

Every Trentina gateway scans untrusted content at its perimeter: deterministic checks, a local classifier, and a quarantined LLM with no tools. In a plain federated link a tool response is scanned **twice** — once by the upstream on the way out, once by the downstream on the way in. Same bytes, double the cost and latency.

**Scan-once** removes the second pass. The upstream scans a response and signs a short verdict — in effect, "I checked these exact bytes; here's the result." The downstream verifies that signature and serves the response without scanning again. The line where the downstream stops re-scanning and relies on the upstream is the **trust boundary**.

Trust is off by default. You turn it on per edge, and only once the plain link already works, because trusting another gateway's scan is a decision you make deliberately — not a default you back into.

## Two keys, two jobs

Federation uses two separate keypairs, and the separation is the whole point:

- An **edge key** proves *which downstream is calling* — like a client certificate. The downstream signs each request; the upstream recognizes the caller by which pinned key verifies it. There's no shared bearer token, so every call carries the real caller's identity into the upstream's audit instead of collapsing to one anonymous identity.
- A **signing key** proves *what the upstream concluded about a response* — it's what the downstream checks before it will trust a verdict.

One key says who's talking; the other says what was decided. Leaking one can't forge the other's job.

## Setting one up, in concept

Three moves (the exact field names, key formats, and env vars live in the config schema and code):

1. **Generate two keypairs** — an edge key for the downstream, a signing key for the upstream. Each private half stays on its own gateway; the public halves cross over and are pinned on the opposite side.
2. **Declare the edge in two profiles** — an *ingress* profile on the upstream that lists the tools it offers and names its peers, and a *federated backend* on the downstream pointing at that ingress. At this stage the link is authenticated but still double-scans. Prove it works here first.
3. **Turn on trust** — on the downstream, pin the upstream's signing key plus a *fingerprint of its scanner*. Now the downstream trusts verdicts that match and scans locally anything that doesn't.

Pinning the scanner's fingerprint, not just the key, is what makes trust safe: a response is trusted only if the upstream scanned it with the exact model and settings you vetted. If the upstream quietly swaps in a weaker scanner, the fingerprint stops matching and the downstream falls back to scanning for itself.

## Constraints, and why they exist

- **HTTPS required.** The per-request token is short-lived but has no replay nonce, so a plaintext link would let an on-path attacker replay it within its window. (A local-network override exists for trusted networks, and warns loudly.)
- **Clocks in sync.** The token is valid only for a narrow window of seconds, so NTP drift between the two gateways will reject otherwise-valid tokens. Clock sync is a requirement, not a nicety.
- **One role per profile.** A profile is either an ingress or a consumer, never both — so a two-way pair of gateways is four profiles, and each operator owns exactly what their own side exposes.
- **No routing.** A gateway uses federated tools but never re-exports them onward. There's no mesh fabric or routing to configure; a single directed link is the whole primitive, which keeps it loop-free by construction.

## Operating concepts

- **Fail-closed.** A missing, forged, stale, or mismatched verdict never means "trust it" — it means "scan it locally." Trust only ever *removes* a redundant scan; it never lets something through unscanned.
- **Staying fresh.** The downstream re-checks the upstream's tool list on an interval, so a newly approved or changed upstream tool shows up on its own, without a manual reconnect.
- **Approvals happen upstream.** A new or changed upstream tool is held for approval by the *upstream's* operator — that's who owns the tool. The downstream only reports that something is held there, and exposes a pending-approval count for monitoring.
- **Verifying it works.** The upstream's audit shows the real caller on every request; the downstream's audit shows whether each response was trusted or re-scanned. Those are the signals to watch.

## Out of scope

Egress and git federation, a mesh fabric, and routing among more than two gateways are deliberately not part of this. Federation is the single directed link between two gateways; anything larger is a separate effort.
