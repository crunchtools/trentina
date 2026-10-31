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

This document is written for the architect or sysadmin who has to stand up and
operate an edge. The first half is procedure — generate the keys, write the two
profiles, turn on trust, verify it. The second half ("How it works" onward) is
the rationale behind each piece.

## The shape of an edge

An edge is **directed**. The upstream *offers* a declared set of tools; the
downstream *consumes* them. The upstream can never enumerate or call the
downstream's local tools — a downstream's Red Hat stack stays local even when it
mounts a public upstream.

An edge lives in **two profiles**, one on each gateway: a consuming profile on
the downstream (a backend with a `federated:` block) and an **ingress** profile
on the upstream (a `federation:` block naming its peers). A single profile may
not be both — a profile with `federation.peers` that also mounts a `federated:`
backend is **refused at load** (`loader._check_federation_topology`): one profile
is one role. A pair of gateways that each want the other's tools therefore
declares **four** profiles in all — a consumer and an ingress on each side.

A gateway **consumes, it does not route**: a mounted tool is never re-exported
onward. That makes the mesh loop-free by construction, so there is no
spanning-tree or routing machinery — the single link is the primitive.

## Setting up an edge

Say the downstream gateway is `breetai` and the upstream is
`lotor` (reachable at `https://lotor.example.com`). We want `breetai`'s
`josui` profile to mount `lotor`'s tools.

### 1. Generate the two keypairs

Federation uses **two** Ed25519 keypairs with distinct jobs (see
[Two keys, two jobs](#two-keys-two-jobs)):

```sh
# A private key must be readable only by the gateway account. openssl writes
# output files per the process umask, so set it tight BEFORE generating — a
# default 022 umask would leave the key group- and world-readable, and a local
# user who reads it can impersonate the peer or sign trusted verdicts:
umask 077

# Edge key — authenticates the downstream caller to the upstream.
openssl genpkey -algorithm ed25519 -out breetai_edge_key.pem
openssl pkey -in breetai_edge_key.pem -pubout -out breetai_edge_key.pub

# Signing key — lets the upstream vouch for its responses.
openssl genpkey -algorithm ed25519 -out lotor_fed_signing_key.pem
openssl pkey -in lotor_fed_signing_key.pem -pubout -out lotor_fed_signing_key.pub
```

The private keys (`*.pem`) are PKCS#8; the public keys (`*.pub`) are
SubjectPublicKeyInfo — the two forms the validators require. The **private**
keys are secrets: deliver each to its gateway as a file and reference it with
the `_FILE` form of its env var (below), never inline in `profiles.yaml`. On the
gateway host confirm the file is mode `600` and owned by the gateway account
(the container's runtime uid) — a copy does not preserve the creating umask, so
`chmod 600` and `chown` it after placing it. The **public** keys are not secret
and go inline in the YAML. A PEM is multi-line, which is another reason the
private side is always a `_FILE` secret, not an environment value.

Hold the private edge key on the **downstream** (`breetai`) and the private
signing key on the **upstream** (`lotor`). The two public keys cross over: the
downstream's edge public key is pinned on the upstream, and the upstream's
signing public key is pinned on the downstream.

### 2. The upstream ingress profile

On `lotor`, add a `role: agent` profile that offers the tools and names
`breetai` as a peer. An ingress **must** be `role: agent` — an operator ingress
would hand admin tools to a peer — and its internal backend, if any, may offer
only `read_part_tool` (`FEDERATION_INTERNAL_ALLOW`), so paging still works:

```yaml
fed-breetai:
  role: agent
  llm_keys:                       # the ingress judges with its own L3
    openrouter:
      api_key_env: LOTOR_OPENROUTER_API_KEY
  backends:
    # ... the tools this edge offers; the internal backend, if present,
    #     restricted to read_part_tool only:
    web:
      url: internal://web
      tools_allow: [read_part_tool]
  federation:
    signing_key_env: LOTOR_FED_SIGNING_KEY   # _FILE form resolves the PEM
    peers:
      breetai:
        public_key: |
          -----BEGIN PUBLIC KEY-----
          <contents of breetai_edge_key.pub>
          -----END PUBLIC KEY-----
```

A profile with `federation.peers` **is** a federation ingress: a peer
authenticates to it with an edge JWT, so the profile needs no `auth:` block and
no shared static bearer. `signing_key_env` is optional — without it the ingress
emits no verdict assertion and every downstream re-judges (authenticated, but no
scan-once).

Set the signing key's `_FILE` env var in `lotor`'s environment, e.g.
`LOTOR_FED_SIGNING_KEY_FILE=/config/lotor_fed_signing_key.pem`, and
`reload_profiles` as operator. `lotor` is now ready to accept an edge JWT;
nothing calls it yet.

### 3. The downstream consumer backend

On `breetai`, point the `josui` profile's backend at the ingress and give it the
edge key. The backend URL is the ingress's gateway MCP endpoint — the audience
the edge JWT is pinned to is the **profile name in the URL**
(`…/gateway/<profile>/mcp`):

```yaml
josui:
  role: operator            # a consumer may be any role; the ingress must be agent
  backends:
    lotor:
      url: https://lotor.example.com/gateway/fed-breetai/mcp
      federated:
        edge_key_env: BREETAI_EDGE_KEY        # _FILE form resolves the PEM
        poll_seconds: 300                     # re-probe the upstream every 5 min (0 = off)
        # trust_verdict omitted for now — re-judge, auth only (step 4 turns it on)
```

Set `BREETAI_EDGE_KEY_FILE=/run/secrets/breetai_edge_key` in `breetai`'s
environment, drop the old `Authorization` header if the link was on the interim
static bearer, and restart. With `edge_key_env` set and `trust_verdict` unset,
the link is **authenticated but still double-judging** — a safe checkpoint. Omit
`edge_key_env` entirely and the backend keeps using its existing headers/auth,
which is how the interim static-bearer edge keeps working during migration.

**Keeping the downstream fresh.** `poll_seconds` (default 300, `0` disables,
floor 30) sets how often this gateway re-probes the upstream in the background
and rebuilds the aggregates that use it, so a tool the upstream newly approves or
changes appears here within one interval — no manual `reconnect_backend`. A
backend whose circuit is open is skipped and picked up when it recovers; a
backend using `auth` instead of a federated edge key cannot set it.

### 4. Turn on scan-once

Only after the authenticated edge is proven: pin the upstream's signing public
key, perimeter stamp, and judge so the downstream trusts the signed verdict and
skips its own L1/L2/L3:

```yaml
      federated:
        edge_key_env: BREETAI_EDGE_KEY
        trust_verdict:
          public_key: |
            -----BEGIN PUBLIC KEY-----
            <contents of lotor_fed_signing_key.pub>
            -----END PUBLIC KEY-----
          perimeter_stamp: "<the upstream's exact perimeter_stamp>"
          judge: "<the upstream's exact judge: provider/model/pack>"
```

**Obtaining the stamp and judge to pin.** Both are the upstream's values, and
today nothing surfaces them to a downstream operator directly. Ask the upstream's
operator for them, or read them from the running upstream container:

```sh
podman exec <lotor-container> python -c \
  "from trentina.perimeter_db import perimeter_stamp; print(perimeter_stamp())"
```

The `judge` is the upstream profile's L3 identity as `provider/model/pack`
(e.g. `openrouter/google/gemini-3.5-flash-lite/<pack>@<hash>`); it also appears
verbatim in the `judge` field of a `_trentina_vsa` assertion the upstream
already returned, which is the authoritative source for what must match. (A
follow-up will surface both in the operator `quarantine_stats` output so the
`podman exec` is not needed.)

Restart the downstream. Trust is now live: a federated response whose assertion
verifies against all pinned values is served without re-judging, and anything
that fails any check falls back to a full local re-judge (fail-closed).

### Verifying the edge

- **Authentication:** the upstream's audit `gateway_calls` rows show
  `caller_peer=breetai` and `caller_sub=josui` (the real caller), not one shared
  identity.
- **Scan-once:** on the downstream, a trusted response's audit row has
  `detections_digest` **NULL** (it was not re-judged); a re-judged response has a
  non-NULL digest. That column is the one reliable tell that trust is working.
- **Fail-closed:** change the pinned stamp to a wrong value and confirm responses
  go back to re-judging (non-NULL digest). Then restore it.

## Keys, timers, and security requirements

### Two keys, two jobs

| Key | Private held by | Public pinned by | Job |
|-----|-----------------|------------------|-----|
| **Edge key** | downstream (`federated.edge_key_env`) | upstream (`federation.peers.<name>.public_key`) | authenticates the caller per request |
| **Signing key** | upstream (`federation.signing_key_env`) | downstream (`federated.trust_verdict.public_key`) | vouches for each response |

They are deliberately distinct: the edge key says *who is calling*, the signing
key says *what the upstream concluded about a response*. One compromised key does
not do the other's job.

### HTTPS is required

A federated backend URL must be `https://`. The edge JWT carries no replay nonce,
so over plain `http://` an on-path peer could replay it inside its lifetime; the
loader **refuses** an `http://` federated backend. `TRENTINA_FEDERATION_ALLOW_INSECURE=1`
lifts this for a trusted local network — warned at startup, and only as fetch's
private-address rule is lifted. Do not set it across an untrusted network.

### Timers are fixed, not tuneable

Three timers govern the edge, and all three are **compile-time constants** — no
env var or profile field changes them:

| Timer | Value | Where | What it bounds |
|-------|-------|-------|----------------|
| Edge JWT lifetime | 60 s | `edge_key.MAX_TTL_SECONDS` | how long a minted request token is valid |
| Clock-skew tolerance | 10 s | `edge_key.CLOCK_SKEW_SECONDS` | drift allowed on each side of the JWT window |
| Verdict assertion freshness | 300 s | `vsa.MAX_AGE_SECONDS` | how old a response assertion may be and still be trusted |

The 60 s lifetime is also enforced on the **verifier** (a token claiming a longer
life is rejected), so it is a ceiling, not just a default — making it an operator
knob would let a downstream mint a longer-lived credential, which is exactly what
the fixed cap prevents. Because the window is fixed and narrow, **keeping both
gateways' clocks in sync (NTP) is an operational requirement**, not merely good
practice: skew beyond ~10 s will reject tokens even though nothing else is wrong.

## How it works

### Authentication: a stateless edge key

The link authenticates with the per-edge **Ed25519 edge key**, not a shared
bearer. For each request the downstream mints a short-lived (60 s) JSON Web Token
and signs it with its private edge key. The token's claims are exactly `sub`
(the real caller), `aud` (the upstream federation profile named in the backend
URL), `iat` and `exp` — a closed set, nothing more. The upstream verifies the
signature against each pinned peer public key; **the name of the key that
verifies is the acting peer** — peer identity comes from the verifying key, not
from a claim inside the token. The verifier is a closed-shape parser, not a
general JWT library: the header is compared by byte-equality to the one header
Trentina issues, so `alg:none`/`jwk`/`jku` confusion cannot arise.

There is no `/token` round-trip and **no grant store** — there is no subject
token to exchange, because callers hold their own credentials upstream of the
downstream, and the JWT is minted fresh per request from the edge key. The key
is read once from its `_FILE`-capable env var at startup and scrubbed from the
environment.

Because the token carries the **real caller**, the upstream's **audit** records
who the request was really for. The `gateway_calls` rows carry two columns:
`caller_peer`, the authenticated downstream (the verifying key's name), and
`caller_sub`, the real caller the downstream asserts. Both are written to the
**audit database**; `caller_sub` is peer-chosen rather than independently
verified, so it is recorded there and nowhere else — never emitted to the
journal (the logging rule, #262, keeps caller-chosen text out of the logs other
agents can read), and, being unverified, it is not an input to the request or
response guards (those evaluate the call itself, as they do for any caller). This
is what the single shared static bearer of the interim arrangement could not do —
every call looked like one identity.

### Provenance, not renaming

A federated tool keeps its short, token-cheap served name — there is no forced
`lotor_` prefix, because short-naming already strips a backend-name prefix, and
a rename would cost the agent tokens and break hooks that key on tool names. The
upstream origin is recorded **internally and in the audit**, and the
"why can't profile X see tool Y?" diagnostic reports it. An operator who wants
visible disambiguation can still set `name_tag` per backend.

### Scan-once at the trust boundary

This is the headline. When trust is configured, a federated response is
delivered **without re-running the downstream's L1/L2/L3**.

**The upstream signs.** A federation ingress with a `signing_key_env` emits a
verdict assertion beside each federated response, SLSA-VSA-shaped:
`{verifier, content_sha256, verdict, perimeter_stamp, judge, ts}`, signed with
its own key and carried in the response `_meta` (the channel the MCP SDK
preserves). The signature covers the RFC 8785 canonical form of the assertion,
and `content_sha256` binds it to the exact delivered bytes both sides can
reproduce. The upstream signs with its **own** signing key — distinct from the
downstream's edge key: the edge key authenticates a caller, the signing key
vouches for a response. (Signing `tools/list` descriptions so a downstream can
trust them too, rather than re-judging each, is a planned follow-on; today the
assertion covers a tool-call response, and descriptions are re-judged.)

**The downstream trusts, or re-judges.** A `federated.trust_verdict` block pins
the upstream's `public_key`, the `perimeter_stamp` it expects, and the `judge`
(provider/model/pack). On each federated response the downstream checks, as a
pure fail-closed function, that the assertion's signature verifies **and** its
`content_sha256` matches the exact bytes delivered **and** its `perimeter_stamp`
equals the pinned stamp **and** its `judge` equals the pinned judge **and** the
resolved mode matches **and** it is no older than 300 s. Only when *all* hold is
the response served as the upstream judged it:

- a clean verdict is delivered as it arrived;
- a flagged verdict under `block` refuses, exactly as a local block would;
- a flagged verdict under `flag` is delivered with a **downstream-authored**
  warning built from the verdict's closed fields — the peer's text is never
  relayed.

Any failure — a missing, forged, stale, hash-mismatched, stamp-mismatched or
judge-mismatched assertion — **falls through to the full local pipeline**
(re-judge). An upstream that retunes its L2 model or L3 prompt changes its stamp
or judge, which auto-invalidates the pin until an operator updates it: a weaker
judge cannot be swapped in under the same stamp.

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

Production keeps `trust_verdict` **unset** until an operator pins a peer's key,
stamp and judge; unset means re-judge, exactly as today.

### Paging is not repeated

A response the upstream already paged is not re-paged. The downstream recognises
the upstream's `_trentina_part` shape (carried in `_meta`) and forwards a
`read_part` call to the peer, rather than cutting the response again.

## Operating and diagnosing an edge

### Reading the trust outcome

There is no per-call log line saying "trusted". The authoritative signals are:

- **Audit, downstream:** `detections_digest` NULL = the response was trusted and
  served without re-judging; non-NULL = it was re-judged (locally scanned).
- **Audit, upstream:** `caller_peer` / `caller_sub` on every `gateway_calls` row.

### What is logged, and what is silent

Only two re-judge reasons are logged (INFO), on purpose — the rest are the quiet
common case and would otherwise be a caller-visible channel (#262):

- `bad_signature` — a response whose assertion did not verify against the pinned
  key. **Logged every time.**
- `stamp_mismatch` — the upstream changed its perimeter policy and the operator
  has not re-pinned. **Logged once per (profile, backend, stamp)**, not per call.

These are **silent** (no log line; the only tell is a non-NULL `detections_digest`):

- `hash_mismatch` — delivered bytes do not match the signed hash.
- `judge_mismatch` — the upstream used a different L3 than pinned.
- `mode_mismatch` — the downstream's resolved mode differs from the upstream's;
  such a response **never** gets scan-once and there is **no diagnostic** saying
  why, so if a correctly-pinned edge never trusts anything, suspect the modes.
- `stale` — the assertion was older than 300 s (clock skew or a very slow hop).
- `absent` — no assertion at all (the upstream has no `signing_key_env`, or the
  link is to a non-Trentina backend).
- `incomplete_verdict` — the upstream's own scan had a gap (oversize, unread
  binary, a layer unavailable); the downstream re-judges rather than trust a
  partial verdict.

### Pinning across a federated edge

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
  reports a gateway-wide `pending_pins` count, so Nagios can alarm on a federated
  upstream that has grown tools awaiting an operator.

Approving a held federated tool happens on the **upstream** that holds it, with
its operator's `tool_pins` tool — the downstream only reports that something is
held there. A pending count on the downstream's view points at work the upstream
operator must do.

### When a call is rejected at the upstream

If the edge JWT itself is rejected, the upstream answers a flat `401` with a
constant reason ("invalid edge token"); the specific cause is deliberately not
disclosed to the caller. Work the short checklist on the downstream side:

1. **Clocks** — is NTP keeping both gateways within ~10 s? (The most common
   cause after setup.)
2. **Audience** — does the profile name in the backend URL
   (`…/gateway/<profile>/mcp`) exactly match the ingress profile's name?
3. **Key pairing** — is the public key pinned in `federation.peers.<name>` the
   `.pub` of the private edge key the downstream is signing with?

### Key rotation and rollback

- **Edge key — zero downtime.** Add the new public key under a second peer name
  on the upstream and reload; swap the private key on the downstream and restart;
  then remove the old peer entry upstream. Both keys verify during the overlap.
- **Signing key.** Rotating it opens a re-judge window: until the downstream
  re-pins the new `trust_verdict.public_key`, assertions fail `bad_signature` and
  responses are re-judged — correct behaviour, just slower, not an outage.
- **Rollback.** Removing `trust_verdict` reverts to re-judge (scan-once off) with
  the edge still authenticated. Removing `federated.edge_key_env` reverts to the
  backend's prior headers/auth. Deleting the ingress profile removes the edge.
- **Reload scope.** An operator `reload_profiles` applies these blocks; an
  **agent** reload **holds** both the `federated:` and `federation:` blocks
  (security-bearing fields are operator-only), so an agent cannot re-point or
  re-key its own edge.

## Migrating from the interim static bearer

Before 3.1.0 a downstream mounted an upstream as a plain MCP backend with a
shared static bearer in an `Authorization` header. That path still works in
3.1.0 but is **deprecated** — superseded by the first-class `federated:` block,
to be removed in a future release; the loader logs a deprecation
warning pointing here. To migrate a live link with no downtime:

1. Stand up the upstream ingress profile (step 2 above) alongside the existing
   bearer-authenticated profile — they coexist.
2. Generate the edge key, pin its public half on the ingress.
3. On the downstream, move the backend URL to the ingress, add
   `federated.edge_key_env`, and remove the `Authorization` header (step 3).
   This is the cutover; it is reversible by restoring the URL and header.
4. Once the authenticated edge is proven, turn on scan-once (step 4).
5. Retire the shared bearer **on the downstream** once nothing else uses it. Do
   not remove the bearer on the upstream if direct (non-federated) callers still
   present it.

## Out of scope

Egress (`:8021`) and git (`/proxy/git`) federation, a mesh fabric, and routing
are deliberately out of scope. Horizontal scaling to thousands of users is a
separate effort; federation's new state is built externalize-ready but is not
that effort.
