# Gateway Audit Log

*Part of Trentina's **Determinism** promise; see [Why Trentina](../README.md#why-trentina).*

Every tool call through the Trentina gateway is recorded in SQLite — including calls the gateway itself refuses. The audit log captures who called what, **what outcome it reached**, how long it took, and what the defense pipeline found. This data drives allowlist tuning, error diagnosis, and usage monitoring.

## Why This Matters

Without observability, you're flying blind. Which tools are your agents actually using? Which backends are producing errors? How often does the defense pipeline flag content? The audit log answers these questions with data, not guesses.

## What Gets Recorded

Each gateway call writes one row to the `gateway_calls` table:

| Column | Type | Example |
|--------|------|---------|
| `timestamp` | datetime | `2026-06-23T10:42:11Z` |
| `profile` | text | `agent2` |
| `backend` | text | `github` |
| `tool` | text | `list_issues_tool` |
| `success` | boolean | `true` (derived from `outcome`) |
| `duration_ms` | integer | `234` |
| `error_message` | text | `null` (or error message) |
| `outcome` | text | `ok`, `blocked_defense`, … (see below) |
| `bytes_arrived` / `bytes_delivered` | integer | response size before and after minifying; for a [tunnel](#client-egress-tunnels) or a [git request](#git-transport), bytes from and to the destination |
| `normalized` | text (JSON) | `{"feed_id": "dropped: below minimum 1"}`: arguments dropped before forwarding ([normalization](gateway.md#argument-normalization)) |
| `destination` | text | `docs.example.org#1a2b3c4d5e6f7a8b`, `q#…`, `C0OPS`: where the call was pointed ([call destinations](profiles.md#call-destinations)). Never logged |
| `destination_kind` | text | `fetch`, `search`, `param`, `model`, `tunnel` or `git`; NULL when the tool names no destination |
| `session` | text | `3f9a…`: a fingerprint of the MCP session the call arrived on. NULL for a client that sends no session header |
| `call_ref` | text | `8c1d…`: a random reference for this call. A `detections` row raised by the call carries the same one |
| `content_digest` | text | `b27e…`: a fingerprint of the delivered result. NULL when nothing was delivered |
| `federated_verdict` | text | `trusted` when the response was served on a secondary's signed verdict without this gateway's own layers running; otherwise why it was re-judged (`absent`, `bad_signature`, `stamp_mismatch`, `judge_mismatch`, `hash_mismatch`, `mode_mismatch`, `stale`, `incomplete`). A closed set, never the peer's text. NULL for every non-federated call |

### How much of a federated link runs on the peer's scan

`federated_verdict` is the answer, and it is the column to read before deciding
whether a trust pin is earning anything:

```sql
-- Of this link's calls, how many were served on the secondary's verdict?
SELECT federated_verdict, COUNT(*)
FROM gateway_calls
WHERE profile = 'myagent' AND backend = 'lotor' AND federated_verdict IS NOT NULL
GROUP BY federated_verdict;
```

`trusted` is the saving the pin was for. Anything else means the primary scanned
it anyway: `stamp_mismatch` or `judge_mismatch` says the secondary changed what
it scans with and nobody re-pinned, so the pin is now costing a round trip and
buying nothing. `incomplete` is not a failure — the assertion verified, but the
secondary could not fully read the content, so the primary applied its own gap
policy instead.

### Joining rows

A flagged response used to share nothing with the call that carried it but a
profile, a tool and a clock. Three columns make the audit readable as a
sequence (#357):

- `detections.call_ref = gateway_calls.call_ref` is the call a detection was
  raised on.
- `session`, in `id` order, is what one client did, call by call: what it
  was delivered, and what it called next.
- `content_digest` is equal on two calls that delivered the same result, so
  "this document again" can be read without the audit holding the document.

```sql
-- What a session did after it was delivered something the layers flagged.
SELECT c.id, c.backend, c.tool, c.outcome
FROM gateway_calls c
JOIN gateway_calls flagged ON flagged.session = c.session AND flagged.id < c.id
JOIN detections d ON d.call_ref = flagged.call_ref
ORDER BY c.id;
```

The session column is a fingerprint, never the header: a session id is a
bearer of the session.

### Honeypot captures

A [honeypot profile](profiles.md#honeypot-profiles) is the one caller whose
delivered content is stored. Each document it reads writes a row to
`honeypot_captures`: `captured_at`, `profile`, `call_ref`, `source`, the
five verdict columns a detection carries (`flagged_by`, `l2_label`,
`l2_score`, `l3_verdict`, `l3_risk`) and `content`. `flagged_by` is NULL
when no layer flagged the document, which is where a miss is found.

```sql
-- Documents no layer flagged, after which the agent tripped a decoy.
SELECT cap.id, cap.source, trip.tool, trip.error_message
FROM honeypot_captures cap
JOIN gateway_calls read ON read.call_ref = cap.call_ref
JOIN gateway_calls trip ON trip.session = read.session AND trip.id > read.id
WHERE cap.flagged_by IS NULL AND trip.outcome = 'decoy_tripped'
ORDER BY cap.id;
```

A call the profile makes to a decoy tool writes a row too (#410): `source`
is `decoy:<backend>:<tool>`, `content` is the call's arguments as JSON, and
`flagged_by` is `decoy`, so the query above never mistakes it for a
document. A planted credential in the arguments is kept as
`{honeytoken:<id>}`. The row carries the trip's `call_ref`:

```sql
-- What each decoy was asked to do, oldest first.
SELECT trip.timestamp, trip.tool, sent.content
FROM gateway_calls trip
JOIN honeypot_captures sent ON sent.call_ref = trip.call_ref
WHERE trip.outcome = 'decoy_tripped' AND sent.flagged_by = 'decoy'
ORDER BY trip.id;
```

A decoy on a profile that is not a honeypot keeps no arguments: it sits
beside real tools and may be handed a real user's text.

Captures are hostile text at rest. They are never logged, are swept with
the audit (`TRENTINA_AUDIT_RETENTION_DAYS`), and are not test fixtures: an
attack found there enters a corpus only rewritten by hand.

### Outcomes

`success` alone cannot describe what happened, and reading it as a health
signal actively misleads. `fetch_tool` and `read_tool` in block mode **fail closed**: when
the defense blocks content the tool raises, which under a boolean is
indistinguishable from the backend being down. An operator reading
`2 ok / 34 errors` concludes the tool is broken when the truth may be that it
blocked 34 hostile pages.

| Outcome | Group | Meaning |
|---|---|---|
| `ok` | ok | Backend returned content and did not flag an error. |
| `blocked_defense` | blocked | L1/L2/L3 refused the content. Working as designed. |
| `denied_allowlist` | blocked | Tool not permitted for this profile. |
| `denied_guard` | blocked | A deterministic request-side or egress denial: a literal request guard, a mode/transform policy, or an egress/proxy refusal. |
| `denied_response_guard` | blocked | A literal response guard rejected the backend's result. |
| `denied_gatekeeper` | blocked | [Semantic request guards](semantic-request-guards.md) refused the call before it was forwarded. The message is the reason code, then what the gatekeeper was told: `first_contact` and `session_flagged`. |
| `denied_response_gatekeeper` | blocked | [Semantic response guards](semantic-response-guards.md) refused delivery of the backend's result. The backend was contacted and answered; the answer was withheld. Distinct from `denied_response_guard`, the deterministic literal response guard. |
| `decoy_tripped` | tripped | A [decoy tool](profiles.md#decoy-tools-and-honeytokens) was called, or a planted credential was in a call's arguments. An alarm about the caller. |
| `tool_error` | failed | Backend completed but reported `isError`. |
| `backend_error` | failed | Upstream failed: network, timeout, auth, 4xx/5xx. |
| `gateway_error` | failed | Our own bug. The only outcome that should page anyone. |
| `cancelled` | unknown | The call's task was cancelled (client hang-up or shutdown, not told apart) before any other row was written; not a failure. |
| *(NULL)* | unknown | Row predates the taxonomy. Never back-fitted. |

**Only the `failed` group is a health signal.** The `blocked` group is a
security metric — a rising `blocked_defense` rate means the defense is
catching more, not that anything is broken. The `tripped` group is neither:
nothing failed and nothing was withheld, but a caller did what an agent
doing its job has no reason to do. One row is worth reading; the
[join columns](#joining-rows) lead back to what that caller was delivered
before it.

`success` is derived (`outcome == "ok"`) rather than stored independently, so
the legacy boolean can never disagree with the taxonomy.

### LLM proxy calls

Every `/proxy/llm/{provider}/...` request from an authenticated profile writes a
row too (#297): `backend` is `llm:<provider>`, `tool` is the admitted
endpoint (`messages`, `chat/completions`, `generateContent`, ...) or `-` when
the request was refused before one was matched, and `destination` is the
model the agent named (`destination_kind = model`). A refused request is
`denied_guard` with the [reason code](llm-proxying.md#what-the-proxy-admits)
in `error_message`; a profile with no key for the provider is
`denied_allowlist`. An admitted call is `ok`, or `tool_error` / `backend_error`
for a provider 4xx / 5xx.

### Client egress tunnels

Every [client egress](client-egress.md) tunnel writes a row when it closes or
is refused (#442): `backend` is `egress`, `tool` is `connect`, and
`destination` is `name:443` as the client named it (`destination_kind =
tunnel`). `bytes_arrived` is what came back from the destination and
`bytes_delivered` is what the agent sent to it. A name the profile does not
list is `denied_allowlist`; a refused port, method, tunnel cap, first TLS
record or a lookup with no free resolver slot is `denied_guard` with the [reason](client-egress.md#refusals) in
`error_message`; the egress guard's refusal is `blocked_defense`. No layer
reads a tunnel, so there is no `detections` row to join.

### Git transport

Every request through the [git transport](git-transport.md) writes a row when
it ends or is refused (#453): `backend` is `git:<remote>`, `tool` is `fetch`
or `push`, and `destination` is `owner/name`, lower-cased
(`destination_kind = git`), followed for a push by the refs it named. One git
command is several requests, so it is a short run of rows. `bytes_arrived` is
what came back from the forge and `bytes_delivered` is what the agent sent to
it. A repository or branch outside the profile's lists is `denied_allowlist`;
every other rule of the route is `denied_guard`, with the
[reason](git-transport.md#refusals) in `error_message`; the egress guard's
refusal of the upstream is `blocked_defense`. `ok` means the gateway carried
the request, not that the forge accepted a push. A caller whose token is no
profile's gets `401` and no row. No layer reads a pack, so there is no
`detections` row to join.

## Accessing Audit Data

The `quarantine_stats` tool exposes audit data through the gateway itself:

```json
{
  "gateway_audit": {
    "total_calls": 5743,
    "days": 30,
    "by_tool": [
      {"backend": "ashigaru", "tool": "status", "calls": 1559,
       "ok": 1553, "blocked": 0, "failed": 6, "outcomes": {"ok": 1553, "backend_error": 6}},
      {"backend": "web", "tool": "read_tool", "calls": 36,
       "ok": 2, "blocked": 34, "failed": 0, "outcomes": {"ok": 2, "blocked_defense": 34}}
    ],
    "totals": {"ok": 1555, "blocked": 34, "failed": 6, "unknown": 0}
  }
}
```

The top-N breakdown shows which tools get the most use and which have the highest error rates — direct evidence for where to focus allowlist tuning or backend debugging.

## Use Cases

### Allowlist Tuning

After running with `tools_allow: ["*"]` for a week, check the audit log to see which tools are actually used. Build an explicit allowlist from the data:

```
Top 10 tools for agent1 (last 7 days):
1. ashigaru__status (1559 calls)
2. github__get_pull_request_checks_tool (195 calls)
3. web__fetch_tool (157 calls)
...
```

### Error Diagnosis

Read the **`failed`** column, never `calls - ok`. A high `failed` rate points
at connectivity, auth, or backend bugs:

```
web__fetch_tool: 157 calls, 133 ok,  0 blocked, 24 failed
web__read_tool:        36 calls,   2 ok, 34 blocked,  0 failed
```

The second row is a healthy tool doing its job. Under the old single-`errors`
column it read as 34 errors and a 94% failure rate, which is how a working
defense got mistaken for a broken one.

### Denial Monitoring

`denied_allowlist`, `denied_guard`, `denied_response_guard`,
`denied_gatekeeper` and `denied_response_gatekeeper` rows record calls the
gateway refused. A consumer repeatedly probing tools outside its
allowlist is a signal worth alerting on — it can indicate a misconfigured
client or a hijacked agent. These were previously not recorded at all.

Every `tools/call` writes exactly one row (#293), including the ones that
never reach a backend:

- A name the profile was never served, a `<backend>__<tool>` naming a backend
  outside it, and an issued short name whose backend has since left it are
  all `denied_allowlist`, with `backend` empty and `tool` the name's
  fingerprint (`sha256:<12> len=<n>`), never its text. The caller gets the
  same `Unknown tool` refusal for each, so it cannot tell which.
- `params` or `arguments` that are not a JSON object are `denied_guard`.
- An exception that escapes every audited path is `gateway_error`, with
  `error_message` naming its class only, before the HTTP edge answers 500.

A response delivered in parts (#340) writes one row for the call that
produced it and one for each `read_part` call, all against the backend and
tool that produced it, with `part 2/5` in `error_message` and the outcome of
that part: `ok`, or `blocked_defense` for a part that was flagged, could not
be fully judged, or follows a flagged one. A handle that resolves to nothing
is `denied_guard` against the internal backend's `read_part_tool`.

A fetch advisory (a suspicious 415/406, a 4xx body the pipeline flags, a
redirect to a binary) is a refusal and audits as `blocked_defense`; until
#293 it was a successful result with no content, audited `ok`. A search whose
provider failed is `backend_error`; one whose L0 leaked its canary is
`blocked_defense`.

`denied_response_guard` and `denied_response_gatekeeper` are the denials that
still cost an upstream call: the backend answered and the answer was withheld
here. A rising rate on either means backend results are being withheld under
the profile's policy — it reflects what the backend returned, not by itself
what the agent intended, unlike the request-side `denied_guard` /
`denied_gatekeeper`, where a rising rate can signal an agent probing. See
[Literal Response Guards](literal-response-guards.md) and
[Semantic Response Guards](semantic-response-guards.md).

### Usage Patterns

Track which agents use which capabilities, how tool usage changes over time, and whether new backends are getting adopted.

## Storage

The audit table lives in the same SQLite database as the blocklist and compression cache (`trentina.db`). Rows are never updated. A row older than `TRENTINA_AUDIT_RETENTION_DAYS` (default 90; `0` keeps every row) is deleted by an hourly sweep (#295): before it, a denied call cost the caller nothing and its row was kept for ever. The sweep deletes at most 500 rows a pass and stays due until a pass comes back short, so a large backlog is cleared over several calls rather than in one statement on the event loop.

`quarantine_stats` reads these tables in a worker thread on a read-only connection of its own (#295). Its aggregates cost about 2.7 s per million rows, which on the event loop stalled every profile; under WAL the reader sees a consistent snapshot while audit writes continue.

Operators can reset the audit history with `reset_gateway_calls()`. It is deliberately **not** exposed as an MCP tool: erasing the audit trail is not a capability any consumer profile should hold. It writes a `reset` checkpoint (below), so the wipe is on the record. Database path is configurable:

```bash
QUARANTINE_DB=/data/quarantine.db  # default on container
```

## Hash chain (#472)

Each `gateway_calls` row carries `prev_hash` (the previous row's `row_hash`) and `row_hash`, the SHA-256 of the RFC 8785 (JCS) form of the row's audited fields, `id` and `prev_hash` included. The canonicalizer is `audit_chain.canonical`, with the RFC's number and key-ordering rules, since `timestamp` is a REAL. Rows older than the chain are not backfilled.

`audit_checkpoints` is append-only and says where the chain starts:

| kind | written when | `last_row_hash` |
|---|---|---|
| `genesis` | the database first opens with the chain | `genesis` |
| `prune` | the retention sweep deletes a batch, in the same transaction | the hash of the last row deleted |
| `reset` | `reset_gateway_calls()` | the hash of the last row deleted |

The sweep deletes a prefix of the chain, selected by `id` and stopping at the first row that is not yet old, so it never leaves a hole. `audit_verify` (operator only) and `trentina-audit-verify` (the configured database) start at the newest checkpoint and report the first break: `unchained`, `prev_hash_mismatch` (a deleted or reordered row), `row_hash_mismatch` (an edited row) or `detections_mismatch`.

The tail read and the insert run under `BEGIN IMMEDIATE`, so a second process cannot fork the chain.

**Detections.** They are written before the call row and expire on their own schedule (blocked rows at `TRENTINA_BLOCKLIST_TTL_DAYS`, flag rows never), so they are not chained. The call row holds `detections_digest`, the SHA-256 of the JCS form of its `call_ref`'s detection rows in `id` order, and `row_hash` covers it. The verifier recomputes it while those rows exist. A mismatch on a call older than the blocklist TTL is counted as `detections_expired`, not as a break. A detection with no `call_ref` (for example one from `decoy.py`) is outside the chain.

**What it proves.** Inside the retained rows, an edit, a removal in the middle, or a reorder is detectable.

**What it does not prove.** Nothing is anchored outside the database. Whoever holds the gateway's uid can rebuild a clean chain, forge a checkpoint, or drop the newest rows (nothing follows them to disagree). Detection rows past the TTL are not checked. Signed receipts and external anchoring are later phases.

## Related

- [MCP Gateway](gateway.md) — where audit recording happens
- [Blocklist](blocklist.md) — detection events that trigger blocklist entries
- [Per-Agent Profiles](profiles.md) — per-profile audit scoping
