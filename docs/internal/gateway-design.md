# Gateway Mode — trentina as the trusted boundary for MCP traffic

**Status:** Design draft (v0.2, Option C — single-endpoint architecture)
**Branch:** `feat/gateway-design`
**Tracking task:** crunchtools/tmp #18 · RT #1438 (Option C)

---

## Summary

Trentina today exposes 6 web-content tools (`fetch`, `read`, `search`, `scan`,
`blocklist`, `stats`) that run untrusted content through a 3-layer prompt-injection
defense (L1 → L2 local classifier → L3 quarantined Gemini
re-extraction) before returning anything to the LLM.

This design extends trentina with a second surface — a **per-consumer MCP gateway**
that proxies traffic to the 14 backend MCP servers, applying the
same defense pipeline to every tool response on the way back, with per-profile
control of which tools each consumer sees and which defense layers run.

Net result: one chokepoint, one audit log, one Cockpit UI, one policy plane
covering both web fetches *and* MCP-server tool outputs.

---

## Mission restatement

Trentina's mission has always been the **trusted boundary between untrusted content
and the LLM**. Web-fetch happens to be the only surface currently implemented because
the LLM platforms the maintainer uses (Claude, Gemini) ship web search/fetch as native tools
and don't route them through MCP — so trentina had to provide replacement tools.

Every MCP server that returns content is the same threat: a wiki page, an RT ticket
comment, a Slack message thread, a Jira issue description, a Confluence page, an
email body — every one is a channel an attacker can plant prompt-injection payloads
in. None of them currently flow through trentina. The gateway extension closes that
gap without changing the mission.

---

## Problem

Three problems converge:

1. **MCP responses bypass trentina.** A malicious Confluence page, a Jira ticket
   description written by a hostile user, a phishing email rendered through the
   Gmail MCP — every one of those reaches the LLM unfiltered today. Trentina is
   the right boundary for this content but has no current path to it.

2. **Per-consumer policy lives in two places.** agent2's deny list lives in
   `~/.claude/settings.json`. agent1's deny list lives in Hermes's
   `config.yaml`. The patterns are identical (`delete_*`, `send_gmail_message`,
   `wordpress_delete_*`, etc.) but expressed differently, maintained
   separately, and the next consumer (agent3/OpenClaw) would make it a third
   place to update. The policy plane wants centralization.

3. **Tool-definition context pollution.** The MCP fleet exposes ~575 tools,
   summing to ~137,000 prompt tokens of tool descriptions per turn. Per-consumer
   deny lists (Claude Code's `permissions.deny`, Hermes's `disabled_tools`) gate
   *execution* but the tool definitions still ship in every prompt. Filtering
   them at the `tools/list` response — *before* they reach the consumer — is
   the only mechanism that actually reduces context cost.

---

## Approach

> **Option C (2026-06-13):** the gateway is the **single** surface. The original
> `/mcp` web-tools endpoint is deprecated — trentina's own tools are folded into
> the gateway as an in-process `internal://` backend (conventionally named `web`),
> so one per-consumer endpoint behind one bearer token covers trentina's tools
> *and* the whole MCP fleet. There is no parallel surface to maintain.

The gateway endpoint family:

```
POST /gateway/<profile_name>/mcp        ← canonical, single surface
POST /mcp                                ← deprecated (404 on the fastmcp 3.1.1 base)
```

Each request to the gateway endpoint:

1. **Authenticates** the caller (bearer token in `Authorization` header, matched
   against the profile's configured token).
2. **Resolves** the consumer's profile (tool allowlist + defense config).
3. **Dispatches** the MCP call by backend URL scheme: `http(s)://` proxies to a
   remote MCP server via the `crunchtools` podman network (container DNS lookup
   — already how agent1 reaches the fleet today); `internal://<label>`
   dispatches in-process to trentina's own FastMCP tool registry. Both paths
   return identical wire shapes to the consumer.
4. **On `tools/list` response:** drops tool definitions not in the profile's
   allowlist *before* forwarding to the consumer. This is where context savings
   come from.
5. **On `tools/call` response:** runs the response content through the configured
   defense layers (L1 always; L2 always; L3 optional per-profile) and returns
   the content + detection metadata to the consumer.
6. **Audits** every passthrough (profile, backend, tool, detection scores, byte
   counts) to trentina's existing SQLite audit table.
7. **Surfaces** in the Cockpit plugin under a new "Gateway" tab.

Under Option C the standalone `/mcp` web-tools endpoint is deprecated; trentina's
own tools are reached through the gateway's `internal://` backend, so every tool
response — web fetches included — flows through the single gateway chokepoint.

---

## Profile schema

YAML in `/etc/trentina/profiles.yaml` (or `$TRENTINA_PROFILES_PATH`). There is no
file watcher: an edit takes effect when someone calls the `reload_profiles` admin
tool, or when the gateway restarts. Editing the file and expecting the running
gateway to notice is the one thing that does not work — the router filters from
the `Profile` objects it loaded at startup, so an un-reloaded edit validates,
looks applied, and changes nothing.

```yaml
profiles:
  agent2:
    role: operator                      # default: agent — see docs/operator.md
    auth:
      bearer_token_env: TRENTINA_GATEWAY_AGENT2_TOKEN
    llm_keys:                           # service identity: pays for compression + perimeter L3
      gemini:
        api_key_env: TRENTINA_GATEWAY_AGENT2_GEMINI_API_KEY
    backends:
      web:                              # trentina's own tools, in-process
        url: internal://web
        tools_allow: ["*"]
        tools_deny: []
      mcp-slack:
        url: http://mcp-slack:8000/mcp
        tools_allow: ["*"]
        tools_deny: []
      mcp-mediawiki:
        url: http://mcp-mediawiki:8000/mcp
        tools_allow: ["*"]
        tools_deny: []
      mcp-atlassian:
        url: http://mcp-atlassian:8000/mcp
        tools_allow: ["*"]
        tools_deny: ["jira_delete_issue"]
      mcp-wordpress-crunchtools:
        url: http://mcp-wordpress-crunchtools:8000/mcp
        tools_allow: ["*"]
        tools_deny:
          - "wordpress_delete_post"
          - "wordpress_delete_page"
          - "wordpress_delete_media"
          - "wordpress_delete_comment"
      google-workspace-personal:
        url: http://google-workspace-personal:8000/mcp
        tools_allow: ["*"]
        tools_deny:
          - "send_gmail_message"
          - "delete*"
          - "batch_delete*"
      # ... rest of agent2's backends
    defense:
      enforcement: flag             # interactive: flagged content is delivered with the verdict attached
      # l2_threshold: 0.6           # unset: the L2 model's own threshold

  agent1:
    auth:
      bearer_token_env: TRENTINA_PROFILE_AGENT1_TOKEN
    backends:
      memory:
        url: http://mcp-memory:8765/mcp
        tools_allow: ["*"]
        tools_deny: []
        headers:
          Authorization: "Bearer ${MCP_MEMORY_API_KEY}"
      mcp-gemini:
        url: http://mcp-gemini:8000/mcp
        tools_allow: ["*"]
        tools_deny: ["gemini_delete_cache_tool"]
      google-workspace-personal:
        url: http://google-workspace-personal:8000/mcp
        tools_allow: ["search_gmail_messages", "get_gmail_*", "list_calendars", "get_events", "manage_event"]
        tools_deny: ["send_gmail_message", "delete*"]
      # ... narrower backend set
    defense:
      enforcement: block            # autonomous: a flagged response is refused outright
      # l2_threshold: 0.6           # below the model's threshold flags BENIGN-labelled content
```

### Allowlist semantics

- `tools_allow` supports `*` (all), exact names, and `prefix*` / `*suffix` /
  `*substring*` globs.
- `tools_deny` runs after `tools_allow` and wins on conflict.
- A tool is exposed to the consumer iff it matches `tools_allow` AND doesn't
  match `tools_deny`.
- The check runs against the *backend's* tool name (not the namespaced
  consumer-visible name).

### Consumer-visible tool names

Backend tools are exposed under their original names, namespaced by backend name
to avoid collisions — including trentina's own tools under the `internal://`
backend's name (conventionally `web`):

```
web__block_fetch_tool
web__clean_fetch_tool
mcp-slack__slack_list_channels
mcp-atlassian__jira_search
google-workspace-personal__get_gmail_message_content
```

Matches the `mcp__<server>__<tool>` convention Claude Code already uses, and
Hermes accepts namespaced tool names natively.

---

## L3 toggle (token-cost control)

L3 (Q-Agent / quarantined Gemini re-extraction) is the only defense layer with a
non-trivial token cost — every L3-triggered call burns Gemini tokens for
re-extraction. Two controls:

1. **Per-profile static toggle**: `defense.quarantine: false` disables L3 for
   that profile entirely. L2 still runs and flags suspicious content in the
   audit log, but the response passes through to the consumer with a detection
   metadata sidecar instead of being re-extracted.

2. **Cockpit runtime override**: a global "L3 enabled" switch in the Cockpit
   backend, persisted to trentina's SQLite settings table, takes precedence over
   per-profile config. Lets the operator kill L3 fleet-wide during a Gemini outage or
   when chasing a quota issue without redeploying.

When L3 is disabled (either path), the response still carries the L1/L2
detection metadata sidecar so the consumer agent can decide whether to trust
or discard.

---

## Integration with existing 3-layer defense

| Layer | Reuse | New |
|---|---|---|
| L1 | Existing `l1/` pipeline applied to MCP response content | None |
| L2 — local classifier | Selectable model, its own threshold (per-profile stricter) | None |
| L3 — Q-Agent | Existing quarantined Gemini path with `quarantine_threshold` trigger | Per-profile + runtime toggle |
| Audit | Existing SQLite events table; add `gateway_passthrough` row type | New columns: `profile`, `backend`, `tool` |
| P-Agent (policy) | Existing blocklist logic applies to backend MCP servers (block a backend if its responses keep tripping L2) | New: blocklist scope expands from URL to MCP-server URL |

The defense pipeline is mostly reused verbatim — what's new is the wrapper that
turns "fetched web content" into "MCP tool-call response content" and routes it
through. ~200 lines of FastMCP server code + ~100 lines of profile loader +
~100 lines of audit-log adapter.

---

## Auth model

**v1**: bearer token per profile. Token value read from the env var named in
`auth.bearer_token_env`. Consumer sends `Authorization: Bearer <token>`.

**Added in 0.8.0**: optional Google-backed OAuth per profile (`oauth.enabled`
plus an `allowed_emails` allowlist), for clients that cannot send a static
header. Trentina runs as an OAuth proxy in front of Google; static bearer is
still tried first, so it is purely additive. See `docs/profiles.md` →
Authentication. Still out of scope: OIDC beyond Google, per-user-within-profile.

Tokens never appear in config files (only env var names do); env file lives at
`/srv/<service>/config/profile-tokens.env` with chmod 600 +
chcon etc_t per the crunchtools convention.

---

## Literal request guards

Tool-name allowlists control *which* tools a consumer can call. Parameter
guards extend this to *what values* can be passed in the arguments. A guarded
parameter's value must match at least one `allow` pattern and must not match
any `deny` pattern — same semantics as `tools_allow`/`tools_deny`, applied to
argument values instead of tool names.

### Motivation

Behavioral enforcement ("the LLM should only send emails to self") is not
reliable. Literal request guards provide deterministic, gateway-level enforcement:
the call is rejected before it reaches the backend MCP server.

### Configuration

Literal request guards are configured per-backend, per-tool in the profile YAML:

```yaml
backends:
  gws-personal:
    url: "http://gws-personal:8000/mcp"
    tools_allow: ["*"]
    literal_request_guards:
      send_gmail_message:
        to:
          allow: ["you@example.com"]
        cc:
          allow: ["you@example.com"]
        bcc:
          allow: ["you@example.com"]
```

Each entry maps: **tool name → parameter name → value constraint**. The
constraint has two fields:

| Field | Default | Description |
|---|---|---|
| `allow` | `["*"]` | Value glob patterns to allow |
| `deny` | `[]` | Value glob patterns to deny (wins over allow) |

Values use `fnmatch.fnmatchcase()` for matching, supporting shell-style globs
(e.g., `*@corp.example.com`). A more permissive character set than tool-name globs is
allowed — values can contain `@`, `.`, `+`, `/`, and spaces.

### Semantics

- **Missing guard**: no `literal_request_guards` entry for a tool = all values allowed.
- **Missing parameter**: if a guarded parameter is absent or `None` in the
  arguments dict, it passes (no value to validate).
- **Deny wins**: a value matching any deny pattern is rejected even if it also
  matches an allow pattern.
- **Error code**: rejected calls return JSON-RPC error `-32602` (invalid params)
  with a terse message that does not include the rejected value.

### Pipeline position

Literal request guards run after the tool-name allowlist re-check and before the
backend call — the same defense-in-depth position:

```
Parse tool name → Backend exists? → Tool in allowlist? → Literal request guards → Backend call
```

A call that fails parameter validation never reaches the backend. No tokens
spent, no side effects.

---

## Audit & Cockpit additions

Every gateway passthrough writes one row to trentina's SQLite audit table:

| Column | Type | Example |
|---|---|---|
| ts | datetime | 2026-06-13T10:42:11Z |
| profile | text | agent2 |
| backend | text | mcp-atlassian |
| tool | text | jira_search |
| op | text | tools/call \| tools/list |
| l1_score | real | 0.02 |
| l2_score | real | 0.71 |
| l3_triggered | bool | true |
| resp_bytes | int | 41882 |
| latency_ms | int | 2340 |

New Cockpit panel **Gateway**:
- **Top-N tools per profile (last 24h)** — informs allowlist tuning
- **Detection events timeline** — every L2 flag and L3 trigger, with drill-down to the response that tripped it
- **Profile editor** — read-write YAML editor with validation, writes back to `/etc/trentina/profiles.yaml`, then calls `reload_profiles` to put the edit in force. It must write in a way the gateway can see: if the gateway is containerized with a single-file bind mount, a temp-file-plus-rename save leaves the container on the old inode and the reload reports no change. See [Applying a Change](../profiles.md#applying-a-change).
- **L3 master switch** — global on/off toggle (token-cost control)
- **Real-time passthrough tail** — live view of in-flight gateway calls

The Cockpit plugin uses trentina's existing D-Bus interface for read access;
write paths (profile editor, L3 switch) go through new D-Bus methods that
update SQLite and the YAML file with locking.

---

## Migration & compatibility

Option C is a **hard cut on the trentina side** (the gateway is the only surface),
with consumers migrating at their own pace. Each consumer collapses its many MCP
entries — including the old direct trentina `/mcp` entry — into a single
gateway entry behind one bearer token. **agent1 cuts over first** (smaller
blast radius, autonomous agent), then agent2.

**An autonomous-agent consumer (small blast radius) — first:**
1. Add its profile to trentina config: the `web` (`internal://web`)
   backend + a narrowed http backend set.
2. Replace its `mcp_servers:` entries with one
   `trentina-gateway` entry pointing at the gateway's
   `/gateway/<profile>/mcp` route (Bearer
   `${TRENTINA_GATEWAY_<PROFILE>_TOKEN}`).
3. Restart it; verify a call exercises both an http backend
   (`mcp-gemini__gemini_query_tool`) and the internal backend
   (`web__block_fetch_tool`); confirm the prompt-token count drops from ~146K
   toward the <50K target.

**An interactive-session consumer — second:**
1. Add its profile with the `web` backend + the full http backend matrix.
2. Replace the ~10 migrated MCP client entries + the old trentina entry
   with one `trentina-gateway` entry pointing at the gateway's
   `/gateway/<profile>/mcp` route. Genuinely-local servers (pcloud,
   trove, claude-in-chrome, …) stay as-is.
3. Shrink the SSH tunnel config from 10 `LocalForward` lines to
   one (the gateway port).
4. Confirm `web__block_fetch_tool` returns content plus L1 metadata and a remote backend
   (`mcp-slack__slack_list_channels`) returns results — both via the same token,
   single endpoint.

Estimated context savings for agent1 when narrowed to (web, memory,
mcp-gemini, google-workspace-personal): ~575 tools → ~150 tools, ~146K → <50K
prompt tokens.

---

## Deployment

Same `/srv/<service>/` layout the trentina service already
uses in production. Adds:

- `/srv/<service>/config/profiles.yaml` — profile definitions
- `/srv/<service>/config/profile-tokens.env` — bearer tokens
  (chmod 600, chcon etc_t, env-file passed to systemd unit)
- `/srv/<service>/data/audit.db` — already exists for L1/L2/L3
  events; gains gateway-passthrough rows
- Cockpit plugin gains the Gateway tab — same `cockpit-airlock/` package, lives
  in `/usr/share/cockpit/airlock/`

No new container, no new port, no new systemd unit. The existing
service unit stays as-is; the trentina binary gains a
new endpoint family on its existing localhost listener.

Cockpit visualization comes free with the existing Cockpit instance —
the Gateway tab appears alongside the current Airlock tab on first login after
the image bumps.

---

## Cascade integration

trentina is already in the cascade (FROM-graph parent: the Hummingbird Python
3.13 base; dispatch fanout already covers it). The version bump for this work
goes through the existing build pipeline:

- Buildah → Trivy (HIGH/CRITICAL block) → SBOM → Quay + GHCR push
- Parent-image-updated dispatches still fire on Hummingbird rebuilds
- No `schedule:` trigger
- SemVer bump: MINOR (0.3.0 → 0.4.0) — backwards-compatible addition

---

## Performance considerations

Per gateway call (worst case, L3 triggered):

| Step | Latency |
|---|---|
| Auth check + profile lookup | <1ms |
| Backend MCP call (over `crunchtools` network) | depends on backend (5-500ms typical) |
| L1 | <10ms |
| L2 classifier | ~200-550ms per 512-token window (model-dependent) |
| L3 quarantine (if triggered) | 1-2s (Gemini round-trip) |
| Audit log write | <5ms |

L3-off case (per profile): drops the 1-2s tail. L3 only fires when L2 > threshold,
so in steady state L3 contributes near-zero latency.

`tools/list` response (allowlist filter only, no content scan): <5ms overhead.

Streaming preserved end-to-end for SSE responses — trentina forwards chunks as
they arrive, applying L1 incrementally; L2/L3 buffer until the stream completes
(or until a watermark, configurable).

---

## Security considerations

- **Fail-closed defaults**: profile not found → 404; auth missing → 401; backend
  unreachable → 502 with retry-after; L2 classifier unavailable → fail-closed
  (response held, error returned to consumer) unless profile sets
  `defense.classify_fallback: allow`.
- **Token rotation**: tokens are env-file-loaded; rotation = update env file +
  systemd reload (no rebuild).
- **Server-to-server trust**: backends are trusted on the `crunchtools` network
  (loopback-bind only, no public reach). Trentina is the only thing talking to
  them through this path.
- **Audit immutability**: SQLite audit table is append-only (existing pattern);
  Cockpit shows but never edits.
- **Cockpit auth**: existing Cockpit auth (RHEL system auth) gates UI access.
  Profile-editor write access requires the existing `cockpit-airlock-admin`
  role.

---

## Non-goals / out of scope (v1)

- OIDC / OAuth (v2)
- Rate limiting (v2 — could fold into trentina's existing P-Agent blocklist)
- Caching backend responses (v2 — backends own their own caching)
- MCP resources / prompts passthrough — v1 covers `tools/list` and `tools/call`
  only; `resources/list`, `resources/read`, `prompts/list`, `prompts/get` come
  in v1.1 (mechanically similar to tools)
- Cross-profile aggregation (one consumer hitting multiple profiles)
- Backend rate-limit fanout (call goes 1:1, no parallel fan-out)

---

## Open questions

1. **L2 fail-closed vs fail-open default?** Recommend fail-closed for safety;
   profiles can override. Confirm.
2. **Per-tool L3 toggle in addition to per-profile?** Some tools' responses are
   structured-data-only (e.g., `slack_list_channels`) and L3 re-extraction adds
   no value. Heuristic: skip L3 when response content-type indicates pure JSON
   with no string fields > N chars. Worth doing in v1?
3. **Long-lived sessions**: streamable-http supports session resumption. Should
   trentina proxy session IDs transparently, or terminate at the gateway?
4. **P-Agent backend blocklist semantics**: if mcp-atlassian keeps tripping L2
   for a agent2 profile, does the P-Agent blocklist apply per-profile or
   globally?
5. **Profile inheritance**: should profiles be able to inherit from a `default`
   profile to share common deny patterns?

---

## Implementation phases

| Phase | Scope | Estimated effort |
|---|---|---|
| 1 | Profile loader + auth + endpoint routing + tool allowlist filter (no defense pipeline yet) | ~half session |
| 1-final (Option C) | `internal://` trentina-tools backend; `/mcp` deprecated; gateway becomes the single surface | ~half session |
| 2 | L1 + L2 on tool-call responses; L3 with profile + Cockpit master switch | ~half session |
| 3 | Audit log integration + Cockpit Gateway tab (read-only) | ~half session |
| 4 | Cockpit profile editor + token rotation UI | ~half session |
| 5 | Migration: agent2 + agent1 cut over to gateway endpoints | ~one session |

Each phase is independently mergeable behind a feature flag (`TRENTINA_GATEWAY_ENABLED=true`).

---

## References

- Existing trentina 3-layer defense: `src/trentina/l1/`,
  `quarantine/` (this repo)
- crunchtools MCP fleet topology: see private ops notes
- Autonomous-agent constitution profile §V (kill switches): drives the L3
  toggle requirement
- FastMCP authentication middleware: https://gofastmcp.com/ (auth section)
