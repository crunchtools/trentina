# MCP Gateway

*Part of Trentina's **Architectural flexibility** promise; see [Why Trentina](../README.md#why-trentina).*

Trentina acts as a single MCP endpoint that proxies traffic to all your backend MCP servers. Instead of each agent connecting directly to 20+ servers with separate credentials and configurations, every agent talks to Trentina. One connection, one token, one policy plane.

## Why This Matters

The typical MCP deployment has agents connecting directly to backend servers. Each connection is a separate configuration entry, a separate trust relationship, and a separate attack surface. A Claude Code `settings.json` with 15 MCP servers means 15 SSH tunnels, 15 API keys, and 15 places where tool definitions bloat the context window.

Trentina collapses all of that into one chokepoint where you can enforce policy, audit calls, compress descriptions, and apply prompt injection defense — without modifying any backend server.

## How It Works

### Endpoint

Each agent connects to a profile-specific gateway endpoint:

```
POST /gateway/<profile_name>/mcp
```

All MCP operations (`tools/list`, `tools/call`) go through this single URL. The profile name determines which backends, tools, and defense settings apply.

#### The legacy `/mcp` endpoint

Earlier versions served Trentina's full tool surface at a bare `/mcp` with no
bearer token, no allowlist and no audit -- a bypass of everything the gateway
enforces. It is disabled by default: `/mcp` answers `410` with directions, and
FastMCP's own MCP app is mounted at a per-boot unguessable path instead.

Setting `TRENTINA_LEGACY_MCP` to a truthy value restores the old unguarded
`/mcp` for consumers that have not migrated. It logs a warning at startup.
Treat it as a temporary migration aid: anything reaching Trentina through it
is not inspected, not allowlisted and not audited. Migrate consumers to
`/gateway/<profile>/mcp` and unset the variable.

### Sessions and restarts

`initialize` issues an `Mcp-Session-Id`. Sessions live in memory, so every
gateway restart ends all of them. A client that sends a session id the gateway
no longer holds gets a `404` whose body is a JSON-RPC error: code `-32001`, and
a message saying why (TTL expiry, eviction, teardown, or "never issued by this
gateway process") and telling it to re-initialize. An `initialize` that still
carries the stale header is accepted and gets a new session. A client that
recovers on its own therefore never needs a human after a deploy.

Claude Code re-initializes on a `404` to a POST, so a stale session is
invisible to it. If a client reports "timed out" right after a restart, the
session isn't the cause. Look at how long the first `tools/list` took: a cold
perimeter store makes that call judge every tool description (see the startup
`caches loaded` line).

### Backend Routing

When an agent calls a tool, Trentina resolves the name it served (see
[Tool Names](#tool-names)) back to the real backend and tool:

```
list_issues  ->  github / list_issues_tool
```

The gateway connects to the backend over the container network (Podman DNS), executes the call, and returns the response. The agent never talks to the backend directly.

### Backend Types

Trentina supports two backend URL schemes:

| Scheme | Description | Example |
|--------|-------------|---------|
| `http://` | Remote MCP server on the container network | `http://mcp-slack:8000/mcp` |
| `internal://` | Trentina's own tools (web quarantine, search, scan) | `internal://web` |

Both return identical wire shapes to the agent. The `internal://web` backend is how Trentina's original quarantine tools are exposed through the gateway — they're just another backend.

### Results

A proxied result reaches the agent as the backend sent it, less two kinds of
bytes the agent would pay for and not read (0.38.0):

- **The repeated copy.** FastMCP servers return every value twice: as a text
  block and as `structuredContent`. When `structuredContent` is exactly the one
  text block again, as JSON or as `{"result": ...}`, it is dropped before
  pre-processing and the scan, so what the perimeter judges is what is
  delivered. Anything else, including a structured copy that differs in one
  value, is kept and judged. Literal response guards run on the result as it arrived.
- **Minified text.** The text blocks go through the profile's transforms,
  `detect` by default, unless the call passes `trentina_preprocess: false`.
  See [Minifying and exact text](profiles.md#minifying-and-exact-text).

### The guard grid

Above the grid sits the **tool guard** (`tools_allow` / `tools_deny`): a
deterministic allowlist that decides whether a tool is reachable at all. It is
the strongest and cheapest check — a denied tool is never called — but it is
all-or-nothing, so it is not one of the four cells below.

The four guards proper vary on two axes. The primary axis is **how** they
judge:

- **Literal** guards are per-tool glob constraints on `allow`/`deny` patterns.
  Deterministic, no model, cannot be argued with.
- **Semantic** guards hand the call to the profile's judge model with a
  plain-English policy; anything but an explicit allow refuses.

The secondary axis is **what** they read: the **request** (arguments, before
the backend is contacted) or the **response** (the backend's result, before it
is relayed). That gives a 2×2 grid:

| | Request (arguments) | Response (result) |
|---|---|---|
| **Literal** (per-tool glob) | [Literal request guards](literal-request-guards.md) — `literal_request_guards` | [Literal response guards](literal-response-guards.md) — `literal_response_guards` |
| **Semantic** (policy a judge reads) | [Semantic request guards](semantic-request-guards.md) — `semantic_request_guards` | *(a semantic response guard is a later feature; no key yet)* |

Each guard only subtracts; none can widen what another allows. The
[defense pipeline](defense-pipeline.md) (L1 ∥ L2 → L3) is a separate
mechanism and sits outside this grid: it judges content for hostility rather
than enforcing operator egress/argument policy.

The names changed in 3.0.0: `parameter_guards` → `literal_request_guards`,
`guarded_execution` → `semantic_request_guards`.

### Argument Normalization

Some models send every optional parameter instead of omitting it, filled with
a placeholder: `feed_id: 0`, `file_type: ""`. The backend rejects them, and a
client may count each rejection against the whole server. Before a proxied
call is forwarded, the gateway checks each argument against the tool's cached
`inputSchema` and applies the first rule that matches:

| Argument | Value | Result |
|---|---|---|
| optional | `""` or `null` | dropped |
| optional | provably fails the schema | dropped when the tool is annotated `readOnlyHint`; otherwise refused with `-32602` |
| required | provably fails the schema, or is absent | refused with `-32602`; the backend is not called |

"Provably" means the gateway checks only `type`, `enum`, `const`, length,
range, item count and the `date`/`date-time` formats, through `anyOf`,
`oneOf`, `allOf` and local `$ref`. Anything else counts as valid, so nothing
is dropped on a guess. `pattern` is never evaluated, since a backend's regex
run on the gateway is a ReDoS. With no cached schema, nothing changes.

Dropping `""` or `null` cannot widen a call: the caller said nothing by it, so
the result is the call it would have made by omitting the argument. Dropping a
value can (0.53.0, #335). An optional often narrows the action, and
`image_prune(all=true, filters=<malformed>)` forwarded without its filter
removes every unused image and reports success. So a value that fails its
schema refuses the call, naming the argument and the rule, never the value.
That includes `0` under a minimum: `feed_id: 0` is a placeholder and
`limit: 0` on a delete is not, and the schema cannot tell them apart. The one
exception is a tool its backend annotates `readOnlyHint: true`, where the
wider call is only a wider read: there the value is dropped and reported. A
backend that publishes no annotations gets the refusal on every tool, so
annotate the read tools of a backend whose clients send placeholders.

A value equal to the schema's `default` is forwarded: it is valid, and
`default` is only an annotation, so a backend may not apply it on omission.
Literal request guards judge the arguments as forwarded. Each drop is reported to
the agent in `_trentina_warning.normalized` and recorded in the audit row.
Internal tools are exempt, since they already read an empty value as unset.

The schema is the backend's tool list, which the gateway caches and persists
so a backend that is down at boot still has its last-known-good list. Since
0.53.0 every persisted list is refetched when the gateway starts, before the
warm-up builds anything, and a backend that cannot be reached keeps the one it
had. Until then a list outlived every backend upgrade until someone ran
`reconnect_backend`, and arguments were judged against a schema the tool no
longer had. A backend upgraded while the gateway runs still needs
`reconnect_backend`.

The normalization is only as good as the backend's schema. An ID declared
`int | None` with no `minimum` cannot show that `0` is invalid. The crunchtools
mcp-server profile requires `ge=1` on IDs for this reason.

### Tool Names

Since 0.38.0 each tool is served under the simplest name that says what it
does (`gateway/names.py`), not `<backend>__<tool>`:

| Backend tool | Served as |
|---|---|
| `jira` / `jira_get_issue_watchers` | `get_issue_watchers` |
| `cloudflare` / `list_zones_tool` | `list_zones` |
| `memory` / `memory_store` | `memory_store` |
| `mail-work` / `send_gmail_message` | `work_send_gmail_message` |
| `mail-home` / `send_gmail_message` | `home_send_gmail_message` |

The rule: drop a trailing `_tool`; drop the leading words every tool of the
backend shares, unless one word would be all that is left; and where two
backends' tools still collide, prefix each with the backend's tag
(`name_tag`, else the backend name). Tags, not numbers: `work_` and
`home_` tell an agent which account it is about to send mail from, and
`send_gmail_message2` would not. On a 376-tool profile this took the names from 10.2 KB
to 6.3 KB, before a client adds its own prefix.

A name, once issued to a profile, is recorded and never reassigned, so adding
a backend later cannot rename a tool an agent already knows: the newcomer
takes the tag. Only the edge sees short names. Allowlists, literal request guards,
`preprocess_tools`, the verdict cache and the audit log all keep using the real
backend and tool names.

`short_names: false` on a profile serves the old `<backend>__<tool>` form.
On a short-names profile only the names `tools/list` served route; the
`<backend>__<tool>` fallback was removed in 0.43.0.

### Configuration

Backends are configured per-profile in `profiles.yaml`:

```yaml
profiles:
  myagent:
    auth:
      bearer_token_env: TRENTINA_PROFILE_MYAGENT_TOKEN
    backends:
      web:
        url: "internal://web"
        tools_allow: ["*"]
      slack:
        url: "http://mcp-slack:8000/mcp"
        tools_allow: ["*"]
      github:
        url: "http://mcp-github:8000/mcp"
        tools_allow: ["*"]
```

Changes to `profiles.yaml` take effect on the next `reload_profiles` call or
gateway restart — there is no file watcher. What one call applies depends on
the caller's `role`: an agent profile applies its own section, an operator the
whole file. See [Roles](profiles.md#roles) and
[Applying a Change](profiles.md#applying-a-change).

### Real-World Scale

The Crunchtools deployment serves 8 profiles over 30 backends. In the 30 days
to 2026-10-01 it handled 18,724 tool calls: 18,007 succeeded, 180 were refused
by the defense pipeline, 61 by literal request guards, 11 by literal response guards and 29
by allowlists (`gateway_calls`, see [Audit Log](audit-log.md)).

## Related

- [Per-Agent Profiles](profiles.md) — how profiles control backend access
- [Tool Filtering](tool-filtering.md) — allowlists and denylists per backend
- [Defense Pipeline](defense-pipeline.md) — content inspection on tool responses
- [Internal: Gateway Design](internal/gateway-design.md) — original design document for contributors
