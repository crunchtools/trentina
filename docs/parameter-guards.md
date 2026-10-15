# Parameter Guards

*Part of Trentina's **Determinism** promise; see [Why Trentina](../README.md#why-trentina).*

Parameter guards validate the *arguments* an agent passes to a tool, not just whether the agent can call the tool at all. They provide deterministic, gateway-level enforcement of constraints like "this agent can send email, but only to these specific recipients."

## Why This Matters

Tool allowlists control *which* tools an agent can call. But some tools are dangerous not because of what they do, but because of what values get passed to them. `send_gmail_message` is fine when sending to yourself. It's a data exfiltration vector when an injected prompt convinces the agent to send your private data to an attacker's address.

You could try to enforce this behaviorally — tell the agent "only send email to these addresses" — but behavioral enforcement depends on the LLM following instructions, which is exactly what prompt injection attacks subvert. Parameter guards enforce the constraint at the gateway, before the call reaches the backend. The LLM's opinion doesn't matter.

## How It Works

Parameter guards are configured per-backend, per-tool in the profile YAML:

```yaml
backends:
  gws-personal:
    url: "http://gws-personal:8000/mcp"
    tools_allow: ["*"]
    parameter_guards:
      send_gmail_message:
        to:
          allow: ["user@example.com"]
        cc:
          allow: ["user@example.com"]
        bcc:
          allow: ["user@example.com"]
```

When an agent calls `send_gmail_message` through this profile, Trentina checks every guarded parameter against the allow/deny patterns. If the `to` field contains any address other than `user@example.com`, the call is rejected with a JSON-RPC `-32602` error before it ever reaches the Gmail backend.

### Constraint Schema

Each guarded parameter has two fields:

| Field | Default | Description |
|-------|---------|-------------|
| `allow` | `["*"]` | Glob patterns the value must match |
| `deny` | `[]` | Glob patterns that reject the value (wins over allow) |

### Pattern Matching

Values are matched using `fnmatch.fnmatchcase()` — shell-style globs with support for `*`, `?`, and `[seq]`:

| Pattern | Matches |
|---------|---------|
| `user@example.com` | Exact match |
| `*@company.com` | Any address at that company |
| `*@gmail.com` | Any Gmail address |
| `https://api.example.com/*` | Any URL under a specific domain |

### Evaluation Rules

- **Missing guard**: no `parameter_guards` entry for a tool = all values allowed
- **Missing parameter**: if a guarded parameter is absent or `None` in the arguments, it passes (nothing to validate)
- **Deny wins**: a value matching any deny pattern is rejected even if it also matches an allow pattern
- **Fail-closed**: a call that fails parameter validation never reaches the backend — no tokens spent, no side effects

## Examples

### Restrict email recipients

```yaml
parameter_guards:
  send_gmail_message:
    to:
      allow: ["*@company.com", "user@example.com"]
      deny: ["*@competitor.com"]
    cc:
      allow: ["*@company.com"]
```

### Restrict file paths

```yaml
parameter_guards:
  read_tool:
    path:
      allow: ["/data/*", "/tmp/*"]
      deny: ["/etc/shadow", "/etc/passwd", "*.key"]
```

### Restrict URLs

```yaml
parameter_guards:
  fetch_tool:
    url:
      allow: ["https*//*"]
      deny: ["*//evil.example.net/*", "*//localhost*"]
```

A pattern cannot hold a colon, so the scheme is matched with `https*//`. The
pattern is a glob over the whole string, not a parsed URL: `https*//www.example.org/*`
also matches a URL that only carries that text in its path, and a redirect is
not checked against it. A guard narrows what an agent asks for; it is not an
egress control ([Deployment hardening](deployment-hardening.md)).

### Narrow the mode on one tool

The mode policy is `defense.modes` on the profile ([Content modes](profiles.md#content-modes)); nothing here is needed for it. A guard on `trentina_mode` narrows one tool further:

```yaml
parameter_guards:
  send_gmail_message:
    trentina_mode:
      allow: ["block"]
```

The guard is checked against the RESOLVED mode — an omitted `trentina_mode` becomes the profile default first — so leaving the argument out cannot skip it, which is what a guard does with any other absent argument. The tool's schema offers only what survives the guard. Every value, glob or not, must match at least one of `block`, `flag` or `redact`, or the profile fails to load: a value that matches no mode (`warn`, the pre-0.35.0 name for `flag`, or `warn*`) could never fire, and a guard that silently denies nothing is worse than a load error.

## Pipeline Position

Parameter guards run after the tool-name allowlist check and before the backend call:

```
Parse tool name → Backend exists? → Tool in allowlist? → Resolve trentina_mode and trentina_preprocess → Parameter guards → Guarded execution (if the tool is guarded) → Backend call
```

A rejected call returns immediately. The backend never sees the request. The error message is terse and does not include the rejected value (to avoid leaking guard configuration to the agent).

## What Parameter Guards Cannot Do

A parameter guard only sees what the agent sent. When a tool's retrieval is
semantic — a memory search, a wiki query — the sensitive material is in the
*response* and the request carries nothing to match on. That case is covered by
[response guards](response-guards.md), which apply the same constraint to the
result.

A parameter guard also cannot judge meaning: whether a mail body is a bulk
export, or a chat message carries a credential. For that, list the tool under
[guarded execution](guarded-execution.md), which runs after the guards and
asks the profile's judge to read the call against a rule written in English.

## Related

- [Response Guards](response-guards.md) — the same evaluator, applied to what a tool returns
- [Guarded Execution](guarded-execution.md) — a judge reads the call against a written policy, after the guards
- [Tool Filtering](tool-filtering.md) — controlling which tools are visible
- [Per-Agent Profiles](profiles.md) — where parameter guards are configured
- [Defense Pipeline](defense-pipeline.md) — content inspection after the call succeeds
