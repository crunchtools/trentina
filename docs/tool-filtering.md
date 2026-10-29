# Tool Allowlists & Denylists

*Part of Trentina's **Token savings** promise; see [Why Trentina](../README.md#why-trentina).*

Trentina filters which tools each agent can see and call. Tools not in the allowlist are stripped from `tools/list` responses before they reach the consumer — they never enter the agent's context window and can never be called.

## Why This Matters

A Google Workspace MCP server exposes ~130 tools. Most agents need maybe 25 of them. The other 105 waste context tokens on tool definitions the agent will never use, and some of them (`delete*`, `send_gmail_message`) are capabilities you don't want an autonomous agent to even know about. Filtering at the gateway means the tools are invisible — not just disabled, but absent from the agent's view of the world.

The CrunchTools deployment reduced agent1's tool count from ~520 to ~210 (60% cut) just through allowlist filtering, before description compression even runs.

## How It Works

Each backend in a profile has two lists:

```yaml
backends:
  gws-personal:
    url: "http://gws-personal:8000/mcp"
    tools_allow:
      - search_gmail_messages
      - get_gmail_message_content
      - get_gmail_messages_content_batch
      - draft_gmail_message
      - send_gmail_message
      - get_events
      - manage_event
      - list_calendars
    tools_deny:
      - "delete*"
```

### Evaluation Order

1. `tools_allow` runs first — a tool must match at least one allow pattern
2. `tools_deny` runs second — a tool matching any deny pattern is removed
3. Deny wins on conflict

### Pattern Syntax

Both lists support exact names and shell-style globs:

| Pattern | Matches |
|---------|---------|
| `search_gmail_messages` | Exact match only |
| `*` | Everything (default allow) |
| `delete*` | `delete_post`, `delete_page`, `delete_media`, etc. |
| `*_gmail_*` | Any tool with `_gmail_` in the name |
| `wordpress_create_*` | `wordpress_create_post`, `wordpress_create_page`, etc. |

Patterns are matched against the backend's original tool name (not the namespaced consumer-visible name).

## Common Strategies

### Full access with targeted denies

```yaml
tools_allow: ["*"]
tools_deny:
  - "delete*"
  - "send_gmail_message"
  - "wordpress_delete_*"
```

Good for human-supervised agents where you trust the human to intervene but want guardrails against destructive actions.

### Explicit allowlist

```yaml
tools_allow:
  - search_gmail_messages
  - get_gmail_message_content
  - draft_gmail_message
  - get_events
  - list_calendars
```

Good for autonomous agents where you want to enumerate exactly what's available. This is what the agent1 profile uses — every tool is explicitly listed for the heavy backends (Google Workspace, Jira, GitHub).

### Read-only access

```yaml
tools_allow:
  - "list_*"
  - "get_*"
  - "search_*"
  - "query_*"
```

Restrict a backend to read-only operations by pattern. Useful for monitoring or reporting agents.

## Context Savings

Tool filtering is the first layer of context reduction. Before description compression even runs, filtering removes tools entirely — their definitions, parameter schemas, and descriptions never enter the agent's context:

| Backend | Total Tools | After Filtering | Reduction |
|---------|------------|----------------|-----------|
| Google Workspace Personal | ~130 | ~25 | 81% |
| Google Workspace Work | ~130 | ~15 | 88% |
| Jira/Atlassian | ~40 | ~14 | 65% |
| Gemini | ~25 | ~12 | 52% |
| Cloudflare | ~20 | ~6 | 70% |

Combined with [description compression](compression.md), the total context reduction can exceed 90%.

## Related

- [Per-Agent Profiles](profiles.md) — where allow/deny lists are configured
- [Literal Request Guards](literal-request-guards.md) — restricting argument *values*, not just tool access
- [Description Compression](compression.md) — reducing context for the tools that pass filtering
