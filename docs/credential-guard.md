# Credential guard

An agent that pastes an API key into a tool's arguments sends it to that tool's backend. The three layers look for injection, not key material, so the gateway checks for it separately (#862): every `tools/call`'s arguments are scanned for credential shapes, as written and unmasked (percent, `\u` and HTML-entity escapes decoded, zero-width characters dropped, fullwidth and other compatibility forms folded by NFKC), right after the [literal request guards](literal-request-guards.md) and before the schema check, the [gatekeeper](semantic-request-guards.md) or the backend.

A hit is refused as `denied_guard` in every mode, `flag` included: what would leave is the secret itself. The agent is told `credential_in_request` with the kinds and the tool; the [audit row](audit-log.md) carries the same. Neither carries the value. The kinds are `credential_shapes.CredentialKind`: `query_secret`, `authorization`, `url_userinfo`, `aws_access_key`, `openai_key`, `google_api_key`, `google_oauth_token`, `matrix_token`, `github_token`, `slack_token`, `jwt`, `pem_private_key`, `trentina_profile_token`.

## Allowing a credential

A tool that takes a token on purpose, such as a secret setter, is allowed by kind on its backend:

```yaml
backends:
  vault:
    url: http://luna:8000/mcp
    credentials_allowed: [github_token, openai_key]   # every tool on this backend
  memory:
    url: http://luna:8001/mcp
    credentials_allowed:
      memory_store: [github_token]   # this tool only
      "*": [jwt]                     # every tool
  scratch:
    url: http://luna:8002/mcp
    credentials_allowed: ["*"]       # every kind, every tool
```

Adding an allowance through `config_tool` waits for a person's [approval](approvals.md); removing one, or narrowing `["*"]` to named kinds, applies at once. An agent reload does not change it. A tool's allowance is its own list plus the `"*"` list. The block is checked at load: an unknown kind, `"*"` beside named kinds, a kind listed twice, an empty list, or a decoy backend carrying it fails the file.

## Known limits

The check reads shapes. A key wrapped in base64 or another encoding the destination does not decode, split across two arguments or two calls, or with no recognisable prefix (most passwords) is not seen. `Authorization` and query-string values count only when they look like a token (mixed case with a digit, or long hex) so prose about a "bearer token" is not refused, which means a lowercase-only secret after `Bearer` passes. A planted honeytoken is matched separately, base64 and fragments included, by the [decoy check](profiles.md#decoy-tools-and-honeytokens).

## Before you deploy: replay past calls

Turning the guard on blind refuses whatever your agents already do on purpose. `trentina-credential-replay` replays past calls against your `profiles.yaml` and prints the `credentials_allowed` blocks that would have let them through.

The audit log cannot be replayed: `gateway_calls` stores no arguments. The input is JSONL you already have, one call per line, in any mix of:

- `{"profile": P, "backend": B, "tool": T, "arguments": {...}}`
- `{"profile": P, "name": SERVED_NAME, "arguments": {...}}`
- a Claude Code session transcript (`~/.claude/projects/*/*.jsonl`). Its `mcp__trentina__<name>` tool calls count; they name no profile, so pass `--profile`.

```
trentina-credential-replay --profiles profiles.yaml --db trentina.db \
  --profile exedore-max ~/.claude/projects/*/*.jsonl
```

```
# profile: exedore-max  (412 calls replayed, 3 would be refused, 0 unresolved)
backends:
  github:
    credentials_allowed:
      create_issue: [github_token]   # 2 calls
```

Paste the blocks under the backend in `profiles.yaml`, after reading each one: a kind listed is a credential that tool may now send. The gateway's own `trentina_mode`, `trentina_prompt` and `trentina_preprocess` are dropped before the scan, as the gateway drops them before forwarding.

| Flag | Effect |
| --- | --- |
| `--profiles PATH` | Required. The `profiles.yaml` to judge against. |
| `--profile P` | Profile for lines that name none. |
| `--mcp-server S` | Transcript server name (default `trentina`). |
| `--current` | Default. Judge against today's `credentials_allowed`; each backend that needs more prints its whole allowance, existing entries plus new, so pasting it drops nothing. |
| `--all` | Ignore existing allowances. |
| `--json` | `{"skipped": n, "profiles": {P: {"replayed", "refused", "unresolved", "needs": {backend: {tool: {kind: calls}}}}}}`. |
| `--db PATH` | The gateway database, opened read-only, to resolve short names. Without it they count as unresolved; an unreadable one is exit 2. |

Files, or `-` for stdin. Exit 0 if nothing would be refused, 1 if something would, 2 on a usage or load error. Lines that are none of the shapes are counted as skipped; names that resolve to no tool are counted as unresolved. No credential value or argument is ever printed: only kinds, tool names and counts.

`profiles.yaml` is read for policy only (`credentials_allowed`, `short_names`), so the secret env vars a full load demands need not be set; the rest of the file is not validated here. Served short names resolve through the database's `tool_names` table, so pass a copy of it with `--db`.
