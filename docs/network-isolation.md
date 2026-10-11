# Matrix Reverse Proxy

*Part of Trentina's **Architectural flexibility** promise; see [Why Trentina](../README.md#why-trentina).*

Proxy Matrix Client-Server API traffic through the gateway so agents on the internal network can communicate via Matrix without direct internet access. Agents point `MATRIX_HOMESERVER` at Trentina instead of matrix.org.

## Why This Matters

Agents that connect to Trentina for MCP tools may still have their own network access. An agent compromised by prompt injection could bypass the gateway entirely — making direct HTTP calls, exfiltrating data to arbitrary URLs, or downloading malicious payloads. The gateway controls MCP tool calls, but it doesn't control the network.

This is Simon Willison's "lethal trifecta" in action: an agent that can (1) read private data, (2) ingest untrusted content, and (3) send data out has all the ingredients for a successful exfiltration attack. Trentina already addresses #2 with the defense pipeline. Network isolation addresses #3 by eliminating the agent's ability to send data anywhere except through the gateway.

The Matrix reverse proxy is the first piece of this: agents that use Matrix for communication (e.g., agent-to-agent messaging, notifications) route that traffic through Trentina instead of connecting directly to the homeserver.

## How It Works

Trentina exposes a transparent reverse proxy at `/matrix/{path}` that forwards Matrix Client-Server API requests to the configured upstream homeserver. Matrix handles its own authentication via access tokens in request headers — the proxy doesn't inject credentials. It's a pass-through with timeout tuning for the long-poll `/sync` endpoint.

### What This Buys You

- **No direct internet for Matrix** — agents on `--network=none` can still use Matrix through the gateway
- **Centralized network egress** — all outbound traffic from agents flows through Trentina
- **Audit trail** — Matrix traffic goes through the same infrastructure as MCP calls
- **Timeout handling** — the proxy handles Matrix's long-poll `/sync` endpoint with appropriate read timeouts (120s)

## Configuration

Matrix proxying is configured in the top-level `matrix` section of `profiles.yaml`:

```yaml
matrix:
  enabled: true
  upstream: https://matrix-client.matrix.org
```

| Field | Default | Description |
|-------|---------|-------------|
| `enabled` | `false` | Whether the Matrix proxy is active |
| `upstream` | `https://matrix-client.matrix.org` | Matrix homeserver to forward to |

The upstream must use HTTPS.

### Agent Configuration

Point the agent's Matrix client at Trentina instead of the homeserver:

```bash
# Instead of:
MATRIX_HOMESERVER=https://matrix.org

# Use:
MATRIX_HOMESERVER=http://trentina:8019/matrix
```

### Which profile a request belongs to

The caller's network decides. Each profile that uses the proxy names the
network its agent is on, and a request from an address in none of them gets
401:

```yaml
profiles:
  hermes:
    auth:
      bearer_token_env: TRENTINA_PROFILE_HERMES_TOKEN
    matrix_ingress:
      source_networks: ["10.89.1.0/24"]   # the agent's own podman network
```

There is no secret in the homeserver URL. Until 0.51.0 a token in the path
(`/matrix/<token>`) picked the profile, and every Matrix client prints the
request URL in a timeout or connection error, so the token landed in agent
logs, and from there in model context whenever the agent read its own logs
(#330). `matrix_ingress.token_env` now fails startup with a message naming
its replacement.

Three rules keep the address trustworthy:

- One agent per network. No two profiles' `source_networks` may overlap; the
  file does not load if they do.
- A host prefix is refused (`10.89.1.5/24` is a typo for `10.89.1.0/24`).
- A request carrying `X-Forwarded-For` is refused. uvicorn replaces the
  client address with that header's for a peer in
  `TRENTINA_FORWARDED_ALLOW_IPS`, so the address could be one somebody named.
  An agent calls the gateway directly from its own network and sends none;
  the Matrix proxy is not reachable through a reverse proxy.

An agent may not change its own `source_networks` by `reload_profiles`; the
operator's reload applies them.

All Matrix Client-Server API operations (`/sync`, `/rooms`, `/send`, etc.) are forwarded, and every response but a write's acknowledgement, E2EE key traffic and binary media is judged first (see [Defense Pipeline](defense-pipeline.md)).

### Architecture

```
┌─────────────────────┐    /matrix/*    ┌─────────────────────┐    HTTPS     ┌──────────┐
│  Agent (no network)  │ ──────────────► │  Trentina Gateway   │ ──────────► │  Matrix  │
│                      │                │                     │             │ Homeserver│
│  MATRIX_HOMESERVER   │ ◄────────────── │  Timeout tuning     │ ◄────────── │          │
│  = trentina:8019     │                │  Transparent proxy  │             └──────────┘
└─────────────────────┘                └─────────────────────┘
                                               │
                                    ┌──────────┼──────────┐
                                    ▼          ▼          ▼
                               MCP backends  LLM APIs  Web content
```

### Full Network Isolation Pattern

For complete network isolation, combine with the [LLM key proxy](llm-proxying.md) and run the agent container with `--network=none` plus a sidecar that only reaches Trentina:

1. **MCP tools** → `http://trentina:8019/gateway/<profile>/mcp`
2. **LLM calls** → `http://trentina:8019/llm/<provider>/<path>`
3. **Matrix** → `http://trentina:8019/matrix/_matrix/<path>`, from the agent's own network
4. **The agent's own HTTPS client** → `HTTPS_PROXY=http://trentina:8021`, tunnelled to the hosts its profile lists ([client egress](client-egress.md))

The agent has no other network access of its own. Every request it makes goes through Trentina and is audited (a tunnel as a host and a byte count, since its contents are TLS no layer reads), but a request is not the only way out: a model provider can fetch, search and connect to MCP servers on the caller's behalf (Anthropic's `web_fetch`, `web_search` and `mcp_servers`, OpenRouter's `web` plugin and `:online` models, Gemini's Google Search grounding and `url_context`). Until #297 the LLM proxy forwarded those untouched, so an agent on `--network=none` could still reach any host through its provider. The proxy now admits only completions with caller-run function tools and inline content, and refuses the rest ([what the proxy admits](llm-proxying.md#what-the-proxy-admits)).

What remains is the provider itself: an agent can still put data in a prompt, and the provider receives it. Treat the provider as a destination the agent can write to.

## Related

- [LLM Key Proxying](llm-proxying.md) — isolating model API keys from agents
- [Client Egress](client-egress.md) — a tunnel for the agent's own HTTPS client
- [MCP Gateway](gateway.md) — the gateway architecture this extends
- [Defense Pipeline](defense-pipeline.md) — content inspection applied to all proxied responses
