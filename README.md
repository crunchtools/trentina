<p align="center">
  <img src="https://raw.githubusercontent.com/crunchtools/trentina/main/docs/images/trentina-logo.png" alt="trentina: a medieval merchant ship anchored offshore while an inspector in a rowboat checks each crate of code before it reaches the harbor gate" width="320">
</p>

# Trentina

<!-- mcp-name: io.github.crunchtools/trentina -->

Trentina sits between your AI agents and everything they touch: MCP servers,
the web, Matrix, LLM providers and alerts. It stops prompt injection at every
ingress, shrinks what reaches the context window, and enforces a policy the
agent cannot talk its way past. It is named after the 1377 *trentino* of
Ragusa, where ships anchored offshore for thirty days before anyone came
ashore: commerce keeps flowing, and nothing dangerous gets in.

<p align="center">
  <img src="https://raw.githubusercontent.com/crunchtools/trentina/main/docs/demo/trentina.gif" alt="Demo: a request crosses Trentina's auth, policy, defense and minify stages; then, in a terminal, a 135-tool list is served as 6 tools, a recipe page with an injection in its comments is refused and then answered through redact, and a send to an outside address is refused while a draft goes through" width="800">
</p>

## Why Trentina

1. **Security.** Untrusted content crosses three independent layers at every
   ingress: L1 deterministic checks, L2 a local classifier, L3 a quarantined
   LLM with no tools. [Semantic request guards](docs/semantic-request-guards.md) judge
   what goes out against a rule you write in English. What is and is not
   defended is in [Coverage](docs/defense-pipeline.md#coverage).
   [Defense Pipeline](docs/defense-pipeline.md) · [Benchmark](docs/benchmark.md) ·
   [OWASP mapping](docs/owasp-mapping.md)

2. **Token savings.** Hidden tools, short names, compacted schemas, compressed
   descriptions and minified responses: **52% fewer response bytes** on
   production traffic. [Compression](docs/compression.md) ·
   [Tool Filtering](docs/tool-filtering.md)

3. **Determinism.** Literal request guards, literal response guards and
   allowlists are evaluated by the gateway, so an agent that ignores its
   instructions is stopped before the backend sees the call.
   [Literal Request Guards](docs/literal-request-guards.md) ·
   [Literal Response Guards](docs/literal-response-guards.md)

4. **Authentication.** Trentina is the OAuth authorization server for web
   clients such as claude.ai: dynamic client registration, a provisioned
   client, external issuers or a static bearer, chosen per profile.
   [Authentication](docs/authentication.md)

5. **Architectural flexibility.** A personal assistant, a coding agent and a
   swarm each get their own profile, with their own backends, defense mode and
   credentials. [Profiles](docs/profiles.md) · [Operator](docs/operator.md)

## Quick Start

```bash
# The container image is the distribution: the L2 model, the parsers and
# their process isolation ship in it. There is no PyPI package.
podman run -d -p 127.0.0.1:8019:8019 \
    -v ./profiles.yaml:/config/profiles.yaml:ro,Z \
    -e TRENTINA_GATEWAY_ENABLED=true \
    -e TRENTINA_PROFILES_PATH=/config/profiles.yaml \
    -e TRENTINA_PROFILE_MYAGENT_TOKEN=your-token \
    -e OPENROUTER_API_KEY=your-key -e TRENTINA_MODEL_PROVIDER=openrouter \
    quay.io/crunchtools/trentina \
    --transport streamable-http --host 0.0.0.0 --port 8019
```

L3 needs a key for one LLM provider. Any of Gemini, OpenRouter, OpenAI,
Anthropic or Ollama works. A minimal `profiles.yaml`:

```yaml
profiles:
  myagent:
    auth:
      bearer_token_env: TRENTINA_PROFILE_MYAGENT_TOKEN
    backends:
      web:
        url: "internal://web"         # Trentina's own content tools
        tools_allow: ["*"]
      gmail:
        url: "http://gws-personal:8000/mcp"
        tools_allow:                  # it may read and draft; you send
          - search_gmail_messages
          - get_gmail_message_content
          - draft_gmail_message
    defense:
      enforcement: block
```

Then point Claude Code at it:

```json
{
  "mcpServers": {
    "trentina": {
      "type": "streamable-http",
      "url": "http://localhost:8019/gateway/myagent/mcp",
      "headers": { "Authorization": "Bearer your-token" }
    }
  }
}
```

## Documentation

| Document | Description |
|----------|-------------|
| [MCP Gateway](docs/gateway.md) | One endpoint per profile: routing, tool names, circuit breakers |
| [Per-Agent Profiles](docs/profiles.md) | Profile schema, modes, minifying, roles, multi-agent setup |
| [Operator Profile](docs/operator.md) | The agent that installs and runs the gateway |
| [Configuration](docs/configuration.md) | Every environment variable |
| [Authentication](docs/authentication.md) | Static bearer, OAuth proxy with DCR or a provisioned client, delegated issuers |
| [Backend OAuth](docs/profiles.md#backend-oauth) | Each profile signs in to OAuth-only backends with its own grant |
| [Defense Pipeline](docs/defense-pipeline.md) | L1/L2/L3, modes, coverage and known gaps |
| [Benchmark](docs/benchmark.md) | Detection rates per layer and per L3 provider |
| [Corpora](docs/corpora.md) | Every attack and benign set the defense is measured on |
| [Prompt Packs](docs/l3-prompt-tuning.md) | The judge's prompts tuned per model |
| [Content Tools](docs/quarantine-tools.md) | fetch, read, dir, content, search, with an egress guard and file confinement |
| [Blocklist](docs/blocklist.md) | A refused source stays refused |
| [Tool Filtering](docs/tool-filtering.md) | Allowlists, denylists, glob patterns |
| [Tool Pinning](docs/tool-pinning.md) | A new or changed tool is held until approved |
| [Tool Discovery](docs/tool-discovery.md) | Find/call or per-session loading for clients without tool search |
| [Description Compression](docs/compression.md) | Description compression and schema compaction |
| [Token Routing](docs/token-routing.md) | Response minifying (implemented); delegation (proposed) |
| [Semantic Request Guards](docs/semantic-request-guards.md) | A judge reads calls to listed tools against a policy in plain English |
| [Literal Request Guards](docs/literal-request-guards.md) | Per-tool argument validation |
| [Literal Response Guards](docs/literal-response-guards.md) | Per-tool result validation |
| [Audit Log](docs/audit-log.md) | Call recording, stats, monitoring |
| [LLM Key Proxying](docs/llm-proxying.md) | Provider keys kept inside the gateway |
| [Matrix Bridge](docs/matrix-bridge.md) | E2EE termination and two-way judging |
| [Channel Bridges](docs/channel-bridges.md) | More than one upstream per agent (RCS, ...) and the bridge wire contract |
| [Matrix Reverse Proxy](docs/network-isolation.md) | Matrix for agents on an isolated network |
| [Client Egress](docs/client-egress.md) | A CONNECT tunnel to listed hosts for the agent's own client |
| [Git Transport](docs/git-transport.md) | Clone, fetch and push to listed repositories and branches |
| [HTTP(S) Egress](docs/egress-http.md) | An agent's outbound request judged and re-originated to a named destination |
| [Deployment Hardening](docs/deployment-hardening.md) | Container flags, secrets, egress, the startup check |
| [Plugins](docs/plugins.md) | Write, test, install and name your own transform plugins |
| [Cockpit Plugin](docs/cockpit-plugin.md) | Live defense pipeline dashboard |
| [Internal: Gateway Design](docs/internal/gateway-design.md) | Original design document, for contributors |

## Development

```bash
uv sync --all-extras
uv run ruff check src tests
uv run mypy src
uv run pytest -v
```

The container image is built by CI, never locally; see `CLAUDE.md`. The demo
is recorded by [`demo.yml`](.github/workflows/demo.yml); its fixtures are in
[`docs/demo/`](docs/demo/).

## License

AGPL-3.0-or-later
