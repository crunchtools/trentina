<p align="center">
  <img src="https://raw.githubusercontent.com/crunchtools/trentina/main/docs/images/trentina-logo.png" alt="trentina: a medieval merchant ship anchored offshore while an inspector in a rowboat checks each crate of code before it reaches the harbor gate" width="320">
</p>

# Trentina

<!-- mcp-name: io.github.crunchtools/trentina -->

Trentina is an MCP gateway that sits between your AI agents and everything they
touch: MCP servers, the web, Matrix, LLM providers and monitoring alerts. Every
agent gets one endpoint and its own profile. Behind that endpoint Trentina
stops prompt injection at every ingress and shrinks what reaches the context
window. It also enforces policy the agent cannot talk its way past and handles
OAuth for web clients like claude.ai and gemini.google.com. The same gateway
can serve a personal assistant, a coding agent and a swarm, wired however you
like. It is named after the 1377 *trentino* of Ragusa, where ships anchored
offshore for thirty days before anyone came ashore. The idea is the same:
commerce keeps flowing, and nothing dangerous gets in.

<p align="center">
  <img src="https://raw.githubusercontent.com/crunchtools/trentina/main/docs/demo/trentina.gif" alt="Demo: a request crosses Trentina's auth, policy, defense and minify stages; then, in a terminal, a 131-tool list is served as 6 tools, a recipe page with an injection in its comments is refused and then answered through redact, and a send to an outside address is refused while a draft goes through" width="800">
</p>

## Why Trentina

1. **Security.** Untrusted content gets the same three independent layers at
   every ingress: tool responses, tool descriptions, web pages, Matrix
   messages, LLM completions and alerts. L1 is deterministic checks, L2 is a
   local classifier and L3 is a quarantined LLM with no tools. L2's model is
   a setting: Horizon-Labs' prompt-injection-guard-small by default, Prompt
   Guard 2 86M one variable away. On our attacks planted inside long
   documents the default catches 21 of 39 where Prompt Guard 2 catches 4,
   2.4x faster on CPU. L3 reads everything L2 lets through.
   Around the layers sit an egress guard, file confinement and a startup
   containment check. What is and is not defended, by kind of content, is in
   [Coverage](docs/defense-pipeline.md#coverage), with every known gap.
   [Defense Pipeline](docs/defense-pipeline.md) · [Benchmark](docs/benchmark.md)

2. **Token savings.** Agents pay for every tool name, schema and response byte
   they read. Trentina hides tools a profile doesn't need, serves short names,
   compacts schemas and compresses descriptions: 154 tool descriptions went
   from 62K to 17K characters. It also minifies responses. On production
   traffic, agents received **52% fewer response bytes** than backends sent,
   across 4,164 calls. [Compression](docs/compression.md) ·
   [Tool Filtering](docs/tool-filtering.md)

3. **Determinism.** Asking a model nicely is not a control. Parameter guards,
   response guards and allowlists are evaluated by the gateway, so an agent
   that ignores its instructions, or assumes it has permission, is stopped
   before the backend sees the call. Trentina can't know when your email is
   ready to send. It can let the agent draft and keep the send for you.
   Production, last 30 days: 61 calls stopped by parameter guards, 11
   responses withheld by response guards. [Parameter Guards](docs/parameter-guards.md) ·
   [Response Guards](docs/response-guards.md)

4. **Authentication.** Web clients need OAuth, and most MCP servers don't
   speak it. Trentina is the authorization server: dynamic client
   registration for claude.ai and Claude Code, a provisioned client for
   gemini.google.com, verified external issuers, or a static bearer, chosen
   per profile. Each token is bound to the profile it was issued for, and LLM
   API keys stay inside the gateway. [Authentication](docs/authentication.md) ·
   [LLM Key Proxying](docs/llm-proxying.md)

5. **Architectural flexibility.** One gateway, many shapes. A personal
   assistant on Matrix, a coding agent in Claude Code and a swarm of locked-down
   autonomous agents each get their own profile, with their own backends,
   defense mode and credentials. An operator agent runs the gateway itself.
   The production deployment serves 8 profiles over 30 backends.
   [Profiles](docs/profiles.md) · [Operator](docs/operator.md)

## Capabilities

### Security

1. **[Three-Layer Defense Pipeline](docs/defense-pipeline.md).** Every payload
   runs L1 ∥ L2, then L3 briefed with both. The profile's mode decides delivery,
   never detection: `block` refuses, `flag` delivers the exact bytes with a
   verdict, `redact` returns an answer L3 extracted and a second pass verified.
2. **[Prompt Packs](docs/l3-prompt-tuning.md).** The L3 judge's prompts,
   tuned and measured for one exact model. On held-out benign content the
   generic prompts flag 19% on Gemini 2.5 Flash Lite and 47% on Gemini 3.8
   Flash; the shipped packs bring that to 2% and 0%, and catch every
   planted-instruction case the generic prompts catch. Packs ship for four
   judges, each through a held-out gate, and an operator can tune their own
   for any model.
3. **[Content Tools](docs/quarantine-tools.md).** `fetch`, `read`, `dir`,
   `content` and `search`, built-in tools that bring outside content in
   through the pipeline. Fetches go through an egress guard that refuses
   private addresses and checks every redirect. Reads are confined to
   configured roots.
4. **[Cumulative Detection Memory](docs/blocklist.md).** A refused source stays
   refused for that profile until its entry expires, whatever a probabilistic
   layer thinks on the next run.
5. **[Matrix Bridge](docs/matrix-bridge.md).** Terminates end-to-end
   encryption in a separate process so every message, in both directions,
   crosses the pipeline.
6. **[Deployment Hardening](docs/deployment-hardening.md).** Container flags,
   secrets from files, network isolation, and a startup check that warns or
   refuses on containment gaps.

### Token savings

6. **[Tool Filtering](docs/tool-filtering.md).** Allowlists and denylists,
   exact or glob. A tool a profile can't use never enters its context window.
7. **[Tool Description Compression](docs/compression.md).** Tool and parameter
   descriptions are compressed once by the operator's model and cached. Schemas
   are compacted, and tools are served under short names.
8. **[Minified Responses](docs/profiles.md#minifying-and-exact-text).** HTML
   becomes Markdown, logs and JSON arrays are grouped by
   [petit](https://github.com/crunchtools/petit), quoted mail threads collapse.
   Minifying fails open: if it breaks, the agent gets the original.

### Determinism

9. **[Parameter Guards](docs/parameter-guards.md).** Per-tool allow/deny
   patterns on argument values: "this agent may send mail, but only to
   `user@example.com`." Refused before the backend is called.
10. **[Response Guards](docs/response-guards.md).** The same constraint on what
    a backend returns, for semantic tools where nothing in the arguments is
    matchable.
11. **[Gateway Audit Log](docs/audit-log.md).** Every call, with profile,
    backend, tool, outcome, bytes in and out, and duration. It tells you
    which guards fired and which allowlisted tools no agent ever uses.

### Authentication

12. **[Authentication](docs/authentication.md).** Static bearer, OAuth proxy
    with DCR, OAuth proxy with a provisioned client, or a delegated external
    issuer, each set per profile. The tokens Trentina issues are bound to
    their profile.
13. **[LLM Key Proxying](docs/llm-proxying.md).** Agents call models through
    the gateway, which adds the real key. Request bodies are allowlisted and
    re-serialized, so a provider can't become a side door out of a
    `--network=none` container.

### Architectural flexibility

14. **[MCP Gateway](docs/gateway.md).** One endpoint per profile in front of
    any number of streamable-HTTP MCP backends, with circuit breakers, hot
    reload and argument normalization.
15. **[Per-Agent Profiles](docs/profiles.md).** Each consumer gets its own
    backends, tools, defense mode, pre-processors and authentication.
16. **[Operator Profile](docs/operator.md).** Trentina is built to be run by an
    agent. The operator seat installs, reloads and administers the gateway, and
    is the identity its own model calls bill to.
17. **[Client Egress](docs/client-egress.md).** An agent's own HTTPS client,
    tunnelled to the hosts its profile lists and to nothing else, by source
    network with no credential in the proxy URL. Recorded, not read.
18. **[Git Transport](docs/git-transport.md).** Clone, fetch and push to the
    repositories and branches a profile lists, with a forge token the agent
    never holds. The repository and the refs are decided and recorded; a
    pack's contents are not read.
19. **[Matrix Reverse Proxy](docs/network-isolation.md).** Agents on an
    isolated network reach Matrix through the gateway rather than the internet.
20. **[Cockpit Plugin](docs/cockpit-plugin.md).** A live dashboard of layers,
    blocklist and pipeline events in the Cockpit console.

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
| [MCP Gateway](docs/gateway.md) | Endpoint, routing, tool names, argument normalization |
| [Per-Agent Profiles](docs/profiles.md) | Profile schema, modes, minifying, roles, multi-agent setup |
| [Operator Profile](docs/operator.md) | The operator agent's seat and the gateway's service identity |
| [Configuration](docs/configuration.md) | Every environment variable |
| [Authentication](docs/authentication.md) | Static bearer, OAuth proxy with DCR or a provisioned client, delegated issuers |
| [Defense Pipeline](docs/defense-pipeline.md) | L1/L2/L3, modes, coverage and known gaps |
| [Benchmark](docs/benchmark.md) | Detection rates per layer and per L3 provider |
| [Corpora](docs/corpora.md) | Every attack and benign set the defense is measured on: source, licence, what it measures |
| [Prompt Packs](docs/l3-prompt-tuning.md) | The judge's prompts tuned per model: shipped packs, the gate, tuning your own |
| [Content Tools](docs/quarantine-tools.md) | fetch, read, dir, content, search |
| [Blocklist](docs/blocklist.md) | Cumulative detection memory |
| [Tool Filtering](docs/tool-filtering.md) | Allowlists, denylists, glob patterns |
| [Description Compression](docs/compression.md) | Description compression and schema compaction |
| [Token Routing](docs/token-routing.md) | Response reduction (implemented); delegation (proposed) |
| [Parameter Guards](docs/parameter-guards.md) | Per-tool argument validation |
| [Response Guards](docs/response-guards.md) | Per-tool result validation |
| [Audit Log](docs/audit-log.md) | Call recording, stats, monitoring |
| [LLM Key Proxying](docs/llm-proxying.md) | Provider keys kept inside the gateway |
| [Matrix Bridge](docs/matrix-bridge.md) | E2EE termination and two-way judging |
| [Matrix Reverse Proxy](docs/network-isolation.md) | Matrix for agents on an isolated network |
| [Client Egress](docs/client-egress.md) | A CONNECT tunnel to listed hosts for the agent's own client |
| [Git Transport](docs/git-transport.md) | Clone, fetch and push to listed repositories and branches |
| [Deployment Hardening](docs/deployment-hardening.md) | Container flags, secrets, egress, the startup check |
| [Cockpit Plugin](docs/cockpit-plugin.md) | Live defense pipeline dashboard |
| [Internal: Gateway Design](docs/internal/gateway-design.md) | Original design document, for contributors |

## Development

```bash
uv sync --all-extras
uv run ruff check src tests
uv run mypy src
uv run pytest -v
```

The demo above is recorded against the published image by
[`demo.yml`](.github/workflows/demo.yml) (`docs/demo/render.sh`); see
[`docs/demo/`](docs/demo/) for the fixtures it runs.

The container image is built by the GHA pipeline
([`container.yml`](.github/workflows/container.yml)), never locally. The model-export
stage needs a gated HuggingFace credential that only CI holds, and building outside
the pipeline causes drift. Push the branch and let the pipeline verify the image.

## License

AGPL-3.0-or-later
