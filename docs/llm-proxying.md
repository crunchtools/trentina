# LLM Key Proxying

*Part of Trentina's **Authentication** promise; see [Why Trentina](../README.md#why-trentina).*

Proxy LLM API calls (Gemini, OpenAI, Anthropic) through the gateway so API keys never leave the trusted boundary. Agents send model requests to Trentina, which forwards them with the real credentials. No API keys in agent configs, no key exposure through prompt injection or tool-call exfiltration.

## Why This Matters

Every agent that calls an LLM API needs an API key. That key is typically stored in an environment variable or config file accessible to the agent. If the agent is compromised — through prompt injection, a malicious MCP server, or any other vector — the attacker gets the API key.

API key theft is particularly dangerous because:

- **Keys are reusable** — unlike session tokens, API keys don't expire on use
- **Keys grant broad access** — a Gemini API key lets the attacker make arbitrary model calls, potentially running up costs or accessing fine-tuned models
- **Exfiltration is subtle** — an agent can embed a key in an outbound API call or tool response without triggering existing malicious-payload detection

## How It Works

Trentina exposes LLM API proxy endpoints at `/llm/{provider}/{path}` that mirror the upstream APIs. The agent authenticates with its **gateway bearer token** (the same token it uses for `/gateway/{profile}/mcp`), as `Authorization: Bearer`; on the Anthropic shape it may instead send it as `x-api-key`, which is how Anthropic SDKs send a key to a proxy. Trentina resolves which profile the token belongs to, strips the agent's token header, injects the real API key for that profile, forwards to the upstream provider, and returns the response. Streaming (SSE) and non-streaming responses are forwarded transparently.

### Per-Profile Keys and Rate-Limit Isolation

Each profile injects **its own** provider key, declared in the profile's `llm_keys` section. This gives every consumer its own rate-limit bucket and its own token accounting on the provider's dashboard — heavy agentic traffic from one consumer can no longer exhaust another's quota (see [#53](https://github.com/crunchtools/trentina/issues/53)).

Authentication is **mandatory**:

| Condition | Result |
|-----------|--------|
| Unknown or disabled `{provider}` | `404` |
| Missing / malformed / unrecognized bearer token | `401` |
| Authenticated profile has no `llm_keys` entry for `{provider}` | `502` |
| Authenticated profile has a key for `{provider}` | Inject the profile's key, forward |

The caller's token (`Authorization` or `x-api-key`) is never forwarded upstream. Trentina's own Q-Agent does not go through `/llm/`; it calls providers directly, but with the same `llm_keys`. Judging a profile's tool response bills that profile's key. Judging a shared tool description, or compressing one, is the gateway's own work, and bills the operator's key ([operator.md](operator.md#service-identity)). The global `GEMINI_API_KEY` applies only when no operator is declared.

### What the Proxy Admits

A provider is not only a model. Several run tools on their own side that
fetch a URL the caller chose: Anthropic's `web_fetch`, `web_search`, code
execution and the `mcp_servers` connector; OpenAI's search models and the
Responses API's `web_search`, `file_search` and `mcp` tools; OpenRouter's
`web` plugin and `:online` model suffix; Gemini's Google Search grounding,
`url_context` and code execution. Each is a channel from an isolated agent to
any host, on the profile's key, that never crosses Trentina's egress guard.

So the proxy admits a request rather than forwarding it (#297,
`gateway/llm_policy.py`). Everything is an allowlist, per API shape:

| Checked | Admitted |
|---|---|
| Endpoint | Completions (`messages`, `chat/completions`, `completions`, `responses`, `generateContent`, `streamGenerateContent`), token counting, embeddings, and `GET` model listings. Files, batches, assistants, cached content and uploads are refused. |
| Query | `beta`/paging (Anthropic), paging (OpenAI, OpenRouter), `alt`/paging (Gemini). Gemini's `key` is refused. |
| Headers | `accept`, `anthropic-version`, and `anthropic-beta` flags that only shape the response (`claude-code-`, `interleaved-thinking-`, `context-1m-`, `effort-`, `fast-mode-`, `compact-`, ...); `mcp-client-`, `code-execution-`, `web-`, `files-api-`, `skills-` and `oauth-` are dropped. Everything else is dropped, including `OpenAI-Organization`/`-Project`, which would point the profile's key at another org. |
| Body keys | The documented completion parameters. An unknown key is refused (`unknown_param`), so a new provider feature is closed until it is reviewed. |
| Tools | Only tools the caller runs: Anthropic tools with no `type` or `custom`, OpenAI `function` (and `custom` on Responses), Gemini `functionDeclarations`. Anything else is `server_tool`; `mcp_servers` is `mcp_servers`; `plugins` is `plugins`. |
| Content | Inline data only. An image, document or file the provider would fetch by URL is `url_source`; a file id is `file_reference`; Gemini `fileData` must name its own Files API. |
| Stored state | `prompt`, `conversation`, `background`, `previous_response_id` (Responses), `cachedContent` (Gemini) and `store: true` (Chat Completions, which keeps the completion and its `metadata` on the provider) are `stored_state`: they carry or keep state the request does not show. |
| Model | A model that searches by itself is `online_model`: `:online`, `*search*`, `sonar`, `perplexity/`, `compound`. That list is a floor; set `allowed_models` for the real control. Every model a request names is checked, including OpenRouter's `models` and Anthropic's `fallbacks`. |
| Nested | Anthropic `output_config` takes `effort`, `format` and `task_budget` only; `fallbacks` is `"default"` or a list of `{"model": ...}`. |

The body is parsed with duplicate keys refused, and the provider receives it
**re-serialized**: it parses exactly the object that was judged. The body is
capped at 32 MiB and a compressed body is refused. A refusal is HTTP 403 (400
for a malformed body, 413 over the cap) with
`{"error": {"type": "trentina_refused", "reason": ..., "detail": ...},
"blocked": true, "block_reason": ..., "scanner": "trentina"}`; `detail` names
the caller's own offending key and goes nowhere else, and the top-level
`blocked`/`block_reason`/`scanner` fields let an egress benchmark read the
verdict from an otherwise opaque response.

Every call from an authenticated profile, admitted or refused, writes a
`gateway_calls` row ([audit log](audit-log.md#llm-proxy-calls)).

**The request content is judged on the way out (#511), not only its shape.**
After admission, the body, query and forwarded headers cross `defend()` as one
document (`source_type=llm_request`), and a deterministic credential detector
(`trentina.credential_shapes`) reads the same document for key material the
prompt-injection layers do not look for — an AWS key, a provider token, a PEM
block, a secret in a query string. The mode is the profile's per-provider
`llm_keys.<provider>.enforcement`: `block` refuses a credential shape, a flag
or a blocking gap before anything is sent (nothing "executed"); `flag` (the
default while the request false-positive rate is measured, moving to `block` at
a future major) forwards and returns the verdict on the `X-Trentina-Warning`
header. `redact` is meaningless on an outbound call and rejected.

Three consequences worth stating plainly:

- **The outbound prompt now reaches L3, with credentials cut.** `defend()` sends
  the request document to the configured judge (Gemini by default), so a profile
  proxying, say, Anthropic has each prompt read by the L3 provider as well. The
  copy the judge reads is credential-redacted (`credential_shapes.redact`, plus
  long percent-escape runs masked), so a detected secret never leaves in the
  judge input — injection content, which is what L3 is for, is untouched. The
  original body is still what forwards to the provider. This is a new data flow;
  if even the redacted prompt should not leave, the profile's `defense` must name
  no L3 provider (every verdict then reports `l3_unavailable`, which `block`
  refuses on and `flag` forwards with a warning).
- **`block` has a token ceiling.** A request larger than
  `Config.admission_tokens` (`min(QUARANTINE_CONTEXT_TOKENS, CLASSIFIER_MAX_TOKENS)`,
  at most 32768) is `oversize` → `not_fully_judged` and refused under `block`.
  Fail-closed is deliberate, but a long agentic conversation will hit it; raise
  the cap or run that provider in `flag` if that is not wanted.
- **The warning header carries flags and findings, not gaps.** Its value is a
  credential marker, an L-layer risk level, or `unjudged`; the specific gap
  names (`oversize`, `l3_unavailable`, …) are in a `block` refusal body only.

The completion streams back unchanged and is judged after the last frame
(`source_type=llm_completion`), which records a flag but cannot withhold what
already streamed (see `_streaming_response`).

### What This Buys You

- **No key in agent environment** — the agent's container/process has no `GEMINI_API_KEY`, `OPENAI_API_KEY`, or `ANTHROPIC_API_KEY`
- **Key rotation without agent restart** — update the key in the gateway's env file, reload the service
- **Adding a provider is a YAML entry, not code** — no code changes to support a new LLM backend

## Configuration

LLM providers are configured in the top-level `llm_providers` section of `profiles.yaml`:

```yaml
llm_providers:
  gemini:
    enabled: true
    upstream: https://generativelanguage.googleapis.com
    auth_header: x-goog-api-key
    api_key_env: GEMINI_API_KEY

  openai:
    enabled: true
    upstream: https://api.openai.com
    auth_header: Authorization
    auth_prefix: "Bearer "
    api_key_env: OPENAI_API_KEY

  anthropic:
    enabled: true
    upstream: https://api.anthropic.com
    auth_header: x-api-key
    api_key_env: ANTHROPIC_API_KEY
```

Each provider entry specifies:

| Field | Description |
|-------|-------------|
| `enabled` | Whether this provider is active |
| `upstream` | Base URL to forward requests to |
| `auth_header` | HTTP header name for the API key |
| `auth_prefix` | Optional prefix before the key value (e.g., `"Bearer "`) |
| `api_key_env` | Environment variable holding the real API key (used by Trentina's own Q-Agent path; the LLM proxy uses per-profile keys) |
| `api` | Request shape: `anthropic`, `openai`, `openrouter` or `gemini`. Inferred for `api.anthropic.com`, `api.openai.com`, `openrouter.ai` and `generativelanguage.googleapis.com`; required for any other upstream (an OpenAI-compatible host is `openai`), or startup fails |
| `allowed_models` | Optional list of globs (`claude-sonnet-*`); a request naming any other model is refused `model_not_allowed` |

Each **profile** then declares the key it wants the proxy to inject, under `llm_keys`:

```yaml
profiles:
  agent1:
    auth:
      bearer_token_env: TRENTINA_PROFILE_AGENT1_TOKEN
    llm_keys:
      gemini:
        api_key_env: AGENT1_GEMINI_API_KEY
  agent3:
    auth:
      bearer_token_env: TRENTINA_PROFILE_AGENT3_TOKEN
    llm_keys:
      gemini:
        api_key_env: AGENT3_GEMINI_API_KEY
```

The provider name under `llm_keys` must match a configured `llm_providers` entry — a dangling reference fails the server closed at startup.

### Architecture

```
┌──────────┐                    ┌────────────────┐    Real API key    ┌──────────┐
│  Agent   │ ────────────────► │   Trentina     │ ─────────────────► │  Gemini  │
│          │  /llm/gemini/...  │   Gateway      │                    │  OpenAI  │
│ No API   │ ◄──────────────── │                │ ◄───────────────── │  etc.    │
│ keys     │    LLM response   │  Key injection │    LLM response   └──────────┘
└──────────┘                   └────────────────┘
```

### Request Flow

1. Agent sends `POST /llm/gemini/v1beta/models/gemini-2.5-flash:generateContent` with `Authorization: Bearer <profile gateway token>`
2. Trentina looks up the `gemini` provider config and resolves the caller profile from the bearer token (`401` if it matches none)
3. Looks up the profile's `llm_keys.gemini` key (`502` if the profile has none)
4. Admits the request ([what the proxy admits](#what-the-proxy-admits)) or refuses it, audited either way
5. Keeps only allowlisted headers (never the caller's `Authorization`), injects `x-goog-api-key: <profile's real key>`
6. Forwards the re-serialized body to `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent`
7. Streams the response back to the agent

### Relationship to Network Isolation

LLM key proxying works independently of the [Matrix reverse proxy](network-isolation.md), but they're complementary. With both enabled, the agent has no network access *and* no API keys — it can only interact with the outside world through Trentina's controlled gateway, and the provider cannot be used to fetch on its behalf.

## Related

- [Matrix Reverse Proxy](network-isolation.md) — eliminating agent network access entirely
- [Per-Agent Profiles](profiles.md) — profile-level configuration
- [Audit Log](audit-log.md) — recording model API calls alongside tool calls
