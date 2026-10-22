# Configuration

Trentina reads its profiles, backends and per-profile policy from a YAML file
([Per-Agent Profiles](profiles.md)). The environment variables below control
the process itself: the gateway switch, the defense layers' models and budgets,
storage, limits and secrets.

## Why it matters

Most of these have safe defaults, and several fail startup when set to
something unsafe or removed (`QUARANTINE_FALLBACK`, `QUARANTINE_MAX_CONTENT`).
The ones an operator has to think about are the LLM provider and its key (L3
does not run without one), `TRENTINA_FORWARDED_ALLOW_IPS` behind a reverse
proxy, and the `_FILE` forms of every secret.

## LLM provider keys

L3 needs one provider. Set `TRENTINA_MODEL_PROVIDER` and that provider's key:
`GEMINI_API_KEY`, `OPENROUTER_API_KEY`, `OPENAI_API_KEY` or `ANTHROPIC_API_KEY`
(Ollama needs none). Each key also takes a `_FILE` form, which keeps it out of
`/proc/<pid>/environ`. Behind the gateway, each profile's `llm_keys` is used
instead; see [Operator Profile](operator.md).

## The configuration file

Gateway mode reads one YAML file, `TRENTINA_PROFILES_PATH`. Its top-level
sections:

| Section | Description |
|---------|-------------|
| `profiles` | One entry per consumer. See [Per-Agent Profiles](profiles.md). |
| `llm_providers` | The providers the [LLM proxy](llm-proxying.md) may reach. |
| `matrix` | The [Matrix reverse proxy](network-isolation.md). |
| `git_remotes` | The forges the [git transport](git-transport.md) may reach; a profile's `git` block names them. |
| `gateway` | Session lifetime and count. |

## Command-line flags

| Flag | Default | Description |
|------|---------|-------------|
| `--transport` | `stdio` | `stdio`, `sse` or `streamable-http`. |
| `--host` | `127.0.0.1` | Address both listeners bind. |
| `--port` | `8019` | The MCP and HTTP routes. |
| `--egress-port` | `8021` | The [client egress](client-egress.md) `CONNECT` listener. Bound only when a profile has a `client_egress` block. |
| `--no-dbus` | off | Do not register the D-Bus interface. |

## Environment variables

Trentina reads its gateway, profile and backend configuration from a YAML file;
these variables control the process itself. Profile tokens
(`TRENTINA_PROFILE_<NAME>_TOKEN`) and provider API keys are covered in
[Per-Agent Profiles](profiles.md) and [LLM Key Proxying](llm-proxying.md).

| Variable | Default | Description |
|----------|---------|-------------|
| `TRENTINA_LOG_LEVEL` | `INFO` | Application log level, sent to stderr. Any standard Python level name. No level prints a secret: a configured key appears as `[REDACTED:<VARIABLE>]`, and credential-shaped text as `[REDACTED]`. |
| `TRENTINA_GATEWAY_ENABLED` | unset (disabled) | Turns on the MCP gateway (profiles, auth, allowlists, audit). See [MCP Gateway](gateway.md). |
| `TRENTINA_PROFILES_PATH` | `/etc/trentina/profiles.yaml` | Path to the gateway's profile YAML file. See [Per-Agent Profiles](profiles.md). |
| `TRENTINA_LEGACY_MCP` | unset (disabled) | Restores the pre-gateway unguarded `/mcp` endpoint. **Bypasses auth, allowlists and audit** — migration aid only. See [MCP Gateway](gateway.md). |
| `TRENTINA_MODEL_PROVIDER` | `gemini` | Global LLM provider for L3 and tool-description compression, overridable per-profile. See [Per-Agent Profiles](profiles.md). |
| `TRENTINA_PROVIDER_FALLBACK` | unset (none) | Comma-separated provider names to fall back to if `TRENTINA_MODEL_PROVIDER` is unavailable. |
| `OLLAMA_BASE_URL` | `http://localhost:11434` | Base URL for the Ollama provider. |
| `OLLAMA_MODEL` | `qwen2.5:0.5b` | Model used when the Ollama provider is selected. See [LLM Key Proxying](llm-proxying.md). |
| `QUARANTINE_MODEL` | `gemini-3.5-flash-lite` | Model used for quarantine agent (L3) extraction/detection calls. See [Supported judges](#supported-judges). |
| `QUARANTINE_REASONING_EFFORT` | unset | `minimal`, `low`, `medium` or `high`: how long a reasoning judge thinks, sent as OpenRouter's `reasoning.effort`. Unset leaves the model's default. Set `minimal` for Gemini 3.8 Flash, which otherwise takes 6 to 17 s a call. Changing it re-judges cached verdicts. |
| `TRENTINA_L3_PROMPT_PACK` | unset | Path to an L3 prompt pack: the judge's three system prompts and Layer 2 caveat for one exact (provider, model), for every profile that does not set `defense.l3_prompt_pack`. `generic` turns shipped packs off. See [L3 prompt tuning](l3-prompt-tuning.md). |
| `QUARANTINE_SEARCH_MODEL` | `google/gemini-3.5-flash-lite` | L0 web search model, an OpenRouter id. Search runs through OpenRouter's `web` plugin; standalone with no OpenRouter key it falls back to Gemini grounding. |
| `TRENTINA_REQUIRE_L2` | `true` | `false` lets `block`/`redact` deliver with a warning when the L2 model is absent, instead of refusing. Never excuses a partial scan. See [Defense Pipeline](defense-pipeline.md). |
| `TRENTINA_REQUIRE_L3` | `true` | The same for an absent L3 provider. Replaces `QUARANTINE_FALLBACK` (removed in 0.31.0; setting it now fails startup). |
| `TRENTINA_MODE` | `block` | Standalone only: the mode an omitted `trentina_mode` resolves to. `flag` or `block`. Under the gateway the profile's `defense.enforcement` decides. |
| `TRENTINA_MODES` | the default | Standalone only: comma-separated modes a call may choose (`block,redact`). A default outside the set fails startup. Under the gateway the profile's `defense.modes` decides. |
| `QUARANTINE_CONTEXT_TOKENS` | `1000000` | What the L3 model reads in one call. The admission cap is the smaller of this and `CLASSIFIER_MAX_TOKENS`; `block` and `redact` refuse a payload over it before any layer runs. Replaces `QUARANTINE_MAX_CONTENT` (removed in 0.43.0; setting it now fails startup). |
| `CLASSIFIER_MODEL` | `prompt-injection-guard-small` | The L2 model, by name under `/models`. The image ships one, `prompt-injection-guard-small` (Horizon-Labs, threshold 0.7); use `CLASSIFIER_MODEL_PATH` for any other. See `docs/defense-pipeline.md` Layer 2. |
| `CLASSIFIER_MODEL_PATH` | unset | Any exported model directory (`scripts/export_l2_model.py`); wins over `CLASSIFIER_MODEL`. Its `trentina-model.json` may state `window_tokens` (default 512, never past the model's `max_position_embeddings`) and `guard_tokens` (default 64, at most half of what a window holds once its two special tokens are taken out); a window the model cannot read refuses to load. |
| `CLASSIFIER_THRESHOLD` | the model's | Overrides the loaded model's own threshold, from its `trentina-model.json` (0.5 for a model without one). |
| `CLASSIFIER_MAX_TOKENS` | `32768` | L2's CPU budget in tokens, and with `QUARANTINE_CONTEXT_TOKENS` the admission cap. `0` removes L2's budget. |
| `TRENTINA_PART_TOKENS` | `12000` | The size, in L2 tokens, that the parts of a paged response aim for (#340). A text response, proxied or from `fetch`, `read` or `content`, up to four thirds of it (16,000) is delivered whole; a larger one is cut into near-equal parts and read with `read_part`. Never over the admission cap. `0` turns paging off. See [Responses delivered in parts](defense-pipeline.md#responses-delivered-in-parts). |
| `TRENTINA_MAX_PARTS` | `16` | The most parts one response is cut into; over it the response is refused as over the admission cap. The backend response byte cap follows it: `TRENTINA_PART_TOKENS` x this x 32 bytes, 6 MiB by default. |
| `TRENTINA_PART_TTL_SECONDS` | `600` | How long a paged response is held with no part of it read (floor 30). |
| `CLASSIFIER_THREADS` | `4` | ONNX Runtime intra-op thread count for the L2 classifier. |
| `TRENTINA_L2_CONCURRENCY` | `2` | L2 scans run at once. Each already uses `CLASSIFIER_THREADS` threads, so size the product to the container's `--cpus`. A freed slot goes to waiting profiles in turn. |
| `TRENTINA_L3_CONCURRENCY_START` | `4` | L3 calls in flight per (provider, model, API key) before the adaptive limiter has learned anything. It grows from here until the provider throttles. |
| `TRENTINA_L3_CONCURRENCY_MAX` | `64` | Ceiling for the adaptive L3 limiter, per (provider, model, API key). A safety cap, not a target. |
| `TRENTINA_L3_THROTTLE_BUDGET` | `20` | Seconds a user-facing L3 call may spend waiting out 429s on one provider before falling back. `0` falls back at once. The boot warm-up uses 300. |
| `QUARANTINE_DB` | `~/.local/share/trentina/trentina.db` (container: `/data/quarantine.db`) | Path to the main SQLite database (blocklist, audit log). See [Audit Log](audit-log.md) and [Blocklist](blocklist.md). |
| `TRENTINA_PERIMETER_DB` | `<QUARANTINE_DB's directory>/perimeter.db` | Path to the perimeter verdict-cache database, deliberately separate from `QUARANTINE_DB`. |
| `TRENTINA_READ_ROOTS` | unset | `os.pathsep`-separated absolute directories `read_tool` and `dir_tool` may reach. Unset behind a gateway refuses every path (production's setting); unset standalone reads anywhere. Kernel and Trentina state/config directories are refused regardless. See [Quarantine Tools](quarantine-tools.md#where-read-and-dir-may-look). |
| `QUARANTINE_TRUST_CONFIG` | `~/.config/mcp-env/trentina-trust.json` | Path to the trust-level configuration JSON. See [Quarantine Tools](quarantine-tools.md). |
| `TRENTINA_FETCH_ALLOW_PRIVATE` | `false` | Lets `fetch` reach loopback, private, link-local and other non-global addresses. Scheme, port (80/443) and redirect rules still apply. Logs a warning at startup. See [Quarantine Tools](quarantine-tools.md). |
| `TRENTINA_RATE_LIMIT` | on | Set to `off`/`0`/`false` to disable rate limiting on the unauthenticated OAuth write paths. An escape hatch for an operator locked out during an incident — not a normal setting. |
| `TRENTINA_MAX_REGISTRATION_BYTES` | `8192` | Largest `POST /register` body accepted, rejected before it is parsed. `0` or negative disables the cap. |
| `TRENTINA_MAX_REQUEST_BYTES` | `1048576` | Largest request body accepted on an MCP route (`/gateway/<profile>/mcp`) and the alert ingress. Over it the request gets 413 and the rest is never read, chunked or not. Floored at 1024. |
| `TRENTINA_BACKEND_TOKEN_KEY_FILE` | unset | A file holding the key that encrypts backend OAuth grants (`auth: {type: oauth}`, see [profiles](profiles.md#backend-oauth)). At least 32 characters; `openssl rand -base64 48`. Unset: those backends report "needs auth". Rotating it drops every grant. |
| `TRENTINA_OAUTH_JWT_SIGNING_KEY_FILE` | unset | A file holding `TRENTINA_OAUTH_JWT_SIGNING_KEY`; wins when both are set. The preferred form: an env var stays readable in `/proc/<pid>/environ` even after startup removes it from `os.environ`. `TRENTINA_OAUTH_GOOGLE_CLIENT_SECRET_FILE` works the same way. |
| `TRENTINA_OAUTH_BASE_URL` | `https://mcp.crunchtools.com` | Public origin OAuth clients reach; the issuer and redirect URLs are built from it, and so are the backend OAuth pages (`/oauth/backend/*`). **Set it** for any deployment but Crunchtools'. See [Authentication](authentication.md). |
| `TRENTINA_OAUTH_GOOGLE_CLIENT_ID` | unset | Google OAuth client Trentina proxies login to. Required when any profile uses the OAuth proxy; the secret is `TRENTINA_OAUTH_GOOGLE_CLIENT_SECRET[_FILE]`. |
| `TRENTINA_REQUIRE_HARDENED` | `false` | On a network transport, refuse to start on any containment gap the startup check finds, or on an L2 model with no passing obfuscation-gate or benign-gate record, instead of warning. See [Deployment Hardening](deployment-hardening.md). |
| `TRENTINA_FORWARDED_ALLOW_IPS` | unset (uvicorn's default of `127.0.0.1`) | Peer addresses whose `X-Forwarded-For` is trusted. **Set this to your reverse proxy's address**, or every caller behind it shares one rate-limit bucket. See [Authentication](authentication.md). |
| `TRENTINA_BLOCKLIST_TTL_DAYS` | `30` | Days a block refusal keeps its source on the calling profile's blocklist. Expired rows stop counting and are swept hourly. See [Blocklist](blocklist.md). |
| `TRENTINA_AUDIT_RETENTION_DAYS` | `90` | Days a `gateway_calls` audit row is kept; swept hourly. `0` keeps every row. See [Audit Log](audit-log.md). |
| `TRENTINA_FETCH_CONCURRENCY` | `8` | Fetches one profile may have in flight; the next waits for one of its own. Each fetch has 60 s of wall clock. See [Quarantine Tools](quarantine-tools.md). |
| `TRENTINA_REGISTRATION_TTL_DAYS` | `90` | How long a DCR registration lives once a token exchange has promoted it. Each later exchange re-stamps it. |
| `TRENTINA_OAUTH_CULL_INTERVAL` | `3600` | Seconds between sweeps that unlink expired registrations, transactions and CSRF records from the OAuth store. Floored at 60. |

## Related

- [Per-Agent Profiles](profiles.md): the YAML side of configuration
- [Deployment Hardening](deployment-hardening.md): `TRENTINA_REQUIRE_HARDENED` and secrets from files
- [Authentication](authentication.md): OAuth settings
- [Defense Pipeline](defense-pipeline.md): what the L2 and L3 settings change

## Supported judges

A judge is **supported** when the prompt pack it runs with passed the pack
gate as production runs it: held-out split, three votes, briefed with Layer
1's counts and a Layer 2 label (`benchmarks/prompt_pack.py --briefing
benign`), and the pack ships that run in its `measured` header. Each
shipped pack says where it stands in its `status` key.

| Judge (through OpenRouter) | Status | Benign flagged, of 362 | Planted instructions missed, of 99 |
|---|---|---|---|
| `google/gemini-3.5-flash-lite` | supported, and the default | 3 | 0 |
| `google/gemini-2.5-flash-lite` | deprecated: fails the gate | 54 | 5 |
| `google/gemini-3.8-flash` | unmeasured | | |
| `anthropic/claude-haiku-4.5` | unmeasured | | |

Any other model, on any provider, runs on the generic prompts and is
unmeasured. A judge that is not supported still works. Startup, and a
profile reload, log one line for each such judge a profile names:

```
judge: provider=openrouter model=google/gemini-2.5-flash-lite is deprecated on the L3 pack gate; supported: openrouter/google/gemini-3.5-flash-lite.
```

A deprecated pack stays in the image through the 1.x releases. A model
becomes supported by passing the gate: tune a pack as
[l3-prompt-tuning.md](l3-prompt-tuning.md) describes, run it held-out with
`--briefing benign`, and ship the pack `--emit` writes with `"status":
"supported"`. The Gemini API serves Gemini 2.5 only to accounts that
already used it, which is the other reason the default moved.
