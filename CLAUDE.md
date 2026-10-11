# trentina

MCP gateway between AI agents and everything they touch. Five promises: prompt-injection
defense (L1 ∥ L2 → L3 at every ingress), token savings, deterministic policy,
authentication (OAuth/DCR), and architectural flexibility. README.md is the
canonical statement of them; keep docs and comments in line with it.

## Quick Start

```bash
uv sync --all-extras
uv run trentina
```

## Environment Variables

- `TRENTINA_MODEL_PROVIDER` + that provider's key (`OPENROUTER_API_KEY`,
  `ANTHROPIC_API_KEY`, ...) — L3 when no gateway profile is bound. Behind the
  gateway each profile's `llm_keys` is used instead. `config.has_llm` and
  `agent.llm_available()` answer "is there an LLM"; `has_api_key` is Gemini's
  key only. Since 0.41.0 it no longer gates L3 or summarize; it only picks
  Gemini grounding as the standalone search fallback.
- `GEMINI_API_KEY` — optional since 0.41.0: Gemini as an L3 provider, and
  search grounding ONLY standalone (no profile bound) with no
  `OPENROUTER_API_KEY`; a bound profile searches on its own OpenRouter key or
  is refused. The lotor gateway
  holds none, so it never calls Google directly.
- `OPENROUTER_API_KEY` — standalone key for `TRENTINA_MODEL_PROVIDER=openrouter`;
  a gateway profile uses `llm_keys.openrouter`. Model ids are OpenRouter's
  (`google/gemini-3.5-flash-lite`).
- `QUARANTINE_MODEL` — Gemini model for Q-Agent (default: gemini-3.5-flash-lite, the one
  supported judge: its pack passed the briefed pack gate, #397)
- `QUARANTINE_SEARCH_MODEL` — L0 web search model, an OpenRouter id (default
  `google/gemini-2.5-flash`). L0 is OpenRouter's `web` plugin and nothing else
  (`_enforce_openrouter_search_quarantine`); the Gemini grounding route strips
  the `google/` prefix.
- `TRENTINA_REQUIRE_L2` / `TRENTINA_REQUIRE_L3` — default true: block and redact
  refuse when that layer is ABSENT. `false` turns absence into a warning; a
  partial read is never excused. `QUARANTINE_FALLBACK` was removed in 0.31.0
  and setting it fails startup.
- `QUARANTINE_CONTEXT_TOKENS` — what the L3 model reads in one call (default
  1000000). With `CLASSIFIER_MAX_TOKENS` it sets `Config.admission_tokens`.
  `QUARANTINE_MAX_CONTENT` was removed in 0.43.0 (#225); setting it fails startup.
- `QUARANTINE_DB` — SQLite blocklist path (default: ~/.local/share/trentina/trentina.db)
- `TRENTINA_BLOCKLIST_TTL_DAYS` — days a block refusal stays on the blocklist
  (default 30, floor 1). Expired rows stop counting at once and are swept
  hourly by `is_blocked` (#263), `SWEEP_BATCH` rows a pass (#295).
- `TRENTINA_AUDIT_RETENTION_DAYS` — days a `gateway_calls` row is kept
  (default 90; 0 keeps every row). Swept with the blocklist, from
  `is_blocked` and `record_gateway_call`, in batches (#295).
- `TRENTINA_FETCH_CONCURRENCY` — fetches in flight per profile (default 8).
  A fetch also has `client.FETCH_DEADLINE` (60 s) of wall clock, every hop
  and the body; `egress.open_guarded` requires a `deadline` (#295).
- `TRENTINA_PERIMETER_DB` — perimeter verdict store, a SEPARATE database from the
  blocklist (default: `perimeter.db` beside `QUARANTINE_DB`). See `perimeter_db.py`
  for why it is its own file. Deleting it costs one slow restart and nothing else.
- `QUARANTINE_TRUST_CONFIG` — Trust allowlist JSON path
- `TRENTINA_READ_ROOTS` — `os.pathsep`-separated absolute directories that
  `read_tool` and `dir_tool` may reach (#261); a relative entry fails startup.
  Unset behind a live gateway refuses EVERY path, and production leaves it
  unset on purpose: the gateway container has no agent workspace. Unset
  standalone keeps full reach. Either way `tools/confine.py` refuses `/config`,
  `/data`, `/proc`, `/sys`, `/run`, `/dev` and the directories of the two
  databases, the trust config and the live `profiles.yaml`. Refusals are a
  closed reason code, never the path. The open walks the resolved path one
  `O_NOFOLLOW` component at a time (#287); a FIFO or device is refused
  unopened, and a hard link to Trentina's own files is denied. The path is checked as written
  (normalized) BEFORE it is resolved, then again resolved; behind a gateway
  `not_found`/`denied_path`/`outside_read_roots` are one reason,
  `not_found_or_denied`, so a refusal is no existence oracle (#263). A
  confinement refusal is a `BlockedSourceError` with no alternatives
  (`confine.refused`), audited `blocked_defense` like egress's (#278).
- `TRENTINA_FETCH_ALLOW_PRIVATE` — default false. Lifts the egress guard's
  address rule so fetch can reach non-global addresses; scheme, port and
  redirect rules still hold. Warns at startup. See `egress.py` (#260).
- `TRENTINA_REQUIRE_HARDENED` — default false. On a network transport,
  `posture.py` reads `/proc/self` at startup and WARNs each containment gap
  (no-new-privileges, capabilities, seccomp, writable rootfs or import path,
  a secret from the environment rather than `_FILE`); true refuses to start
  on any. See `docs/deployment-hardening.md` (#268). The image sets
  `PYTHONSAFEPATH=1` so the working directory is never on `sys.path`.
  `GEMINI_API_KEY`, `OPENAI_API_KEY`, `ANTHROPIC_API_KEY` and
  `OPENROUTER_API_KEY` take `_FILE` forms too.
- `TRENTINA_RATE_LIMIT` — "off" disables limiting on the unauthenticated OAuth
  write paths (default on). An incident escape hatch, not a setting.
- `TRENTINA_FORWARDED_ALLOW_IPS` — peer addresses whose `X-Forwarded-For` is
  trusted, forwarded to uvicorn. **Unset behind a proxy, every caller shares
  one rate-limit bucket** — the limiter keys on `scope["client"]`, which
  uvicorn only rewrites for a trusted peer. Startup logs which is in effect.
- `TRENTINA_MAX_REGISTRATION_BYTES` — `POST /register` body cap (default 8192)
- `TRENTINA_MAX_REQUEST_BYTES` — request body cap on every MCP route
  (`/gateway/<profile>/mcp`, FastMCP's own mount) and the alert ingress
  (default 1 MiB, floor 1 KiB). Over it: 413, the rest unread, chunked or
  not (`httpbody.RequestBodyCap`, #267). A backend's RESPONSE has its own
  cap, derived rather than set: `paged_tokens * 32` bytes (every part of the
  largest response paging can deliver, #340; the admission cap with paging
  off), floor 1 MiB
  (`gateway/backend.py` `BYTES_PER_TOKEN`); over it, admission's oversize
  refusal with no alternatives, audited `blocked_defense`.
- `TRENTINA_OAUTH_JWT_SIGNING_KEY` / `TRENTINA_OAUTH_JWT_SIGNING_KEY_FILE` and
  `TRENTINA_OAUTH_GOOGLE_CLIENT_SECRET[_FILE]` — read once at startup; `_FILE`
  wins. After startup `gateway/envscrub.py` pops these, the `Config` LLM keys
  and `llm_providers` keys from `os.environ` unless a profile references the
  name (`reload_profiles` re-reads those). `/proc/self/environ` still holds
  every value: only `_FILE` keeps a secret out (#268).
- `TRENTINA_REGISTRATION_TTL_DAYS` — lifetime of a PROMOTED registration
  (default 90). A new one is provisional for an hour; a token exchange
  promotes it and every later exchange re-stamps it. See `gateway/oauth_store.py`.
- `TRENTINA_OAUTH_CULL_INTERVAL` — seconds between sweeps of the OAuth store
  (default 3600, floor 60). Nothing else removes an expired record: the store
  unlinks one only when something reads its key, and an abandoned flow never
  is read again.
- `CLASSIFIER_MODEL` — the L2 model, by name under `/models` (#350). Default
  `prompt-injection-guard-small` (Horizon-Labs, Apache-2.0), the one model the
  image ships (#362 dropped `prompt-guard-2-86m`, which fails the obfuscation
  gate). A model directory carries `trentina-model.json` (id, pinned
  revision, threshold, which outputs are malicious, the window it is scanned
  in), written by
  `scripts/export_l2_model.py`; without one, labels come from `config.json`
  and any label not a known benign or malicious name refuses to load. The
  model, revision, threshold, polarity, gate state and window are in
  `perimeter_db.perimeter_stamp()`, so switching sweeps cached verdicts. The
  manifest's `obfuscation_gate` record is written by
  `benchmarks/l2_obfuscation.py --record` (the Containerfile's `l2-gate`
  stage); `posture.check_l2_gate` warns on a model without a passing one and
  refuses under `TRENTINA_REQUIRE_HARDENED`. The same stage then runs the
  benign gate (#411): `benchmarks/l2_benign.py --record` over
  `corpora/benign_ops.py`, read through `transform_response` as a tool
  response is, at most 2% of held-out flagged. Its `benign_gate` record
  holds the threshold, so another `CLASSIFIER_THRESHOLD` reads as
  `unrecorded`. `benign_ops.KNOWN_GAPS` is scored and never gated.
- `TRENTINA_L3_PROMPT_PACK` — an L3 prompt pack file (#354), or `generic`.
  `quarantine/packs.py` loads and checks packs: closed key set, the framing
  sentences in every system prompt, an exact (provider, model). The pack for
  the judge answering a call is chosen in `agent._from_pack`; its stamp is in
  the verdict key. `benchmarks/prompt_pack.py` is the tuning harness and the
  gate a shipped pack must pass; `docs/l3-prompt-tuning.md` is the guide.
- `CLASSIFIER_MODEL_PATH` — any model directory; wins over `CLASSIFIER_MODEL`.
  How to try a model the image does not ship.
- `CLASSIFIER_THRESHOLD` — overrides the model's own threshold (0.7 for
  Horizon, 0.5 for Prompt Guard 2; 0.5 with no manifest). A profile's
  `defense.l2_threshold` is unset by default and can only make L2 stricter.
- `CLASSIFIER_MAX_TOKENS` — L2's CPU budget in tokens; 0 removes it, leaving
  L3's context as the cap (default: 32768)
- `CLASSIFIER_THREADS` — ONNX intra-op threads; 0 uses the ONNX default of one per core (default: 4).
  Set it to match the container's `--cpus`; threads beyond that quota contend and slow scans down.
- `TRENTINA_L2_CONCURRENCY` — L2 scans at once (default 2); each uses `CLASSIFIER_THREADS`.
  A freed slot goes to waiting profiles in turn (`classifier.FairGate`, #291).
- `TRENTINA_L3_CONCURRENCY_START` / `TRENTINA_L3_CONCURRENCY_MAX` — the adaptive
  L3 limiter's starting point and ceiling per (provider, model, key
  ordinal) (4 / 64). See `quarantine/limiter.py`: it grows until the
  provider throttles, then AIMD. The key is in it because a provider
  throttles per key (#291).
- `TRENTINA_L3_THROTTLE_BUDGET` — seconds a user-facing L3 call waits out 429s
  on one provider before falling back (default 20; the boot warm-up uses 300).

### Bridge process (`python -m trentina.bridge.main`)

Its own environment, never profiles.yaml; full table in `docs/matrix-bridge.md`.
Required: `BRIDGE_PROFILE`, `BRIDGE_USER_ID`, `BRIDGE_GATEWAY_URL`,
`BRIDGE_INGRESS_TOKEN`, `BRIDGE_TOKEN`, `BRIDGE_PICKLE_KEY`. Optional:
`BRIDGE_HOMESERVER`, `BRIDGE_STORE_DIR` (`/data`), `BRIDGE_LISTEN_HOST`
(`127.0.0.1`), `BRIDGE_LISTEN_PORT` (8471), `BRIDGE_DEVICE_NAME`,
`BRIDGE_LOG_LEVEL`, `BRIDGE_ALLOWED_INVITERS` (comma-separated Matrix IDs
whose invites are accepted; empty or unset refuses every invite and leaves
every joined room, #264), and one way in: `BRIDGE_DEVICE_ID` + `BRIDGE_ACCESS_TOKEN`
(adopt) or `BRIDGE_PASSWORD` (new device). One-shot commands:
`BRIDGE_OLD_ACCESS_TOKEN` (`logout-device`), `BRIDGE_RECOVERY_KEY`
(`sign-device`). Secrets and `BRIDGE_ALLOWED_INVITERS` take `_FILE`. The
gateway half of #264 (drop another bridged agent's events, relay into no room
holding one or whose members were never reported) reads every profile's
`matrix_bridge.public_user_id`, plus `matrix.other_agent_user_ids` in
`profiles.yaml` for agents it does not bridge (Ashigaru); bound at startup.

## onnxruntime telemetry

`ORT_DISABLE_TELEMETRY=1` is set in the Containerfile and defaulted in
`quarantine/classifier.py` before the lazy `import onnxruntime`. Left on,
onnxruntime's init reads `/etc/machine-id` and `/proc/cpuinfo`, reads
`/etc/os-release` four times, writes `/tmp/mat-debug-1.log`, and creates a
session file at `/tmp/.ses`. Disabling leaves only the `/sys/class/drm` and
`/sys/class/accel` probes it needs to choose an execution provider.

The same code path causes an import-time segfault in a shell-less image (see
the Containerfile's `/etc/machine-id` note). Both mitigations are in place;
either alone prevents the crash.

## Boot warm-up and L3 pacing (#216)

`gateway/warmup.py` runs from the FastMCP lifespan and builds every profile's
aggregate through `router.ensure_profile_build`, the same single-flight task a
client's `tools/list` joins. Descriptions within a backend are judged
concurrently (`scan_tool_list`); what paces them is the per-judge
`AdaptiveLimiter` wrapped around every `provider.generate` call via
`limited_generate`. Call `generate` through `limited_generate`, never
directly: a bare call is invisible to the limiter and competes with it blind.

## Logging rule (#262)

The gateway's journal is readable by agents through other backends'
`journal_query`/`container_logs`, so a logged string a caller chose is a
cross-agent message board. Never log one: not a URL, path, query, argument
name, header, unresolved profile or tool name, backend or provider error
text, Matrix id, nor an exception's message (`logger.exception` and
`exc_info` print it). Log the profile, a resolved tool, `logsafe.exc_kind`/
`exc_where`, and `logsafe.redact_source(s)` (`sha256:<12> len=<n>`) for
anything else; the audit DB holds the rest. `logsafe.install` holds uvicorn's
access log, httpx and the SDKs to the same rule at every level.
`tests/test_log_hygiene.py` enforces it: canaries at DEBUG through every tool,
the HTTP edge, the bridge's refusal path, the proxies' failure paths, the
alert ingress, a refused reload and the OAuth store's CIMD path (#292), and
an AST check over the whole package that only a call marked
`# logsafe: ours` may print an exception.

The backstop (#341) does not depend on call sites. `logsafe.guard()` runs
when the package is imported and installs a `LogRecord` factory every record
from every logger passes through: a value `logsafe.hold(value, name)` knows
prints as `[REDACTED:<NAME>]`, and credential-shaped text nobody registered
(a `?key=`/`access_token=` query value, a `Bearer` value, URL userinfo,
`sk-…`/`AIza…`/JWT shapes) prints as `[REDACTED]`. A record from
`fastmcp.server.auth` or `mcp.server.auth` keeps only the library's literal
format string; every value, any run-time message and any traceback text is
fingerprinted (#343), since an OAuth client's code or `resource` is not
credential-shaped. `read_secret_env` holds
every secret it returns, so a new secret is read THERE and nowhere else (one
under 4 characters cannot be held and is warned about by name; a setting that
only shares the `_FILE` form, like `BRIDGE_PROFILE`, is read with
`read_env_or_file` instead, #344); `guard()`
also holds any environment variable named `*_KEY`, `*_TOKEN`, `*_SECRET` or
`*_PASSWORD` of 8 characters or more. `extra=` fields are merged after the
factory returns, so `guard()` wraps `Logger.makeRecord` for those. A
traceback is rendered in the factory only when an exception's own text
carries something to cut: rendering frames reads source files, and doing it
on every `exc_info` stalls the caller. `logsafe.configure` is the only `basicConfig` in
the package (gateway and bridge both call it), and an AST test in
`tests/test_log_scrub.py` fails a second one or a second record factory. A
new pattern goes into that file's attack, benign and linearity tables.

## Endpoints

- A second listener, `--egress-port` (8021): HTTP `CONNECT` only, for a
  profile's `client_egress` (#442). Not a route on the app below.
- `GET /health` — unauthenticated liveness probe returning `{status, classifier, profiles}`.
  A timeout here means the asyncio event loop is blocked, not merely that a
  backend is slow.

## Layer 2 scanning limits

`classify()` slides the model's window across the payload, so cost grows
linearly with input length. The window is the model's (#438): its manifest's
`window_tokens` and `guard_tokens`, read into `ModelInfo`, else 512 and 64,
never past the model's `max_position_embeddings`. The shipped model states
512 (stride 446): `benchmarks/l2_window.py` measured no wider window
reliably faster and 4096 and 8192 far slower. One cap bounds the scan (#225):

- `Config.admission_tokens` = `min(CLASSIFIER_MAX_TOKENS, QUARANTINE_CONTEXT_TOKENS)`,
  in L2's tokens. `defend()` counts first (`defense.admission`), before any
  inference. Admitted content is read WHOLE by every layer; nothing is sliced.
- Over the cap, block and redact refuse at admission (`DefenseVerdict.oversize`,
  `Gaps.oversize`, layers `not_admitted`) with no L2 or L3 call; L1 still runs. flag scans
  the head and L3 reads the same token-bounded head (`classifier.head`), so
  `l2_truncated`/`l3_truncated` exist only on flag.

A proxied text response over `Config.whole_tokens` (16K) is not judged in one
call (#340): `gateway/paging.py` cuts it once into parts of about
`TRENTINA_PART_TOKENS` (12000; 0 is off), the router delivers part 1
(`_hold_paged`, `_deliver_part`) and answers the `read_part` tool itself
(`_read_part`), never forwarding it. Each part crosses `scan_tool_response`
with the previous part's last 64 tokens as `lead_in`. The remainder is held
in memory only, by a handle bound to the profile. Wording an agent reads is
in `paging.py`; say "part", never "page" (wiki and PDF pages own that word).
A profile without `read_part_tool` on its internal backend is not paged, and
the internal tools are not paged yet.

Async callers must use `classify_async`. Calling the
synchronous `classify()` from a coroutine blocks the event loop for the whole
scan and takes the gateway down with it. The same holds for L1 (#295):
`run_l1`, `run_l1_json` and a document processor's selection run under
`asyncio.to_thread`, and `quarantine_stats` reads SQLite in a worker on
`database.snapshot_reader(path)`'s own connection. A new L1 regex goes into
`tests/test_l1_patterns.py`'s linearity tests with the unit that repeats it.

Anything that can reach a PDF or OCR worker (`unpack`, `read_blobs`, the
stage-1 PDF and JSON reducers) runs under `unpack.child.run_unpacking`, never
`asyncio.to_thread` (#383): a thread waits up to a minute on a child process,
and the default pool is the one L1 and the tokenizer use.

## Tools

### Five tools, three modes, one policy (0.32.0; renamed 0.35.0)

Rules P1–P10 are in `docs/defense-pipeline.md` (Pipeline Flow); the decision
lives in `modes.py`, the tool-side path in `tools/judged.py`.

Tools: `fetch_tool`, `read_tool`, `dir_tool`, `content_tool`, `search_tool`.
Every call runs L1 ∥ L2 on the arrived bytes, then L3 briefed with both. The
`trentina_mode` ARGUMENT decides delivery, never detection:

- `block` — refuses a flag or any blocking gap. Allowlisted → redact instead.
- `flag` — bytes IDENTICAL to what arrived, `_trentina_warning` attached. A
  security-researcher grant; leave it out of agent policies.
- `redact` — L3 detect, extract, verify; any objection refuses. Spelled
  `{"redact": "<question>"}` since 0.39.0: the question travels inside the
  mode (`modes.parse_mode_arg`); a call still sending `trentina_prompt` is
  refused (0.43.0). No
  tool declares `trentina_mode` unless the profile sets `declare_modes`.

"Arrived" means arrived at the perimeter, AFTER pre-processing. Output is
minified by default (0.38.0): the `detect` pre-processor picks the minifier by
format (`preprocess/detect.py`), and takes undeclared text for HTML only when
no tag name in it is foreign to HTML, because `html` deletes `<a@b.c>` and
`Vec<String>`. `trentina_preprocess` is a switch (#183): `false` exact, `true`
minified, omitted the tool's default (`read` and any `preprocess_tools` entry
with `enabled: false` default to exact). Every tool accepts it; a proxied
tool's schema declares it only where `selectable`, the internal fetch, read
and content always. `required` is the floor it cannot remove,
and the one failure rule is: floor fails closed, minifying fails open. The
internal tools run it in `tools/preprocess.py` (the router skips
`transform_response` for them) with `INTERNAL_CHAIN`. Policy:
`preprocess/policy.py`; gateway side rides `modes_policy.py` like the mode.
Proxied conversion hands L1 the ORIGINAL's hiding counts (#229).

Tools are served under short names (`gateway/names.py`), tagged with a backend
only on collision, recorded in `tool_names` and never reassigned. Only
tools/list and tools/call see them; everything behind the edge uses the real
(backend, tool). A repeated `structuredContent` is dropped before the scan
(`router._drop_duplicate_structured`).

Until 0.32.0 the mode was the tool's NAME prefix (#193), so the agent chose
its own posture and nothing enforced it. Now the policy does:

- Gateway: `defense.modes` per profile (default `[enforcement]`).
  `gateway/modes_policy.py` STRIPS any `trentina_*` param a backend declares
  before the perimeter scan, INSERTS the gateway's after it (only when more
  than one mode is allowed), resolves an omitted mode to `enforcement` BEFORE
  checking it, and strips both args before forwarding. Every backend's tools
  get it — `redact` on a proxied response is real now (`scan_tool_response`).
  Internal tools receive the RESOLVED mode; admin tools (no declared
  `trentina_mode`) get nothing inserted.
- Standalone: `TRENTINA_MODE` / `TRENTINA_MODES`, both defaulting to block.
- Refusals carry `{reason, mode, flagged_by|gaps, alternatives}` —
  JSON-RPC `error.data` for web tools, `_trentina_refusal` for proxied ones.
  Flagged → `redact` only, NEVER `flag`; gap-only → `flag`.
- A response withheld AFTER the backend answered (defense block, response
  guard, byte cap, failed required pre-processor) is not a refusal for a tool
  that may write (#425): `router._executed` rewords it as "executed, response
  withheld", `isError` the backend's own (true at the byte cap, where it was
  never read), `_trentina_refusal.executed` true.
  `_may_have_acted` is the test: remote and not annotated `readOnlyHint`. A
  new path that withholds a remote response goes through it.

No text written by L3 reaches an agent: finding types are a closed enum
(`prompts.FINDING_TYPES`). Every L3 answer is held to its response schema in
`_call_gemini` (`quarantine/schema.py`, #294); outside it is
`MalformedResponseError` and then `l3_unavailable`, never clean.

NOTE: `defense.enforcement` is the DEFAULT mode and accepts only `flag` and
`block` — a call that omits the mode carries no extraction prompt.

`warn`/`clean`, the pre-0.35.0 names (#200), were removed in 0.36.0; a
profile or call still using one is refused like any unknown mode. The names are OpenRouter's guardrail actions; our `redact` is an L3
rewrite, not their span substitution. Precedence: block > redact > flag.

`read_part_tool` (#340) is the tenth tool: it delivers the parts of a
response another tool produced, and behind the gateway the router answers
it.

### Stats
- quarantine_stats — operator `config` carries `provider` and `llm_available`
  (0.41.0); its `has_api_key` was removed in 0.43.0.
  `admission_tokens` replaced `max_content` there and in the D-Bus status
  (0.43.0, #225): the one cap, in L2's tokens.
- quarantine_stats — role-scoped like the gateway admin tools below: an agent
  profile gets its own audit rows, its own detections and the defense settings
  it runs under; an operator gets the gateway.
  `surface` (`gateway/surface.py`) is the tool list offered vs. served;
  `gateway_audit.delivery` is response bytes arrived vs. delivered. Tokens are
  bytes/4 — a comparison, not a bill.

### Operator profile / service identity (#138)

Trentina is AI-native: an Operator agent installs and configures it, and
`role: operator` is that agent's seat (`docs/operator.md`). At most one per
file, and it must hold `llm_keys` for its own provider (`loader._check_operator`).
The gateway's own model calls — compression, perimeter L3 over tool
descriptions, anything added later — run AS the operator via
`gateway/service.py` (`service_context()` binds it; the Q-Agent resolves key and
model from the bound profile). No operator: env-global, logged at startup.
Verdict keys carry the judging (provider, model) except for the env default,
which keeps the pre-#137 spelling so persisted verdicts stay reachable.

### Gateway admin

All four are scoped by the calling profile's `role` (`gateway/scope.py`, and
the Roles table in `docs/profiles.md`). `role: agent` — the default — sees and
acts on its own slice; `role: operator` holds the gateway. Refusals name
nothing, so a backend in another profile is refused exactly like one that does
not exist. Standalone (no gateway registered) is single-tenant and therefore
operator; a live gateway with no bound caller is refused.

- cache_flush — flush tool-list caches. Agent: its own aggregate ONLY, with a
  constant body; the per-URL cache is shared, so an agent flushing it and
  reporting what was warm was a channel between profiles (#263).
  Operator: every cache. A name is resolved by EXACT name, never by substring
  over cached URLs — that is how `gw` used to reach `gw-work` and
  `gw-personal` both.
- reconnect_backend — reset one backend's circuit breaker + re-probe after it
  restarts, without restarting the gateway. Agent: a backend in its own
  profile, with the tool count that profile would actually see, refreshing
  the tool list in place and rebuilding only its own aggregate (#291). The
  breaker is keyed by URL, so healing it heals it for every profile sharing
  that URL — that is the point of the tool, not a leak.
- reload_profiles — re-read `profiles.yaml` and apply it. Nothing else applies
  a profile edit: the router filters from the `Profile` objects loaded at
  startup, and `cache_flush`/`reconnect_backend` rebuild that aggregate from
  the same in-memory objects, so they look like they worked and change nothing.
  Validates the whole file before swapping (a bad edit keeps the running
  config) and leaves the perimeter verdict cache alone so nothing is re-judged.
  Agent: applies its own section only, and cannot apply a change to its own
  `role` or `defense` block (held, reported as `operator_only`, #298).
  Operator: the whole file, plus what it could not apply — `llm_providers`,
  `matrix`, ingress routes and proxy-mode `oauth` clients/redirects bind at
  startup.

## OAuth token binding (#298)

The proxy has one JWT audience for every proxied profile, so the audience
cannot separate seats. `gateway/oauth_binding.py` binds the profile the
`/authorize` resource names to the flow (keyed on client id + PKCE
challenge), then to the token's upstream lineage at `/token`; a refresh keeps
it. `verify_oauth` asks the verifier's `bound_profile` and challenges any
answer but the profile being called; a verifier without `bound_profile` is
refused. Delegated verifiers answer their own profile (audience pin).

## Development

```bash
uv run ruff check src tests corpora    # Lint
uv run mypy src                # Type check
uv run pytest -v               # Test
TRENTINA_REQUIRE_L2_MODEL=1 CLASSIFIER_MODEL_PATH=<export> uv run pytest tests/test_l2_integration.py  # L2 against a real model; fails, not skips, if it does not load
podman run --rm -v .:/repo:Z quay.io/crunchtools/gourmand:latest check /repo  # Slop detection
# Container image: built by GHA (.github/workflows/container.yml), never locally —
# the model-export stage needs a gated HF credential held only in CI. Push and let
# the pipeline build it.
uv run python benchmarks/provider_benchmark.py  # L3 detection benchmark across providers — see docs/benchmark.md
CLASSIFIER_MODEL_PATH=<export> uv run python benchmarks/l2_lone_flag.py --packs <pack.json> --judged <detonation.json> --corpora <benchmark.json>  # what L2 flags of a judge's stored misses; calls no judge (#404)
podman run --rm -v .:/src:Z docker.io/semgrep/semgrep semgrep --config /src/.semgrep --error /src/src  # in-repo rules
uv run python -m trentina.gateway.profile_lint <profiles.yaml>  # posture lint
uv run python tests/boundary_review_eval.py  # boundary-review skill eval; needs ANTHROPIC_API_KEY
```

Boundary review (#90, #269): `.claude/skills/trentina-boundary-review/` is the
judgment half, `.semgrep/` and `.github/codeql/trentina-queries/` the
mechanical half. A semgrep hit is fixed or suppressed inline with
`# nosemgrep: <rule> -- <reason>`; a crossing gets a `# TRUST:` comment in the
skill's format.

## Architecture

Layer contract (`docs/defense-pipeline.md#layer-contract`, enforced by
`tests/test_layer_contract.py`): nothing is delivered that the layers did
not read, in its original or decoded form, or, for binary, by its type;
every layer reads the delivery once, unpacked; layers share findings, never
inputs; a model's weakness is fixed in the model or at selection
(`benchmarks/l2_obfuscation.py`, enforced since #362), never with an extra pass. #359 removed the
last workaround that broke it.

Coverage (`docs/defense-pipeline.md#coverage`) is what is and is not
defended, by kind of content, plus every known gap. Each gap that a test can
hold open has one in `tests/test_coverage_gaps.py`, which asserts the gap
STILL exists: closing a gap fails its test, and the fix moves the Coverage
row and the Known gaps entry in the same change. #365 is the plan.
garak's encodings (`corpora/garak_encodings.py`, #423) are measured by
`benchmarks/l2_encodings.py`, attacks and benign text alike, and gate
nothing: each is a Coverage row or one of gaps 21 to 23.

Pre-processing is two stages, always in this order (#365). Stage 1,
`preprocess/`, decides what the agent receives. Stage 2, `unpack/`, builds
what L1, L2 and L3 read from that delivery, inside `defense.defend()`, and
never changes it. Nothing restores anything afterwards, because nothing was
replaced.

- `unpack/` — stage 2 (#367). `scan.unpack(text)` decodes canonical
  base64 and hex that decode to text (never a run of decimal digits up to
  twenty long, which is a number, #431), in place and unmarked (a bracketed
  marker raised L2's false positives fourfold), to two levels; labels binary
  of 64 characters or more by its signature (`signatures.py`),
  `(image/png, 1.1 KB, not read)`; and leaves identifiers, short binary and
  anything non-canonical as it arrived. Binary an agent's tools could open
  (image, PDF, archive) is `Unpacked.unread`, which becomes the
  `binary_unread` gap: block and redact refuse it, flag warns. Kind names
  are a closed set: a data URI's declared type is mapped, never echoed.
  `UnpackStats` rides in L1's `PipelineStats` as `unpacked` and is
  informational, not suspicious. Binary an agent cannot open is labelled
  only when its own characters read as noise (`_reads_as_noise`): a label
  means no layer reads the token, and `MIIB` plus an instruction written
  without spaces decodes to a DER signature.
  `archive.py` opens zip, tar, gzip, bzip2 and xz in memory, within limits
  on bytes, files, ratio and nesting (#368); every read is bounded by the
  budget, never by a header, and a zip with bytes its directory does not
  list is refused whole. `office.py` reads docx, xlsx and pptx: every text
  node of every part for the layers, hidden text counted into
  `hidden_elements`; XML with a DOCTYPE is not parsed. A file inside an
  archive goes back through `scan.py`'s own rules. Stage 1 reduces a base64
  office file in a JSON string to `{"format", "as_markdown"}`
  (`preprocess/structured.py`).
  `pdf.py` reads a PDF by running `pdf_worker.py` as a child process (#369)
  through `child.ask`: pypdf under RLIMIT_CPU and RLIMIT_AS, no credential
  in its environment, a wall-clock kill, a bounded wait for a slot, and its
  JSON checked field by field. Never import pypdf into the gateway process. `preprocess/pdf.py` is the stage-1 reducer, for
  a fetched PDF (handed over as base64 by `client.py`) and for a base64 PDF
  in a JSON string.
  `ocr.py` reads images the same way (#370): `ocr_worker.py` runs RapidOCR
  in a child, once per payload. `scan.py` does not OCR an image where it
  meets it: `_Darkroom` sets each aside and leaves a mark carrying a random
  token, and `_Pass.result` replaces the marks after one request has read
  them all. `read_blobs` shares one darkroom across the blocks of a
  response. Tests run with `scan.read_images` stubbed to "unread"
  (`conftest._no_ocr_process`); mark a test `@pytest.mark.ocr` to run the
  real worker.

- `l1/` — Layer 1: the deterministic pipeline, plus module shadow detection.
  It does not make content safe — it counts what it found, by type, and L3's
  briefing names each count (`PipelineStats.findings`). `content` is what the
  agent receives, byte-identical to what arrived, and the ONLY thing L1, L2
  and L3 detect on, each once. Its stages normalize a private copy to match
  through obfuscation; that copy never leaves `_run_stages` (#360). Redact's
  extraction reads `DefenseVerdict.read`, the unpacked text the layers
  judged. L1 also takes a directory's stdlib-shadow counts (`ShadowStats`),
  merged in by the `dir` producer. A new stage is count-only, gets a
  `FINDING_NAMES` entry, a near-miss and a linearity case in
  `tests/test_l1_stages.py`, and a run of `benchmarks/l1_false_positives.py`
  before it joins `suspicious_detections` (#363).

  There is no "scan view" and no "delivery view". Those names were retired in
  0.29.0 along with `sanitize`/`scanview`: a reader cannot tell from "scan
  view" which layer consumes it, and "sanitized" claimed the layer made
  content safe, which it does not and cannot. Layers are L1/L2/L3 in code and
  in prose, with no invented aliases.

  Called `sanitize/` until 0.24.0. FORMAT-AGNOSTIC since 0.28.0: one entry
  point, `run_l1`, which scans whatever it is handed. The `looks_like_html`
  sniffer and the second `build_scan_view_from_html` pipeline are gone (#172)
  — the sniffer keyed on a leading `<!DOCTYPE` or `<html>`, so an HTML
  FRAGMENT took the text path and identical bytes were defended two different
  ways. `defend()` no longer takes `is_html` either.
  - `hidden.py` — content-hiding fingerprints (`display:none`, off-screen
    positioning, same-colour text), counted on EVERY payload rather than
    behind a format guess. Tier 2 of the markup answer; tier 1 is
    `preprocess/html.py`, which removes the class outright. Counts only — the
    hidden text's words are what L2 should still read. Owns the predicate
    table that `preprocess/html.py` imports, so the converter that strips an
    element and the stage that counts one decide by one rule.
  - `shadows.py` — Python stdlib module shadow detection and obfuscation scanning.
    `scan_shadows` reads through the descriptor `dir_tool` listed (#287) and
    never follows a link; `detect_module_shadows` takes a path and is NOT
    confined, so no tool may hand it a caller's path.
  - `unicode.py` — strips every invisible character from L1's copy but
    COUNTS one only in the context an attack needs (#204): zero-width inside
    a Latin word, a lone ESC, a run of variation selectors.
  - `directives.py` — the exact patterns, named after OpenRouter's guardrail
    (#201). Near-misses matter as much as hits: every pattern has an attack
    and a benign line in `corpora/l1_patterns.py` (`L1_PATTERN_CASES`),
    kept out of `CORPUS` because that is the semantic L3 benchmark.
  - `evasion.py` — undoes scrambles, one-edit typos and character spacing,
    then asks the exact patterns again. A typo alone is never a detection.
- `quarantine/` — holds BOTH judging layers, which is why the directory name
  matches neither: `classifier.py` is L2 (a pluggable local ONNX classifier) and
  `agent.py` is L3 (Gemini REST via httpx, NO SDK, NO tools). CLAUDE.md called
  this "Layer 2: Q-Agent" until 0.29.0, which was simply wrong.
- `egress.py` — the ONE egress guard (#260) for every gateway-side fetch
  (`client.fetch_url`, grounding redirects). Refuses on the RESOLVED address,
  pins the connection to it (`PinnedBackend` under httpx's pool; TLS still
  verifies the hostname), and follows redirects by hand, checking each hop.
  Refusal reasons are a closed set and never name the address. Never give an
  outbound `httpx.AsyncClient` an agent-chosen URL without it. DNS lookups
  are capped per profile (4) and gateway-wide (64), never queued (#291).
- `gateway/client_egress.py` — the CONNECT listener (#442) on `--egress-port`
  (8021), bound only when a profile has `client_egress`, started and stopped
  by `warmup.trentina_lifespan`. The peer address picks the profile (no
  credential, as #330); the name must be in `hosts`, port 443, and pass
  `egress.check_url`; the tunnel connects to a checked address
  (`open_upstream` is the test seam). After `200` the first TLS record must
  be a ClientHello whose SNI is the CONNECT host, or the tunnel closes before
  a byte is forwarded (a handshake check only: it does not stop a different
  `Host` inside the TLS). One `gateway_calls` row per tunnel (`egress` /
  `connect`, `DestinationKind.TUNNEL`). Nothing reads the bytes: known gap 26.
  The block is held on an agent reload (`_hold_perimeter_fields`) and refused
  on a honeypot.
- `tools/` — Tool implementations called by server.py wrappers
- `database.py` — SQLite blocklist for cumulative detection memory, keyed on
  (profile, source) since #263: `is_blocked(source, profile)` sees the
  caller's own rows, `gateway_wide=True` (operator, standalone) every row,
  and NULL-profile rows are operator-only. It answers a bool; a refusal
  (`judged.blocklisted`) is constant and carries no timestamp.
- `perimeter_db.py` — the perimeter's own store, deliberately a second database:
  verdicts `defend()` reached, so a restart does not re-judge ~210 tool
  descriptions through all three layers before the first `tools/list` answers
- `channels.py` — the two driver roles, the ingresses a driver may be bound to,
  and what each ingress hands a driver (`Kind`). Guards decide admission;
  pre-processors transform outside the perimeter. Everything wired into a
  request path is one of the two.
- `jsonwalk.py` — the ONE JSON walk. There were two hand-maintained copies
  until #167; `tests/test_full_is_defend_json.py` proves they agreed, which is
  what made deleting one safe.
- `reserved.py` — the keys only the gateway may write (#265): `_trentina_*`
  at any depth, `RESERVED_ROOT_KEYS` at a document's root. Every path that
  carries someone else's JSON strips them before the scan and before adding
  its own marker. A new marker takes the prefix and is covered automatically.
- `preprocess/` — Payload transformation, OUTSIDE the perimeter. May subtract
  but never absolve: it drops, collapses, normalizes and restructures, and
  everything it emits still crosses `defend()` as untrusted. Reduction is the
  common case, not the contract. Two INPUT SHAPES, not two roles: most are
  `str -> str`; `select.py` and `matrix.py` take parsed JSON and return the
  strings worth reading (`view.py`'s `DocumentProcessor`). A driver may read
  less than its call site delivers, and then it accounts for every byte it
  declined.
  - `html.py` — markup to Markdown. The only CONVERTER here, and the reason
    it is a default: conversion ELIMINATES the hidden-content class rather
    than detecting it, because Markdown cannot express `display:none`. Lived
    in `l1/html.py` behind the sniffer until 0.28.0. Declines what it cannot
    parse instead of asking whether anything "is HTML", so it sits in the
    chain permanently and no-ops on everything else. It transforms without
    existing to shrink, so configure it under `chain` — `best_of` selects on
    size and would discard it.
  - `petit.py` — record grouping via the `petit-log-crunchtools` package
    (petit itself, https://github.com/crunchtools/petit). Picks no driver and
    no stopword file: petit 3.2.0 made a hash driver declare its own
    normalization, so the policy lives with the format that needs it. Needs
    >= 4.1.1, where framing made the unit a RECORD rather than a line — the
    fingerprint cap is now `max_record_chars` INSIDE the library, because
    capping lines here cut records mid-JSON and silently disabled grouping.
    Samples are selected by `sample_spans`, so what is delivered is the
    original bytes; a record's first line is often just `{`.
  - `structured.py` — JSON. Fingerprints ARRAY ELEMENTS in element-index
    space and emits valid JSON, which is why petit does not replace it:
    petit reports positions as source LINE ranges and exposes group
    membership only for samples, so neither a minified array nor a
    per-element account is expressible through its API. A string VALUE of
    twenty lines and 1 KB or more is handed to `PetitProcessor.reduce`
    (#419) and kept only when petit names a log format for it: its raw
    fallback trims blank lines and brackets out of documents. The summary
    there carries no `[petit]` tag (#411). Known gap 19 stays open.
  - `email.py` — mail. Collapses quoted reply chains and strips signatures;
    leaves repeated footers to petit, which is what `chain` is for. Rewrites
    the thread, where petit's `EmailHash` only fingerprints its skeleton.
- `bridge/` — the Matrix bridge PROCESS (#162, spec 015): upstream login,
  crypto store, sync. Untrusted; runs as its own container and can reach only
  matrix.org and the gateway. Sends every type encrypted itself, because nio
  sends `m.reaction` in the clear.
- `gateway/matrix_bridge/` — the gateway's half: judges every bridged event in
  both directions and is the only writer into the agent's Conduit (appservice).
- `gateway/` — Per-consumer MCP gateway proxy with tool allowlists, parameter guards, and defense pipeline
  - `args.py` — schema-driven argument normalization (#241): drops an
    optional that is `""` or `null`, never one equal to its `default`, which
    is only an annotation. An optional that provably fails its schema is
    dropped only on a `readOnlyHint` tool and otherwise reported, like a
    failing required one, for the router to refuse (#335: the call without it
    can do more than was asked). Never evaluates
    `pattern` (a backend's regex is a ReDoS here).
  - `llm_policy.py` — what `/llm/<provider>/` admits (#297), per API shape
    (`anthropic`, `openai`, `openrouter`, `gemini`; a provider's `api`,
    inferred for the four known hosts, required otherwise). Allowlists
    endpoint, query, headers and body keys; refuses provider-run tools,
    `mcp_servers`, URL-fetched content and self-searching models. The body
    goes upstream RE-SERIALIZED, never raw, so the provider parses what was
    judged. A provider is a second way out of `--network=none`; a new
    request key stays refused until someone reads what it does.
  - `ratelimit.py` — the token bucket and the ASGI guard on `/register`,
    `/authorize` and `/consent`. NOT on `/token`: that is reached with a code
    or refresh token this gateway issued, so it is not unauthenticated, and
    limiting it throttles a legitimate refresh for no gain. Reads the address
    from `scope["client"]` and never from a header — reading `X-Forwarded-For`
    here would hand an attacker a fresh bucket per request.
  - `oauth_store.py` — registration lifetimes and the sweep that enforces
    them. `PromoteOnExchange` is mixed into the provider because that class is
    defined inside a function, where every method counts against its
    complexity budget.
  - `consent_ui.py` — patches fastmcp's consent page on the way out (a
    double-submit explanation, a client-side submit guard). Fails soft: markup
    it does not recognize passes through unchanged.
  - **Parameter guards**: per-tool argument validation with allow/deny value patterns — see `docs/gateway-design.md`
  - `drivers.py` — the ONE registry. A configured name becomes a driver, for
    either role, with one channel lock and one parity test. Two registries
    here is what left the pre-processor table with no channel lock at all.
  - `schema_compact.py` — drops null branches, null defaults and `$schema`
    from served inputSchemas, AFTER the perimeter scan. Tighten-only, and a
    subset of the judged strings, so it changes no verdict. Per backend
    `compact_schemas`, default on.
  - `transform.py` — the pre-processor call site on the tool path (was
    `reduce.py`; the contract is transformation, not reduction).
  - `selection.py` — the call site on the Matrix path. Runs the document
    processor, degrades to reading everything if it raises, and turns coverage
    into the fields an operator reads.
