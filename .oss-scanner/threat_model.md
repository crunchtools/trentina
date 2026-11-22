# Trentina gateway threat model

Scope: attacks on the gateway process itself. `SECURITY.md` and the
constitution's Threat Model cover attacks on the agents it protects. Paths are
under `src/trentina/`. The constitution (`.specify/memory/constitution.md`,
Threat Model and Layer Contract) governs; this file only maps surfaces to
controls. Verified by reading the code at the commit this file was added.

## Trust assumptions

| Actor | Treated as |
|---|---|
| Agent (caller of `/gateway/{profile}/mcp`) | Untrusted; may be hijacked by planted content |
| Backend, fetched page, tool metadata | Untrusted content |
| L3 judge | Assumed compromised (constitution): no tools, output never delivered |
| Operator agent (holds the operator profile) | A model; may be talked into widening trust, so widening needs a person |
| Operator / host / config file | Trusted. A compromised host or operator is not defended |

## Untrusted input surfaces

| Surface | What enters / who controls it | Entry point | Control |
|---|---|---|---|
| MCP tool-call arguments | JSON-RPC body from an agent | `gateway/app.py:_handle_post` (size cap, JSON parse) then `transports/mcp.py:route_jsonrpc` | `gateway/app.py:_authorize` (bearer / OAuth / federation JWT); `gateway/args.py:normalize_arguments` (schema); `gateway/guards.py:check_request_guards` (literal guards); `gateway/request_edge.py` (unknown tool, decoy, leaked credential); `gateway/gatekeeper.py:judge_call` (semantic guard, subtract-only, fails closed) |
| Backend tool responses | Any content a backend (or the page behind it) returns | `transports/mcp.py` forwarding, then `gateway/response_edge.py:prepare_response_scan` | `response_edge.py:disposed_response` runs L1/L2/L3 through `orchestrator.defend`; `gateway/guards.py:check_response_guards`; oversize text is judged in parts (`gateway/parts.py`), never truncated |
| Tool metadata (names, descriptions, schemas, annotations) | Backend `tools/list` | `gateway/aggregate.py` builds list; `gateway/tool_list_edge.py:scan_tool_list` | Each definition judged, flagged ones annotated or withheld, cached entries judged too; `gateway/tool_pins.py:check_tools` pins definitions and holds changed ones (`decide` / `decide_all` need approval) |
| Web fetch responses | Body, headers, redirects from any http(s) URL an agent names | `tools/fetch.py:fetch_page` -> `client.py:fetch_url` | `reach/egress.py:open_guarded` (global addresses, pinned IP, redirect re-check, `identity` encoding only); `client.py` `MAX_RESPONSE_SIZE` 5 MB; content then judged by the three layers |
| Human-approval HTTP routes | Browser requests to `/approve*` and WebAuthn ceremony JSON | `gateway/approval_routes.py:register_approval_routes` (routes `/approve`, setup, begin/finish, sign-out) | State-changing routes POST-only with body caps and `RateLimiter`; `_same_origin` Origin check, CSRF token, SameSite=Strict session (`gateway/approval_session.py`); `gateway/approver.py` stores only verifiers, `enrolling()` refuses once an approver exists; `gateway/webauthn.py` verifies assertions |
| Staged proposals | Operator agent proposes; person approves | `tools/config.py:propose_trust`, `gateway/pending.py:stage` | `gateway/pending.py:approve`: applied once, only if the digest the page showed matches (`hmac.compare_digest`); 900 s TTL |
| OAuth / DCR / token auth | Bearer tokens, OAuth `/authorize`, `/token`, DCR registrations (DCR handler is the FastMCP OAuth provider, not code here) | `gateway/app.py:_authorize`, `gateway/auth.py:verify_bearer`, `verify_oauth` | Constant-time bearer compare (`hmac.compare_digest`); token bound to one profile (`gateway/oauth_binding.py`, unbound token refused); email allowlist (`auth.py:_check_identity`, `gateway/google_verifier.py`); DCR records provisional and culled (`gateway/oauth_store.py`) |
| Federation ingress | A peer gateway's primary JWT on a derived ingress profile | `gateway/app.py:_authorize` -> `gateway/auth.py:verify_primary_jwt_header` | `gateway/federation_keys.py:verify_primary_jwt` (Ed25519, audience, expiry); a bad token is 401, never a fall-through; `federation.peers` is a human-approved decision (`config_guard`) |
| Federation egress: signed verdicts | A peer's signed verdict on a response | `transports/mcp.py` (calls `gateway/vsa.py:verify_assertion`) | `vsa.py:check_trust`: bound to exact content digest, perimeter stamp and judge; any mismatch falls through to the full local pipeline |
| Git transport | Smart-HTTP clone/fetch/push from an agent | `gateway/git_transport.py:GitRoute`, parsing in `gateway/git_wire.py` | Caller authenticated; repo matched to profile `fetch`/`push` lists (deny first); endpoints, services, protocol, v2 commands and push ref list checked before any pack byte is forwarded; forge token injected by gateway; egress guard, no redirects; hidden ref namespaces filtered. A pack and ref names are not judged (known gap 29) |
| Matrix bridge routes | Appservice transactions and homeserver traffic | `gateway/matrix_bridge/routes.py:register_bridge_routes`, `gateway/matrix_proxy.py` | `routes.py:_matches` token check on the `Authorization` header only; event content judged both directions before write; undecrypted events withheld (`matrix_proxy.py:_withhold_undecrypted`); bridge process holds the upstream login, gateway holds none (constitution, Matrix Bridge Credential Split) |
| Bridge process API | `/send /upload /redact /typing` from the gateway | `bridge/api.py:build_app` | Strict pydantic models (`extra="forbid"`); the bridge judges nothing and fails reports to the gateway, which withholds |
| Other ingress | `/alert` webhook, `/proxy/llm`, forward route, client egress | `gateway/alert_ingress.py`, `gateway/llm_proxy.py`, `gateway/forward.py`, `gateway/client_egress.py` | Per-profile bearer (constant-time); payload through the layers; outbound requests scanned for credentials (`gateway/outbound.py:detect_credentials`) |
| config_tool writes | `get/set/unset/normalize` by an operator agent | `tools/config.py:manage_config` | `config_guard.check_write_request` (hash-gated, no blind overwrite); `config_guard.equivalent` rejects non-semantic rewrites; `config_guard.trust_stays_human` and the `_needs_approval` path stage widening changes for a person; narrowing applies at once; `mask_inline_secrets` on reads; candidate config must load (`_candidate_loads`) |
| File reads | A path from an agent to `read_tool` / `dir_tool` | `tools/read.py` -> `tools/confine.py:open_confined` | Default deny without `TRENTINA_READ_ROOTS`; lexical then resolved check (`check_lexical`, `check`); `HARD_DENIED` dirs; per-component `O_NOFOLLOW` walk (`walk_open`); inode check (`_verify_opened`); one merged refusal reason behind a gateway; text only, read-only |
| Egress, fetch and proxies | Any URL the agent names | `reach/egress.py:check_url` | Every resolved address must be global (`is_global_address`, embedded-v4 checked); connect pinned to checked address (`PinnedBackend`); http/https, ports 80/443, max 5 redirects; `TRENTINA_FETCH_ALLOW_PRIVATE` is the one operator opt-out |
| Egress, CONNECT tunnel | An agent's HTTPS client | `gateway/client_egress.py` (admit/relay), dial in `transports/perimeter.py:_open`, `check_url` | CONNECT only, host must be on the profile list, global address, first TLS record must carry SNI equal to the CONNECT host; bytes inside are not read (known gap 26) |
| Hostile parsers: PDF, images (OCR) | Binary inside a response or fetch | `unpack/scan.py` -> `unpack/pdf.py:read_pdf`, `unpack/ocr.py:read_images` | Run as child processes (`unpack/child.py:ask`): constant argv, env with no credential, `cwd=/`, wall-clock kill, bounded slots and output, `RLIMIT_CPU` and `RLIMIT_AS` set in `pdf_worker.py` / `ocr_worker.py`. No network or read-only root is a container property checked by `tests/image/`, not set by `child.py` |
| Hostile parsers: archives, office | zip/tar/gz/bz2/xz, OOXML | `unpack/archive.py:open_archive`, `unpack/office.py:parse` | In-process, not child processes. Stdlib only, in memory, bounded by a `Budget`; a bomb or broken archive fails closed to `binary_unread`; OOXML parsed with expat, any DTD refused |
| L3 judge response | Judge output from the provider, shaped by hostile content | `quarantine/agent.py:_call_*`, `quarantine_generate` | `quarantine/schema.py:conform` (closed schema, off-schema raises); `_check_canary` (leak refuses); only closed-enum labels and scores leave the gateway |

## Invariants

| Invariant | Enforced at |
|---|---|
| L3 requests carry no tools or function declarations, surviving `python -O` | `quarantine/providers/base.py:enforce_no_tools` (called by every driver before posting); `quarantine/agent.py:_enforce_quarantine` |
| No judge-written text reaches an agent; only closed labels and scores | `quarantine/schema.py:conform`; constitution, Layer Contract |
| Fetches, proxied URLs and egress dial only addresses that were checked as global, and connect to the checked address | `reach/egress.py:check_url`, `PinnedBackend`, `open_pinned` |
| File tools read only inside configured roots, never denied paths or symlink swaps, text only | `tools/confine.py:open_confined` |
| An approval applies only to the facts a person saw, once | `gateway/pending.py:approve` (digest compare, removed before apply) |
| With no approver configured, approval-gated decisions stay refused; the agent cannot read the capability | `gateway/approver.py` (`enrolling`, verifier-only storage); POST-only routes in `approval_routes.py` |
| Only widening needs approval, and each approval is one decision | `gateway/config_guard.py`, `tools/config.py` (`_needs_approval`) |
| Federation trust is bound to exact bytes, stamp and judge, and fails closed to local judging | `gateway/vsa.py:check_trust` |
| A token issued for one profile does not verify at another | `gateway/oauth_binding.py` |
| No caller-chosen string is logged; a backstop redacts credential-shaped text | `logsafe.py` (`guard`, `exc_kind`, `redact_source`); `tests/test_log_hygiene.py` |
| Hostile PDF and image parsers never run in the gateway process | `unpack/child.py:ask` |
| A tool definition change is held, not silently served | `gateway/tool_pins.py:check_tools` |
| A verdict cache is the layer's own read reused: keyed on content, tenant and versions, completed verdicts only | `gateway/verdict_cache.py`, `quarantine/l3_cache.py`; `tests/test_verdict_cache_rule.py` |
| The gateway never executes or shells out on untrusted content | Constitution, "What the Gateway Never Does"; the only subprocess is `unpack/child.py` with a constant argv |

## Out of scope

The constitution's Threat Model "Not defended" list governs: a user
jailbreaking their own model directly; an agent with a second path to the
content that does not cross the gateway; a compromised host or operator; and
every entry in the known gaps (`docs/defense-pipeline.md`, "Known gaps",
including 26 CONNECT bytes, 29 git packs and ref names, 30 the guard judge is
a model, 33 the federation stamp). Also out of scope: vulnerabilities in the
FastMCP OAuth provider that implements DCR, the container runtime and the
upstream model providers. Report in-scope findings per `SECURITY.md`.
