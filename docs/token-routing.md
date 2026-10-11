# Token Routing

*Part of Trentina's **Token savings** promise; see [Why Trentina](../README.md#why-trentina).*

> **Status: mostly proposed.** Only [Response Reduction](#response-reduction-implemented) is
> implemented. File-read delegation (`delegation:`) is a design, not a feature, and the
> savings figures quoted below are other people's, not Trentina's.

Route expensive I/O work to cheap models at the gateway layer. When a coding agent reads a large file or generates boilerplate code, Trentina intercepts the call, delegates it to a smaller model (Gemini Flash, GPT-4o-mini), and returns the result to the frontier model. The frontier model never sees the raw content — it gets a summary or confirmation instead.

## Why This Matters

Most of what a coding agent does isn't reasoning — it's I/O. Reading five files to answer a question about one method. Generating a test file that follows the same pattern as twenty test files next to it. All of it fed to a frontier model (Opus, Fable) that's wildly overqualified for the task. [Spotify reported 90% token savings](https://engineering.atspotify.com/2026/9/portal-by-spotify-cut-my-claude-code-token-usage-by-90) by routing bulk reads to Gemini Flash.

Spotify's implementation is client-side — a Claude Code plugin that intercepts Read calls via hooks and delegates through their Portal backend. The routing rules are advisory: the agent can ignore them. Every project needs its own configuration.

Trentina's implementation is server-side. The gateway already intercepts every tool call for every agent profile. Delegation is enforced — the agent can't bypass it. Configuration lives in `profiles.yaml` alongside the existing tool allowlists, parameter guards, and defense settings. Every agent that connects through the gateway gets routing automatically.

### Cost Context

By 2028, AI coding costs are [projected to exceed average developer salaries](https://www.gartner.com/en/newsroom/press-releases/2026-06-24-gartner-predicts-ai-coding-costs-will-surpass-average-developer-salary-by-2028-as-token-consumption-surges). A quarter of engineering leaders already burn $200–$500/developer/month on tokens. Token routing turns this from a systems engineering problem into a configuration problem — one YAML section per profile.

## How It Works

### Interception Point

Token routing sits in the gateway call pipeline between parameter guards and the backend call:

```
Parse tool → Backend exists? → Tool in allowlist? → Parameter guards → Token routing → Backend call
```

When a tool call matches a routing rule, the gateway short-circuits the normal backend call. Instead:

1. The gateway reads the content itself (file read) or assembles the request (code generation)
2. Sends it to the configured worker model via the LLM proxy
3. Returns the worker's response to the calling agent as if it were the backend's response

The agent never knows delegation happened. From its perspective, it called Read and got a response.

### Two Delegation Modes

#### Mode 1: Bulk Read

For when an agent would read multiple large files just to answer one question.

**Trigger:** A file read tool call where the file exceeds the configured line threshold. Targeted reads (with `offset`/`limit` parameters) pass through — the agent already knows what section it needs.

**Flow:**
```
Agent calls Read(file_path="/src/Service.java")
  → Gateway checks: file is 2,400 lines, threshold is 350
  → Gateway reads the file directly from disk
  → Gateway sends file + agent's surrounding context to worker model
  → Worker returns structured summary (bullets, types, line references)
  → Gateway returns summary to agent (with metadata noting delegation)
```

**Worker prompt:** Tight extraction instructions — "structured bullets only, no prose, no preambles. Lead every bullet with the exact name, type, or line number."

#### Mode 2: Code Generation

For tests, config scaffolding, type stubs, or anything where the output is predictable from existing patterns.

**Trigger:** Explicit delegation via a gateway-provided tool, or pattern detection on Write calls that follow a reference file pattern.

**Flow:**
```
Agent calls delegate_codegen(spec="Write tests for UserService", reference="tests/OrderTest.java", target="tests/UserTest.java")
  → Gateway reads the reference file
  → Gateway sends spec + reference to worker model
  → Worker generates code matching the reference patterns
  → Gateway writes output to target path
  → Gateway returns confirmation to agent (file written, N lines)
```

The frontier model never sees the generated code. The reference file goes to the cheap model, not to the agent's context.

### What Passes Through

Not everything should be delegated. The routing rules explicitly exempt:

- **Targeted reads** — reads with `offset`/`limit` where the agent already knows what section it needs
- **Small files** — below the line threshold, delegation overhead exceeds savings
- **Piped/filtered reads** — `cat file | grep pattern` via Bash is already a targeted read
- **Editing context** — when the agent needs to make edits, it needs the actual content with reliable line numbers (worker summaries don't include these)

## Configuration

> **What ships today (2026-09-17): response reduction.** The `delegation:` schema described below
> covers file-read interception for coding agents and is **not implemented**. What is wired is the
> narrower, more general half: reducing oversized TOOL RESPONSES for any backend, configured under
> `preprocess:`. It targets the measured problem — agent transcripts running 88-99% tool output —
> rather than file reads specifically. Both can coexist; `delegation:` remains the plan for Mode 2.

### Response Reduction (implemented)

Two levels. The profile answers *how aggressive is this agent*; the per-tool override answers
*is this payload shape worth it*. A tool's entry wins field-by-field and anything it leaves unset
inherits from the profile.

```yaml
profiles:
  agent1:
    auth:
      bearer_token_env: TRENTINA_PROFILE_AGENT1_TOKEN
    preprocess:
      enabled: true
      strategy: auto          # none | chain | best_of | auto
      processors: [petit]     # FREE only; add 'summarize' to spend LLM calls
      target_bytes: 20000     # 'auto' escalates to METERED only above this
      min_bytes: 4096         # below this, leave the response alone
    backends:
      syslog:
        url: http://mcp-syslog:8000/mcp
        preprocess_tools:               # per-tool overrides, keyed by tool name
          syslog_tail_tool:
            strategy: chain             # log-shaped: always worth petit
          syslog_stats_tool:
            enabled: false              # pre-aggregated; nothing to collapse
```

The per-tool override lives on the **backend**, next to `parameter_guards`, because whether
reduction helps is a property of the tool's output shape rather than of who called it —
`syslog_tail_tool` is log-shaped for every profile, and a second copy per profile would drift.

| Field | Level | Default | Notes |
|-------|-------|---------|-------|
| `enabled` | both | `true` | Whether an omitted `trentina_preprocess` minifies (on since 0.38.0). The agent's `true`/`false` wins |
| `strategy` | both | `auto` | `auto` runs FREE always, escalates to METERED only while over `target_bytes` |
| `processors` | both | `[detect]` | `detect` picks the minifier by format. Order matters for `chain`. Adding `summarize` costs two model calls per response — see Defense Pipeline Interaction |
| `target_bytes` | both | `20000` | Shared across a response's text blocks, not per block |
| `min_bytes` | both | `4096` | Reduction has a fixed cost; small payloads cannot repay it |

**What is not reduced:** `structuredContent` that merely repeats the one text block is dropped
before reduction (0.38.0, [Results](gateway.md#results)); otherwise `structuredContent` and resource blocks are deliberately left untouched —
they are typed data a caller may parse and a backend may validate against its `outputSchema`.
A backend that returns its bulk only in `structuredContent` therefore sees no reduction; the honest
fix is to teach that backend to emit reducible text, not to have the gateway mangle typed payloads.

**Failure behaviour:** every layer fails open. A processor that raises is logged and skipped,
config resolution errors pass the response through, and a reduction that achieves nothing returns
the original bytes. A reducer must never be able to cost you the response.


### Profile Schema Extension

> **Not built.** Everything from here to the end of this section is a design, not
> configuration. No `DelegationConfig` has ever existed in `gateway/profile.py`, and
> `Profile` is `extra="forbid()"` — a profile carrying a `delegation:` block does not
> warn, it refuses to start the gateway. The pre-processing described above this section
> IS shipped; this is the part that is not. Tracked by `tests/test_docs_yaml_snippets.py`,
> which skips these two blocks by name.

Token routing would be configured per-profile in `profiles.yaml` under a new `delegation`
section:

<!-- trentina:proposed delegation-schema -->
```yaml
profiles:
  coding-worker:
    auth:
      bearer_token_env: TRENTINA_PROFILE_CODING_WORKER_TOKEN
    delegation:
      enabled: true
      worker_model: gemini-2.5-flash
      worker_provider: gemini
      line_threshold: 350
      modes:
        bulk_read:
          enabled: true
          prompt: |
            You are a precise code analyst. Read the provided files and
            answer the question concisely. Output structured bullets only.
            No greetings, no prose, no preambles. Lead every bullet with
            the exact name, type, or line number. Use nested bullets for
            details. Skip anything the caller did not ask for.
        code_write:
          enabled: true
          prompt: |
            You generate code files based on a spec and reference files.
            Match the existing patterns, conventions, naming, and style
            exactly. Output only the code — no explanations, no markdown
            fences unless asked.
    backends:
      # ... normal backend config
    defense:
      # ... normal defense config
```

### Schema Fields

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `delegation.enabled` | bool | `false` | Master switch for token routing |
| `delegation.worker_model` | string | — | Model name for the worker (e.g., `gemini-2.5-flash`, `gpt-4o-mini`) |
| `delegation.worker_provider` | string | — | Provider for the worker model (`gemini`, `openai`, `anthropic`) |
| `delegation.line_threshold` | int | `350` | File line count above which reads are delegated |
| `delegation.temperature` | float | `0.2` | Temperature for worker model calls |
| `delegation.max_input_chars` | int | `100000` | Max chars sent to worker (the old `QUARANTINE_MAX_CONTENT` default) |
| `delegation.modes.bulk_read.enabled` | bool | `true` | Enable bulk-read delegation |
| `delegation.modes.bulk_read.prompt` | string | (built-in) | System prompt for the bulk-read worker |
| `delegation.modes.code_write.enabled` | bool | `true` | Enable code-write delegation |
| `delegation.modes.code_write.prompt` | string | (built-in) | System prompt for the code-write worker |

### Per-Profile Examples

<!-- trentina:proposed delegation-per-profile -->
```yaml
profiles:
  # Human-supervised IDE agent — light delegation
  agent2:
    delegation:
      enabled: true
      worker_model: gemini-2.5-flash
      worker_provider: gemini
      line_threshold: 500    # higher threshold — human can redirect

  # Autonomous coding agent — aggressive delegation
  coding-worker:
    delegation:
      enabled: true
      worker_model: gpt-4o-mini
      worker_provider: openai
      line_threshold: 200    # delegate more aggressively
      modes:
        code_write:
          enabled: true

  # Chat agent — no delegation (doesn't read code)
  agent3:
    delegation:
      enabled: false
```

## Implementation

### Gateway Changes

#### New Module: `delegation.py`

Sits alongside `guards.py` in the gateway package. Exports a single function:

```python
async def maybe_delegate(
    profile: Profile,
    tool_name: str,
    arguments: dict,
    llm_proxy: LLMProxy,
) -> dict | None:
    """
    Check if this tool call should be delegated to a worker model.
    Returns the delegated response, or None to proceed normally.
    """
```

Called from `router.py` after parameter guards pass but before the backend call. If it returns `None`, the normal call proceeds. If it returns a dict, that becomes the tool result.

#### File Size Check

For Read-like tools, the delegation module:

1. Resolves the `file_path` argument
2. Counts lines (or uses `os.path.getsize()` as a fast pre-check)
3. If below threshold or if `offset`/`limit` are present, returns `None`
4. If above threshold, reads the file, sends to worker, returns summary

#### Worker Calls via LLM Proxy

Delegation uses the existing LLM proxy infrastructure. The worker call goes through `/llm/{provider}/` with the profile's credentials — no new API key management needed. The worker model is configured per-profile, same as `llm_keys`.

#### Response Metadata

Delegated responses include metadata so the calling agent knows what happened:

```json
{
  "content": "## /src/Service.java (2,417 lines — delegated to gemini-2.5-flash)\n\n- Class `UserService` extends `BaseService`\n  - Line 45: `createUser(...)` — validates input, writes to `users` table\n  ...",
  "delegation": {
    "worker_model": "gemini-2.5-flash",
    "original_lines": 2417,
    "worker_tokens": 1247,
    "saved_tokens_estimate": 18500
  }
}
```

### New Gateway Tool: `delegate_codegen`

Exposed as a gateway-internal tool (like the existing `cache_flush` and `reconnect_backend`):

```
delegate_codegen(spec, reference, target)
```

The tool is only visible to profiles that have `delegation.modes.code_write.enabled: true`. The gateway reads the reference file, sends spec + reference to the worker, writes output to the target path, and returns a confirmation.

### Security Considerations

#### Defense Pipeline Interaction

> **Corrected 2026-09-17.** An earlier revision of this section said the defense pipeline does **not** run on delegated responses, on the grounds that the input is local files and scanning would negate the savings. **The implementation deliberately reversed that, and the implementation is correct.** Do not build from the old stance — it reintroduces a defense bypass.

Pre-processing runs **outside** the perimeter and never replaces it. The three invariants live in `preprocess/base.py`; the second is the one that governs here:

> A pre-processor never bypasses `defend()`. Everything it emits is scanned. Whether the *delivered* bytes are its output or the untouched original is the CALL SITE's decision, not the driver's.

So the order is always **transform → scan → deliver**, enforced at the call site in `gateway/router.py::_assemble_call_result` and pinned by a test. Two properties follow:

- **What a processor dropped never reaches the agent, and never reaches the scanner either.** There is nothing to smuggle through a collapsed group — colliding a payload into one deletes it.
- **The bytes the wall judged are the bytes the agent receives.** Transforming after the scan would hand the agent content the perimeter never saw.

That first property is about **deletion**, not about getting smaller. A processor that rearranges rather than deletes does not inherit it — its bytes are still delivered — so it has to carry its own argument for why reshaping them is safe.

##### Reading less than you deliver

A driver may read only part of what its call site forwards. That is real and necessary — reading less is the only lever that keeps the Matrix perimeter inside its readiness budget — and it is not a separate kind of driver:

| | reads | its call site delivers |
|---|---|---|
| `petit`, `structured`, `email`, `summarize` | its own output | its output |
| `select`, `matrix` | a selected subset | the full original |

What binds the second row is accounting, not a different contract: every declined byte is counted by reason, and low coverage is reported as a finding in its own right. See [defense-pipeline.md](defense-pipeline.md#where-the-line-falls).

##### Subtract, never absolve

Invariant 1 is directional, and it is easy to misread as "pre-processors must not touch security at all." They already do: `petit` deletes lines, `structured` drops array elements, `email` drops quoted chains. Dropping content **is** a filtering operation, and it is always permitted, because a byte that is deleted reaches no one.

What is forbidden is the other direction. A pre-processor never marks content clean, never shortens or skips `defend()`, and never lets its output be trusted more than its input. It may subtract; it may not absolve.

One consequence is worth knowing before you build on it. A per-record **filtering** processor — one that drops the records a policy names and delivers the rest — is permitted by that invariant and is a better fit than a whole-response guard wherever partial results beat no results. It is not safe on this framework yet: composition fails **open** by design (`compose.py` swallows a processor's exception and passes the original through), so a filter that raised would deliver exactly what it exists to remove. Fail-closed handling has to come first.

##### Listing, not deleting (0.43.0)

`structured` has one transformation that reshapes rather than deletes, and this is its argument. Array elements that differ only in identifier-shaped values (`PROJ-1000`, `"10234"`, an integer id, a UUID, `#42`, a git SHA) and are otherwise EXACTLY equal are delivered as the first element and one marker:

```json
[{"key":"PROJ-1000","summary":"Nightly build failed"},
 "PROJ-1001, PROJ-1002, ...; 100 more element(s) with this shape, /key"]
```

The marker lists every element; the `...` is only this page's. Exact equality is what makes it lossless: the representative plus the list reconstructs each record. Fields that do not vary stay out of the list, a marker names at most 100 elements before the next one opens a fresh group, and a record with more than four identifier fields is left alone so the list never becomes the payload. Everything listed is delivered and judged. An identifier is at most 64 characters with no whitespace, matched by bounded patterns (petit's `pull_identifiers`), so a listed value cannot carry a sentence. The details report `groups_listed` and `elements_listed` beside `groups_collapsed` and `elements_dropped`.

##### A log in a string (#419)

`journal_query` answers `{"logs": "<a hundred lines>"}`: one string, so no
array to group, and petit is only offered a whole text block. `structured`
hands a string value of at least twenty lines and 1 KB (petit's own floors)
to petit, anywhere in the document, and the value becomes what petit makes
of a text block: the sample lines as they were written, then its summary.

```json
{"logs":"Oct 08 02:00:00 host01 sshd[2000]: Connection closed by 203.0.113.0 port 40000\n...\n\n100 records reduced to 3 line(s); 1 repetitive group(s) collapsed (showing first 3 of each):\n  100x: sshd[#]: Connection closed by #"}
```

This one deletes, and the deletion rule is petit's: a dropped line is never
delivered and never judged, a line that differs in a word is its own group
and is delivered, and the summary is in-band and spoofable. Three things
differ from a text block. The summary has no `[petit]` tag, because a
bracketed tag inside a document's data reads to L2 as an injected note
(#411, measured again in [benchmark.md](benchmark.md#a-log-in-a-json-string-419)).
The value is reduced only when petit names a log format for it: on its raw
fallback petit groups any repeated line, which in a file or a page is the
blank lines and the closing brackets. And base64, wrapped or not, is never
offered. A value petit declines or fails on is left as it arrived. The
details report `logs_reduced`, `log_lines_in`, `log_lines_out`,
`log_groups_collapsed`, `logs_failed` and `log_error` (the class of the last failure).

##### Composition is still size-driven

The contract is transformation; the selection strategies are not. A processor that does not shrink behaves differently per strategy:

| strategy | a non-shrinking transformation |
|---|---|
| `chain` | runs, output carried forward |
| `best_of` | runs, then loses to any processor that shrank more |
| `auto` | runs if FREE; METERED escalation is gated on `target_bytes` |
| `none` | never runs |

Below the `min_bytes` floor (default 4096) nothing runs at all, and each FREE processor self-declines when `bytes_out >= bytes_in`. Use `chain` if you need a reshaping processor's output to survive.

Why the original reasoning was wrong: the risk is not the *input*, it is the *worker*. A model reading hostile text can be talked into emitting a payload, and what it emits is short, fluent, and free of instruction-override syntax — precisely the shape L2 is documented to miss. Gating L3 on an L2 score would let a poisoned summary through every time.

Hence the provenance rule in `preprocess/compose.py`:

| processor | cost | provenance of output | L3 |
|---|---|---|---|
| `petit` | FREE | inherits the input's | gated as normal |
| `summarize` | METERED | `MODEL_OUTPUT` | **unconditional** |

Deterministic transformation cannot compose a payload, so petit keeps the input's provenance. An LLM rewriting the payload makes it model output, and model output always earns the Q-Agent's opinion.

**Cost consequence, stated plainly:** enabling `summarize` spends **two** model calls per response — the worker plus the mandatory L3 — not one. The original cost model in this doc assumed zero defense overhead and is therefore optimistic for the METERED path. The FREE path carries no such penalty, which is why `petit` alone is the shipped default.

#### File System Access

The delegation module needs read access to the file system to count lines and read files for the worker. This is the same access level the backend MCP servers already have — Trentina runs on the same host as the code.

For remote deployments where the agent's file system isn't local to Trentina, the delegation module would need to call through the backend's Read tool first (one cheap backend call to get the content, then delegate to the worker). This adds complexity but preserves the architecture.

#### Worker Model Isolation

The worker model call follows the same isolation principles as the Q-Agent:

- **No tools** — the worker can't execute actions
- **No memory** — each delegation is stateless
- **Tight prompt** — extraction/generation only, no reasoning
- **Low temperature** — 0.2 default, deterministic output

## What Doesn't Work

Taken from Spotify's experience and adapted:

1. **Can't delegate editing** — Worker summaries don't include reliable line numbers. If the agent needs to make edits based on analysis, it still has to read the specific section directly. The line threshold and targeted-read passthrough exist for this reason.

2. **Can't delegate reasoning** — Cheap models miss subtle bugs (thread-safety issues, race conditions, security vulnerabilities). The routing explicitly excludes debugging, architectural decisions, and safety-critical analysis.

3. **Latency adds up** — Each delegation is a network round-trip to the worker model provider. 10-30 seconds per call. Acceptable for large reads (18k tokens saved > 15s wait), counterproductive for small ones (hence the line threshold).

4. **Context fragmentation** — The agent builds understanding from file contents. Summaries lose nuance. For tasks that require deep cross-file understanding, the agent may need to re-read sections that were summarized. The delegation metadata helps the agent decide when to request a targeted re-read.

## Relationship to Existing Features

| Feature | Relationship |
|---------|-------------|
| [LLM Proxy](llm-proxying.md) | Delegation uses the proxy for worker model calls — same key management, same provider support |
| [Parameter Guards](parameter-guards.md) | Guards run before delegation — a rejected call is never delegated |
| [Defense Pipeline](defense-pipeline.md) | Defense runs on backend responses, not delegated responses (see Security) |
| [Per-Agent Profiles](profiles.md) | Delegation is profile-level config — different agents get different routing |
| [Tool Filtering](tool-filtering.md) | `delegate_codegen` tool visibility follows normal allowlist rules |
| [Compression](compression.md) | Complementary — compression shrinks tool descriptions, delegation shrinks tool responses |

## Open Questions

1. **Should delegated summaries be cached?** If the agent re-reads the same large file within a session, should the gateway return the cached summary? Pro: eliminates redundant worker calls. Con: stale summaries if the file changed.

2. **Should the agent be told delegation happened?** Spotify's approach is transparent — the agent doesn't know. But telling the agent enables it to request a targeted re-read when it needs more detail. The metadata sidecar is a middle ground.

3. **Multi-file bundling** — Spotify's bulk-read accepts multiple files in one call. Should Trentina batch adjacent Read calls into a single worker request? This requires call-sequence awareness in the gateway.

4. **Write interception** — Beyond explicit `delegate_codegen`, should the gateway detect when an agent is about to Write boilerplate (e.g., test files that match a pattern) and offer to delegate? This moves into heuristic territory.

5. **Token accounting** — How to report savings. The gateway knows how many tokens the worker consumed and can estimate how many the frontier model would have consumed. This data belongs in the audit log.
