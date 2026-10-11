# trentina Constitution

> **Version:** 2.5.0
> **Ratified:** 2026-09-22
> **Amended:** 2026-10-11
> **Status:** Active
> **Inherits:** [crunchtools/constitution](https://github.com/crunchtools/constitution) v1.24.0
> **Profile:** Security Gateway

This file holds what is specific to Trentina. The fleet rules and the
Security Gateway profile (image-only distribution, a judging path that fails
closed, delivery of exactly what was judged, a versioned perimeter, declared
coverage, measured detector changes, hostile parsers in child processes)
apply at the inherited version and are checked against this repo's files by
`constitution.yml`. They are not restated here.

## Threat Model

Trentina stands between AI agents and everything they read or call. The
attacker is whoever can put text in front of an agent: the author of a web
page, a ticket, a mail, a chat message, a file, a tool description, or a
tool's response. The attack is an instruction planted in that content, which
the agent follows because it cannot tell data from instructions.

- **Defended:** planted instructions in tool output and tool metadata,
  whether plain, obfuscated, encoded, hidden in markup, or inside an archive,
  office file, PDF or image; a server steering an agent toward tools that
  bypass the gateway; an agent's own calls leaving its policy (tool filters,
  parameter and response guards, egress).
- **Assumed compromised:** the L3 judge. It reads hostile content, so it has
  no tools, no memory and no ability to act, and its prose is never delivered.
- **Not defended:** a user jailbreaking their own model directly (the judge
  is not a chat-safety filter); an agent with a second path to the content
  that does not cross the gateway; a compromised host or operator; and every
  entry in the known gaps.

## Limits and Credentials

- **Credentials:** `GEMINI_API_KEY` is a Pydantic `SecretStr`, scrubbed from
  every error message by `errors.py`, and kept in an env file separate from
  mcp-gemini's for cost isolation.
- **Input limits:** URL schemes are http/https only; path traversal is
  rejected; content size limits apply before processing; web fetches are
  capped at 5 MB, and every outbound call (web fetch and provider) times out.
- **Admission cap:** one cap before any inference, in L2's tokens: the
  smaller of L2's CPU budget and the Q-Agent's context window. Admitted
  content is read whole by every layer; `block` and `redact` refuse what is
  over the cap, and no layer is handed a truncated slice of content it was
  asked to judge. `flag` alone scans an over-cap payload's head, and alone
  delivers binary no layer can read yet (`binary_unread`, below); it says so
  in the warning both times.
- **Supply chain:** no google-genai SDK, which enforces the Q-Agent
  quarantine architecturally.

## What the Gateway Never Does

Trentina fetches and processes untrusted content by design, so what it will
not do with that content is fixed: it never executes it, never shells out on
its behalf, and limits its file tools to read-only text. The parsers it runs
in child processes (PDF, OCR) are its own modules, started with a constant
argument list.

- No `safe_exec` tool, permanently.
- File reading is scoped to text files: binary is rejected, read-only, no
  writes. This governs the file tools, the paths an agent names. It does not
  govern state the process owns: the SQLite stores (blocklist, perimeter
  verdicts, OAuth, bridge mappings), the caches, and the Matrix bridge's
  crypto store and session, all written by deterministic code under the
  process's own configured data directory only: the blocklist's directory for
  the gateway, `BRIDGE_STORE_DIR` for the bridge (each its container's
  `/data`). The bridge's operator commands read that same store.
- The one read of a store the process does not own is `import-mautrix`: an
  operator-run command that opens another client's crypto store read-only,
  never reachable from a tool or an agent.

## Layer Contract

Every untrusted payload crosses three independent layers, with no off switch
per layer. The four rules a change to any layer is held to (nothing delivered
unread and each layer reads once; layers share findings, never inputs; a
layer's weakness is fixed inside that layer or at model selection; read time
is linear) are written in `docs/defense-pipeline.md` under the same heading,
and `tests/test_layer_contract.py` enforces the first two.

- **L1 (deterministic):** `l1/` counts obfuscation, hidden markup, encoded
  blobs, exfiltration URLs, delimiters and directives, by type; its counts
  brief L3. It never modifies what the agent receives.
- **L2 (classifier):** a local ONNX prompt-injection classifier
  (`quarantine/classifier.py`). The model is an operator setting
  (`CLASSIFIER_MODEL`, #350): Horizon-Labs' prompt-injection-guard-small by
  default and the one model the image ships, exported from a pinned
  revision with a manifest that states its polarity and threshold. A shipped
  model passes the obfuscation gate (`benchmarks/l2_obfuscation.py`): the
  image build runs it and records the result in the manifest, and the
  gateway names a model without a passing record at startup and refuses to
  start on one under `TRENTINA_REQUIRE_HARDENED` (#362). Llama Prompt Guard
  2 86M fails the gate and is no longer shipped. A shipped model also passes
  the benign gate (`benchmarks/l2_benign.py`, #411), at the same threshold
  and under the same enforcement: it flags at most 2% of the held-out benign
  corpus, read as the gateway reads a tool response. A shape it is known to
  flag is measured on every build and listed as a known gap, never dropped
  from the corpus. A model
  an operator brings through `CLASSIFIER_MODEL_PATH` without a manifest
  loads only when every label in its `config.json` is a known benign or
  malicious name, at the 0.5 default. A model whose polarity cannot be read
  does not load; L2 is then absent, never guessed.
- **L3 (judge):** a quarantined LLM (`quarantine/agent.py`): no tools, no
  memory, no SDK, per-request canary.

Nothing is delivered that the layers did not read, in its original or
decoded form, or, for binary, by its identified type (#365). Pre-processing
is two stages in that order: the pre-processors decide what is delivered, and
the unpack stage (`unpack/`) builds what the layers read from it, never
changing it. Canonical base64 and hex that decode to text are read decoded;
binary is read as a label naming its type. A run of decimal digits up to
twenty long is a number and not hex, read as it arrived (#431). Every layer reads that once (the
Layer contract in `docs/defense-pipeline.md`). Binary an agent's tools could
open and no layer can read yet (an image, a PDF, an archive, audio, video)
is the `binary_unread` gap: `block` and `redact` refuse it. One exception: an
image whose header states 4 by 4 pixels or less, too small to draw a letter
or a QR code, is read by its type.

The mode (`trentina_mode`, chosen per call within the profile's policy)
decides what is delivered, never which layers run. No text written by L3
reaches the agent: findings leave the perimeter as closed-enum labels and
scores only.

The L3 quarantine is enforced architecturally: raw httpx REST calls to the
provider, no function declarations in API requests, no memory beyond a
single request, structured JSON output via a response schema. Provider
drivers are pluggable (Gemini, OpenAI-compatible including OpenRouter,
Anthropic, Ollama); the default model is `gemini-3.5-flash-lite`, the judge whose prompt pack
passes the pack gate briefed as production briefs it (#397). A shipped
pack states whether it is supported, deprecated or unmeasured on that gate,
and startup names a judge in use that is not supported.

A new L1 stage is a module in `l1/`, wired into `_run_stages` in
`l1/pipeline.py` with its stats added to `PipelineStats`, and tested on
normal input and adversarial vectors.

## Decoys and Honeypot Profiles

The layers judge what an agent reads. Two deterministic tripwires watch
what it then does (#357): a call to a decoy tool (a `decoy://` backend's,
declared in the profile and answered by nothing), and a planted credential
(a honeytoken) in the arguments of any call. Both are exact matches with no
model behind them, recorded as `decoy_tripped`. They are not a layer: they
read no content, decide nothing about delivery, and a profile without them
is no less judged. No L3 request carries a tool because of them.

A profile declared `honeypot` belongs to an agent meant to be attacked, and
three rules hold for it and for no other profile:

- **It holds nothing real.** Only `decoy://` backends and the internal
  reading tools, by name; no remote backend, no admin tool, no operator
  role, no other channel in. The loader refuses anything else.
- **It is told nothing of the verdict.** Its only mode is `flag`, every
  layer runs, and what is delivered is exactly what was judged, with no
  warning, report or score attached. The rule that what is delivered is
  what was judged is unchanged; what is withheld is the gateway's opinion.
- **What it reads and what it sends a decoy are kept.** The delivered
  content and every layer's verdict on it go to `honeypot_captures`, and so
  do the arguments of each call it makes to a decoy tool (#410): whether a
  trip was the agent's job or an attacker's turns on what was asked for. A
  planted credential in those arguments is kept by id, never by value. This
  is the one place the gateway stores content a caller chose, and the stated
  exception to keeping such text out of everything but the audit's
  `destination`: it is a table, never a log line, written for honeypot
  profiles only and swept with the audit. A decoy on any other profile keeps
  no arguments.

Captured content is not a test fixture. An attack found there enters a
corpus only rewritten by hand, with every third party's name, handle and
host replaced (constitution XVII, profile VII).

## Blocklist Integrity

The SQLite blocklist is writable by deterministic code only. The Q-Agent
cannot write to it; its output is parsed by deterministic code, which decides
whether to record. A compromised Q-Agent therefore cannot manipulate the
blocklist.

## Matrix Bridge Credential Split

Matrix end-to-end encryption terminates in the bridge process, never in the
agent (spec 015). The split is structural, not a convention:

- The bridge process holds the upstream Matrix login and crypto store, no
  credential for the agent's homeserver, and shares no network with it.
- The gateway holds the appservice token for the agent's homeserver and no
  upstream Matrix credential.
- Every event that carries content crosses all three layers in both
  directions before it is written to either side. A redaction carries none:
  it names an event already judged, and its reason text is dropped rather
  than carried, so it is mirrored without a verdict.

## Trust Allowlist

Trust decisions are administrator-set in a server-side JSON config file, not
agent-controlled. An allowlisted source still runs all three layers; the
allowlist changes what a finding costs, never whether a layer runs. A
compromised agent cannot override trust levels.

## Python Version Coverage

Two rules, not negotiable independently; the second only works because the
first bounds it.

1. Everything that can run on the whole matrix MUST run on the whole
   matrix: every Python version from the `requires-python` floor to the
   newest supported release, inclusive, no gaps. A version admitted by
   `requires-python` but absent from the CI matrix is an untested claim,
   which is how a floor of 3.10 survived while being uninstallable
   (issue #100).
2. Anything that can only run on one version MUST run on the newest
   supported version, the one the container ships. Work that needs a
   credential only one job holds, costs live API quota, or runs inside the
   built image runs where production runs.

When a new Python release is adopted, the matrix ceiling and the
single-version jobs move together. Type checking is exempt from rule 2:
mypy's `python_version` selects the language semantics checked against and
should track the floor; where a dependency's stubs make that impossible the
config MUST record the specific blocker.

## Test Coverage Specifics

Beyond the profile's mocked tests: sanitization unit tests per module,
pipeline integration tests, Q-Agent tests that verify no function
declarations are sent, mode tests (every family x mode runs every layer in
`test_mode_parity`; gaps refuse or warn in `test_mode_gaps`), file-read tests
(binary rejection, size limits) and adversarial injection vectors.

## Known Gaps

The numbered list is `docs/defense-pipeline.md`, "Known gaps", beside the
coverage table. `tests/test_coverage_gaps.py` holds both open: each gap has a
test asserting it still exists, so closing or opening one changes the test
and the document together. `PERIMETER_VERSION` (`perimeter_db.py`) moves with
every change to what is decided.

## Gourmand Exception Reasons

Beyond the profile's acceptable reasons, security-tool vocabulary
(sanitization stage names, threat category labels) is an accepted
justification in `gourmand-exceptions.toml`.

## Instance

| Context | Name |
|---------|------|
| GitHub repo | `crunchtools/trentina` (was `crunchtools/mcp-trentina`) |
| Python module and commands | `trentina`, `trentina-bridge` |
| Container image | `quay.io/crunchtools/trentina`, `ghcr.io/crunchtools/trentina` |
| Service and address | `trentina.crunchtools.com` |
| PyPI | not published; `mcp-trentina-crunchtools` stops at 0.54.1 |
| HTTP port | 8019 |
| Client egress port | 8021 (CONNECT only; bound when a profile has `client_egress`) |
| HTTP clients | httpx (application), httpx2 (MCP transport) |
| Extra stack | beautifulsoup4, markdownify, SQLite; pypdf, rapidocr and opencv-python-headless (each run only in a child process, #369, #370) |

## History

| Version | Date | Changes |
|---------|------|---------|
| 1.0.0 | 2026-03-09 | Initial constitution |
| 1.0.1 | 2026-03-10 | Gourmand, Development Workflow and Governance sections added |
| 1.0.2 | 2026-03-16 | Container Conventions section added |
| 1.0.3 | 2026-09-20 | Python floor 3.10+ to 3.11+ (3.10 was uninstallable, issue #100); httpx2 recorded as the MCP transport client |
| 1.1.0 | 2026-09-20 | Python version coverage: full matrix from floor to newest, single-version jobs on newest |
| 1.1.1 | 2026-09-22 | Inherit v1.16.0 (XVII); examples, tests and docs moved to its fictional roster (RT #1504) |
| 1.2.0 | 2026-09-24 | Inherit v1.17.0. Three-layer defense rewritten to match the code (Gatehouse critical on #182); allowlist, quality gates and the L1 stage recipe corrected |
| 1.2.1 | 2026-09-25 | Q-Agent backend: pluggable provider drivers, default gemini-2.5-flash-lite since spec 002 |
| 1.3.0 | 2026-09-27 | The 100K-character truncation before the Q-Agent becomes one token admission cap (#225) |
| 1.4.0 | 2026-09-27 | File rule scoped to the file tools; process-owned state named. Matrix bridge credential split added (#162) |
| 1.4.1 | 2026-09-27 | Bridge operator commands read the bridge's own store; `import-mautrix` named as the one read of a foreign store |
| 1.5.0 | 2026-10-02 | Manifest under constitution v1.18.0: profile restatement removed, repo-specific security design kept under its own headings; the stale `block_`/`warn_`/`clean_` tool-prefix wording replaced by the per-call `trentina_mode` |
| 1.6.0 | 2026-10-03 | L2 is a pluggable local classifier (#350): Horizon-Labs prompt-injection-guard-small by default, Prompt Guard 2 86M selectable, polarity and threshold from a pinned-model manifest |
| 1.7.0 | 2026-10-04 | Layers read the delivery unpacked, not the arrived bytes: nothing is delivered that the layers did not read, in its original or decoded form, or for binary by its type (#365, #367). Binary no layer can read is the `binary_unread` gap; `flag` delivers it with the warning, as it does an over-cap payload's tail |
| 1.8.0 | 2026-10-05 | The L2 obfuscation gate is enforced (#362): run by the image build, recorded in the model manifest, checked at startup. The image ships one L2 model; Prompt Guard 2 86M fails the gate and is dropped |
| 1.9.0 | 2026-10-05 | PDFs are read (#369): pypdf joins the stack, and runs only in a child process with CPU and memory limits and no credential in its environment |
| 1.10.0 | 2026-10-05 | Images are read by OCR (#370): rapidocr and opencv-python-headless join the stack, child process only. Matrix media and undecrypted events are not forwarded unread under withhold (#371) |
| 2.0.0 | 2026-10-06 | Profile changed from MCP Server to Security Gateway (constitution v1.19.1): Trentina is a perimeter, not an API wrapper. Renamed from mcp-trentina to trentina (repo, module, commands, images, service); distributed as a container image only, no PyPI. Threat Model and Known Gaps sections added; Three-Layer Defense becomes Layer Contract; the CI-only build rule is now the profile's |
| 2.1.0 | 2026-10-06 | Decoys and Honeypot Profiles added (#357): decoy tools and honeytokens are deterministic tripwires, not a layer; a `honeypot` profile holds nothing real, is delivered content with no verdict attached, and its content is kept in `honeypot_captures`, the one stated exception to storing caller-chosen text |
| 2.2.0 | 2026-10-08 | A honeypot profile's decoy-call arguments are kept in `honeypot_captures` beside what it read, planted credentials by id (#410); no other profile's are |
| 2.3.0 | 2026-10-10 | The L2 benign gate is enforced beside the obfuscation gate (#411): run by the image build at the shipped threshold, recorded in the model manifest with that threshold, checked at startup |
| 2.3.1 | 2026-10-11 | A run of decimal digits up to twenty long is a number, not hex the unpack stage decodes: a byte count was being read by every layer as the text its digits spell in hex (#431) |
| 2.4.0 | 2026-10-11 | The default judge is gemini-3.5-flash-lite (#397). A judge is supported when its prompt pack passes the pack gate briefed as production; shipped packs carry that status and startup reports a judge that is not supported |
| 2.5.0 | 2026-10-11 | Client egress (#442): a CONNECT listener tunnels an agent's own HTTPS client to the hosts its profile lists. The gateway decides the caller (by network), the host, the address and the TLS server name, and records the bytes; it does not read them, which is known gap 26. The block is perimeter: held on an agent reload, refused on a honeypot |
