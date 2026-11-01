# trentina Constitution

> **Version:** 2.13.0
> **Ratified:** 2026-09-22
> **Amended:** 2026-11-01
> **Status:** Active
> **Inherits:** [crunchtools/constitution](https://github.com/crunchtools/constitution) v1.28.0
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
  request and response guards, egress, semantic request guards).
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
  asked to judge. A proxied text response too large to judge in one call is
  not refused: it is cut into parts, each under the cap, and each part is
  admitted, read whole by every layer and delivered on its own (#340). The
  parts not yet asked for are held in memory, never stored, and reach no
  agent unjudged. A part is read behind the end of the part before it, so
  those tokens are read with both. `flag` alone scans an over-cap payload's head, and alone
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

The one boundary at which a payload may be delivered without this gateway
running its three layers is a **declared federation trust boundary** (#592):
where an operator has pinned a federated upstream's key, perimeter stamp and
judge, a response the upstream already scanned is delivered on its signed
verdict instead of being re-judged. This is not an off switch — the layers ran
once, at the upstream's ingress, and the downstream serves exactly that
conclusion, the same "each layer reads once" rule carried over a signed
channel. It is bound to the exact delivered bytes, the upstream's perimeter
stamp and its judge, and it is fail-closed: an absent, forged, stale or
mismatched verdict falls through to the full local pipeline. The carve-out
lives in the response edge, never in a layer, so the four rules above still
hold for every other ingress. See `docs/federation.md` and known gap 33.

- **L1 (deterministic):** `l1/` counts obfuscation, hidden markup, encoded
  blobs, exfiltration URLs, delimiters and directives, by type; its counts
  brief L3. It never modifies what the agent receives.
- **L2 (classifier):** a local ONNX prompt-injection classifier
  (`quarantine/classifier.py`). The model is an operator setting
  (`CLASSIFIER_MODEL`, #350): Horizon-Labs' prompt-injection-guard-small by
  default and the one model the image ships, exported from a pinned
  revision with a manifest that states its polarity, its threshold and the
  window it is scanned in (#438). A shipped
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

## Semantic Request Guards

A profile's `semantic_request_guards` block names tools whose calls the profile's
judge reads, against an operator's policy in plain language, before they are
forwarded (#456). It asks the judge a second question, and four rules keep
that inside the threat model, which assumes the judge compromised:

- **It only subtracts.** An allow grants nothing: the call still passes the
  allowlist, the literal request guards and every other rule, which all run first.
  No answer from the judge forwards a call another rule refused.
- **It fails closed.** No judge, an error, a timeout, a malformed or
  off-schema answer, a leaked canary, and any answer but an explicit allow
  refuse the call.
- **The arguments are judged before the judge reads them.** They are the
  agent's text, so they cross L1, L2 and L3 through `defend()` like any
  payload, and a flag or an unfinished read refuses. The judge is then
  called through `quarantine_generate`: no tools, a canary, a closed schema.
- **Nothing it writes reaches the agent.** The agent is told a reason code
  from a closed set; the policy and the judge's output stay in the gateway.

The facts the judge is given (first contact, from the audit; a session's
flagged mark, held in memory) are the gateway's own, written by
deterministic code. The block is perimeter: held on an agent reload, refused
on a honeypot. `PERIMETER_VERSION` does not move: no scan reaches a
different conclusion. That the judge is a model is known gap 30.

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

## Human Approval

The clause above is about the allowlist, and was read for a while as though it
governed every trust decision in the product. It does not. Federation's
scan-once trust is a different mechanism in a different file, and it *does*
decide whether a layer runs — so what governs it is written here rather than
inferred from a neighbour.

Five decisions are not an operator agent's to make alone. Not because the
operator lacks the authority — it is root on its gateway — but because it is a
model, so the question is not whether it may but whether it can be talked into
it.

1. **Who holds the operator seat**, including how a caller becomes one.
2. **Turning on a trust that stops a layer running.**
3. **Who may authenticate** to a federation ingress as a primary gateway.
4. **Standing a profile's perimeter down** from enforcing to detect-only.
5. **Opening a way out of network isolation.**

The last three were added by the security hardening pass. Each is a grant an
operator could previously make with nobody watching, and the fifth is the
widest of the five: a trusted peer has at least run three layers over the
response it hands over, while nothing reads the bytes inside a CONNECT tunnel
at all.

An operator agent MAY **propose** any of them. It MUST NOT be able to **apply**
one. The gateway holds the proposal, a person approves it, and only then does
it take effect. Agent-controlled trust stays forbidden; agent-proposed trust
with a human in the loop is what this permits.

**Only widening needs a person.** Withdrawing a peer, taking `flag` away,
removing an egress host: each makes the gateway stricter, and each MUST apply
at once. A gate standing in front of tightening teaches an operator that the
approval page is something to get past, which costs more than it protects.

**Each approval is one decision.** A write that would need two is refused
rather than shown as one, because a page can put a single question in front of
a person and the rest would be applied unseen on the back of the one they read.

What makes several changes ONE decision is that the page states all of them
and the person reads all of them before answering. "Admit these three gateways
to this ingress" is one decision with three rows; "move the seat *and* believe
this peer's scan" is two, because no single page can carry both facts tables
and whichever is not rendered is applied unread. The test is therefore whether
anything would be applied that the person was not shown — not how many keys
the write touched. A rule MAY collapse a set of like grants into one proposal
when every member is named on the page, and MUST NOT collapse unlike ones.

The corollary is that a proposal has a size past which it stops being read. A
rule that can collapse grants MUST bound how many it will render and refuse
beyond it, because one unfamiliar row among forty familiar ones is approved by
a person who read all forty. Trust pins do not collapse at all: each is its own
belief about its own scanner and judge, so two pins in one write is two
decisions and is refused.

Three properties make that real, and each is a requirement:

1. **The approval capability is something the agent cannot read.** Not a token
   in a tool result, not a file the gateway hands back, not anything returned
   by the call that staged the proposal. A secret a person holds and the
   gateway only verifies.
2. **The approval states what is being changed**, in values a person can
   check, and nothing a peer chose reaches that page unbounded.
3. **No approver configured means no approval.** Every one of these decisions
   stays refused. The absence of a way to approve is never an approval anyone
   can give.

What does NOT come here is anything high-volume. A gateway holds hundreds of
tool pins and a restart can re-hold every remote tool at once; routing those
through a person would push operators toward turning pinning off, which costs
more than it protects.

## Stability Tiers

Trentina is one program with one version, so a breaking change anywhere used to
force a major bump for everything. An operator reading a version number could
not tell whether the break landed in the defense pipeline they depend on or in
a feature they do not use.

Most of the gateway is **stable**: its configuration keys, wire formats and
tool shapes change only in a major release. A small, named set of features is
**preview**, declared in `src/trentina/stability.py` and documented in
`docs/stability.md`. A breaking change CONFINED to a preview surface is a MINOR
bump, listed in the changelog under a `### Preview` heading naming the surface.

Three rules, and the tier is worth nothing without all three:

1. A change reaching anything outside every declared preview surface is a
   major. "Mostly confined" is not confined.
2. A surface is declared BEFORE the release that relies on it, never during
   one. Declaring a feature preview in the same release that breaks it is
   re-characterising the break after the fact, which is what a version number
   exists to prevent.
3. A preview surface carries the same test, lint, review and documentation bar
   as everything else. The tier is a promise about BLAST RADIUS, not a licence
   for churn, and not a place to put work that is not finished.

Leaving preview is a deliberate decision, not a reward for surviving long
enough. The reverse does not exist: a shape that has been promised cannot be
un-promised, only broken in a major release.

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
| Git transport | `/git/{remote}/{owner}/{repo}` on the HTTP port (smart HTTP only; registered when the file has `git_remotes`) |
| Egress route | `/egress/{upstream}/{path}` on the HTTP port (terminating reverse proxy to named upstreams; registered when the file has `egress_upstreams`, #511) |
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
| 2.5.1 | 2026-10-11 | The window L2 scans in is the model's, stated in its manifest beside polarity and threshold (#438); the shipped model states 512 |
| 2.6.0 | 2026-10-11 | A proxied text response too large to judge in one call is delivered in judged parts (#340) where it was refused: each part is admitted and read whole, behind the last tokens of the part before it. Known gap 27: such a response is judged a part at a time |
| 2.7.0 | 2026-10-11 | The internal tools' responses are delivered in judged parts too (#446), each part judged as the tool's source. L1 counts a line written to look like the gateway's own (#447). Known gap 28: L2 flags machine-written meeting notes that end in bare links (#450) |
| 2.8.0 | 2026-10-12 | Git transport (#453): a route carries git's smart HTTP to the repositories a profile lists, with the forge token injected by the gateway. The gateway terminates the connection, so it reads and enforces everything that is deterministic text (the path, the service, the protocol, a fetch request, a push's command list, ref listings) and hands none of it to the three layers: a pack is passed on unread and ref names are bounded but not judged, which is known gap 29 and a stated exception to the first rule of the layer contract. The block is perimeter: held on an agent reload, refused on a honeypot. `PERIMETER_VERSION` does not move: the route reaches no verdict a cache holds |
| 2.9.0 | 2026-10-14 | Guarded execution (#456): a profile names tools whose calls its judge reads against an operator's plain-language policy before they are forwarded. It only subtracts, fails closed, judges the arguments with the three layers before the judge reads them, and returns a closed reason code. The block is perimeter: held on an agent reload, refused on a honeypot. Known gap 30: the gatekeeper is a model and judges one call at a time |
| 2.10.0 | 2026-10-30 | Gateway-to-gateway federation (#592): a declared trust boundary added to the Layer Contract. Where an operator pins a federated upstream's key, perimeter stamp and judge, a response the upstream already scanned is delivered on its signed verdict instead of being re-judged — bound to the exact bytes, stamp and judge, fail-closed, carved out in the response edge not a layer. The promise reads "at every ingress — or at a trusted boundary you declare". Known gap 33: the stamp binds the upstream's model, gates and judge, not its defense-policy block. `PERIMETER_VERSION` does not move: the local pipeline's conclusions are unchanged |
| 2.11.0 | 2026-10-31 | Human Approval (#637): the Trust Allowlist clause is about the allowlist, and had been read as governing every trust decision in the product. Federation's scan-once trust is a different mechanism and does decide whether a layer runs, so what governs it is stated rather than inferred. Two decisions — who holds the operator seat, and turning on a trust that stops a layer running — may be PROPOSED by an operator agent and applied only on a person's approval. Three requirements: the approval capability is something the agent cannot read, the approval states what is being changed in values a person can check, and no approver configured means both decisions stay refused. High-volume approvals (tool pins) deliberately stay out. `PERIMETER_VERSION` does not move: no verdict changes |
| 2.12.0 | 2026-11-01 | Human Approval extended by the federation security hardening pass: three more decisions an operator agent may propose and not apply — who may authenticate to a federation ingress (`federation.peers`), standing a profile's perimeter down to detect-only (`defense.modes`, `enforcement`, `llm_completion` reaching `flag`), and opening a way out of network isolation (`client_egress.hosts`, `egress_upstreams`, `llm_providers`). The last is the widest of the five: a trusted peer has run three layers over its response, while nothing reads a CONNECT tunnel's bytes (known gap 26). Two rules stated rather than left to each rule's author: only WIDENING needs a person, since narrowing only makes the gateway stricter and a gate in front of tightening teaches an operator to click through; and each approval is ONE decision, a write needing two being refused rather than shown as one. `PERIMETER_VERSION` does not move: no verdict changes |
| 2.13.0 | 2026-11-01 | Stability Tiers: one program with one version meant a break anywhere forced a major bump for everything, so a version number could not say whether the break landed in the defense pipeline or in a feature the operator does not use. Most of the gateway is stable; a named set of surfaces is preview (`src/trentina/stability.py`, `docs/stability.md`), and a break CONFINED to one is a minor. Three rules: a change reaching outside every declared surface is still a major, since "mostly confined" is not confined; a surface is declared BEFORE the release that relies on it, never during one, because declaring a feature preview in the release that breaks it re-characterises the break after the fact; and a preview surface carries the full test, lint, review and documentation bar, since the tier promises blast radius and not permission to churn. Federation (#592) is the first and only surface — API-driven config (#633) and human approval (#637) stay stable precisely because they break in this release. `PERIMETER_VERSION` does not move: no verdict changes |
