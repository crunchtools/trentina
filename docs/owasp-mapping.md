# OWASP Mapping

*Part of Trentina's **Security** promise; see [Why Trentina](../README.md#why-trentina).*

How Trentina covers the [OWASP MCP Top 10](https://owasp.org/www-project-mcp-top-10/)
(2025 edition, Beta), the OWASP Top 10 for Agentic Applications 2026 and
LLM01:2025. Ratings are **Strong**, **Partial** or **Out of scope**, and they
describe what ships today. Each **Gap** line comes from
[Coverage](defense-pipeline.md#coverage) and its
[Known gaps](defense-pipeline.md#known-gaps) (numbers below are those gaps).
Where a rating depends on open work, the issue is linked and the rating does
not assume it.

## OWASP MCP Top 10

| Risk | Rating | Trentina mechanisms |
|---|---|---|
| [MCP01](#mcp01-token-mismanagement--secret-exposure) Token Mismanagement & Secret Exposure | Strong | [LLM key proxying](llm-proxying.md), [secret scrubbing and `_FILE` secrets](deployment-hardening.md), [log hygiene](../CLAUDE.md#logging-rule-262), [honeytokens](profiles.md#decoy-tools-and-honeytokens) |
| [MCP02](#mcp02-privilege-escalation-via-scope-creep) Privilege Escalation via Scope Creep | Strong | [Tool filtering](tool-filtering.md), [roles](profiles.md), [parameter guards](parameter-guards.md), [modes](defense-pipeline.md#pipeline-flow) |
| [MCP03](#mcp03-tool-poisoning) Tool Poisoning | Partial | Tool definitions judged by [L1/L2/L3](defense-pipeline.md#the-three-layers) on every `tools/list`, [served-surface filtering](tool-filtering.md), [description compression](compression.md) |
| [MCP04](#mcp04-software-supply-chain-attacks--dependency-tampering) Software Supply Chain & Dependency Tampering | Partial | Backend allowlists, [hardened image](deployment-hardening.md), L2 model pinned by revision and gated, [unpack stage](defense-pipeline.md#coverage) |
| [MCP05](#mcp05-command-injection--execution) Command Injection & Execution | Strong | [Parameter guards](parameter-guards.md), [guarded execution](guarded-execution.md), [content tools' egress guard and file confinement](quarantine-tools.md), [git transport](git-transport.md) |
| [MCP06](#mcp06-prompt-injection-via-contextual-payloads-intent-flow-subversion) Prompt Injection via Contextual Payloads (Intent Flow Subversion) | Strong | L1 ∥ L2 → L3 at every ingress, [blocklist](blocklist.md), [benchmark](benchmark.md) |
| [MCP07](#mcp07-insufficient-authentication--authorization) Insufficient Authentication & Authorization | Strong | [OAuth with DCR, static bearer, delegated issuers](authentication.md), per-profile [backend OAuth](profiles.md#backend-oauth), token binding |
| [MCP08](#mcp08-lack-of-audit-and-telemetry) Lack of Audit and Telemetry | Partial | [Audit log](audit-log.md) of every call, refusals included; `quarantine_stats` |
| [MCP09](#mcp09-shadow-mcp-servers) Shadow MCP Servers | Partial | One gateway endpoint per profile, backend allowlist, [network isolation](network-isolation.md), [client egress](client-egress.md) |
| [MCP10](#mcp10-context-injection--over-sharing) Context Injection & Over-Sharing | Partial | [Redact mode](defense-pipeline.md#pipeline-flow), [response guards](response-guards.md), per-profile scoping, [token savings](token-routing.md) |

### MCP01 Token Mismanagement & Secret Exposure

**Risk.** Long-lived tokens and secrets leak through context, logs or
configuration.

**Trentina.** Provider keys stay inside the gateway
([LLM key proxying](llm-proxying.md)); the agent holds only a profile token.
Secrets are read once, from `_FILE` where possible, and scrubbed from the
environment. The gateway's logs redact credential shapes and never print a
caller-chosen string. Backend OAuth grants are stored encrypted per
(profile, backend).

**Gap.** Gap 17: the honeytoken tripwire matches a planted credential only as
it was planted, so an encoded or split value is not seen, nor is anything an
agent sends without a tool call through the gateway.

### MCP02 Privilege Escalation via Scope Creep

**Risk.** An agent's permissions grow beyond what the task needs.

**Trentina.** Each profile lists the backends and tools it may reach
([tool filtering](tool-filtering.md)); anything else is not served and is
refused as if it did not exist. [Parameter guards](parameter-guards.md) and
[response guards](response-guards.md) are evaluated by the gateway, not the
agent. Roles separate the operator from agents, and an agent cannot reload a
change to its own role or defense block.

**Gap.** Gap 30: [guarded execution](guarded-execution.md) is a model and
judges one call at a time. Rules that can be stated exactly belong in a
parameter guard.

### MCP03 Tool Poisoning

**Risk.** A malicious or changed tool description, schema or annotation steers
the agent.

**Trentina.** Every tool definition on every `tools/list` crosses the three
layers (`tool_description`), after compression, and a verdict is cached in the
perimeter store. Under `block`, a flagged description is not served. A
compressed description is model output and gets unconditional L3.

**Gap.** Detection is the only control today: a description that reads as
benign to all three layers is served (gap 12: L3 misses 14% of attacks written
to evade L1 and L2). There is no runtime pinning, so a description that
changes after review is judged again but not compared with the one an operator
approved. That is [#469](https://github.com/crunchtools/trentina/issues/469);
this rating does not assume it.

### MCP04 Software Supply Chain Attacks & Dependency Tampering

**Risk.** A compromised dependency, server or model changes behavior.

**Trentina.** The container image is the distribution, built by CI with the L2
model pinned to a revision and gated for obfuscation and benign text before it
ships. Parsers for PDFs and images run in resource-limited child processes
with no credentials. Backends are named in the profile, and what they return
is untrusted whichever backend it came from.

**Gap.** Trentina does not verify the code of a backend it proxies; a
compromised backend is contained by what its responses and calls are allowed
to do, not detected. Its own Python dependencies are locked, and it makes no
claim beyond that here.

### MCP05 Command Injection & Execution

**Risk.** Agent-supplied input reaches a shell, a file path or an outbound
request.

**Trentina.** Arguments are normalized against the tool's schema and held to
parameter-guard patterns before the backend sees the call. The content tools
fetch through one egress guard (resolved address, pinned connection, checked
redirects) and read files only within confined roots. Calls to listed tools
can be judged against a rule in English before they run. The git transport
holds pushes to listed repositories and branches.

**Gap.** Gap 30 as above. Gap 26 and gap 29: nothing reads a client-egress
tunnel or a git pack, so the route decides the host or branch and records the
bytes, but the content is not judged.

### MCP06 Prompt Injection via Contextual Payloads (Intent Flow Subversion)

**Risk.** Untrusted content in a tool result, document or message carries
instructions that redirect the agent. OWASP's own file for this item is named
"Intent Flow Subversion".

**Trentina.** The core of the product. Every ingress (tool responses, fetched
pages, Matrix events, alerts, tool descriptions) crosses L1 deterministic
checks and L2 a local classifier in parallel, then L3 a quarantined LLM with no
tools, whose answer is a closed enum. Base64, hex, archives, office files, PDFs
and images are unpacked and read. A flagged source is blocklisted.
`redact` mode delivers only what L3 extracts and verifies. Detection rates are
in the [benchmark](benchmark.md).

**Gap.** Detection is not perfect: gap 12 (evasive attacks), gap 20 (a request
that reads as an ordinary one passes every layer; guarded execution limits
what it can lead to), gaps 21 to 23 (encodings L2 cannot read), gap 1 (image
text beyond OCR) and the `binary_unread` rows of Coverage.

### MCP07 Insufficient Authentication & Authorization

**Risk.** Callers or backends are not authenticated, or authorization is
missing or bypassable.

**Trentina.** Each profile authenticates by static bearer, Trentina's own OAuth
authorization server with dynamic client registration, a provisioned client or
an external issuer ([authentication](authentication.md)). An OAuth token is
bound to the profile it was issued for, so one seat cannot present it to
another. Unauthenticated write paths are rate limited. Backends that need
OAuth use each profile's own grant.

**Gap.** Rate limiting keys on the peer address, so behind a proxy it needs
`TRENTINA_FORWARDED_ALLOW_IPS` set or every caller shares one bucket. A static
bearer is a shared secret and is as strong as its custody.

### MCP08 Lack of Audit and Telemetry

**Risk.** Actions cannot be reconstructed, or the record can be altered.

**Trentina.** Every call is recorded, including calls the gateway refuses,
with outcome, bytes arrived and delivered, destination fingerprint, session
and a call reference that joins detections to the call. Rows are scoped by
profile, and the journal never carries caller-chosen strings
([audit log](audit-log.md)).

**Gap.** The log is a SQLite table with a retention sweep, not a tamper-evident
record: rows are not hash-chained, so deletion or edit by someone with
database access is not detectable. That is
[#472](https://github.com/crunchtools/trentina/issues/472); this rating does
not assume it.

### MCP09 Shadow MCP Servers

**Risk.** Unapproved MCP servers are reachable by agents or hold data.

**Trentina.** An agent's client points at one gateway endpoint; the servers
behind it are those in its profile. With the agent on an isolated network
([network isolation](network-isolation.md)), model providers, the web and git
are reachable only through the gateway's guarded routes
([client egress](client-egress.md), [git transport](git-transport.md)).

**Gap.** Trentina cannot discover servers it is not in front of. An agent whose
client is also configured with a direct MCP server, or that has unrestricted
network access, bypasses it. The control is the deployment, not the gateway.

### MCP10 Context Injection & Over-Sharing

**Risk.** Context from one task, user or agent leaks into another, or too much
is put in front of the model.

**Trentina.** Profiles are separate: blocklist, audit rows, cache flushes and
admin tools are scoped to the calling profile, and a refusal names nothing in
another profile. Held remainders of paged responses are bound to the profile.
Tools and bytes the agent does not need are hidden, compacted or minified
(52% fewer response bytes on production traffic), and `redact` mode returns
only the answer to a stated question. Response guards validate results.

**Gap.** Trentina does not know what is sensitive inside an allowed response:
what an allowed tool returns reaches the agent whole unless a response guard
or `redact` narrows it. Gap 14: under `unjudged: annotate`, Matrix media and
undecrypted events are forwarded unjudged by the operator's choice.

## OWASP Top 10 for Agentic Applications 2026

| Risk | Rating | Trentina |
|---|---|---|
| ASI01 Agent Goal Hijack | Strong | Injection defense at every ingress; [guarded execution](guarded-execution.md) judges the call a hijack leads to (gaps 12, 20) |
| ASI02 Tool Misuse & Exploitation | Strong | Allowlists, [parameter guards](parameter-guards.md), [response guards](response-guards.md), guarded execution (gap 30) |
| ASI03 Identity & Privilege Abuse | Strong | Per-profile identity, roles, token binding, per-profile backend grants ([authentication](authentication.md)) |
| ASI04 Agentic Supply Chain Vulnerabilities | Partial | Tool descriptions judged on every `tools/list`; no pinning ([#469](https://github.com/crunchtools/trentina/issues/469)); backend code not verified |
| ASI05 Unexpected Code Execution | Partial | No code runs in the gateway on an agent's behalf; parsers are sandboxed children; what a backend executes is guarded only by its parameter guards |
| ASI06 Memory & Context Poisoning | Partial | Content is judged before it enters context, and a flagged source stays refused ([blocklist](blocklist.md)); the agent's own memory store is outside the gateway |
| ASI07 Insecure Inter-Agent Communication | Partial | [Matrix bridge](matrix-bridge.md) judges events in both directions and drops another bridged agent's events; agent-to-agent channels the gateway does not carry are not covered |
| ASI08 Cascading Failures | Partial | Circuit breakers per backend, concurrency and rate limits, fail-closed layers ([when a layer errors](defense-pipeline.md#when-a-layer-errors-or-times-out)); no cross-agent blast-radius analysis |
| ASI09 Human-Agent Trust Exploitation | Out of scope | Trentina does not control how an agent presents information to a person; it limits what an injected instruction can send (gap 20) |
| ASI10 Rogue Agents | Partial | Profile scoping, audit, decoys and honeytokens detect and contain an agent that misbehaves (gap 17); the audit is not tamper-evident ([#472](https://github.com/crunchtools/trentina/issues/472)) |

## LLM01:2025 Prompt Injection

| Risk | Rating | Trentina |
|---|---|---|
| LLM01:2025 Prompt Injection (indirect, via content the model reads) | Strong | L1 ∥ L2 → L3 on every ingress; `block`, `redact` and `flag` modes ([defense pipeline](defense-pipeline.md)). Gaps 12 and 20 apply. |
| LLM01:2025 Prompt Injection (direct, typed by the user) | Out of scope | The user's own prompt does not cross the gateway; Trentina defends what agents read, not what the user says |
