# Literal Response Guards

*Part of Trentina's **Determinism** promise; see [Why Trentina](../README.md#why-trentina).*

Literal response guards validate what a backend *returns* before the gateway relays it. They are the egress half of [literal request guards](literal-request-guards.md): the same allow/deny constraint, the same evaluator, the same fail-closed behaviour — applied to the tool result instead of the tool arguments.

## Why This Matters

Literal request guards can only match what the agent typed. That is enough for `send_gmail_message`, where the dangerous value *is* an argument. It is not enough for a semantic tool.

A memory server is the clear case. An agent asks it for "my employer's OS roadmap." The request carries no matchable token — no company name, no project code, nothing an argument-side glob could catch. The restricted material arrives in the *response*, which a literal request guard never sees. The same shape appears anywhere retrieval is semantic: a wiki search, a ticket query, a feed reader.

That gap matters when agents on one gateway are not equally trusted. Trentina's own deployment runs work-supervised and internet-isolated agents side by side against a shared memory backend; the isolated ones must not receive work-covered material, and "ask the model nicely" is not a control. Literal response guards make the refusal happen at the gateway, where the agent's cooperation is not a variable.

## What This Is Not

**A literal response guard is a literal content filter, not a classifier.** It matches globs against text. A backend that paraphrases the restricted term, encodes it, translates it or splits it across fields will pass a guard written for the plain term. This is a known and accepted limitation, not an oversight — the honest framing is "deterministic enforcement for known literals," and the strong configuration is the deny-all one below, which does not depend on predicting vocabulary at all.

For semantic judgement of content, that is what the [defense pipeline](defense-pipeline.md) is for. The two are complementary: the pipeline asks "is this hostile?", a literal response guard asks "is this agent allowed to receive this at all?"

## How It Works

Literal response guards are configured per-backend, per-tool, with exactly the shape of literal request guards:

```yaml
backends:
  memory:
    url: "http://mcp-memory:8000/mcp"
    tools_allow: ["*"]
    literal_response_guards:
      memory_search:
        content:
          deny: ["*NIGHTJAR*", "*Nightjar*"]
```

When the backend answers, Trentina evaluates the guard against the raw result. On a match the whole response is withheld: the agent gets a JSON-RPC `-32602` error naming the field, never the content, and the call is audited as `denied_response_guard`.

### Addressing a Field

A tool result has no named parameters, so a literal response guard addresses one of two things:

| Field | What it matches |
|-------|-----------------|
| `content` | Every text block in the result, newline-joined. Includes the text form of an embedded `resource` block. Always present — a result with no text is the empty string. |
| any other name | That key of the result's `structuredContent`, if the result has one |

A structured field that is absent is skipped, symmetric to a missing parameter on the request side. `content` is never absent, so `deny: ["*"]` blocks an empty result too.

Image blocks and binary blobs carry no string to match. A guard cannot speak about them directly — but a `deny: ["*"]` guard still blocks a purely binary result, because the joined text is the empty string and `*` matches it.

### Constraint Schema

Identical to literal request guards — the same `ParameterConstraint` model, validated by the same rules:

| Field | Default | Description |
|-------|---------|-------------|
| `allow` | `["*"]` | Glob patterns the value must match |
| `deny` | `[]` | Glob patterns that reject the value (wins over allow) |

In practice literal response guards are deny-oriented: `allow` is left at its default and `deny` carries the policy. An `allow` list is useful for a tool with a small known output vocabulary (a status tool that may only ever say `ok`), and a trap for anything free-form.

Matching uses `fnmatch.fnmatchcase()`, which matches across newlines — so `*NIGHTJAR*` catches the term anywhere inside a multi-line memory blob.

## Pipeline Position

```
Tool in allowlist? → Literal request guards → Backend call → Literal response guards → Pre-process → Defense scan → Agent
```

Two properties of that position are deliberate:

**Before pre-processing.** [Transforms](token-routing.md#defense-pipeline-interaction) collapse, summarize and paraphrase. A guard reading the transformed artifact would be matching text a model rewrote, and a literal the operator forbade could be dissolved on the way past. The guard reads the bytes the backend actually sent.

**On internal backends too.** Internal (`internal://`) backends skip pre-processing and the defense scan, because the firewall already filtered that content where it *entered*. Egress policy is a different question — it is about who is asking, and the asker is the same either way — so literal response guards run regardless.

The backend was contacted and did spend its call. That is unavoidable: the restricted material is only identifiable once it exists. What the guard controls is whether it is relayed. For a tool that is not annotated `readOnlyHint`, the agent is therefore told the call was executed and its response withheld, not handed an error it would retry ([A withheld response is not a failed call](quarantine-tools.md#a-withheld-response-is-not-a-failed-call)).

## Blocking, Not Scrubbing

A violation rejects the whole response. Trentina does not strip the matched portion and deliver the rest.

Scrubbing sounds friendlier and is worse. Partial delivery makes the guard a leak oracle — an agent that receives "everything except the parts that matched" can narrow down what matched by varying its query. Blocking outright keeps the refusal uninformative, which is the same reason the error message names the field and never the content.

## Examples

### Firewall one topic from an isolated agent

```yaml
memory:
  url: "http://mcp-memory:8000/mcp"
  tools_allow: ["*"]
  literal_response_guards:
    memory_search:
      content:
        deny: ["*NIGHTJAR*", "*Nightjar*", "*nightjar*"]
    memory_list:
      content:
        deny: ["*NIGHTJAR*", "*Nightjar*", "*nightjar*"]
```

Leaves the backend usable for everything else. Fails open on paraphrase — read **What This Is Not** before relying on it.

### Deny the whole backend's output

```yaml
memory:
  url: "http://mcp-memory:8000/mcp"
  tools_allow: ["*"]
  literal_response_guards:
    memory_search:
      content: { deny: ["*"] }
```

Depends on no vocabulary and therefore cannot be paraphrased past. When *every* record in a backend is restricted for this agent, this is the correct configuration — and dropping the tool from `tools_allow` achieves the same thing more cheaply, without the wasted upstream call. Prefer the allowlist cut when the whole tool is off-limits; use deny-all when you want the block recorded in the audit log, or as a second line behind an allowlist you do not fully trust.

### Constrain a structured field

```yaml
jira:
  url: "http://mcp-jira:8000/mcp"
  tools_allow: ["*"]
  literal_response_guards:
    jira_get_issue:
      project:
        allow: ["PUBLIC-*"]
```

## Operations

A block appears in the [audit log](audit-log.md) as outcome `denied_response_guard`, in the `blocked` group — policy working, not an error. It is counted separately from `denied_guard` because the cost differs: this one spent the upstream call.

Editing `literal_response_guards` in `profiles.yaml` shows up in the reload tool's diff by field name, never by pattern:

```json
{"memory": {"literal_response_guards": {"memory_search": {"fields_added": ["content"]}}}}
```

Guard patterns are operator-authored and are not echoed back, for the same reason the error message isn't.

## Related

- [Literal Request Guards](literal-request-guards.md) — the request-side half, same evaluator
- [Tool Filtering](tool-filtering.md) — removing a tool entirely, when no response is acceptable
- [Per-Agent Profiles](profiles.md) — where literal response guards are configured
- [Defense Pipeline](defense-pipeline.md) — semantic judgement of content, downstream of this
- [Audit Log](audit-log.md) — where `denied_response_guard` is recorded
