# Semantic Response Guards

*Part of Trentina's **Security** promise; see [Why Trentina](../README.md#why-trentina).*

Name the tools that matter, write the rule in plain English, and Trentina's
judge reads every one of those tools' *responses* before the agent receives
it. A response the judge does not allow is withheld, and the agent never sees
it.

```yaml
semantic_response_guards:
  policy: |
    Nothing about unreleased products, customers by name, or pricing may reach
    this agent. No credentials, keys or connection strings in any result.
  tools:
    memory: [search_memory, read_note]
```

## Why it matters

This is the semantic twin of the [literal response guard](literal-response-guards.md),
and it fills the last empty cell in the [guard grid](gateway.md#the-guard-grid):
literal and semantic, each on the request and the response.

A literal response guard is a per-field glob: it withholds a result that
contains a known string. That catches `NIGHTJAR` in a memory search, but not
the same secret paraphrased, base64-encoded, or split across two calls. A
restriction that is about *meaning* — "nothing about unreleased products", "no
customer records in bulk", "no credentials, whoever the result names" — cannot
be written as a pattern. Semantic response guards hand that judgment to the
profile's model.

It is the response-edge counterpart of [semantic request guards](semantic-request-guards.md):
those judge what a call *sends*, these judge what a response *gives*. The
danger they cover is egress of restricted material the agent should not hold,
whether the agent was steered into a call that pulls back more than it should
or the backend simply returns material this agent is not allowed to receive.

## It is the policy judge, not the defense pipeline

Semantic response guards enforce the operator's **policy**. They do **not** run
the [defense pipeline](defense-pipeline.md) (L1 ∥ L2 → L3), which judges
content for **hostility**. The perimeter scan runs on the same response a beat
later, in the response-edge assembly, so re-scanning here would be redundant.

This is deliberately asymmetric with the request path. A semantic request guard
runs the arguments through the three layers first, because a call's arguments
have no other scan — nothing else reads them. A response is read by the
perimeter regardless, so the response guard adds only the policy verdict.

## How it stacks

A guarded tool's response passes these checks, in order, and stops at the
first that withholds it:

```
Backend answers → Literal response guards → The response gatekeeper → Defense pipeline (L1 ∥ L2 → L3) → Agent
```

1. **[Literal response guards](literal-response-guards.md).** Exact glob rules
   on result fields. No model, nothing can argue past them.
2. **The response gatekeeper.** The profile's judge reads the raw result
   against the policy and answers allow or refuse.
3. **The [defense pipeline](defense-pipeline.md).** The same response is
   scanned for hostility, reduced, and shaped for the configured mode.

The gatekeeper can only take away. A withheld response is never delivered, and
nothing the judge writes reaches the agent.

## Configuration

```yaml
profiles:
  research-agent:
    auth:
      bearer_token_env: TRENTINA_PROFILE_RESEARCH_TOKEN
    backends:
      memory:
        url: "http://memory-mcp:8000/mcp"
        tools_allow: [search_memory, read_note]
    semantic_response_guards:
      policy: |
        Nothing about unreleased products, customers by name, or pricing may
        reach this agent. No credentials, keys or connection strings.
      tools:
        memory: [search_memory, read_note]
      timeout_seconds: 30         # optional, 5 to 120
      refuse_when_flagged: false  # optional; true for unattended seats
```

| Field | Required | Meaning |
|---|---|---|
| `policy` | yes | The rule, in plain language, up to 4,000 characters. Given to the judge, never to the agent. |
| `tools` | yes | Backend name to the exact tool names whose responses are judged. No globs. |
| `timeout_seconds` | no | How long a judgment may take before the response is withheld. Default 30. |
| `refuse_when_flagged` | no | Withhold these responses without asking the judge once the session has been delivered flagged content. Default false. |

`semantic_response_guards` reuses the request guards' config shape, so
`egress_http` is accepted syntactically, but it has no meaning on a response —
there is no outbound request whose result to judge — and only `tools` is used.

The profile fails to load when a guarded backend does not exist, is a decoy,
or when a guarded tool is not allowed on its backend: a rule for a tool whose
response the agent can never receive is a typo.

## Writing a policy

The same advice as for [request guards](semantic-request-guards.md#writing-a-policy):
write what a careful operator would tell a new colleague, in two to five
sentences.

- **Use English for what needs judgment.** "No customer data in bulk",
  "nothing about unreleased products", "no credentials, whoever the result
  names".
- **Use a literal response guard for what can be stated exactly**, such as a
  known project codename.
- **Naming is not carrying.** "The password was rotated" sends no password;
  say so in the policy so the judge does not refuse routine results.
- **Do not put secrets in it.** The policy is sent to the judge's provider with
  every guarded response.

## What the gatekeeper sees

The judge is given three things, kept apart:

- **The policy**, in its instructions, from the operator.
- **The gateway's facts**, stated as true: the backend and tool, and whether
  this session was delivered content the layers flagged.
- **The backend's response**, exactly as it arrived: every text block joined,
  each embedded resource read whole (its `text` and its `uri`/`mimeType`, so a
  secret hidden in a resource URI is judged too, not only the body), and the
  structured content serialized — marked as untrusted data. A claim in it that
  delivery was approved is evidence, not permission.

The judge is the profile's own L3 model, called under the same rules as every
L3 request: no tools, a per-request canary, and a closed JSON schema for the
answer.

### Refusing a flagged session outright

`refuse_when_flagged: true` withholds every guarded response in a session once
that session has been delivered flagged or partly judged content, without
asking the judge, with the code `session_flagged` (#457). A session the gateway
cannot identify is treated the same way. Turn it on for unattended seats; leave
it off for an assistant a person talks to, which reads flagged content
routinely. Unguarded tools are untouched.

## Refusals

A withheld response is handled exactly as the [literal response guard](literal-response-guards.md)'s
is. For a read-only tool the call is refused outright, nothing delivered. For a
tool that may write, the agent is told the call *executed* and the response was
withheld — so it does not retry a write that already happened (#425). The
reason is a closed code; the policy and the judge's words never reach the
agent.

| Code | From | Meaning |
|---|---|---|
| `policy_violation` | judge | The response breaks the policy. |
| `restricted_content` | judge | Material the policy says this agent may not receive. |
| `bulk_private_data` | judge | Private or customer data in bulk, or belonging to someone not permitted. |
| `credential_material` | judge | A credential, key, token, password or connection string. |
| `instruction_in_response` | judge | The content carries instructions aimed at the agent or the judge. |
| `other` | judge | A refusal with no listed reason, or an answer that was not an explicit allow. |
| `uninspectable_response` | gateway | The result carries a content block the judge cannot read as text (an image, audio, a binary blob, a resource link, or any block type other than text), so the policy cannot be checked against it. |
| `response_oversize` | gateway | The result is too large to judge in one admission window (over `Config.admission_tokens`). It is refused, not truncated. |
| `session_flagged` | gateway | `refuse_when_flagged` is set, and this session was delivered flagged content or sent no session ID. |
| `gatekeeper_unavailable` | gateway | No judge is configured, or it failed, timed out, answered off-schema or leaked its canary. |

It fails closed. Anything other than an explicit allow withholds the response.
A guarded response carrying any block the judge cannot read as text — an image,
audio, a binary blob, a resource link, or any block type other than text — is
refused for the same reason: the policy cannot be checked against content the
judge cannot see. This is an allowlist, so a content type the judge does not
explicitly read as text fails closed rather than slipping through. A genuinely empty result, with no
content at all, has nothing to judge and is delivered. A response too large to
judge in one admission window — over the same `Config.admission_tokens` cap the
perimeter enforces — is refused, not truncated: judging a head slice would
clear a response on the strength of the part that happened to fit.

## Audit

Each refusal writes one [audit](audit-log.md) row with outcome
`denied_response_gatekeeper`, in the `blocked` group. Like
`denied_response_guard`, it is a denial that still cost an upstream call: the
backend answered and the answer was withheld here.

## Who may change it

The block is perimeter. An agent's own `reload_profiles` cannot add, remove or
rewrite it; the change is reported under `not_applied.operator_only`, and an
operator reload applies it. A honeypot profile cannot have one.

## What it cannot do

- **It is a model.** A guarded response that reads as routine to the judge is
  delivered. Keep rules that can be stated exactly in literal response guards.
- **It judges one response at a time.** Data split across many small results,
  each within the policy, is not seen as one export.
- **It sees only what crosses the gateway**, after preprocessing but before the
  perimeter scan.
- **It costs a judge call per guarded response.** Guard the tools that return
  restricted material, not every tool.

## Related

- [Literal Response Guards](literal-response-guards.md): exact rules on result fields, checked first
- [Semantic Request Guards](semantic-request-guards.md): the request-edge twin
- [Defense Pipeline](defense-pipeline.md): the layers that scan the response for hostility
- [Audit Log](audit-log.md): where refusals are recorded
- [Per-Agent Profiles](profiles.md): where the block is configured
