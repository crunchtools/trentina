# Specification: Guarded Execution

> **Spec ID:** 019-guarded-execution
> **Status:** Implemented (1.11.0)
> **Version:** 0.1.0
> **Author:** crunchtools
> **Date:** 2026-10-14
> **Ticket:** #456 (from #29)

## Overview

Varonis's customer-export request passes every inbound layer (known gap 20):
nothing in its text separates it from a colleague's. The call it leads to,
bulk records to an address the profile has never written to, from a session
that was just delivered flagged mail, is easy to judge. Today only static
allowlists stand in its way, and only on the tools an operator remembered to
guard.

**Done is:** a profile names the tools that send, writes the rule in plain
English, and the profile's judge reads each call to them before it leaves.
Anything but an explicit allow refuses it.

## Decision

Product (Scott, 2026-10-14): a gatekeeper modelled on linux-mcp-server's
Guarded Command Execution, not a human approval queue. Opt-in per profile;
only named tools are judged; a "no" refuses outright. Rejected: an approval
queue (unattended seats have no human to ask), judging every tool not marked
read-only (cost and false refusals), turning it on for every seat (#270
keeps the assistants broad).

### Why after the guards, and why it only subtracts

The constitution assumes the judge compromised. A control built on it is
safe only if no answer from it can widen what an agent may do. So it runs
after the allowlist and the parameter guards, and an allow forwards nothing
those refused.

### Why the arguments cross the layers first

The arguments are the agent's text, perhaps an attacker's, and a model is
about to read them. They go through `defend()` as any payload does, which
also keeps the layer contract's one-read rule: no new L2 call site.

### Why first contact and the session mark

Both are facts the gateway already owns. The destination is recorded per
call (`destination.py`, #266); whether a profile has completed a call there
is one indexed probe. Whether the session was delivered flagged content is
known at delivery and was simply not kept; it is now, in memory.

## What is not decided

- Escalation to a human on a refusal (a later phase if wanted).
- A policy per tool rather than per profile.
- Session taint that removes tools outright (#457), which will reuse the
  session marks.

## Security considerations

- Fail closed on every judge failure, including a canary leak.
- The agent sees a closed reason code; the policy never leaves the gateway.
- Perimeter block: an agent reload cannot change it; refused on a honeypot.
- Known gap 30: the gatekeeper is a model, and judges one call at a time.

## Module changes

| File | Change |
|---|---|
| `gateway/gatekeeper.py` | new: facts, the arguments step, the judge, the refusal |
| `gateway/session_marks.py` | new: flagged sessions, by fingerprint, bounded |
| `gateway/profile.py` | `GuardedExecutionConfig`, `Profile.guarded_execution`, honeypot rule |
| `gateway/loader.py` | guarded tools must be allowed on their backend |
| `gateway/router.py` | `_refuse_call` runs the gatekeeper last; deliveries mark sessions |
| `tools/reload.py` | the block is held on an agent reload |
| `gateway/profile_lint.py` | `guarded-tool-no-destination` |
| `database.py` | `has_sent_to`, `idx_gateway_calls_sent_to` |
| `outcomes.py` | `DENIED_GATEKEEPER` |

## Testing

`tests/test_gatekeeper.py`, `tests/test_gatekeeper_corpus.py`, reload and
coverage-gap tests. `benchmarks/gatekeeper.py` over `corpora/gatekeeper.py`,
the six documented scenarios, per shipped judge, in the `gatekeeper` job of
`benchmark-decoys.yml` (merged code only).

## Changelog

| Version | Date | Changes |
|---|---|---|
| 0.1.0 | 2026-10-14 | Initial specification |
