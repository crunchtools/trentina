# Plan: Guarded Execution

> **Spec ID:** 019-guarded-execution
> **Status:** Complete
> **Last Updated:** 2026-10-14

## Summary

One new step at the end of `router._tools_call`'s refusals: for a guarded
tool, the arguments through `defend()`, then `quarantine_generate` with the
policy, the gateway's facts and the arguments as data. A refusal is audited
`denied_gatekeeper` and returned as `-32602` with a reason code.

## Architecture

### Request flow

```
tools/call → allowlist → mode → normalize → parameter guards → schema
           → [guarded] defend(arguments) → judge(policy, facts, arguments)
           → backend → response guards → scan → deliver (marks the session)
```

### Data flow

- First contact: `gateway_calls` (`profile`, `destination`, `outcome = 'ok'`).
- Session mark: set in `_deliver` and `_read_part` when a warning is
  delivered, read by `gather_facts`.

## Implementation Steps

### Phase 1: Configuration
`GuardedExecutionConfig`, the loader check, the reload hold, the honeypot rule, lint.

### Phase 2: The gatekeeper
`gatekeeper.py`, `session_marks.py`, `has_sent_to` and its index, the outcome.

### Phase 3: The router
`_refuse_call`, `_mark_session`.

### Phase 4: Tests and measurement
Unit, router, profile, reload and gap tests; the corpus, the runner and the CI job.

### Phase 5: Documentation and gates
`docs/guarded-execution.md`, README, profiles, parameter guards, audit log,
defense pipeline (gap 30), constitution 2.9.0, CHANGELOG 1.11.0.

## Decisions taken during implementation

- Internal backends may be guarded: `fetch_tool` carries data out in a URL.
  Only decoys are refused.
- The corpus describes payloads rather than reproducing them; the figures
  are stated as measured on described calls.
- The benchmark runs on merged code only, like every job that holds the key,
  so the docs ship with the control marked unmeasured and the figures follow.

## Risks and Mitigations

| Risk | Impact | Mitigation |
|---|---|---|
| The judge allows an attack | High | Parameter guards still bind; gap 30; per-scenario measurement |
| The judge refuses routine work | Med | Opt-in per tool; audit rows to tune the policy; false-refusal rate measured |
| Latency on guarded calls | Med | Only named tools; timeout refuses |
| The arguments flood the judge | Low | Admission cap through `defend()`; over it refuses |

---

## Changelog

| Date | Changes |
|---|---|
| 2026-10-14 | Plan written and completed |
