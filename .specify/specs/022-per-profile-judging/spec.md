# Specification: A Profile Pays For Its Own Tool Descriptions

> **Spec ID:** 022-per-profile-judging
> **Status:** Implemented (6.1.0)
> **Version:** 0.1.0
> **Author:** crunchtools
> **Date:** 2026-11-02
> **Ticket:** standalone (narrows #661; follows #138, #291)

## Overview

Judging and compressing a backend's tool descriptions runs as the **operator**
today, on the operator's key, and the resulting verdicts and compressed text are
shared by every profile whose thresholds and judge match. That was right when a
gateway held one person's agents and backends were shared between them. It is
wrong for a gateway holding tenants: one tenant's key pays for another tenant's
work, and a cache hit is a fact about a neighbour.

**Done is:** every model call a profile's own tool list causes runs on that
profile's key, and no verdict or compressed description reached for one profile
is ever served to another.

## Decision

Product (Scott, 2026-11-02), verbatim in substance: "We should not share this
cache between users. If/when we have a service, this is an attack vector I do
not want. Everything that a user's account touches should be done by its own
key. Also, users will not share backend MCP servers. Each profile will have its
own MCP servers. Imagine 1000 users. Yes, many of them will have Gmail accounts,
but many will have custom MCP servers used by no other accounts. No point in
having the operator account pay for tool description judging and compression."

Explicitly **not** in scope, and Scott agreed: the approved-`config_tool`-write
apply (`tools/config.py`) keeps binding the operator. It spends nothing — an
approval arrives from a browser with no bound caller, and `reload_profiles`
applies the whole file only for an operator, so without a bound operator an
approved change would be replaced and then refused by the reload. That is
operator work in the literal sense.

CTO (Josui, 2026-11-02): the caches are keyed per **`grant_owner`**, not per
name, so a derived federation ingress shares with the profile it was derived
from. Both are the same tenant spending the same key, and keying by name would
make every federated list a second bill. Separating the two halves of `role:
operator` (#661) is not needed for this and stays open for the admin half.

## What changes, in behaviour

| | Today | After |
|---|---|---|
| L3 over a tool **description** | operator's key and model | the listing profile's own |
| Description **compression** | operator's key and model | the listing profile's own |
| Verdict cache scope | every profile with equal thresholds and judge | one `grant_owner` |
| Compression cache scope | gateway-wide, keyed by description hash | one `grant_owner` |
| A profile with no `llm_keys` | the operator covered it | judges nothing; warned, and reported by `config_tool` |
| Approved config write | operator | operator (unchanged) |

## Why this is a MINOR

Scott challenged the first draft's 7.0.0 — "that feels excessive" — and he was
right; the reasoning behind it was sloppy. Taking the candidates apart:

- **Cache invalidation is not a break.** `PERIMETER_VERSION` has been bumped
  twenty times and `tool_list_edge.py` treats the cold start as a routine
  documented cost. The first boot re-judges and re-compresses each profile's
  descriptions — in production, 1,456 across 9 profiles, with 10 extra list fetches
  (26 distinct URLs becoming 36 partitions). Measured, not estimated.
- **The keyless-profile LOAD ERROR is gone.** It was this draft's main reason
  for a major and it was never part of what Scott asked for. Such a profile is
  already non-functional — every response reports `l3_unavailable` and block
  refuses it, and the loader has warned since RT #1505 — so refusing the file
  surfaces an existing breakage rather than preventing a new one. It stays a
  warning, and `config_tool` reports it in the write result, which closes the
  gap a warning leaves now that an agent writes the config (#633).
- **The result-shape changes are additive**: `no_llm_key`, `tool_pins`'s
  `hash`, and `/health`'s `pending_pins` counting distinct tools so its meaning
  is preserved. No config key changes meaning, no wire format changes, no tool
  is removed or renamed, and both tables are migrated rather than emptied.
- **The one genuine break** is a federated peer's `trust_verdict` re-pin, whose
  blast radius is inside `federation` — a declared preview surface — so it is a
  MINOR with a `### Preview` heading naming it.

CI's Gatehouse read Stability Tiers rule 1 as "any change reaching stable code
is a major". That would make every bug fix a major and the tier meaningless:
rule 1 is the contrapositive of the sentence above it, *a breaking change
confined to a preview surface is a minor*, and 6.0.0 applied exactly that test
on itself — a major for two rules that refused files which loaded before, with
its federation work noted as "a minor on its own". Ruled by the `cto` agent
after the version was challenged twice.

The sharpest consequence, and the one the Upgrading notes lead with: because
`internal://` descriptions are judged too, a keyless OPERATOR profile loses
`quarantine_stats` and `config_tool`, which worked before.

## Security Considerations

### The cross-profile channel being closed

`tool_list_edge.scan_tool_list` carries a `# TRUST:` block justifying the shared
verdict cache on the ground that "no agent chooses the text, so a hit is no
channel". That argument is sound for one person's gateway and insufficient for a
service: a hit is evidence that another profile is configured with the same
backend, and the shared cache makes one tenant's judging latency and spend
depend on another's. The block is rewritten rather than deleted, stating the new
scope and what it now rests on.

### What does not change

The perimeter still judges every description before any profile sees it, with
the same layers, the same briefing and the same provenance rule (compressed text
is `MODEL_OUTPUT` and earns unconditional L3). A profile's thresholds were
already its own and stay so. Nothing becomes reachable that was not reachable.

### One thing that gets stricter by accident, and is kept

`identity.posture()` reads the honeypot flag from the bound scope. With the
operator bound, a honeypot profile's descriptions were judged under the
operator's posture; with the profile bound they are judged under its own. That
is more correct and is asserted in a test rather than left as a side effect.

## Module Changes

### Modified Files

| File | Changes |
|------|---------|
| `gateway/tool_list_edge.py` | `_judge_description` binds the listing profile instead of `service_context(operator)`; `scan_tool_list` resolves `judge_of(profile)`; the `# TRUST:` block rewritten |
| `gateway/compress.py` | `compress_tools` takes the profile; `_service_provider` becomes `_provider_for(profile)`; `_cache` and `_param_key` keyed per `grant_owner` |
| `gateway/aggregate.py` | passes the profile into `compress_tools` |
| `gateway/verdict_cache.py` | `_cache_key` gains `grant_owner`; docstring records why the pre-#137 spelling no longer buys anything here |
| `database.py` | `tool_compressions` and `tool_list_cache` gain an `owner` column keyed `(owner, hash)` and `(backend_url, owner)` — the grant owner, so a derived federation ingress shares its source's rows; their accessors and a rebuild migration follow |
| `gateway/loader.py` | a new registry check: every profile holds a key for its resolved provider (ollama excepted), with the operator's existing rule folded into it |
| `gateway/warmup.py` | binds each profile for its own build if the per-description binding is not sufficient |
| `docs/operator.md` | the Service identity table and the Thresholds paragraph |
| `docs/compression.md` | who pays, and that the cache is per profile |
| `CLAUDE.md` | the "Operator profile / service identity (#138)" section |
| `CHANGELOG.md`, `pyproject.toml`, `server.json`, `__init__.py`, `uv.lock` | 7.0.0 |

## Testing Requirements

- [ ] Two profiles configured with the same backend URL judge its descriptions
      separately, each billing its own key (assert the provider was constructed
      with each profile's key, not one of them twice).
- [ ] A verdict reached for profile A is never served to profile B: same text,
      same thresholds, same judge, two judgements.
- [ ] A compressed description reached for A is never served to B.
- [ ] A derived federation ingress and its source DO share, via `grant_owner`.
- [ ] Warm-up judges every profile's descriptions with that profile bound
      (assert per-profile, not one identity for the run).
- [ ] A honeypot profile's descriptions are judged under its own posture.
- [ ] A profile with no `llm_keys` for its provider still LOADS, is named in
      `config_tool`'s `no_llm_key`, and ollama stays exempt.
- [ ] The `tool_compressions` migration: an old-schema database opens, and the
      pre-migration rows are not served to any profile.
- [ ] A cold-start cost measurement on a production-shaped config (9 profiles, 1,456
      descriptions, several shared backends), recorded in the PR so the
      regression is known rather than discovered in production.

## Dependencies

- Narrows: #661 (separating "may administer" from "whose key pays") — the
  billing half is answered here; the admin half stays open.
- Touches: #138 (service identity), #291 (the shared caches), #137 (the judge in
  the verdict key).

## Open Questions

1. Whether to delete the unreachable `tool_compressions` and perimeter verdict
   rows at migration or leave them to age out. Leaning delete: dead rows that
   can never match are worse than the disk they free.

## Changelog

| Version | Date | Changes |
|---------|------|---------|
| 0.1.0 | 2026-11-02 | Initial draft |
