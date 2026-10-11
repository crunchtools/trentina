# Specification: Paging and Client Egress Follow-ups

> **Spec ID:** 017-paging-followups
> **Status:** Implemented (1.9.0)
> **Version:** 1.0.0
> **Author:** crunchtools
> **Date:** 2026-10-11
> **Tickets:** #446, #447, #448, #449, #450

## Overview

Five problems found while shipping response paging (#340, 1.8.0) and client
egress (#442, 1.6.0) were written down and left. This closes them together.

## What changed

| Ticket | Problem | Change |
|---|---|---|
| #446 | `fetch`, `read` and `content` judge at their own ingress, so they were not paged: over the admission cap they were refused, or read head-only under flag | Behind the gateway, `judge_and_deliver` cuts and holds through `gateway/paging.py`, returns part 1 in the tool's shape, and the rest is read with `read_part`. Every part is judged as the tool's source, so a late flag blocklists the URL |
| #447 | A document can carry a line that reads as the gateway's own `[TRENTINA]` notice | L1 counts it (`forgery_gateway_lines`); it raises L1's risk |
| #448 | Nothing measured L3 on an attack split across parts | `benchmarks/paging_l3.py`, run per shipped judge by the `paging` job |
| #449 | A client's opening burst of CONNECTs ran out of resolver slots and was refused as `unresolvable` | One check per name per burst, kept five seconds; a busy resolver is `resolver_busy`, 503 `denied_guard` |
| #450 | L2 flags machine-written meeting notes; block refuses them | Measured: it is the notes followed by a bare link ending in an identifier. The corpus carries the pair; the linked shape is known gap 28 |

## Decisions

- **#446, part 1 keeps the tool's shape.** An internal tool answers in JSON,
  so part 1 is `content`/`scan` led by `_trentina_part`, whose `read_next`
  holds the footer's words. Parts 2 on are the router's three text blocks.
- **#446, who is paged.** A profile that can call `read_part`, through the
  router. Standalone, an unbound caller and a honeypot are not: there is no
  store, or nothing may be said. `dir` and `search` are not cut.
- **#447 joins `suspicious_detections`.** Over this repository per file it
  fires in one of 441, and L1 alone refuses the same 34 with it as without.
- **#449 does not queue.** `egress._resolve` never waits for a slot (#291).
  Sharing one check per name removes the normal client's case without that.
- **#450 is not closed by a pre-processor.** The identifier is what the
  agent came for. Like gap 19, it is fixed at model selection.

## Not in this release

- A recorded run of `benchmarks/paging_l3.py`, and of the lone-flag join
  over the meeting notes: both need judge quota and run on merged code.
- Parts around image or blob blocks; valid JSON per part; read-ahead. Stated
  under known gap 27.

## Changelog

| Version | Date | Changes |
|---------|------|---------|
| 1.0.0 | 2026-10-11 | Implemented in 1.9.0 |
