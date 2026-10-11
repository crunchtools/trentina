# Specification: Responses Delivered in Parts

> **Spec ID:** 016-response-paging
> **Status:** Implemented (1.8.0)
> **Version:** 1.0.0
> **Author:** crunchtools
> **Date:** 2026-10-11
> **Ticket:** #340

## Overview

L2's cost is linear in what it reads and an MCP client waits about a minute.
A large proxied response either ran past that wait or, over 32,768 tokens,
was refused. An agent could not read a long transcript, wiki page or search
listing through the gateway at all.

A proxied text response too large to judge in one call is now cut into parts
and each part is judged, whole, by all three layers when the agent asks for
it.

## What was measured first

30 days of `gateway_calls` on production, 11,481 calls with a size:

| delivered size | calls over it | share of bytes |
|---|---|---|
| 2 KB (about 512 tokens) | 28% | 93% |
| 32 KB | 2.1% | 36% |
| 128 KB (about the admission cap) | 0.3% | 15% |

Median 360 bytes, mean 4.3 KB, 95th percentile 21 KB. With the current L2
model, a 32 to 64 KB response took 13.5 s at the median and 29 s at the 95th
percentile; 19 of 5,711 calls passed 50 s, several under the cap.

Part size does not change the total L2 work, and each extra part costs an
L3 call and an agent turn. So a part is the largest thing that reliably
beats the timeout. Paging at L2's 512-token window would page 28% of calls
to fix a problem in 2% of them.

## Decision

- Parts aim for 12,000 L2 tokens (`TRENTINA_PART_TOKENS`). A response up to
  16,000 is delivered whole. Over that: `ceil(total / 12,000)` near-equal
  parts, at most 16 (`TRENTINA_MAX_PARTS`).
- The call returns part 1. One new tool, `read_part(handle, part)`, returns
  the rest and reaches no backend.
- Paging applies in every mode.
- The word is "part". `get_page`, wiki pages and PDF pages own "page".

Two designs were written independently and merged. Both rejected re-calling
the original tool with a page argument: an agent that drops the argument on
a tool that writes makes it act twice.

## What the agent reads

Three text blocks per part, all gateway-written:

```
[TRENTINA] Part 2 of 5 of the get_doc response. It was too large to judge in
one call, so it is delivered in 5 parts, each judged by all three layers.
This part is not the whole response.

<the part>

[TRENTINA] End of part 2 of 5. For part 3 call read_part(handle="…", part=3).
Do not call get_doc again for the rest: the whole response is already held,
and calling it again starts over. If you answer from fewer than 5 parts, say
which you read. The handle expires after 10 minutes without use.
```

`_trentina_part` carries `part`, `parts`, `delivered`, `handle` and `next`.
`read_part()` with no arguments lists what the profile holds, for an agent
that lost its handle. The count never changes after the cut.

## Rules

1. Parts end to end are the response's text: nothing added, removed or
   repeated between them.
2. Every part crosses `defend()` in full, when asked for, in the first
   call's mode unless the `read_part` call names another its policy allows.
3. A part is judged behind the last 64 tokens of the part before it and
   delivered without them.
4. block: a flagged part is refused, and every later part is refused
   unjudged. The refusal says the parts already delivered are untrusted.
   flag: delivered with the warning. redact: the question is asked of each
   part. A gap on one part refuses that part only.
5. The remainder lives in memory only, under a 128-bit handle bound to the
   profile: 10 minutes unread, 4 responses and 32 MiB a profile, 128 MiB in
   all, released after the last part.
6. Unknown, expired, evicted and another profile's handle get one refusal.
7. A profile whose internal backend does not allow `read_part_tool` is not
   paged. A response with an image or a blob is not paged. Over 16 parts is
   refused as over the admission cap.

## Security considerations

- **Unjudged content at rest.** The remainder is attacker text nobody has
  judged. It is never written to disk and is bounded per profile and in all.
- **Forged markers.** A backend's `_trentina_part` is stripped with every
  other reserved key before the scan. A document can still contain a line
  that reads like the gateway's; a forged "last part" makes an agent read
  less, and a forged handle resolves to nothing.
- **Cross-profile.** The handle is bound to the profile, and every failure
  to resolve one is the same refusal.
- **What is weaker.** L3 reads a part, not the response, and parts delivered
  before a flag cannot be recalled. Known gap 27.

## Module changes

| File | Change |
|------|--------|
| `gateway/paging.py` | New: the cut, the store, the text an agent reads |
| `gateway/router.py` | `_hold_paged`, `_deliver_part`, `_read_part` |
| `gateway/ingress_defense.py` | `scan_tool_response(lead_in=…)` |
| `quarantine/classifier.py` | `token_offsets` |
| `config.py` | part size, part count, hold time; `whole_tokens`, `paged_tokens` |
| `gateway/backend.py` | byte cap follows `paged_tokens` |
| `server.py` | `read_part_tool` declared |

## Testing

`tests/test_paging.py`: the cut, the store, and the router end to end in
every mode. `benchmarks/paging_split.py` measures L2 on an attack a boundary
cuts in two.

## Not in this release

- The internal tools (`fetch`, `read`, `content`) are not paged.
- An L1 pattern for gateway-styled lines inside a document.
- Parts around image or blob blocks; valid JSON per part; read-ahead.
- L3 measured on an attack split across parts.

## Changelog

| Version | Date | Changes |
|---------|------|---------|
| 1.0.0 | 2026-10-11 | Implemented in 1.8.0 |
