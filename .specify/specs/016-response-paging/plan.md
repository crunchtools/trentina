# Implementation Plan: Responses Delivered in Parts

> **Spec ID:** 016-response-paging
> **Status:** Complete
> **Last Updated:** 2026-10-11

## Summary

Cut once at the router, after the pre-processors and before the scan; judge
each part through the existing `scan_tool_response`; serve later parts from
an in-memory store through a tool the router answers itself.

## Flow

```
tools/call get_doc
    │  backend answers, response guards, transform_response
    ▼
router._hold_paged ── text only, over whole_tokens, read_part allowed?
    │  no  → the path every response took before
    │  yes → paging.cut (tokenizer, off the loop) → paging.hold
    ▼
router._deliver_part(1) → scan_tool_response(part, lead_in="") → header, part, footer

tools/call read_part(handle, part=N)
    │  router._answered_here → router._read_part  (no backend)
    ▼
paging.find(profile, handle) → policy of the tool that produced it
    ▼
router._deliver_part(N) → scan_tool_response(part, lead_in=end of N-1)
    ▼
one gateway_calls row against that backend and tool, "part N/M"
```

## Decisions made while building

- The cut returns None, and nothing is paged, whenever it cannot place a
  token boundary: no model, a slow tokenizer, paging off. The old path then
  refuses or reads the head, as before.
- A character-count gate runs before the tokenizer: a text no longer than
  `whole_tokens` characters cannot be over it in tokens.
- `read_part` is declared in `server.py` so it is listed, judged at the
  perimeter and allowlisted like any internal tool, and answered in the
  router so its rows and its mode policy are the original tool's.
- A part's L3 briefing says it is a fragment and names its position; the
  briefing is in the verdict key, so a part's cached verdict is its own.
- `PERIMETER_VERSION` 17.
