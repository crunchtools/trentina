# Plan: Tool Discovery

> **Spec ID:** 021-tool-discovery
> **Status:** Complete
> **Last Updated:** 2026-10-17

## Summary

A `ToolDiscoveryConfig` on the profile, a search index over the served
aggregate, and a shaping step between the cached aggregate and the
tools/list answer. Discovery tools are answered in `_route_tools_call`
before name resolution; `call_tool` re-enters `_tools_call`.

## Architecture

```
tools/list → aggregate (cached, judged) → discovery.shape(profile, session)
tools/call find_tools → tool_search over the aggregate → audited ok
tools/call call_tool  → _tools_call(inner name) → every rule → one row
tools/call load_tools → session's loaded set → notify_session(fingerprint)
```

## Implementation Steps

1. `profile.py`: `ToolDiscoveryConfig`, `Profile.tool_discovery`,
   `category_of`, validators.
2. `tool_search.py`: tokenizer and stemmer, BM25F, trigram fallback.
3. `discovery.py`: definitions, `shape`, `find`, `load`, per-session sets,
   the instructions line, `describe`.
4. `router.py`: initialize, tools/list, the meta dispatch, `_leaked`
   unwrapping `call_tool`, `describe` in the build.
5. `sessions.py`: the `list_changed` spelling, `notify_session`,
   `on_remove`.
6. Corpus, benchmark, tests, docs.

## Testing

`tests/test_tool_search.py` (ranking, stemming, accuracy floor) and
`tests/test_gateway_discovery.py` (listing per mode, instructions, find,
call parity with the allowlist, guarded execution and honeytokens, dynamic
loading and per-session notify, config validation).
