# Tool Pinning

A changed tool description is re-judged by the three layers, but a rug pull
that stays benign-looking is not: a new destructive tool behind
`tools_allow: ["*"]`, a `destructiveHint` that flips to false, a schema that
grows a `recipient` or `url` parameter. Pinning (#469) notices that a tool
*changed*.

## What is pinned

Every tool a remote backend lists is hashed whole: SHA-256 of the canonical
JSON of the tool object (name, title, description, inputSchema, outputSchema,
annotations, and any other field the backend sends; `_trentina_*` keys
excluded). The pin is keyed on the backend (a hash of its URL) and the tool
name, so it belongs to the backend and not to a profile.

The check runs every time a profile's tool list is built, which includes the
rebuild after a `notifications/tools/list_changed` re-list.

## What is held

A tool that is **new**, or whose hash differs from the approved one, is
withheld from **every** profile until an operator approves it. An explicit
`tools_allow` entry and `*` do not exempt it, and neither does the profile's
mode. A change that loosens a safety hint (`readOnlyHint` to true,
`destructiveHint` to false) is marked as such. Each hold writes a `detections`
row (`source_type` `tool_pin`) and a warning log naming the backend, the tool
and the changed fields. Nothing the backend wrote is logged.

A held tool that reverts to the approved definition is released. A tool that
disappears keeps its pin.

## Releasing

The operator profile's `tool_pins` tool takes `action` (`list`, `approve`,
`reject`), `backend` and, for the last two, `tool`. `list` shows what is held,
the fields that changed and whether a safety hint loosened. `reject` keeps the
tool withheld and quiet until it changes again.

## First boot, and a lost store

Pins live in the perimeter store (`perimeter.db`), beside the verdicts, and
never expire. On the first start after upgrading an existing store, the tools
seen in the first ten minutes are pinned as approved so nothing goes dark. A
store that is missing holds every tool until an operator releases it: that is
the fail-safe direction.

The store is a second database from the blocklist on purpose; losing it costs a
slow restart AND every **non-federated** tool held for re-approval, which is
dark rather than silently trusted. A **federated** backend is the one exception
(see below): with its pins gone, its first reconnect is a first connect, so its
whole offered set is auto-approved as a unit rather than held — the trust there
is in the declared edge, not the store. `cache_flush` and `reconnect_backend` rebuild a profile's
aggregate from the in-memory config and do **not** touch pins — a pin is cleared
only by `tool_pins reject`/`approve` or by losing the store. The held tools for
a backend are the rows in `perimeter.db`'s `tool_pins` table with a non-null
`pending_hash`, keyed by the backend's URL hash.

## Federation: first connect, and held on the secondary

When a backend is a **federated** peer (see [Federation](federation.md)),
pinning behaves differently in two ways, both because the primary trusts the
declared link:

- **No first-connect storm.** A federated backend's **first** tools/list is
  approved as a unit, not held tool by tool — a large secondary offering hundreds
  of tools does not storm the operator, and its set already passed the peer's
  own pin gate. "First" is a persisted marker (so an empty first list still
  records the connect); after it, a newly added or changed secondary tool is held
  one at a time, exactly as a non-federated backend's would be. A non-federated
  remote backend still holds every new tool on first sight.
- **Held state is visible on the primary.** The secondary reports a count of the
  tools it is withholding in the caller's slice (names never cross), surfaced per
  federated backend. When the secondary's call gate refuses a held tool, the
  primary reads the closed `tool_held` reason and answers the agent with its
  own `tool_held_secondary` — "held on the secondary, awaiting approval" — never
  the peer's text. The unauthenticated `/health` probe carries a gateway-wide
  count of tools pending approval, for monitoring. Approving a federated hold is
  done on the **secondary** that holds it.

## The call gate: detection at list time, enforcement at call time (#469)

A held tool is withheld from `tools/list` AND refused if called: a call to a
held remote tool is refused before the backend, as an ordinary result (not a
JSON-RPC error) carrying `reason: tool_held`. A federated primary maps that
reason to its own words ("held on the secondary, awaiting approval"). Internal
and decoy backends are not gated — only remote ones.

Detection of a changed tool stays at `tools/list` time (the aggregate build);
enforcement is at call time. There is deliberately no per-call re-validation of
a tool's current definition against its approved hash. A pin binds the
definition the AGENT READS — tool poisoning works through the description and
schema the model is shown, and the agent only ever sees the gateway's served
(approved) list. A backend that changed its definition after approval but
before the next `tools/list` has changed something no agent has read, and the
call the agent makes was composed against the approved text, so that window
holds no exposure the pin exists to close. What a backend DOES on a call can
change at any time with no definition change at all; the response perimeter,
which runs on every call, is the defence there, not the pin.
