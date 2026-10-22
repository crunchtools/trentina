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
