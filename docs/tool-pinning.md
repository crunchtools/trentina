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

## The call gate: detection at list time, enforcement at call time (#469)

A held tool is withheld from `tools/list` AND refused if called: a call to a
held remote tool is refused before the backend, as an ordinary result (not a
JSON-RPC error) carrying `reason: tool_held`. A federated downstream maps that
reason to its own words ("held upstream, awaiting approval"). Internal and
decoy backends are not gated — only remote ones.

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
