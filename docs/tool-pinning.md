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
excluded). The pin is keyed on the backend (a hash of its URL), the tool name
and **that hash**, so it belongs to the backend and not to a profile — and
since 6.1.0 one tool can hold several pins, one per definition it has been seen
with. That is because tool lists are fetched per credential: a backend whose
schemas depend on the account answers two profiles differently, and both
answers are real.

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

A tool that reverts to an approved definition is served again — but any OTHER
definition that was held stays held. Through 6.0.0 the revert cleared it, which
is unsound once lists are partitioned: "the backend went back to X" is only
true for the profile that listed X, and another profile may still be served Y.
Clearing Y on one profile's say-so was how two of them flapped the hold and
logged a detection on alternate passes. `tool_pins reject` is how an unwanted
definition goes away. A tool that disappears keeps its pins.

## Releasing

The operator profile's `tool_pins` tool takes `action` (`list`, `approve`,
`reject`, `approve_all`), `backend` and, for the middle two, `tool`. `list`
shows what is held, each entry's `hash`, the fields that changed against the
most recently approved definition, and whether a safety hint loosened. `reject`
keeps that definition withheld and quiet.

`approve` and `reject` also take an optional `hash`, which names WHICH held
definition. It is needed only where a tool has more than one — two profiles
served different bytes. With exactly one it is implied, so the two-argument
call stays correct; with several and no hash the tool refuses and lists the
hashes on offer, because there is no single thing "approve this tool" could
mean.

(Through 6.1.1 `hash` existed on the implementation and was never declared by
the registered tool, so the refusal named a parameter no caller could send and
a tool holding two definitions could not be released through the API at all.
6.2.0 wires it through. `tests/test_server.py` now fails on any registered tool
that drops, or silently ignores, a parameter its implementation takes.)

**One approval per distinct definition, not per profile.** A thousand profiles
on a backend that answers them identically is one decision. A backend that
bakes account state into a schema — an enum of that account's projects — is the
costly case: it will hold one definition per profile, and hold again whenever
that account's data changes. Nothing here can fix that; it is the backend's
shape.

**A pin follows the COMPRESSOR, not the backend.** The hash covers the
definition as SERVED, and under `preprocess_tool_descriptions` the served
description is a model's rewrite. So anything that makes the gateway
re-compress — losing `tool_compressions`, or a migration that cannot attribute
its rows, as 6.1.0's `owner` column did — changes every compressed definition
and holds every one of them, because re-compressing is a fresh call and not
byte-identical. It is fail-closed and correct, and on a real deployment it was
582 definitions across 352 tools on one federation link.

Tell it apart from a genuine upstream change by the fields: a re-compression
reports `description` or `description,inputSchema` across a whole backend at
once, where a rug pull is a few tools. The text in that case is your own
gateway's output over a list its own perimeter judged, so `approve` is the
right answer; it is still an operator's call rather than an automatic one,
because "the whole backend changed at once" is also what a hostile re-list
looks like.

### `approve_all`: one decision for a whole set (6.2.0)

Which is why that case is a batch and not a loop. 582 individual approvals is
not a control — it is how an operator learns to stop reading — so `approve_all`
makes the SET the unit of decision and gates it twice.

`list` returns a `digest`: SHA-256 over the sorted `(tool, hash)` pairs still
held. `approve_all` requires it and refuses if the live set no longer matches,
so a re-list that landed between the read and the decision cannot ride along.
A count would not do this: a re-list swapping N definitions for N others keeps
the count exactly, and the premise of #469 is that an approval names a
*definition*. This names a set of them.

Then the field rule: the batch refuses **unless every row's changed fields are
a subset of `description` and `inputSchema`** — the two the gateway's own
compressor rewrites. `annotations`, `name`, `title`, `outputSchema` and `new`
each refuse the whole batch, naming the tool that did it, and stay one
deliberate approval at a time. A tool with no approved definition at all is
exactly what pinning exists to put in front of a person; that does not change
because forty-nine of them arrived together.

`inputSchema` is in that set because the compressor rewrites the descriptions
**inside** a schema as well as the tool's own
(`compress._compressed_properties`) — which is why a re-compression reports
`description,inputSchema` on hundreds of tools at once, 278 of one gateway's 582.
What keeps that honest is the third gate: **a schema may differ from the
approved one only in its descriptions.** Both are compared with every
`description` annotation taken out, and anything else that moved refuses the
batch. Each held entry carries `schema_shape_changed` so a listing shows it.

It is deliberately an equality test and not a "did it grow" test. Growth was
the first design, and it would have passed a widened `enum`, a changed `type`,
a relaxed `additionalProperties`, a dropped property, and a `required` entry
added to one nested object that a sibling already had — none of which add a key
or a name, all of which change what a call means. Comparing what must not
change beats enumerating the ways it could.

Two positions where `description` is *not* an annotation are kept, because
there it is part of what a call must send: a property genuinely **named**
`description` (`_NAME_MAPS` tells an author's name from the schema's own
vocabulary), and a `description` key inside a `const`, `default`, `examples` or
`enum` value (`_LITERALS`, whose values are compared whole and never walked).

Nothing is approved unless every row qualifies, and the refusal names **every**
disqualifying tool (up to twenty, then a count) rather than the first — at 582
definitions, stopping at one would make clearing a backlog a round trip per
exception, which is the reading-nothing failure the affordance exists to avoid.
Clear those individually, then batch the rest.

The write itself is one transaction (`perimeter_db.set_pin_states`), and it
requires each row to still be `pending`: if any pair no longer matches, nothing
is committed and the operator is told to list again. That is what stops a
rejection landing mid-write from being overwritten. A batch that
released most of itself and reported the rest would be read as a success, and
the rows it skipped are the ones that needed reading. A `rejected` definition
is outside the digest entirely: it neither blocks the batch nor is reversed by
it.

What comes back is the manifest — every tool, hash and changed-field list it
released — and one `detections` row (`approved_bulk`, with the count) so the
decision is auditable after the fact and not only at the moment it was taken.
Tool names stay out of the log (#262); the count stands for them there.

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
a backend are the rows in `perimeter.db`'s `tool_pins` table whose `state` is
`pending`, keyed by the backend's URL hash, the tool and the definition hash. A
store written before 6.1.0 is re-keyed on first open and the old table is kept
as `tool_pins_pre_6_1`, so a rollback finds its approvals instead of holding
every remote tool at once.

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

Renaming the profile a link shares changes the URL path, hence the pin key, so the
peer's pins do not move and its next list is a first connect: the whole offered
set is approved as a unit again, loudly, once. There is deliberately no way to
carry pins across a rename — a one-time re-approval an operator can read beats a
setting that would migrate trust across a renamed link forever. Rewriting the
same endpoint a different way (a trailing slash, an explicit `:443`) is not a
rename and does carry its pins, reported as `federated_pins_migrated`.

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
