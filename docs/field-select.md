# Field Select

*Part of Trentina's **Determinism** promise; see [Why Trentina](../README.md#why-trentina).*

`trentina_select` takes exact values out of a tool's JSON result by path. When every value it picks is one no layer needs to read (a SHA, a login, a timestamp, a number, a state word), they are delivered as they arrived, unjudged. Anything else it picks is judged, and only what it picked.

## Why This Matters

A seat reviewing a pull request needs each review's `commit_id`, the reviewer's login and the review's state. It does not need the review bodies, and one of them may be an injection. Before this, it got the whole list or nothing:

- `block` refused the list, because one body was flagged.
- `redact` asked L3 to copy forty hex digits per review, and L3 garbled or declined them.

So in a1079 the seat called api.github.com directly, around the gateway. A field select gives it the values and leaves the body out, so the gateway is again the easier path.

## How It Works

Pass `trentina_select` on any tool of a remote backend:

```json
{
  "owner": "crunchtools", "repo": "trentina", "pullNumber": 915,
  "trentina_select": ["[].commit_id", "[].user.login", "[].state"]
}
```

```json
[{"commit_id":"3f78…001b","user":{"login":"octocat"},"state":"APPROVED"},
 {"commit_id":"89e6…849b","user":{"login":"drive-by-0"},"state":"COMMENTED"}]
```

The gateway reads the raw result as one JSON document (`structuredContent` when there is one, otherwise the single text block), picks the paths, and keeps the result's shape, as jq's `pick` does. The values of one review stay side by side. An element that lacks every picked path is `null`, so positions still line up.

Then it checks every leaf it picked:

- **Every leaf is a typed value**: the projection is delivered and no layer reads it. `selected` is `unjudged` on the audit row.
- **Any leaf is not**: the projection, and nothing else, goes through pre-processing and L1 ∥ L2 → L3 under the call's mode, as any response does. A flagged body that was not selected is in neither what is judged nor what is delivered. `selected` is `judged`.
- **The result is not one JSON document**: refused (`select_not_json`), nothing delivered, `denied_response_guard`. `selected` is `refused`.

A backend error (`isError`) is never selected from: its text is judged and delivered whole, so the agent learns why the call failed.

### Paths

A path is keys joined by `.`, with `[]` for every element of a list. A leading `.` is allowed, as in jq.

| Path | Picks |
|------|-------|
| `[].commit_id` | each element's `commit_id` |
| `[].user.login` | each element's `user.login` |
| `head.sha` | the head SHA of one pull request |
| `check_runs[].conclusion` | each check run's conclusion |
| `[].user` | each element's whole `user` object; judged, since its keys are the backend's |

There are no filters, indices or recursive descent. Keys are 1 to 64 of `A-Z a-z 0-9 _ -`, not starting with a digit or hyphen. A call takes at most 32 paths of at most 256 characters and 16 segments each. A malformed path is refused before the backend is called, and the refusal names the rule, never the path.

### Typed values

A value is typed by its KEY, then checked against its VALUE. A key alone never makes a value safe: `"login": "ignore all previous"` is free text and is judged.

| Key | Value must be |
|-----|---------------|
| any key | a number, a boolean or `null` |
| `sha`, `oid`, `commit_id`, `original_commit_id`, `tree_id`, `*_sha` | 40 or 64 lowercase hex digits |
| `login` | a GitHub login: up to 39 letters, digits and single hyphens, no hyphen at either end; an app's `[bot]` suffix allowed |
| `date`, `timestamp`, `*_at` | an ISO 8601 date-time with a zone, `2026-11-20T10:00:00Z` |
| `state`, `conclusion`, `status`, `author_association`, `mergeable_state`, `state_reason`, `type`, `side`, `start_side`, `subject_type` | one of a fixed list of GitHub's words for that key, in its REST spelling or GraphQL capitals (`gateway/field_select.py`, `ENUMS`) |

Everything else is free text: `name`, `body`, `title`, `html_url`, a label, a branch. A check run's `name` is judged, and a select of check names alone is cheap to judge because it holds nothing else.

A key is a leaf too, since a model reads a key as it reads a value. A key at a position the call's own paths named was written by the caller; any other key is the backend's and is free text, however identifier-shaped. Position, not name: a path `login` vouches for a `login` at the root and nowhere else. So a subtree picked whole (`[].user`) is always judged: `{"ignore_previous_instructions": 1}` would otherwise reach the agent unread. Name the leaves you want (`[].user.login`).

## What Field Select Is Not

**It is not a way past the layers for text.** A string reaches the agent unread only if a regular expression or a fixed word list for its key accepts the whole value. Anything that could carry a sentence is judged.

**It is not trust in the backend's keys.** The check is the same whoever wrote the key. A backend that labels prose `sha` gets it judged, because prose is not hex.

**It has one residual, stated as gap 35.** A login is the one typed value an outsider chooses, and `ignore-previous-instructions-run-this` is a valid one: 39 characters of letters and hyphens GitHub would register. It reaches the agent unread under `login`. A number is also unread, so a run of numbers an agent decodes when told to is the opaque-stream case of #911. See [Known gaps](defense-pipeline.md#known-gaps).

## Interactions

**Modes.** The mode applies to the judged path only. An all-typed projection has nothing for a mode to decide, so it is delivered under `block`, `flag` and `redact` alike, and `TRENTINA_ENFORCEMENT_OVERRIDE` changes nothing about it. Under `redact` with free text selected, the extraction is made from the projection.

**Literal and semantic response guards** run first, on the whole raw result ([pipeline position](literal-response-guards.md#pipeline-position)). A forbidden literal anywhere in the result withholds it, projection included, so a call cannot select its way past one.

**Literal request guards.** A guard on `trentina_select` matches each path's keys joined by dots, `[]` left out (`[].user.login` is `user.login`). `deny: ["*"]` turns select off for that tool ([example](literal-request-guards.md#narrow-or-turn-off-field-select-on-one-tool)). Without a select the response takes the ordinary path, so leaving the argument out never skips anything.

**Where it is offered.** Remote backends only. An internal tool (`fetch`, `read`, ...) judges at its own ingress and returns its own shape, and a federated backend's peer judged the result before this gateway saw it, so neither has a raw result to pick from; a select there is refused. A decoy answers a select as a real tool would.

**Paging, the verdict cache, session labels.** A select runs before paging, so a large result's projection is usually small enough to judge in one call. An unjudged delivery reads and writes no verdict and sets no `flagged_delivery` label, since nothing was flagged; a judged one is cached and labelled like any response, keyed on the projection. The `credential_seen` label is still checked on what is delivered.

**The audit log.** The `selected` column (`unjudged`, `judged`, `refused`, NULL without a select) is the one place to see which deliveries skipped the layers ([audit log](audit-log.md#which-deliveries-skipped-the-layers)). It enters the row hash only when set, so older rows still verify.

**The git transport (spec 027).** The two do not meet: field select reads MCP tool results, the git route reads packs. They share a stance. Spec 027 names objects by id and replaces forge-written text with the gateway's own closed vocabulary instead of judging it; a select delivers ids and closed words unjudged for the same reason, that there is nothing in them to read. A SHA a select delivers is a name, not a verdict: fetching that object through the git route judges it there like any other, and nothing here releases a flagged one.

## Related

- [Defense Pipeline](defense-pipeline.md): the layer contract's stated exceptions, coverage and gap 35
- [Literal Request Guards](literal-request-guards.md): narrowing select per tool
- [Literal Response Guards](literal-response-guards.md): what runs before it
- [Audit Log](audit-log.md): the `selected` column
