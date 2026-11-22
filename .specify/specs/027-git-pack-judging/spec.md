# Specification: Judging What the Git Transport Carries

> **Spec ID:** 027-git-pack-judging
> **Status:** Draft, for review
> **Version:** 0.2.0
> **Author:** Scott McCarty
> **Date:** 2026-11-22
> **Ticket:** #453 (known gap 29), Ashigaru a1054

## Overview

`/proxy/git` decides which repository and which branch, and reads none of
what it carries (known gap 29). A pack crosses unjudged in both directions;
ref names are bounded and not read; forge-written text (side-band progress,
capability strings, a push's `ng` reasons) is passed on. A seat that clones
therefore reads repository content no layer saw, and `refs/pull/` stays
hidden because an outsider's pull request is exactly the content nobody
judged.

**Done is:** every object a profile receives through the route was judged by
L1 ∥ L2 → L3, or the fetch was refused, or the agent was told by object id
what went unjudged; at a cost bounded by what is new to that profile's judge,
not by the size of a repository's history. That is the precondition for
listing `refs/pull/` to a profile.

This spec decides **what is judged on a fetch**, **what it costs**, and **what
happens to a flagged object**, and names the rulings it needs. Push is phase 3
and only a credential scan.

v0.2.0 follows an adversarial review against the code and against git
2.56.1. The review's experiment overturned v0.1.0's main `block` mechanism
(leaving a flagged blob out of a partial clone): see
[A flagged object](#a-flagged-object).

## Decisions

- **Judge objects, read as git reads them.** The gateway inflates every entry,
  resolves deltas, and hashes each object itself. A pack's own claims (a
  `REF_DELTA` base id, its object count, its trailer) are checked, never
  trusted. Hashing follows git's `sha1dc` (collision-detecting SHA-1), or
  SHA-256 for a repository with that object format.
- **Chunks are the unit of caching, not objects.** A text blob is cut at line
  boundaries by a content-defined rule, about 2 KB a chunk (the boundary is a
  hash of the line, so an edit moves only the chunks around it). A chunk's
  verdict is keyed as `verdict_cache._cache_key` already keys one: `kind`
  (`git_blob`) and the chunk's text under the grant owner, thresholds, judge
  and prompt-pack stamp. A new version of a file costs only its changed
  chunks. This replaces v0.1.0's delta judging, which needed the previous
  version as a delta base: with `thin-pack` stripped (below) an incremental
  fetch carries no such base.
- **Chunks are judged with a lead-in**, the previous chunk's last 64 tokens,
  as a paged tool response's parts are (`gateway/paging.py`). A chunk is
  therefore read the same way a part is today. Whether that meets the layer
  contract for a whole file is the same question parts already answer; it is
  stated under [rulings](#rulings-needed) rather than assumed.
- **Strip what moves content off the judged path.** In the fetch request,
  before `check_upload_request` reads it and with pkt-line lengths recomputed,
  so the forge still parses exactly the bytes that were checked: `thin-pack`
  (a thin pack's deltas name objects only the client holds), `packfile-uris`
  (moves the pack to a URL), and `sideband-all` (re-frames every section and
  would need a second reader). The response is held to the sections git v2
  defines for `fetch` (acknowledgments, shallow-info, wanted-refs, packfile);
  anything else ends it. `bundle-uri` and `object-info` are already refused as
  commands (`git_wire.py`) and are now also removed from the advertised
  capabilities.
- **Forge-written text is replaced, not judged.** The forge's side-band
  channel 2 and 3 lines, on fetch and on push, are dropped and the gateway
  writes its own from a closed vocabulary. The `agent=` capability is
  rewritten to the gateway's. A push's `ng <ref> <reason>` keeps the ref and
  replaces the reason with `rejected`. Zero cost, and it closes a third
  unjudged channel.
- **Two modes, no off switch.** `flag` or `block`, per git grant, the way
  `EgressGrant.enforcement` is per grant, with the same disposition code:
  `dispose()` and `gaps_of().blocking()` as `judge_egress_response` uses them,
  and `TRENTINA_ENFORCEMENT_OVERRIDE` honoured. `profile.py` holds that every
  input runs every layer with no off dial, so v0.1.0's `off` is withdrawn.
  The consequence is a deployment cost, not a design one: turning this on
  starts judging every git grant at once, so it ships behind a release note
  and a warm-up (phase 1), and the default is `flag`. `redact` is refused, as
  for `llm_completion`.

## What is judged on a fetch

Each kind is judged through `defend()` with `provenance=EXTERNAL`, `source`
`git:<remote>/<owner>/<repo>@<oid>`, and `source_type` as below.

| Item | `source_type` | Text judged |
|------|---------------|-------------|
| Ref listing | `git_refs` | every ref name and `symref` target not already cached clean. The listing is buffered (4 MiB whole) so a name is judged before it is listed; the hidden-prefix and token rules still run first. |
| Commit | `git_commit` | the whole object text: message, author and committer names and emails, `encoding`, `mergetag`, `gpgsig` and any unknown header. Nothing verifies a signature at fetch, so it is text like the rest. |
| Annotated tag | `git_tag` | the whole object text |
| Tree | `git_tree` | entry names new to this fetch |
| Text blob | `git_blob` | its chunks, as above |
| Binary blob | `git_blob` | through the unpack stage, via `unpack.child.run_unpacking`. What unpack cannot open is `binary_unread`. |

Text is git's own rule: no NUL in the first 8,000 bytes. A NUL there makes
any file binary, which an attacker can use to make a file unreadable; that
lands it in `binary_unread`, which `block` refuses and `flag` names, so it
hides nothing.

Commits, tags, trees and ref names are small and many. They are grouped into
parts of up to `TRENTINA_PART_TOKENS` for one L3 call each, and their
verdicts are cached per part, never credited to a member: a member judged
alone could read differently.

**Out of scope, stated:** an instruction split across files (each is judged
alone); Git LFS objects and submodules, which reach the agent by other routes
(an LFS endpoint, another repository) and are judged, or not, there.

### Pack reading

A new module, `gateway/git_pack.py`; `git_wire.py` stays the no-pack reading
it is. Pure Python in a worker thread, written to the unpack stage's archive
discipline: zlib inflates, hashlib hashes, and nothing new joins the runtime
image. Its correctness bar is git's own reading: a differential fuzz against
`git index-pack --strict` (varint headers, a copy size of 0 meaning 0x10000,
duplicate objects, a `REF_DELTA` naming itself) gates the module, since a
reader that disagrees with git is a way past it.

Bounds, each a refusal in `block` and an unjudged delivery in `flag`:

- the pack spooled to the data volume, and inflated objects spooled there too
  rather than held in memory: `git.max_judged_pack_bytes`, default 256 MiB
  arrived and 2 GiB inflated;
- 1,000,000 objects; a delta chain depth of 50 (git's default);
- one judged fetch in flight per profile (the other seven slots still serve
  listings and pushes), so the inflated bound is per profile, not per request;
- a judging deadline, `git.judge_deadline`, default 15 minutes; past it the
  rest is unjudged;
- a `REF_DELTA` whose base is not in the pack (a thin pack sent anyway):
  refused, `thin_pack`.

`block` holds the pack until it is judged. While it waits the gateway sends
side-band progress lines (`Trentina: judged 1200/4810 objects`), which keep
git's connection alive and tell the agent why it is waiting. Under v2 these
start only after the `packfile` section header is forwarded, the first point
band 2 is valid. A v0 client that did not negotiate `side-band-64k` is
refused; git always does.

## Cost

L2 is 0.7 ms a token on production CPU (`DEFAULT_PART_TOKENS`'s note in
`config.py`), about 1,430 tokens a second. L3 runs on every judged text and
bills the fetching profile's `llm_keys`. Tokens are estimated at four bytes a
token, which is optimistic for code; the real ratio is a phase-1 measurement.

Measured on this repository (1,867 commits, 9,241 blobs), with the chunk rule
above run over every text blob in history:

| Fetch | New to the judge | ~Tokens | L2 CPU | L3 calls |
|-------|------------------|---------|--------|----------|
| Full clone, cold, whole blobs (v0.1.0 baseline) | 401 MiB | 105M | ~20 h | ~8,800 parts |
| Full clone, cold, chunked | 26,091 unique chunks, 46 MiB; 1.4 MB of messages | 12M | ~2.4 h | ~1,000 parts |
| Checkout of HEAD, cold (partial clone) | 949 files, 15.5 MiB | 4M | ~50 min | ~340 parts |
| Any of these, warm cache | nothing | 0 | seconds to inflate and hash | 0 |
| A day of fetches, steady state (~26 commits a day here) | ~25 KB of new chunks a commit | 160K a day | ~2 min a day | ~26 |

L3 calls assume new chunks are grouped into 12K-token parts. Whether a clean
part may be credited to each chunk in it is a [ruling](#rulings-needed); if
not, every chunk is its own call and the cold-clone row is about 26,000 calls.
The benchmark's $0.14 to $0.19 per 1,000 calls was measured on short
documents, so L3 dollars for 12K-token parts are a phase-1 measurement, not a
figure this spec can quote.

Four things follow:

1. **Whole-blob judging of history is not viable**, and chunking makes a full
   clone a few hours of L2 rather than a day.
2. **The cold first fetch is the cost, paid once per judge while the verdicts
   last.** The gateway warms the cache ahead of the agent (phase 2): a grant's
   `warm` list names repositories whose default branch the gateway fetches and
   judges on a schedule, so a seat's clone finds it judged.
3. **The steady state is cheap**: minutes of L2 a day for a busy repository.
4. **L2 is shared, and a clone must not starve tool calls.** The gateway runs
   two L2 scans at once (`TRENTINA_L2_CONCURRENCY`), handed out by
   `classifier.FairGate`. Git judging and warming take a background class there
   that yields to any waiting tool call. Their L3 calls count against a quota
   of their own, `git.l3_daily_quota`, so a clone cannot spend the profile's
   `l3_daily_quota` and refuse its tool calls.

The verdicts live in their own bounded table in `perimeter_db`, read on demand
and LRU-evicted, not loaded into the 16K-entry in-memory cache at startup:
an attacker-controlled repository can mint chunks without limit.

## A flagged object

A pack cannot be edited in place: an object's id is its content, and every
tree and commit above it names that id. The review then established, on git
2.56.1, that **git cannot take a partial answer either**. A blobless clone's
checkout fetches every blob it needs in one promisor batch, and when that
fetch is refused git prints `fatal: could not fetch <oid> from promisor
remote`, exits 128 and checks nothing out. So under `block` a flagged object
refuses the fetch it came in, whole.

| | `flag` | `block` |
|---|---|---|
| Flagged object (any kind) | delivered; named on side-band | that fetch refused |
| Unjudged (bounds, deadline, `binary_unread`, L3 unavailable or over quota) | delivered; named as unjudged | that fetch refused |
| Flagged ref name | listed; named | dropped from the listing |

- **Named, not quoted.** The side-band line is `Trentina: flagged <kind>
  <oid> (<layer>, <risk>)` or `Trentina: unjudged <kind> <oid> (<gap>)`:
  closed words and an id, never a path or any content. git prints it as
  `remote: Trentina: ...`. More than 20 is one line with the count. The agent
  maps an id to a path with `git rev-list --objects`.
- **Refusing a fetch** sends band 3 `refused by Trentina: git_flagged` (or
  `git_unjudged`), which git prints as `fatal: remote error:`. In `block` no
  byte of the pack was sent. Outcome `blocked_defense`.
- **Recorded per object.** One `detections` row per flagged object, joined by
  `call_ref`, `blocked` set in `block`. Unjudged objects are counted on the
  `gateway_calls` row; they are not detections.
- **Released by a person.** An operator-only `git_object_release` adds an
  object id, per remote and grant, that is delivered despite its verdict,
  after someone read it. It stages through the approvals flow; an agent cannot
  release its own. Under `block` this is not an edge case but the main path
  (below), so it ships with `block`, not after it.
- **A partial clone's narrower blast radius is untested.** Leaving one blob
  out of an otherwise delivered pack, for a client that asked with `filter`,
  might let the rest of a fetch through; it might equally trip the client's
  connectivity check. It is an experiment in the harness, not a mechanism,
  until it passes. A sparse checkout that never asks for the file is the
  agent's own way round a flagged blob.
- **No session label.** The route is sessionless, as `/proxy/http` is
  (spec 026): a flagged fetch cannot mark the session that runs git.

**What that means for `block`.** The best judge flags about 0.8% of benign
cases (3 of 362, `docs/benchmark.md`). Across this repository's 9,241 blobs
that is on the order of 75 objects, any one of which refuses a full clone,
and this repository ships attack fixtures on purpose. A font, a `.so` or a
`.jar` is `binary_unread`, which `block` never excuses. So `block` is for
repositories whose history has been warmed and released clean, and is
measured on code before it is offered: phase 1 runs `flag` and records the
false-positive rate on real fetches.

## Push (phase 3)

A push is the agent's own output, so injection judging buys little. The same
reader runs `credential_shapes.kinds` over every new blob and commit of a
push before the pack is forwarded, and refuses `credential` on a match unless
the kind is in the profile's `credentials_allowed`. Deterministic, no L2 or
L3. It needs the push spooled, which holds it until read.

## Configuration

```yaml
profiles:
  agent1:
    git:
      github:
        fetch: [acme/*]
        enforcement: flag          # flag (default) | block
        max_judged_pack_bytes: 268435456
        judge_deadline: 900
        l3_daily_quota: 2000
        warm: [acme/widgets]       # phase 2
        show_refs: [refs/pull/]    # phase 3; loads only with enforcement: block
```

Lowering a grant from `block` to `flag` is standing a perimeter down and
stages for a person, as `config_guard.defense_downgraded` does for
`llm_completion`. `show_refs` lifts a `hidden_refs` prefix for one grant and
loads only under `block`, where a pull request's content is judged before
delivery. `want` by object id stays unrestricted; under `block` what it
fetches is judged too.

## Rulings needed

1. **Verdict lifetime.** `verdict_cache.py` expires verdicts (24 h, #817,
   constitution 2.20.0 condition 3) because a model alias can drift under one
   name. "Paid once per judge" needs git verdicts to live longer: days, or
   until the judge stamp changes where the stamp pins an exact model version.
   Without a ruling they take the existing TTL, and warming becomes a daily
   job.
2. **Crediting a part.** May a clean verdict on a 12K-token part be credited
   to each chunk in it? Yes is ~1,000 L3 calls for the cold full clone above;
   no is ~26,000.
3. **Chunks and the layer contract.** A file judged as chunks with a lead-in
   is read the way a paged response is. Is that rule 1 of the layer contract
   for a file the agent receives whole?
4. **Unreadable binaries under `block`.** `binary_unread` is never excused.
   Either `block` refuses any repository with a font in it, or git gets a
   ruling the rest of the gateway does not have.

## Phasing

1. **Reader and `flag`.** `git_pack.py` and its differential fuzz, chunking
   and the verdict table, the request and capability rewrites, forge text
   replaced, side-band naming, detection rows, the FairGate background class
   and the git L3 quota. Measured on the development seats: false-positive
   rate on real fetches, bytes per token on code, L3 dollars per part.
2. **`block` and warming.** Holding the pack with keepalives, refusal,
   `git_object_release`, `warm`. The partial-clone omission experiment.
3. **`show_refs` and push.** `refs/pull/` to a `block` grant; the push
   credential scan.

Each phase that narrows gap 29 moves its Coverage rows in
`docs/defense-pipeline.md` and its hold-open test in
`tests/test_coverage_gaps.py` in the same change, as every gap does. What
remains after phase 3: push contents, cross-file instructions, and
authorship (a judged commit is still not one the owner wrote).

## Tests

- Real `git` against `git http-backend` through the route (the existing
  harness), protocols v0, v1 and v2, SHA-1 and SHA-256 repositories: a clean
  clone under `block` arrives intact and `git fsck` passes; a planted
  instruction in a blob, a commit message, a commit header, a file name, a
  branch name and a `symref` target is each named under `flag` and refuses the
  fetch under `block`; a refused lazy fetch fails as git 2.56.1 was seen to.
- The reader: a differential fuzz against `git index-pack --strict`, and
  hostile packs (a delta chain past 50, a base outside the pack, a count that
  lies, a bad trailer, an inflation bomb, a `REF_DELTA` naming its own id),
  each a refusal and none a hang.
- The cache: a second clone performs no `defend()` call; an edited file
  re-judges only the chunks around the edit; a changed threshold re-judges
  everything.
- What the forge receives has no `thin-pack`, `packfile-uris` or
  `sideband-all`; what the client receives has no forge side-band text, no
  forge `agent=`, and no `bundle-uri` or `object-info` capability.
