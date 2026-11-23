# Specification: Judging What the Git Transport Carries

> **Spec ID:** 027-git-pack-judging
> **Status:** Draft, rulings recorded
> **Version:** 0.3.3
> **Author:** Scott McCarty
> **Date:** 2026-11-22
> **Ticket:** #453 (known gap 29), Ashigaru a1054

## Overview

`/proxy/git` decides which repository and which branch, and reads none of
what it carries (known gap 29). A pack crosses unjudged in both directions;
ref names are bounded and not read; forge-written text (side-band progress,
`ERR` packets, capability strings, a push's status lines) is passed on. A
seat that clones therefore reads repository content no layer saw, and
`refs/pull/` stays hidden because an outsider's pull request is exactly the
content nobody judged.

**Done is:** every object a profile receives through the route was judged by
L1 ∥ L2 → L3, or the fetch was refused, or the agent was told by object id
what went unjudged or is still pending; at a cost bounded by what is new to
that profile's judge, not by the size of a repository's history. That is the
precondition for listing `refs/pull/` to a profile.

This spec decides **what is judged on a fetch**, **what it costs**, and **what
happens to a flagged object**. Push is phase 3 and only a credential scan.

History: v0.1.0 was revised after an adversarial review against the code and
git 2.56.1 (v0.2.0), whose experiment overturned leaving a flagged blob out of
a partial clone. v0.3.0 records the four rulings, made on a second review.

## Decisions

- **Judge objects, read as git reads them.** The gateway inflates every entry,
  resolves deltas, and hashes each object itself. A pack's own claims (a
  `REF_DELTA` base id, its object count, its trailer) are checked, never
  trusted. Object ids follow git's `sha1dc` or SHA-256, by the repository's
  object format; they name objects and are never what a verdict is keyed on.
- **Text blobs are judged as chunks, with keyed boundaries.** A blob is cut at
  line boundaries where a keyed hash of the line (a secret per gateway, so an
  author cannot place a cut) selects one, between a minimum and a maximum chunk
  size (1 KB and 8 KB, aiming near 2 KB), with a forced cut inside any line
  longer than the maximum. An edit moves only the chunks around it.
- **A chunk is judged with its lead-in, and keyed with it.** Each chunk is
  read behind the previous chunk's last 64 tokens, as a paged response's
  parts are (`gateway/paging.py`), and its cache key hashes the lead-in and
  the chunk together. A chunk whose context changed is judged again.
- **Files at the tip are judged whole.** A file at the tip of a fetched ref
  that is at most `Config.whole_tokens` (16K) is judged whole at L3, on top
  of its chunks. That is the file an agent opens. Chunks of history are the
  [named residual](#residual-gap) the layer contract does not reach.
- **L1 and L2 per chunk; L3 on small groups.** L1 and L2 run on every chunk.
  L3 judges new chunks in groups of at most 4K tokens, and a clean group is
  credited to each chunk in it, a flagged group debited to each. A chunk whose L2 score is over a lower
  "suspicious" mark, below the flag threshold, is judged alone at L3, so a
  borderline chunk is never diluted by its neighbours. Commits, tags, tree
  names and ref names follow the same rule and are cached per member, so a
  second `ls-refs` or a refetch of known commits is a cache hit.
- **Strip what moves content off the judged path.** In the fetch request,
  before `check_upload_request` reads it and with pkt-line lengths recomputed,
  so the forge still parses exactly the bytes that were checked: `thin-pack`,
  `packfile-uris` and `sideband-all`. The response is held to the sections git
  v2 defines for `fetch` (acknowledgments, shallow-info, wanted-refs,
  packfile); anything else ends it. `bundle-uri` and `object-info` are
  already refused as commands and are now also removed from advertised
  capabilities.
- **Forge-written text is replaced, not judged.** On fetch and push the
  forge's side-band channel 2 and 3 lines are dropped and the gateway writes
  its own from a closed vocabulary. An `ERR <message>` pkt-line becomes `ERR
  refused by forge`. A push's `unpack <reason>` becomes `unpack error` (or
  stays `unpack ok`), and its `ng <ref> <reason>` keeps the ref with
  `rejected`. The `agent=` and `session-id=` capabilities are rewritten to the
  gateway's own value or dropped. Zero cost.
- **Two modes, no off switch.** `flag` or `block`, per git grant, as
  `EgressGrant.enforcement` is, with the disposition `judge_egress_response`
  uses (`dispose()`, `gaps_of().blocking()`), honouring
  `TRENTINA_ENFORCEMENT_OVERRIDE`. `profile.py` holds that every input runs
  every layer with no off dial. Default `flag`; `redact` is refused, as for
  `llm_completion`.

## What is judged on a fetch

Each kind is judged through `defend()` with `provenance=EXTERNAL`, `source`
`git:<remote>/<owner>/<repo>@<oid>`, and `source_type` as below.

| Item | `source_type` | Text judged |
|------|---------------|-------------|
| Ref listing | `git_refs` | every ref name and `symref` target not already cached. The listing is buffered (4 MiB whole) so a name is judged before it is listed; the hidden-prefix and token rules run first. |
| Commit | `git_commit` | the whole object as git renders it: headers, names, emails, `mergetag`, `gpgsig`, unknown headers, and the message decoded by its `encoding` header as `git log` decodes it. An `encoding` not on an allowlist of ASCII-compatible encodings (UTF-8, US-ASCII, ISO-8859-*, Windows-125x) is flagged as such, since UTF-7 or UTF-16 text reads one way to the layers and another to a tool. |
| Annotated tag | `git_tag` | the whole object, rendered the same way |
| Tree | `git_tree` | entry names new to this fetch |
| Text blob | `git_blob` | its chunks; whole at L3 too if at the tip and at most 16K tokens |
| Binary blob | `git_blob` | see [binaries](#binaries) |

Text is git's own rule: no NUL in the first 8,000 bytes. A NUL there makes a
file binary, which now means it is read for its strings rather than left
unread.

**Out of scope, stated:** an instruction split across files (each is judged
alone); Git LFS objects and submodules, which reach the agent by other routes
and are judged, or not, there.

### Binaries

A binary blob goes to the unpack stage through `unpack.child.run_unpacking`.
What it opens (images by OCR, PDFs, zip and tar archives, office files) is
read as it is anywhere else. Everything else is read by
`unpack.scan._labelled_with_strings`, extended for git to UTF-16LE runs and to
runs without spaces, so a binary is judged on the text a `strings` tool would
show an agent. A binary with no extractable text is judged as its label and
is not `binary_unread`.

Still `binary_unread`, refused under `block` and released only through
`git_object_release`: a compressed or encrypted stream unpack does not open
(7z, rar, zstd, an encrypted entry), and anything over the unpack limits (an
archive past 1 MiB uncompressed, 256 files, a 200 to 1 ratio or two levels of
nesting). A `.jar` is a zip and is opened as one, its class files read for
their strings; most real jars are over 1 MiB uncompressed and land in the
release path.

### Pack reading

A new module, `unpack/git_pack.py`; `git_wire.py` stays the no-pack reading
it is. Pure Python, written to the unpack stage's archive discipline: zlib
inflates, hashlib hashes, and nothing new joins the runtime image. It runs in
a child process (`unpack/git_pack_worker.py`) with CPU and memory limits, no
credential and a constant argument list, killed at `git.judge_deadline`: the
Security Gateway profile asks that of a parser for a format an attacker
controls, and a thread inflating 2 GiB cannot be stopped (v0.3.3, found in
review; v0.3.2 said a worker thread). A differential fuzz against `git
index-pack --strict` (varint headers, a copy size of 0 meaning 0x10000,
duplicate objects, a `REF_DELTA` naming itself) gates the module.

Bounds, each a refusal in `block` and an unjudged delivery in `flag`:

- the pack and its inflated objects spooled to the data volume:
  `git.max_judged_pack_bytes`, default 256 MiB arrived and 2 GiB inflated;
- 1,000,000 objects; a delta chain depth of 50 (git's default);
- a judging deadline, `git.judge_deadline`, default 15 minutes;
- a `REF_DELTA` whose base is not in the pack: refused, `thin_pack`.

### Lanes

A profile's judged fetches run in two lanes of one each: **fetch** (clones and
fetches) and **promisor** (a partial clone's lazy fetches, recognised by
`filter` with explicit blob wants), so a checkout's lazy fetch never waits
behind a clone. A judged fetch that finds its lane busy **queues** rather than
being refused, up to four waiting per lane, and past that is refused `busy`.
Listings and pushes keep the route's existing slots.

### Delivery and keepalives

The route's idle timeout is 300 s on each side, and a cold judgement takes
longer. Whenever the gateway is holding bytes, it sends a side-band progress
line (`Trentina: judged 1200/4810 objects`) at least every 60 s. Under v2
these start after the `packfile` section header is forwarded, the first point
band 2 is valid. A v0 client that did not negotiate `side-band-64k` is
refused; git always does.

- **`block`** holds the pack until every object is judged, then streams it.
- **`flag`** streams the pack as it arrives, judging alongside, and holds only
  the tail (the last pack entries and the trailer) for up to 30 s for judging
  to catch up. Then it names what was flagged and, in one line, counts what is
  still **pending**, and delivers. Pending objects go on being judged in the
  background, at the background class, so the verdicts warm the cache and land
  as `detections` rows. The agent learns of them on its next fetch, not this
  one.

## Cost

L2 is 0.7 ms a token on production CPU (`DEFAULT_PART_TOKENS`'s note in
`config.py`), about 1,430 tokens a second. L3 bills the fetching profile's
`llm_keys`. Tokens are estimated at three bytes a token, for code, and every
chunk carries a 64-token lead-in.

Measured on this repository (1,867 commits, 9,241 blobs), with line-hashed
chunks of about 2 KB over every text blob in history:

| Fetch | New to the judge | ~Tokens | L2 CPU | L3 calls |
|-------|------------------|---------|--------|----------|
| Full clone, cold, whole blobs (v0.1.0 baseline) | 401 MiB | 140M | ~27 h | n/a |
| Full clone, cold, chunked | 26,091 unique chunks, 46 MiB, with lead-ins; 1.4 MB of messages | 18M | ~3.5 h | ~4,500 groups, plus ~950 tip files |
| Checkout of HEAD, cold (partial clone) | 949 files, 15.5 MiB | 6M | ~70 min | ~1,500 groups, plus ~950 tip files |
| Any of these, warm cache | nothing | 0 | seconds to inflate and hash | 0 |
| A day of fetches, steady state (~26 commits a day here) | ~25 KB of new chunks a commit, with lead-ins | 240K a day | ~3 min a day | ~60 groups and ~130 tip files a day |

L3 counts exclude chunks judged alone for an L2 score over the suspicious
mark; how many that is depends on the mark, set in phase 1. The benchmark's
$0.14 to $0.19 per 1,000 calls was measured on short documents, so L3 dollars
for 4K groups and whole tip files are a phase-1 measurement.

Four things follow:

1. **Whole-blob judging of history is not viable**, and chunking makes a full
   clone hours of L2 rather than a day.
2. **The cold fetch is the cost, paid once per judge while verdicts last.**
   Until a1061 lands (below), verdicts last 24 h, so warming is a daily job:
   a grant's `warm` list names repositories whose default branch the gateway
   fetches and judges on a schedule.
3. **The steady state is cheap**: minutes of L2 a day for a busy repository.
4. **L2 is shared, and a clone must not starve tool calls.** The gateway runs
   two L2 scans at once (`TRENTINA_L2_CONCURRENCY`), handed out by
   `classifier.FairGate`. FairGate today rotates between callers and has no
   priority. A background class that yields to any waiting tool call is new
   code there. Git judging, flag's pending objects and warming run in it. Their
   L3 calls count against `git.l3_daily_quota`, not the profile's
   `l3_daily_quota`.

### Verdict lifetime

Git verdicts live in their own bounded table in `perimeter_db`, read on demand
and LRU-evicted, never loaded whole at startup, since an attacker-controlled
repository can mint chunks without limit. Their lifetime:

- **Once a1061 lands** (the L3 judge pinned to a dated model id and
  `perimeter_stamp` in the cache key): until the stamp changes, with a
  30-day ceiling.
- **Until then:** 24 h, the existing `TRENTINA_VERDICT_TTL_HOURS`, for the
  model-alias drift reason #817 gives.

## A flagged object

A pack cannot be edited in place: an object's id is its content, and every
tree and commit above it names that id. Nor can git take a partial answer. A
blobless clone's checkout fetches every blob it needs in one promisor batch.
When that fetch is refused, git 2.56.1 prints `fatal: could not fetch <oid>
from promisor remote`, exits 128 and checks nothing out. So under `block` a
flagged object refuses the fetch it came in, whole.

| | `flag` | `block` |
|---|---|---|
| Flagged object (any kind) | delivered; named on side-band | that fetch refused |
| Unjudged (bounds, deadline, `binary_unread`, L3 unavailable or over quota) | delivered; named as unjudged | that fetch refused |
| Not yet judged when the tail hold ends | delivered; counted as pending | (does not arise: `block` holds) |
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
  `gateway_calls` row.
- **Released by a person.** An operator-only `git_object_release` adds an
  object, per remote and grant, that is delivered despite its verdict, after
  someone read it. A release names the object id and the sha256 of its
  content, and holds only for an object matching both, so a SHA-1 collision
  cannot ride on it. It stages through the approvals flow; an agent cannot
  release its own. Under `block` this is the main path, so it ships with
  `block`.
- **A partial clone's narrower blast radius is untested.** Leaving one blob
  out of an otherwise delivered pack might let the rest of a fetch through, or
  might trip git's connectivity check. It is a harness experiment until it
  passes. A sparse checkout that never asks for the file is the agent's own
  way round a flagged blob.
- **No session label.** The route is sessionless, as `/proxy/http` is
  (spec 026).

**What that means for `block`.** The best judge flags about 0.8% of benign
cases (3 of 362, `docs/benchmark.md`). Across this repository's 9,241 blobs
that is on the order of 75 objects, any one of which refuses a full clone,
and this repository ships attack fixtures on purpose. So `block` is for
repositories whose history has been warmed and released clean, and is
measured on code before it is offered: phase 1 runs `flag` and records the
false-positive rate on real fetches.

## Residual gap

Gap 29 narrows to these, each stated in the docs when its phase lands:

- **History is judged in chunks.** A file at the tip is judged whole; an older
  version an agent reads with `git show` was judged chunk by chunk, with
  lead-ins, never whole. An instruction spread across a chunk boundary
  wider than a lead-in is the case this misses.
- **Instructions split across files**, and authorship (a judged commit is
  still not one the owner wrote).
- **Opaque decodable streams.** A binary with no magic and no strings (raw
  deflate, brotli, a bare encrypted stream) is judged as its label, so an
  instruction an agent could decode with a hint from elsewhere is unread
  ([#911](https://github.com/crunchtools/trentina/issues/911)).
- **Push contents**, beyond the credential scan.
- **Pending under `flag`**: objects delivered before their verdict, named as
  pending and judged after.

## Push (phase 3)

A push is the agent's own output, so injection judging buys little. The same
reader runs `credential_shapes.kinds` over every text-bearing thing a push
sends before the pack is forwarded: each new blob (a binary's strings, as
read on fetch), commit, annotated tag and tree entry name, and the ref names
and push options in the request. It refuses `credential` on a match unless
the kind is in the profile's `credentials_allowed`. An object the reader
cannot read refuses the push, never forwards unscanned. Deterministic, no L2
or L3. It needs the push spooled, which holds it until read.

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
loads only under `block`. That gate is policy, not containment: `want <oid>`
is unrestricted, so a pull request's commit can be fetched by id whether or
not its ref is listed, and under either mode what it fetches is judged as
any other object.

## Migration

Every clone made before phase 1 holds history no layer read, and a fetch
afterwards brings only what is new. Judging does not reach back into a
checkout. After phase 1 deploys, each seat re-clones the repositories it
works in, and the release note says so.

## Phasing

1. **Reader and `flag`.** `git_pack.py` and its differential fuzz; keyed
   chunking with lead-in keys; tip files whole; the verdict table at 24 h; the
   request, capability and forge-text rewrites; the strings reader for
   binaries; streaming with the tail hold, keepalives and pending; lanes; side-
   band naming and detection rows; the FairGate background class and the git
   L3 quota. Measured on the development seats: false-positive rate on real
   fetches, bytes per token on code, L3 dollars, and the L2 suspicious mark.
2. **`block` and warming.** Holding the pack, refusal, `git_object_release`,
   `warm`; the 30-day lifetime once a1061 has landed; the partial-clone
   omission experiment.
3. **`show_refs` and push.** `refs/pull/` to a `block` grant; the push
   credential scan.

Each phase that narrows gap 29 moves its Coverage rows in
`docs/defense-pipeline.md` and its hold-open test in
`tests/test_coverage_gaps.py` in the same change, as every gap does.

## Tests

- Real `git` against `git http-backend` through the route (the existing
  harness), protocols v0, v1 and v2, SHA-1 and SHA-256 repositories: a clean
  clone under `block` arrives intact and `git fsck` passes; a planted
  instruction in a blob, a binary's strings, a commit message, a commit
  header, a UTF-16 `encoding`, a file name, a branch name and a `symref`
  target is each named under `flag` and refuses the fetch under `block`; a
  slow judgement under either mode outlasts 300 s without the connection
  idling out; `flag` names pending objects and later records their verdicts;
  a refused lazy fetch fails as git 2.56.1 was seen to.
- The reader: a differential fuzz against `git index-pack --strict`, and
  hostile packs (a delta chain past 50, a base outside the pack, a count that
  lies, a bad trailer, an inflation bomb, a `REF_DELTA` naming its own id),
  each a refusal and none a hang.
- Chunking: cut points move with the gateway's key; no chunk is over the
  maximum, a single long line included; an edited file re-judges only the
  chunks around the edit and the one after it.
- The cache: a second clone and a second `ls-refs` perform no `defend()` call;
  a changed threshold re-judges everything; a release bound to one sha256 does
  not release a colliding object.
- What the forge receives has no `thin-pack`, `packfile-uris` or
  `sideband-all`; what the client receives has no forge side-band text, `ERR`
  message, `unpack` reason, `agent=` or `session-id=` value of the forge's,
  and no `bundle-uri` or `object-info` capability.
