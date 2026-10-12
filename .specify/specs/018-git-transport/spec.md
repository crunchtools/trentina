# Specification: Git Transport

> **Spec ID:** 018-git-transport
> **Status:** Implemented (1.10.0)
> **Version:** 0.1.0
> **Author:** crunchtools
> **Date:** 2026-10-12
> **Ticket:** #453

## Overview

An agent that runs `git` reaches its forge through a client-egress tunnel
(#442). A tunnel decides a host. Behind that host is every repository on the
forge, the credential is the agent's to hold, and the gateway cannot see
which repository or branch a push went to. An agent that has been talked
into it can push to a public repository, or into a branch another agent
deploys from, and the audit says "443 bytes to the forge".

**Done is:** an agent with no route to its forge of its own, whose `git`
goes through a route that knows the repository and the refs, holds the forge
token, and refuses what the profile does not list.

## Decision

A route on the main port that speaks git's smart HTTP protocol and nothing
else, to an upstream the operator names.

```
git ──HTTP──▶ gateway :8019 /git/{remote}/{owner}/{repo}[.git]/... ──HTTPS──▶ forge
  (gateway bearer)   │                                    (profile's forge token)
                     ├─ bearer → profile
                     ├─ remote in profile's git block
                     ├─ owner/name validated, lower-cased; one of three endpoints
                     ├─ ?service=, Git-Protocol allowlisted
                     ├─ repository in fetch or push, deny first
                     ├─ fetch request read whole: v2 command, ref-prefix, want-ref
                     ├─ push command list read to its flush: push_refs, no tag, no delete
                     ├─ egress.check_url, pinned; no redirect
                     ├─ ref listings: hidden refs dropped
                     └─ one gateway_calls row: repository, refs, bytes, outcome
```

### It terminates the connection, so it owes a verdict where it can give one

The tunnel's gap (26) is justified by the gateway holding no key. This route
ends the client's HTTP, so "not read" is a choice. The rule taken from
`client_egress.parse_connect` is that a request the gateway could read is one
it owes a verdict on. Everything on the wire that is deterministic text is
therefore read and enforced: the path, the query, `Git-Protocol`, the whole
of a fetch request, a push's command list, and ref listings. What is left
unread is the pack and the side-band stream it travels in, declared as known
gap 29 under the existing binary-unread precedent.

### Why a push list and not a switch

`push: true` would make every fetchable repository writable. The fence that
matters is the one between "may read" and "may write here", so `push` is its
own list, and `push_refs` is required with it.

### Why tags and deletes are refused whatever is listed

A tag is what a release pipeline builds from, and a delete cannot be undone
by the next push. Neither is something an agent working in its own branch
namespace needs, and both are what a hijacked one would reach for. They are
refused by the route, not by a pattern an operator might forget.

### Why no redirect is followed

A forge redirects a renamed or transferred repository. Following it would
send the injected token to a repository that was never matched against the
lists. `egress.open_pinned` refuses any 3xx.

### Why the fetch request is buffered and the push is not

A fetch request is negotiation: wants, haves, and under v2 a command with
arguments. All of it is text the route checks (`ref-prefix`, `want-ref`, the
command), git gzips it, and it is small. It is read whole, to 8 MiB
inflated, and sent on inflated so the forge parses what was checked. A
push's body is a short command list and then a pack of any size. The list is
read to its flush packet (at most 64 KiB and 64 commands), the decision is
made, and the bytes already read are sent on ahead of the rest as it
arrives. No pack is held in memory.

### Why hidden refs, and what that does not close

`refs/pull/*` is where a forge keeps every pull request's head, an
outsider's included. A v2 `ls-refs` whose `ref-prefix` names the namespace
is refused, as is a `want-ref`, and lines for those refs are dropped from
every advertisement and `ls-refs` answer. This removes the names. A `want`
names an object id, and a forge that serves any reachable commit by id will
serve a pull request's to a client that learned the id elsewhere. That is
not closed and is part of gap 29. The namespace list is per remote
(`hidden_refs`), because GitLab's is `refs/merge-requests/`.

### Why the caller is a bearer token here and a network on the tunnel

The tunnel has no place for a credential but the proxy URL, which clients
print. Git can send a header (`http.extraHeader`), which it does not print,
so the route identifies its caller the way `/llm` does.

## What is not decided

Pack contents, in either direction: code, file names, commit messages. Whose
commits they are. A `want` by object id. What a ref name in a listing says:
a name is held to one token of printable ASCII, at most 255 bytes, the rule
the Matrix proxy applies to identifiers it keeps unjudged, and no layer
reads it. Whether the forge accepted a push the gateway carried. Each is
stated in `docs/git-transport.md` and in known gap 29.

## Security considerations

- **Perimeter, not performance.** The `git` block is held across an agent's
  own reload and refused on a honeypot profile. `llm_keys` is not held; this
  is, with a test.
- **Nothing of the caller's goes upstream.** The URL is built from the
  operator's origin and validated, lower-cased names. Every header is built
  by the route.
- **Nothing of the forge's comes back but its git answer.** A non-200 is a
  status with no body.
- **No second resolution.** The connection is made to an address
  `check_url` returned, shared for five seconds per profile as the tunnel's
  is.
- **Bounded.** 8 requests in flight per profile; 5 minutes idle on any read
  or write, either side; fetch request 8 MiB; command list 64 KiB.
- **Closed reasons.** Every refusal reason is one of a fixed set. The
  repository and refs are stored only as the audit row's destination, and
  only once validated.
- **`PERIMETER_VERSION` does not move.** It keys cached verdicts, and this
  route reaches none.

## Module changes

| File | Change |
|------|--------|
| `gateway/git_wire.py` | New: path parser, pkt-line reader, command parser, upload-request check, `RefFilter` |
| `gateway/git_transport.py` | New: route, admission, upstream, relay, audit |
| `egress.py` | `open_pinned`: checked target, streamed body, idle timeout, no redirects |
| `errors.py` | `redirect` joins `EGRESS_REASONS` |
| `gateway/profile.py` | `GitRemote`, `GitGrant`, `Profile.git`; honeypot rule |
| `gateway/loader.py` | `git_remotes` parsed and cross-checked; grant tokens resolved; `ActiveConfig.git_route_registered` |
| `gateway/client_egress.py` | `_check` becomes `checked_target`, shared |
| `gateway/destination.py` | `DestinationKind.GIT` |
| `tools/reload.py` | Hold the block on an agent reload; report a first remote as unapplied |
| `__init__.py` | Register the route when the file has `git_remotes` |

## Testing

`tests/test_git_wire.py` covers the reading with no I/O.
`tests/test_git_transport.py` runs the route and a forge as real HTTP
servers on loopback: every refusal's status, reason and audit row; the
headers that reach the forge; streaming in both directions; the cap and the
idle timeouts; the guard; config, loader, honeypot and reload rules. Its
`TestRealGit` class drives the `git` binary against `git http-backend`
through the route, under protocol v0, v1 and v2, including the gzipped fetch
request and the chunked push git itself produces.
`tests/test_coverage_gaps.py` holds gap 29 open.

Not covered by a test and checked at deployment: a clone and a push against
the real forge, with its TLS, its keep-alives and its side-band progress.

## Changelog

| Version | Date | Changes |
|---------|------|---------|
| 0.1.0 | 2026-10-12 | Implemented in 1.10.0 |
