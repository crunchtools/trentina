# Git Transport

Clone, fetch and push through the gateway, to the repositories and branches
you name, with a forge token the agent never holds.

## Why it matters

A coding agent runs `git`. Until now the way to let an isolated agent reach
its forge was a [client egress](client-egress.md) tunnel to the forge's
host. A tunnel decides the host and nothing else: every repository on that
forge is reachable, the agent holds the credential, and the gateway cannot
see which repository or branch a push went to.

This route carries git's smart HTTP protocol instead. The gateway ends the
agent's connection, so it can read the request: which repository, which
operation, and on a push which refs. It checks each against the profile's
lists, injects the profile's forge token, and opens its own connection to
the forge.

**What this is not:** a path the defense pipeline reads. The gateway decides
*which repository* and *which branch*. It does not read *what is in them*. A
pack (file contents, file names, commit messages, author names) crosses in
both directions without any layer looking at it, ref names are bounded
but not judged, and the gateway cannot tell a commit the repository's owner
wrote from one an outsider wrote and someone merged. This is [known gap 29](defense-pipeline.md#known-gaps), and
[what is not enforced](#what-is-not-enforced) below says exactly where the
line is.

The repository lists only mean something when this route is the agent's one
way to the forge. An agent that also has a tunnel to the same host, or a
route of its own, goes round them.

## Configuration

```yaml
git_remotes:
  github:
    upstream: https://github.com

profiles:
  agent1:
    auth:
      bearer_token_env: TRENTINA_PROFILE_AGENT1_TOKEN
    git:
      github:
        token_env: AGENT1_GITHUB_TOKEN
        fetch: [acme/*]
        push: [acme/widgets, acme/gadgets]
        push_refs: ['refs/heads/agent1/*']
        deny: ['*-private']
```

`git_remotes`, at the top level, names each forge:

| Field | Description |
|-------|-------------|
| `upstream` | The forge's origin: `https://` and a lower-case DNS name. No port, path, userinfo or address. |
| `username` | The HTTP Basic username sent with a profile's token. Default `x-access-token`, which GitHub takes; GitLab takes `oauth2`. |
| `hidden_refs` | Ref namespaces never listed to a client, as prefixes ending in `/`. Default `[refs/pull/]`. For GitLab add `refs/merge-requests/`. |

A profile's `git` block has one entry per remote it may use:

| Field | Description |
|-------|-------------|
| `token_env` | The environment variable (or `_FILE`) holding this profile's token for that forge. Required. |
| `fetch` | `owner/name` patterns the profile may clone and fetch. |
| `push` | `owner/name` patterns the profile may push to. A list, never a switch: a repository that is fetched is not thereby pushed to. |
| `push_refs` | Branch patterns a push may create or move, each under `refs/heads/`. Required with `push`. |
| `deny` | Patterns refused for fetch and push alike, checked first. |

Repository patterns are lower-case and compared with the owner and name the
caller asked for, lower-cased. `*` stands for any run of name characters and
does not cross the `/`, so `acme/*` is every repository of one owner and
nothing else. `fetch` and `push` entries must name an owner. A `deny` entry
may be a bare name pattern, which then holds for every owner: `*-private` is
`*/*-private`. In `push_refs` a `*` does cross `/`, so `refs/heads/agent1/*`
covers `refs/heads/agent1/fix/typo`.

A name the profile's `git` block uses that is not in `git_remotes` is a load
error, as is a token variable that is unset. At most 64 patterns a list.

Give the agent a branch namespace of its own, and keep it apart from
anything that deploys. `push_refs: ['refs/heads/*']` loads, and lets the
agent push to `main`.

Use a token that can do no more than the lists say: a machine identity that
is on no ruleset bypass list, scoped to the repositories in `push`. The
lists are the gateway's limit; the token's scope is the forge's, and it
still holds if a pattern here is wrong.

### Pointing git at it

The route is on the main port. The caller is identified by its gateway
bearer token, as on [`/proxy/llm`](llm-proxying.md), so the profile needs a static
token (`auth.bearer_token_env`) and git has to send it:

```bash
export GIT_CONFIG_COUNT=1
export GIT_CONFIG_KEY_0=http.http://trentina:8019/proxy/git/.extraHeader
export GIT_CONFIG_VALUE_0="Authorization: Bearer $TRENTINA_PROFILE_AGENT1_TOKEN"

git config --global url.http://trentina:8019/proxy/git/github/.insteadOf https://github.com/
git clone https://github.com/acme/widgets
```

The token goes in a header and not in the URL, because git prints URLs in
its errors and writes a remote's URL into `.git/config`. It is passed
through `GIT_CONFIG_*` and not `git config`, so it stays in the agent's
environment, where its MCP client already reads it, and is never written to
a configuration file. The `insteadOf` line carries no secret and is a
convenience so existing remotes keep working. It is not the control: the
agent's network is. With no route to the forge of its own, a URL git was not
told to rewrite goes nowhere.

Set `GIT_TERMINAL_PROMPT=0` for an agent. A refusal then ends the command
instead of asking a terminal nobody is at for a password.

## What is enforced

In order, each one deterministic. A request that fails a rule is refused
there and nothing is sent upstream.

1. **The caller is known.** Its bearer token is a profile's. Otherwise
   `401`, before the remote or the path is looked at.
2. **The profile holds a grant on that remote.** A remote that is not
   configured and one the profile has no entry for are the same refusal, so
   a caller cannot list the remotes other profiles use.
3. **The path is `owner/name[.git]/` and one of three endpoints:**
   `info/refs`, `git-upload-pack`, `git-receive-pack`. Owner and name are
   `[A-Za-z0-9_.-]`, at most 100 characters, with no `..`, and a name
   may not end in `.git` once one `.git` is taken off. A `%` anywhere in
   the path is refused: no valid name needs encoding, so an encoded slash or
   dot is a path written to be read two ways. The upstream URL is built from
   the validated parts, lower-cased, with `.git` added; nothing the caller
   sent is copied into it.
4. **The method and query fit the endpoint.** `info/refs` is a `GET` whose
   query is exactly `service=git-upload-pack` or `service=git-receive-pack`.
   Without it a forge answers in the "dumb" protocol, a file server over the
   repository. The other two are a `POST` with no query.
5. **`Git-Protocol` is absent, `version=1` or `version=2`.**
6. **The repository is in the list for that operation**, `deny` first.
   Upload-pack is `fetch`; receive-pack, and the listing a push starts with,
   is `push`.
   Then, for a `POST`, the body's declared type must be the endpoint's own,
   and its encoding identity, or gzip on a fetch: git gzips a fetch request
   and never a push.
7. **A fetch request asks only for what is admitted.** It is read whole (at
   most 8 MiB and 200,000 pkt-lines, inflated if git sent it gzipped) and
   must be pkt-lines from
   end to end. Under protocol v2 it must be one command, `ls-refs` or
   `fetch`, ending at its flush packet. A `ref-prefix` or a `want-ref` that
   names a hidden namespace is refused. It goes upstream inflated, so the
   forge parses the bytes that were checked.
8. **A push moves only listed branches.** The command list at the head of
   the request is read before a byte of the pack is forwarded. Every command
   must name a ref matching `push_refs`. A delete (an all-zero new id) is
   refused. A tag, and anything else outside `refs/heads/`, is refused
   whatever `push_refs` says. One refused ref refuses the whole push. Push
   options and signed-push certificates are refused. The list is at most 64
   commands and 64 KiB.
9. **The upstream resolves outward.** Its name goes through the
   [egress guard](deployment-hardening.md): every address must be global,
   and the connection is made to an address that was checked. One check
   serves a profile's requests to that forge for five seconds, so a clone
   with submodules does not run out of lookup slots.
10. **No redirect is followed.** Any `3xx` from the forge is refused. A
    renamed or transferred repository redirects, and following it would send
    the profile's token to a repository that was never matched against the
    lists. Use the repository's current name.
11. **Only the forge's git answer is delivered.** A `200` of the expected
    content type is streamed back. A `403` or `404` is passed on as that
    status with no body; anything else is `502`. The forge's own error text
    is never forwarded.
12. **Hidden refs are not listed, nor is a name that is not one plain
    token.** In a ref advertisement and in an `ls-refs` answer, every line
    whose ref starts with a `hidden_refs` prefix is dropped as the listing
    streams past. So is a ref whose name is over 255 bytes or holds anything
    but printable ASCII: a name is delivered unjudged, so it is held to what
    cannot hide a character. Such a branch cannot be fetched by name through
    this route.

The headers sent upstream are built by the gateway: the profile's token as
HTTP Basic, `User-Agent`, `Accept`, `Content-Type`, the validated
`Git-Protocol`, and `Accept-Encoding: identity`. None of the caller's
headers go upstream, its `Authorization` least of all, and none of the
forge's come back.

Bodies are streamed in both directions, with two bounded exceptions that
are read before anything is sent: a fetch request, and a push's command
list. A profile holds at most 8 requests in flight. There is no limit on how
long a clone or push takes; any single read or write, on either side, that
makes no progress for 5 minutes ends it.

## What is not enforced

- **Pack contents are not read.** Not on a fetch and not on a push. A pack
  is compressed objects: file contents, file names, commit and tag messages,
  author names. The gateway terminates this connection and could inflate
  one; it does not, and no layer judges any of it. An instruction written
  into a README, a source comment or a commit message reaches the agent's
  checkout as it was written. What the agent then does with a file it opens
  is not something this route sees.
- **The gateway cannot tell whose commits they are.** `fetch: [acme/*]` is
  "these repositories", not "code these people wrote". A merged pull
  request, a dependency bot's commit and a change by a compromised account
  are all history on a branch the profile may fetch.
- **A `want` for an object id is not restricted.** Hiding `refs/pull/`
  removes the *names*. A commit the forge will serve by id can still be
  fetched by a client that learned the id somewhere else, such as an issue
  comment or a tool response. Whether it is served is the forge's setting,
  not the gateway's; a forge that serves any commit reachable from any ref
  serves a pull request's.
- **Ref names are not judged.** Branch and tag names are text someone with
  push access chose. The gateway drops hidden namespaces and names that are
  not one token of printable ASCII, at most 255 bytes, and passes the rest
  on. No layer reads them, and a name can still be words joined by hyphens.
- **The forge's progress and status lines are not read.** They travel in
  the same side-band stream as the pack.
- **`ok` means carried, not accepted.** A push the forge rejects (a
  protected branch, a failed hook) is still an HTTP `200` whose answer says
  so inside that stream. The audit row says the gateway forwarded it.
- **A force-push inside `push_refs` is allowed.** The old id of a command
  is not checked. A branch the agent may move, it may rewrite.
- **What a push carries out is not limited.** An agent that has been talked
  into it can commit whatever it holds and push it to any repository and
  branch its lists allow. Treat every entry in `push` as a place the agent
  can write to.
- **Names are lower-cased before they are matched and sent.** GitHub, GitLab
  and Gitea treat owner and repository names without regard to case. On a
  forge that does not, a repository with an upper-case letter in its name is
  not reachable through this route.

## Refusals

A refusal is a status, an `X-Trentina-Reason` header and a one-line body,
which git shows its user as `remote: refused by Trentina: <reason>`. The
reasons are a closed set and never quote the caller.

| Status | Reason | Meaning |
|--------|--------|---------|
| 401 | (none) | The bearer token is no profile's. No audit row. |
| 403 | `remote` | The profile has no grant on that remote, or there is no such remote. |
| 400 | `name` | An owner or repository name outside the grammar, or an encoded path. |
| 404 | `path` | Not one of the three endpoints. |
| 405 | `method` | The wrong method for the endpoint. |
| 400 | `service` | A query other than the one the endpoint takes. |
| 400 | `protocol` | A `Git-Protocol` value that is not forwarded, or a body that does not match it. |
| 403 | `repo_denied`, `repo_not_listed` | The repository matches `deny`, or is not in the list for this operation. |
| 415 | `content_type`, `encoding` | A body of another type, or compressed in a way git does not use here. |
| 400 | `malformed` | A body that is not what its endpoint takes. |
| 413 | `too_large` | A fetch request or a command list over its limit. |
| 403 | `command` | A protocol v2 command other than `ls-refs` and `fetch`. |
| 403 | `hidden_ref` | The request names a hidden namespace. |
| 403 | `ref_not_listed`, `tag`, `delete`, `push_options` | A push the rules above refuse. |
| 408 | `idle` | The client stopped sending. |
| 503 | `busy` | The profile already has 8 requests in flight. |
| 503 | `resolver_busy` | No DNS lookup slot was free; the upstream was not checked. Try again. |
| 403 | `non_global_address`, `unresolvable`, `encoded` | The egress guard refused the upstream or its answer. |
| 502 | `redirect` | The forge answered with a redirect. |
| 403, 404, 502 | `upstream_status` | The forge answered with an error. |
| 502 | `upstream_content`, `upstream_failed` | Not a git answer, or the connection failed. |
| 504 | `upstream_idle` | The forge stopped answering. |

Once an answer has started, a failure can only end it: `upstream_idle`,
`upstream_failed`, `idle`, and `advertisement` (a ref listing that could not
be filtered: it was not pkt-lines, the hidden ref was the line carrying the
forge's capabilities, or a line that is kept named a hidden ref as a
symref's target). Git reads a listing or a pack that stops short as an
error. The reason is in the audit row.

## Audit

One `gateway_calls` row per HTTP request, written when it ends or is
refused. A clone is two or three requests and a push three or four, so one
git command is a short run of rows. `backend` is `git:<remote>`, `tool` is
`fetch` or `push`, and `destination` is `owner/name`, lower-cased, with
`destination_kind = git`. For a push the refs it named follow the
repository, separated by spaces, within the field's 256 characters:
`acme/widgets refs/heads/agent1/fix`. `bytes_arrived` is what came back from
the forge and `bytes_delivered` is what the agent sent to it.

A request refused before its repository was validated records no
destination, and one refused before its remote was matched has the backend
`git` with no name after it: neither value is the caller's unchecked text.

| Outcome | When |
|---------|------|
| `ok` | The forge answered `200` and the answer was delivered whole. |
| `denied_allowlist` | `remote`, `repo_denied`, `repo_not_listed`, and `ref_not_listed` for a branch outside `push_refs`. |
| `denied_guard` | Every other rule of this route: `name`, `path`, `method`, `service`, `protocol`, `content_type`, `encoding`, `malformed`, `too_large`, `command`, `hidden_ref`, `tag`, `delete`, `push_options`, `ref_not_listed` for a ref that is not a branch, `busy`, `idle`, `resolver_busy`, `redirect`. |
| `blocked_defense` | The egress guard refused the upstream (`non_global_address`, `unresolvable`, `encoded`), or a listing could not be filtered (`advertisement`). |
| `tool_error` | The forge answered `403` or `404`. |
| `backend_error` | Any other forge error, `upstream_content`, `upstream_failed`, `upstream_idle`. |
| `cancelled` | The client went away, or the request's task was cancelled, before the answer was complete. |

No layer reads a pack, so there is no `detections` row to join.

## Who may change it

A profile's `git` block is perimeter. An operator reload applies an edit to
it, and to `git_remotes`, at once. An agent's own `reload_profiles` never
moves its block: an agent able to reload its own lists could add the one
repository it was talked into wanting. The held block is reported under
`operator_only`.

Adding the first `git_remotes` entry to a gateway that started with none
needs a restart, because the route is registered at startup. The reload says
so. A [honeypot profile](profiles.md#honeypot-profiles) cannot have a `git`
block.

## Related

- [Client Egress](client-egress.md): a tunnel, for a client the gateway cannot read
- [LLM Key Proxying](llm-proxying.md): the same caller-by-token, key-injected shape for model calls
- [Deployment Hardening](deployment-hardening.md): the egress guard and container flags
- [Audit Log](audit-log.md): the row a request writes
