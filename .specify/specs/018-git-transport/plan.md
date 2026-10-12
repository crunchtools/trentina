# Implementation Plan: Git Transport

> **Spec ID:** 018-git-transport
> **Status:** Complete
> **Last Updated:** 2026-10-12

## Summary

A `/git` route built like the LLM proxy (caller by bearer, credential
injected) on the egress guard's pinned connections, with the reading of
git's wire format kept in a module of its own that does no I/O.

---

## Architecture

### Request flow

```
git client
    │  Authorization: Bearer <gateway token>
    ▼
git_transport.serve            resolve the profile, or 401
    │
    ▼
git_transport._carry           remote, path, service, protocol, lists, slot
    │      └─ git_wire         parse_repo_path, check_upload_request,
    │                          parse_command, refuse_ref_update
    ▼
client_egress.checked_target   egress.check_url, shared per burst
    │
    ▼
egress.open_pinned             pinned, streamed, no redirect, idle timeout
    │
    ▼
git_transport._Relayed         stream back; RefFilter on listings;
                               finish once: slot, upstream, audit row
```

### Data flow

1. A fetch: `GET info/refs` (listing, filtered), then one or more
   `POST git-upload-pack` (request buffered and checked; answer streamed,
   filtered only when the request was `ls-refs`).
2. A push: `GET info/refs?service=git-receive-pack` (listing, filtered),
   optionally a probe (`0000`), then `POST git-receive-pack` (command list
   read and decided; the rest of the body and the answer streamed).

---

## Implementation Steps

### Phase 1: Egress

- [x] `egress.open_pinned`; `redirect` in `EGRESS_REASONS`
- [x] `client_egress.checked_target` made public

### Phase 2: Configuration

- [x] `GitRemote`, `GitGrant`, `Profile.git`, honeypot rule
- [x] Loader: `git_remotes`, dangling-remote check, token resolution
- [x] Reload: hold the block; unapplied note for a first remote

### Phase 3: The route

- [x] `gateway/git_wire.py`
- [x] `gateway/git_transport.py`
- [x] `DestinationKind.GIT`; registration in `__init__.py`

### Phase 4: Tests

- [x] `tests/test_git_wire.py`, `tests/test_git_transport.py`, `tests/git_harness.py`
- [x] `tests/test_egress.py`, `tests/test_reload.py`, `tests/test_coverage_gaps.py`

### Phase 5: Documentation and gates

- [x] `docs/git-transport.md`; known gap 29 and its Coverage row
- [x] profiles, audit-log, network-isolation, client-egress, configuration, README, CLAUDE.md
- [x] CHANGELOG, constitution manifest 2.8.0, version 1.10.0
- [x] ruff, mypy, pytest, Semgrep, Gourmand

---

## Decisions taken during implementation

| Question | Decision |
|----------|----------|
| One audit row per git command, or per HTTP request? | Per request. Smart HTTP is stateless and carries no id that ties a clone's requests together; inventing one would be a guess. |
| A row for a caller with no valid token? | No. A row belongs to a profile, and an unauthenticated writer to the audit database is a way to fill it. Same as `/llm`. |
| Inflate a gzipped push? | Refuse it. Git gzips a fetch request and never a push, so a compressed push is not a client this route serves, and refusing keeps the bytes checked equal to the bytes forwarded. |
| Bump `PERIMETER_VERSION`? | No. Its rule in `perimeter_db.py` is "a change that could alter what a scan concludes", and a bump re-judges every tool description. Client egress did not bump it either. |
| Filter or refuse a listing whose capability line is a hidden ref? | End it. Dropping that line loses the capabilities and rewriting the listing is more parser than the case is worth. |
| Pass the forge's error body to the client? | No. It is text nothing judged. Status only. |
| Parse the forge's push report to audit accepted versus rejected? | No. It is inside the side-band stream with the pack. `ok` is documented as "carried". |

---

## Risks and Mitigations

| Risk | Impact | Mitigation |
|------|--------|------------|
| A rule here refuses something a real git client sends | High | `TestRealGit` runs the `git` binary under v0, v1 and v2 against `git http-backend` |
| An operator lists `refs/heads/*` | High | Documented beside the field; the forge token's own scope is the second limit |
| A forge that serves commits by id makes hidden refs look like more than they are | Med | Stated in the doc, the gap and a test that holds it open against a real server |
| A stalled peer holds a slot | Med | Idle timeout on every read and write, both sides; finish is in the response, not a generator's `finally` |

---

## Changelog

| Date | Changes |
|------|---------|
| 2026-10-12 | Initial plan, written with the implementation |
