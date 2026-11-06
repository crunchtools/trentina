# Specification: A Backend's Own redirect_uri

> **Spec ID:** 024-backend-callback-url
> **Status:** Draft
> **Version:** 0.1.0
> **Author:** Scott McCarty
> **Date:** 2026-11-05
> **Ticket:** #725 (lineage #479)

## Overview

The gateway's backend-OAuth client (#479) advertises one redirect_uri for every
backend: `public_base_url()` plus the constant `/oauth/backend/callback`. An
authorization server with a **fixed redirect-URI allowlist and no dynamic client
registration** cannot be signed into at all — it will not accept the URI we
send, and we cannot self-register the one it would accept. The Red Hat Hub MCP
server (ServiceNow, KB0031804) is the live case: it accepts only
`http://127.0.0.1:{8787,54321,46817}/oauth/callback`, and ServiceNow compares
the redirect_uri string at the authorize step, so no reverse-proxy rewrite
helps.

Until now that forced an external `mcp-remote` worker, which owns the tokens and
sits outside the perimeter.

**Done is:** a backend with a pre-registered `client_id`, its secret, and one
`auth.callback_url` completes `backend_auth` against such a server, stores the
grant in the existing backend-token store, and refreshes and revokes there —
with no external worker, no subprocess, and no new runtime in the image.

## Decision

Technical (Josui, 2026-11-05, answering the triage question on #725, and
superseding the `callback_path` + loopback-listener sketch in the issue body):

**One full-URL override, served on the existing listener. No second bound
socket.**

- A path override alone is insufficient: here `public_base_url()` is
  `http://127.0.0.1:8019` and the allowlist entry is
  `http://127.0.0.1:8787/oauth/callback`, so the authority is wrong too.
- A per-backend loopback listener was rejected. The browser is outside the
  container, so podman has to publish the port either way — binding it inside
  buys no reachability and costs a bound socket, lifespan start/stop wiring, a
  posture entry, and a second place the callback route exists.
  `PublishPort=127.0.0.1:8787:8019` onto the existing container port gets the
  identical result.

## Behaviour

1. `BackendAuth.callback_url` is the exact redirect_uri advertised for that
   backend. Unset, nothing changes: `public_base_url()` + `CALLBACK_PATH`.
2. It is used in all three places a redirect_uri is built — the authorize
   request, the DCR registration body, and `BackendFlow.redirect_uri`, which the
   token exchange already reads per flow, so a grant made before an edit keeps
   exchanging against the URI it was authorized with.
3. The gateway mounts that URL's **path** as an additional callback route,
   deduplicated across backends, behind the same rate limiter and the same
   handler as `/oauth/backend/callback`. Two backends may share one path.
4. Routes bind at startup. A `callback_url` added by `reload_profiles` is
   reported under `not_applied` ("restart to serve it"), on the pattern every
   other startup-bound section already follows — the silent validated no-op is
   what that reporting exists to prevent.
5. The port is a deployment fact: a published-port mapping onto the gateway's
   own port, documented in the Quadlet unit and in Authentication.

## Validation

Refused at load, as a closed set of reasons on a schema that already forbids
extras:

- absolute `http` or `https`; no userinfo, no query, no fragment;
- `http` only for the loopback literals `127.0.0.1` and `[::1]` (RFC 8252's
  loopback exception). `localhost` is refused: it resolves, and what it resolves
  to would receive an authorization code;
- the path absolute, at most 128 characters, no empty, `.` or `..` segment, no
  trailing slash, each segment `[A-Za-z0-9._~-]+`;
- the path not under a prefix the gateway already serves, so a backend entry
  cannot shadow a real route.

Mounting an extra path is not a new trust surface: a callback is tied to a flow
only by its single-use `state`, so the same handler reached by another path
proves nothing more. The existing `_param` cap, the rate limiter and the
`issuer_changed` and `backend_moved` checks are unchanged.

## Not in scope

A second listener on a chosen port; `callback_loopback_port` as a field; any
change to refresh, revoke or the token store; #724's stdio carrier (answered
and deferred on that issue).
