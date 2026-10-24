# Terminating HTTP(S) egress

The egress route (#511) carries an agent's own outbound HTTP(S) request on the
main port, alongside [`/llm`](llm-proxying.md) and [`/git`](git-transport.md):

    /egress/{upstream}/{path}

It is a **terminating** inspecting proxy, not a wiretap. The agent speaks HTTPS
to Trentina; Trentina reads the plaintext only inside the trust boundary, where
L1/L2/L3 and the credential detector run; Trentina re-originates the outbound
TLS itself. Encryption on every wire, plaintext confined to the boundary.

It is a **reverse** proxy to **named** destinations — the client points a base
URL at Trentina (`OPENAI_BASE_URL`, `GITHUB_API_URL`, an SDK `base_url`). A
client that cannot be re-pointed stays on the [client-egress tunnel](client-egress.md),
which gates the destination but reads no bytes (known gap 26).

## Why, not just where you go

The CONNECT tunnel refuses a request to a host that is not allowlisted, but it
cannot see what an agent sends to a host that *is*. A secret read from one tool
and posted to an allowed API passes it uninspected. The egress route reads the
request, so it can refuse that.

## What it decides, in order

1. **Who is calling** — the gateway bearer token, as on `/llm` and `/git`
   (`resolve_profile_by_token`), never the peer address. An unknown token is
   `401` with no audit row. The caller's own `Authorization`/`Cookie` are
   dropped and never forwarded.
2. **Which upstream and path** — a configured `egress_upstreams` name the
   profile was granted (`egress_http.<name>`), and a path matched against the
   grant's `paths`. An unknown upstream and a profile with no grant are one
   refusal (`unknown_upstream`), so a caller cannot probe what exists. The URL
   is built from the operator's origin and the validated path — never from
   anything the caller sent as a host.
3. **What the request carries** — method, path, query, forwarded headers and
   body cross `defend()` as one document (`egress_request`), judged on a
   credential-redacted copy so a detected secret never reaches the external L3,
   plus the deterministic credential detector over the same document. The
   layers always run; the detector is an added signal, not a per-layer off
   switch.
4. **Where it goes** — through the [egress guard](../src/trentina/egress.py) to
   an address that was checked; no redirect is followed. The profile's token
   for the upstream is injected (`egress_upstreams.<name>.credential`), so the
   agent never holds it.
5. **What comes back** — the response is untrusted content the agent will
   ingest, judged as ingress like the `fetch` tool (`egress_response`).

## Modes

The mode is **profile-fixed** (`egress_http.<name>.enforcement`): there is no
`trentina_mode` argument on a raw HTTP request, and `redact` is meaningless on
an outbound call, so it is rejected at load.

- `block` (default) — a credential shape, a flag or a blocking gap refuses the
  request before anything is sent (`credential_in_request` / `flagged` /
  `not_fully_judged`); nothing executed. On the response, a flagged, unjudged or
  binary answer is withheld with **"executed, response withheld"** (#425): the
  request did reach the destination.
- `flag` — the request is forwarded and the verdict rides back on
  `x-trentina-warning` (the researcher grant).

A refusal is a JSON deny marker (`{blocked, block_reason, scanner}`), with
`X-Trentina-Reason` and a closed reason from `egress_policy.REASONS`.

## Configuration

```yaml
egress_upstreams:
  github:
    upstream: https://api.github.com   # https origin only; no port, path or query
    body: verbatim                      # or json: parse and re-serialize so the
                                        #   destination parses exactly what was judged
    headers_allow: [x-github-api-version]
    credential:
      header: Authorization
      prefix: "Bearer "

profiles:
  agent1:
    auth:
      bearer_token_env: TRENTINA_PROFILE_AGENT1_TOKEN
    egress_http:
      github:
        token_env: AGENT1_GITHUB_TOKEN
        methods: [GET, POST]
        paths: ["/repos/example-corp/*"]
        enforcement: block
    # token_env is optional (absent = no injected credential); a write method is
    # listed, never a switch; paths are prefix globs and empty allows any.
```

`egress_upstreams` are shared; `egress_http` grants are per profile, mirroring
`git_remotes`/`git`. An agent reload cannot add or widen its own `egress_http`
(held, reported `operator_only`, #511): which destinations it may reach is the
operator's.

## Known residues

- A **streaming** response and the **guarded-execution** hook on an egress call
  are #511's next slice. This slice buffers and judges the whole response.
- A **binary** response is not read (gap 32): `block` withholds it, `flag`
  delivers it with the `binary_unread` warning. A non-UTF-8 (binary) **request**
  body is the same: `block` refuses it (`binary_body`), `flag` forwards it.
- A response **larger than the admission cap** is refused (`too_large`,
  executed) rather than split into judged parts: response paging is a later
  slice. Nothing oversized is delivered unjudged.
- Forged-CA TLS MITM (cracking the agent's own end-to-end TLS to a destination)
  is out of scope and not implemented; terminating-as-endpoint is the design.

One `gateway_calls` row is written per request that resolved to a profile
(`egress:<name>`, `DestinationKind.EGRESS`); a request whose bearer token
matches no profile is `401` with no row, so an unknown caller cannot fill the
audit database.
