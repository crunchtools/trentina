# Client Egress

A tunnel for the HTTPS an agent's own client opens, to the hosts you name
and to nothing else.

## Why it matters

An agent on an internal network reaches its tools through the gateway. Some
agents also run a client that opens connections itself: a coding agent calls
its model API and its session service, and `git` calls a forge. Without this
you either give the agent a route out, or run a second proxy beside the
gateway that the gateway knows nothing about.

With it, the agent's network needs one peer. The gateway resolves the names,
decides which ones the agent may reach, and records every connection.

**What this is not:** a path the defense pipeline reads. The bytes in a tunnel
are TLS between the agent's client and the destination, and the gateway holds
no key. No layer judges them. This is
[known gap 26](defense-pipeline.md#known-gaps). Client egress bounds *where* an
agent's client can talk and records *how much*; it does not decide *what*. Since
#511 the tunnel is the **fallback** for a client that cannot be re-pointed: a
client that can speak to a base URL should use the [egress route](egress-http.md)
or [`/llm`](llm-proxying.md), which read the request and the response.

For `git`, prefer the [git transport](git-transport.md), and for HTTP a
re-pointable client, the [egress route](egress-http.md). A tunnel to a
forge's host reaches every repository on it with a credential the agent
holds; the git route decides the repository and the branch and keeps the
token in the gateway.

## Configuration

```yaml
profiles:
  agent1:
    auth:
      bearer_token_env: TRENTINA_PROFILE_AGENT1_TOKEN
    client_egress:
      source_networks: [192.0.2.0/29]
      hosts:
        - api.example.com
        - git.example.net
```

| Field | Description |
|-------|-------------|
| `source_networks` | CIDRs the agent's connections come from. The peer address picks the profile, so no two profiles may overlap, and a profile's egress network may not be another profile's Matrix network. |
| `hosts` | Exact lower-case DNS names, at most 64. No wildcards, no addresses, no ports: each name is one decision. |

The listener is a second port, `--egress-port` (default 8021). It is bound
only when some profile has a `client_egress` block, on the same address as
`--host`. Publish it on the agents' internal networks, never on the host.

Point the client at it with the usual variable, by address if the agent's
network has no DNS:

```bash
HTTPS_PROXY=http://192.0.2.2:8021
NO_PROXY=192.0.2.2          # MCP calls to the gateway itself are not proxied
```

There is no credential in that URL, and no field to configure one. Clients
print their proxy URL in errors and status output, which is how a token in a
URL reaches an agent's context. The agent's network is its credential, as it
is for the [Matrix reverse proxy](network-isolation.md).

## What a tunnel must pass

In order, each one deterministic:

1. **The caller is known.** Its address is in exactly one profile's
   `source_networks`. Otherwise `403`, and nothing is recorded against any
   profile.
2. **The request is `CONNECT name:443`.** Any other method is `405`: there is
   no plain-HTTP proxying, because a request the gateway could read is one it
   would owe a verdict on, and that path is the `fetch` tool. Any other port
   is `403`.
3. **The name is listed** in that profile's `hosts`, compared exactly after
   lower-casing.
4. **The name resolves outward.** It goes through the same
   [egress guard](deployment-hardening.md) as every gateway-side fetch: every
   address it resolves to must be global, and the tunnel connects to an
   address that was checked, not to a second lookup. A client opens its
   connections in a burst, so tunnels to one name that start together share
   one check, and its answer serves that profile's tunnels to that name for
   five seconds more (#449). A refusal is never kept.
5. **The client opens TLS naming the host it asked for.** The gateway answers
   `200`, then reads the client's first TLS record before forwarding a byte.
   It must be a ClientHello whose server name (SNI) is the CONNECT host. A
   different name, no name, an encrypted ClientHello or anything that is not
   TLS closes the tunnel.

This last check is on the handshake, not on what follows it. Once TLS is up
the gateway sees nothing, and a client can ask the server for a different
virtual host than the one it named (a `Host` header or HTTP/2 `:authority`
that differs from the SNI, known as domain fronting). Whether that reaches
another site is the server's decision: a dedicated service ignores it, and a
shared CDN may or may not refuse it. So a listed name on a shared front end
is, at worst, a path to whatever else that front end will serve under that
handshake. Prefer names whose servers answer only for themselves, and read
"listed hosts" as "listed TLS endpoints".

A profile holds at most 64 tunnels at once, and a tunnel with no byte in
either direction for 15 minutes is closed.

## Refusals

A refusal before the tunnel opens carries its reason in an
`X-Trentina-Reason` header. The reasons are a closed set:

| Status | Reason | Meaning |
|--------|--------|---------|
| 400 | `malformed` | Not a request the listener understands, or a target that is not `name:port`. |
| 403 | `unknown_caller` | The address is in no profile's `source_networks`. |
| 403 | `port` | A port other than 443. |
| 403 | `host_not_listed` | The name is not in this profile's `hosts`. |
| 403 | `non_global_address`, `unresolvable` | The egress guard refused the name. |
| 405 | `method` | Not `CONNECT`. |
| 502 | `connect_failed` | No checked address accepted the connection. |
| 503 | `busy` | The profile already holds its 64 tunnels. |
| 503 | `resolver_busy` | No DNS lookup slot was free (a profile has 4, and they do not queue). The name was not checked; try again. |

After `200` the client is speaking TLS, so the tunnel is simply closed and the
reason is in the audit row: `no_hello`, `not_tls` or `sni_mismatch`.

## Audit

One `gateway_calls` row per tunnel, written when it closes or is refused:
`backend` is `egress`, `tool` is `connect`, `destination` is `name:443` with
`destination_kind = tunnel`. For a tunnel `bytes_arrived` is what came back
from the destination and `bytes_delivered` is what the agent sent to it.

| Outcome | When |
|---------|------|
| `ok` | The tunnel opened and later closed, by either end or by the idle timeout. |
| `denied_allowlist` | `host_not_listed`. |
| `denied_guard` | `port`, `method`, `malformed`, `busy`, `resolver_busy`, `no_hello`, `not_tls`, `sni_mismatch`. |
| `blocked_defense` | The egress guard refused the name: `non_global_address`, `unresolvable`. |
| `backend_error` | `connect_failed`. |

A burst of `denied_allowlist` rows names the hosts a client wanted and did not
get, which is how a missing entry shows up.

## Who may change it

`client_egress` is perimeter. An operator reload applies an edit to `hosts` or
`source_networks` at once. An agent's own `reload_profiles` never moves its
block: an agent able to reload its own host list could add the one host it was
talked into wanting. The held block is reported under `operator_only`.

Adding the first `client_egress` block to a running gateway needs a restart,
because the listener is a socket bound at startup. The reload says so. A
[honeypot profile](profiles.md#honeypot-profiles) cannot have one.

## Related

- [Matrix Reverse Proxy](network-isolation.md): the full isolation pattern
- [LLM Key Proxying](llm-proxying.md): model calls the gateway can read and admit
- [Git Transport](git-transport.md): git the gateway can read and admit
- [Deployment Hardening](deployment-hardening.md): the egress guard and container flags
- [Audit Log](audit-log.md): the row a tunnel writes
