# Specification: Client Egress

> **Spec ID:** 016-client-egress
> **Status:** Implemented (1.6.0)
> **Version:** 0.1.0
> **Author:** crunchtools
> **Date:** 2026-10-11
> **Ticket:** #442

## Overview

An agent on an internal network with no DNS reaches its tools through the
gateway. Its own client does not always fit that shape. A coding agent's model
API, its session service and its login refresh are HTTPS the client opens
itself, and `git` opens its own to a forge. The choices were to give the agent
a route out, or to run a second proxy beside the gateway that the gateway
knows nothing about.

**Done is:** an agent whose network has one peer, the gateway, running a
client that needs three or four named hosts, with every connection it opens
decided and recorded by the gateway.

## Decision

A second listener in the gateway process that speaks HTTP `CONNECT` and
nothing else, and tunnels to the hosts a profile names.

```
agent ──CONNECT name:443──▶ gateway :8021 ──TCP──▶ a checked address of name
          (no credential)      │
                               ├─ peer address → profile        (source_networks)
                               ├─ name in profile's hosts, port 443
                               ├─ egress.check_url: every answer global
                               ├─ first TLS record: ClientHello, SNI == name
                               └─ one gateway_calls row: host, bytes, outcome
```

### Why not route the model calls through `/llm`

The LLM proxy admits and judges completions and holds the provider key. A
client that authenticates with its own subscription login and whose session
service refuses a custom base URL cannot use it. The tunnel is for that
client. An agent that can use `/llm` should: the gateway reads those calls.

### Why the network is the credential

`matrix_ingress` moved from a token in the URL to the caller's address in
0.51.0 (#330) because clients print request URLs. A proxy URL is printed just
as freely, in errors and in status output, and it sits in the agent's
environment. `ClientEgressConfig` has no field for a credential, and a test
keeps it that way.

### Why the ClientHello is read

`CONNECT host:443` names a host; the bytes that follow need not be for it. On
a shared CDN the address is the same for thousands of sites and the server
picks one by SNI, so a tunnel to one listed name would reach all of them. The
gateway reads the first TLS record, requires a ClientHello, and requires its
server name to be the CONNECT host. An encrypted ClientHello carries a
different outer name and is refused; that is the safe direction.

It also makes the listener TLS-only by construction. Anything else on port
443 is refused before a byte is forwarded.

What the check does not do is bind the requests inside the TLS to that name.
A client can complete the handshake for a listed name and then ask for
another virtual host (domain fronting), and only the server decides whether
to serve it. Closing that would take terminating TLS in the gateway, which
means holding a CA the agent trusts and reading its model traffic; that is a
different product decision and is not made here. It is part of known gap 26.

## What is not decided

The bytes. They are TLS and the gateway holds no key. This is a path through
the gateway that the three layers do not read, recorded as known gap 26 with
a test that holds it open. The tunnel narrows where an agent's client can talk
to a short list and counts what goes each way. A hijacked agent can still
send what it holds to a listed host.

## Security considerations

- **Perimeter, not performance.** The block is held across an agent's own
  reload and refused on a honeypot profile. One agent per network, checked
  against other profiles' egress and Matrix networks.
- **No second resolution.** The tunnel connects to an address `check_url`
  returned, so a DNS answer that changes between check and connect cannot
  move it.
- **Bounded.** Request head 8 KiB and 10 s; ClientHello 64 KiB and 10 s; 16
  tunnels per profile; 15 minutes idle.
- **Closed reasons.** Every refusal reason is one of a fixed set. The host a
  client named is caller-chosen text and is stored only as the audit row's
  destination.

## Module changes

| File | Change |
|------|--------|
| `gateway/client_egress.py` | New: listener, CONNECT parser, ClientHello reader, relay, audit |
| `gateway/profile.py` | `ClientEgressConfig`, `Profile.client_egress`, `is_dns_name`; honeypot rule |
| `gateway/loader.py` | `_check_egress_networks`; `ActiveConfig.egress_listener_configured` |
| `gateway/destination.py` | `DestinationKind.TUNNEL` |
| `gateway/warmup.py` | Start and stop the listener with the lifespan |
| `tools/reload.py` | Hold the block on an agent reload; report a first block as unapplied |
| `__init__.py` | `--egress-port`; configure the listener when a profile has the block |

## Testing

`tests/test_client_egress.py` runs the listener and a destination on loopback
sockets with a ClientHello produced by the `ssl` module: bytes both ways; each
refusal's status, reason and audit row; a name that resolves inward; the wrong
server name, no server name, plain HTTP; a split ClientHello; the tunnel cap;
the idle timeout; an unknown caller; the config, overlap, honeypot and reload
rules. `tests/test_coverage_gaps.py` holds gap 26 open.

Not covered by a unit test and checked at deployment: a real client holding a
long-lived session through the tunnel.
