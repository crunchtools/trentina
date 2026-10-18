# Specification: Channel Bridges

> **Spec ID:** 020-channel-bridges
> **Status:** In Progress
> **Version:** 0.1.0
> **Author:** crunchtools
> **Date:** 2026-10-17
> **Ticket:** #483 (RT #1529)

## Overview

Spec 015 terminates Matrix E2EE in a bridge process and makes the gateway
the only writer into each agent's Conduit. The gateway half was already
channel-neutral: it judges a `BridgeEvent`, writes it as a stand-in, and
hands the agent's replies to the bridge's `/send`. A profile could hold only
one bridge, though, so an agent had exactly one upstream.

**Done is:** a profile lists more bridges under `bridges`, keyed by channel
name, and each one is a separate upstream speaking the same wire contract
(`docs/channel-bridges.md`). Phase 2 of RT #1529 adds an RCS bridge for
Scott's phone. Existing profiles load and behave exactly as before.

## Decision

CTO (2026-10-17, plan approved by Scott): RCS and any later channel join
behind the gateway, not beside it. A standalone appservice would bypass the
judge and the sole-writer rule, and SMS is the least trusted input we would
carry. Rejected:

- `bridges.matrix` with `matrix_bridge` as a legacy alias. It would migrate
  every profile to buy no behavior.
- A `kind` field. The gateway treats every channel identically. A channel
  that cannot do something (RCS cannot redact) says so by refusing the call.

## Shape

```yaml
matrix_bridge:            # unchanged; the channel named "matrix"
  ...
bridges:
  rcs:                    # same schema as matrix_bridge
    public_user_id: "@kagetora:rcs.invalid"
    bridge_url: http://10.89.0.40:8472
    ...
    local:
      user_prefix: rcs_
      sender_localpart: trentina_rcs
```

- Channel names match `^[a-z][a-z0-9]{0,15}$` and may not be `matrix`.
- Every bridge on one profile has its own Conduit appservice registration.
  No two may share a `bridge_url`, a token env var, or an appservice
  namespace on the same homeserver (an exclusive namespace in both would
  deliver the agent's events to two channels). The profile validator
  refuses any of these.
- Routes: `/bridge/{profile}/{channel}/event` and
  `/bridge/as/{profile}/{channel}/_matrix/app/v1/...`. The matrix channel
  keeps its existing paths.
- Mapping store: `bridge-<profile>-<channel>.db`; matrix keeps
  `bridge-<profile>.db`.
- The agent rule (#264) refuses rooms holding any bridged agent's upstream
  ID on any channel. A profile's own IDs on every channel are exempt.
- Logs and audit name the bridge `<profile>/<channel>`; matrix stays
  `<profile>`, so existing alerts and dashboards keep matching.

## Security Considerations

- No new credential reaches the gateway beyond each channel's four tokens,
  which are resolved the way `matrix_bridge`'s are and only when enabled.
- A new channel's bridge is as untrusted as the Matrix one: it can hand the
  gateway bytes to judge, never deliver them.
- The namespace-collision check is the one new rule. Without it, a
  misconfigured second channel could receive the agent's replies to the
  first.

## Testing Requirements

- Existing bridge tests pass unchanged.
- Config: a valid second channel loads; `matrix` as a key, a bad name, a
  shared `bridge_url`, a shared token env and an overlapping namespace on
  one homeserver are each refused.
- Routes: an event to `/bridge/p/rcs/event` reaches the rcs bridge with the
  rcs ingress token and is refused with the matrix one, and the reverse.
- The agent rule refuses a room holding another profile's rcs ID.
