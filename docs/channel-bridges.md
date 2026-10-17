# Channel Bridges

An agent can be reached on more than one upstream channel (#483, spec 020).
Each channel is a bridge process that holds that upstream's credentials and
nothing else. The gateway judges everything in both directions and is the
only writer into the agent's Conduit, exactly as for Matrix
([matrix-bridge.md](matrix-bridge.md)). A channel bridge can hand the gateway
bytes to judge. It cannot deliver them.

```
upstream A ── bridge A ──┐                      ┌── @remote_* rooms
                         ├── gateway (judges) ──┤                    ── agent
upstream B ── bridge B ──┘                      └── @rcs_* rooms
```

## Profile

`matrix_bridge` is the `matrix` channel. Every other channel goes in
`bridges`, keyed by a name matching `[a-z][a-z0-9]{0,15}`, with the same
schema:

```yaml
bridges:
  rcs:
    enabled: true
    public_user_id: "@agent1:rcs.invalid"   # the agent's upstream identity
    bridge_url: http://10.89.0.40:8472
    bridge_token_env: AGENT1_RCS_BRIDGE_TOKEN
    ingress_token_env: AGENT1_RCS_INGRESS_TOKEN
    local:
      homeserver: http://10.89.10.3:6167    # the same Conduit as matrix
      server_name: agent1.local
      agent_localpart: agent1
      as_token_env: AGENT1_RCS_AS_TOKEN
      hs_token_env: AGENT1_RCS_HS_TOKEN
      user_prefix: rcs_
      sender_localpart: trentina_rcs
```

Each channel is its own appservice registration on the agent's Conduit.
Conduit pushes an agent's event to every appservice whose namespace a room
member matches, so the profile refuses two channels that share a bridge URL,
any token env var, or an overlapping namespace (one prefix starting the
other, or a sender inside another's prefix) on one `server_name`. Register
the channel like the matrix one, with its own id, tokens, sender and regex,
and the channel in the URL:

    url: http://<gateway ip>:8019/bridge/as/agent1/rcs
    sender_localpart: trentina_rcs
    namespaces:
      users:
        - exclusive: true
          regex: '@rcs_.*:agent1\.local'

Logs and audit name the bridge `agent1/rcs`. The matrix channel stays
`agent1`. The mapping store is `bridge-agent1-rcs.db`. The agent rule
(#264) treats every channel's `public_user_id` of every profile as an
agent, except this profile's own.

## The wire contract

This is the whole interface a new channel implements. IDs are opaque to the
gateway but must be Matrix-shaped (`@user:server`, `!room:server`,
`$event`). A channel with no such IDs invents stable ones under a server
name it owns or under `.invalid`.

**Bridge to gateway:** `POST /bridge/{profile}/{channel}/event`, with Bearer
`ingress_token` and a JSON `BridgeEvent` (`gateway/matrix_bridge/routes.py`).
The bridge retries until it gets a 200: the gateway answers only once the
event is in Conduit, or deliberately withheld or skipped, and dedupes on
`event_id`.

- `org.crunchtools.trentina.room`: announce a room the agent should be
  in, with `room.members` (every member but the bridge's own user) and, for
  a DM, `room.is_direct` and `room.peer`. Announce every room on every start.
  A room whose members were never announced is refused outbound.
- `org.crunchtools.trentina.room_left`: retire a room's mirror.
- `m.room.message`, `m.reaction`, `m.sticker`: judged and carried.
  `m.room.redaction`: mirrored, never judged (it can only remove).

**Gateway to bridge:** Bearer `bridge_token` on `bridge_url`.

- `POST /send` `{room_id, type, content, txn_id}`. The bridge answers
  `{"event_id": ...}`, idempotent on `txn_id`.
- `POST /redact` `{room_id, event_id, txn_id}`.
- `GET /health`: 200 when ready, 503 while starting.

A 4xx other than 401, 403, 408 or 429 means "never": a type the channel has
no form for, or a channel that cannot unsend (RCS answers `/redact` with
422). The gateway drops that event, counts it in `/health`'s
`outbound_refused`, and posts the agent a notice. Any other failure leaves
the appservice transaction unacknowledged, so Conduit retries it.

Everything the gateway receives is untrusted and capped (#267). The bridge
gets back only what the judge passed.
