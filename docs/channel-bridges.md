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
- An event whose content names media (`url` or `file`) carries its bytes
  in `media` `{status, content_type, base64}` (#491): `status` is `ok` (with
  `base64` holding the bytes, at most 6 MiB), `too_large` or `unavailable`. One
  without `media`, or not `ok`, is withheld. See
  [matrix-bridge.md](matrix-bridge.md#attachments-491).

**Gateway to bridge:** Bearer `bridge_token` on `bridge_url`.

- `POST /send` `{room_id, type, content, txn_id}`. The bridge answers
  `{"event_id": ...}`, idempotent on `txn_id`.
- `POST /upload` `{room_id, content_type, filename, base64}` (#491): judged
  media as base64. The bridge answers `{"url": mxc}`, or `{"file": ...}` in
  an encrypted room, and the gateway puts it in the `/send` that follows. A
  channel that cannot carry media answers 404, and the agent is told.
- `POST /redact` `{room_id, event_id, txn_id}`.
- `POST /typing` `{room_id, typing}` (#1533): whether the agent is typing
  there. Best effort: answer 200 with `{"shown": true|false}`, never an
  error for a bubble that did not go; the gateway tries again on the
  agent's next push, not by retrying. It carries nothing to judge. The gateway sends
  a change, and a still-typing agent again every 15 s, since upstream
  indicators lapse. It reads only `m.typing` from the transaction's
  ephemeral section, which the homeserver sends only to a registration
  with `receive_ephemeral: true`. Typing goes upstream only: the agent never
  sees the owner's.
- `GET /health`: 200 when ready, 503 while starting.

A 4xx other than 401, 403, 408 or 429 means "never": a type the channel has
no form for, or a channel that cannot unsend (RCS answers `/redact` with
422). The gateway drops that event, counts it in `/health`'s
`outbound_refused`, and posts the agent a notice. Any other failure leaves
the appservice transaction unacknowledged, so Conduit retries it.

Everything the gateway receives is untrusted and capped (#267). The bridge
gets back only what the judge passed.

## The RCS bridge (#485)

`python -m trentina.rcs_bridge.main run` (`trentina-rcs-bridge`), one per
agent, from the same image. It carries one agent's Twilio RCS sender and one
owner's phone: a single DM room, `!<agent>-owner:rcs.invalid`, with the owner
as `@tel<digits>:rcs.invalid` (the agent sees `@rcs_tel<digits>=3arcs.invalid:<server>`).

| Variable | |
|---|---|
| `BRIDGE_PROFILE`, `BRIDGE_CHANNEL` (`rcs`) | which gateway bridge this is |
| `BRIDGE_GATEWAY_URL`, `BRIDGE_INGRESS_TOKEN`, `BRIDGE_TOKEN` | as the Matrix bridge's |
| `BRIDGE_LISTEN_HOST`/`_PORT` (8472) | private API, the gateway's network only |
| `RCS_WEBHOOK_HOST`/`_PORT` (8473) | public webhook, behind the proxy only |
| `RCS_WEBHOOK_URL` | the exact https URL set in Twilio: the signature covers it |
| `RCS_AGENT_USER_ID` | the profile's `bridges.rcs.public_user_id` |
| `RCS_OWNER_NUMBER`, `RCS_OWNER_NAME` (`Owner (phone)`) | the one number accepted (E.164), and its display name |
| `RCS_ROOM_TOPIC` | the room's topic, which the agent reads (default: text messages with the owner's phone over RCS). The gateway judges it with every message, so it must describe, never instruct: a topic that reads as an instruction gets every text withheld. Put trust guidance in the agent's own instructions |
| `RCS_SERVER` (`rcs.invalid`) | the server name the synthetic IDs live under |
| `RCS_TWILIO_ACCOUNT_SID`, `RCS_TWILIO_AUTH_TOKEN` | the agent's account (a subaccount per agent keeps one agent's token from speaking as another) |
| `RCS_TWILIO_SENDER_ID` | the RCS sender's ID (`rcs:` optional). Messages go `From` it, so there is no Messaging Service, which Twilio allows an RCS sender into only after carrier approval, and no SMS fallback |
| `BRIDGE_STORE_DIR` (`/data`) | `rcs.db`, 0600: the inbox and the sent log |
| `RCS_TWILIO_API` (`https://api.twilio.com`) | the API base, for tests |
| `RCS_TWILIO_MESSAGING_API` (`https://messaging.twilio.com`) | the typing indicator's API base, for tests |
| `BRIDGE_LOG_LEVEL` (`WARNING`) | as the Matrix bridge's |

Inbound, `POST /twilio/inbound` refuses anything unsigned (403), for
another account (ignored), or from any number but the owner's (403). A
message is written to the store before Twilio hears 200, because Twilio does
not retry, and leaves the store only once the gateway has it. Attachments are
named, not carried.

The agent's typing shows on the owner's phone through Twilio's typing
indicator (`POST {RCS_TWILIO_MESSAGING_API}/v3/Indicators/Typing.json`,
default host `https://messaging.twilio.com`), at most one every 12 s. RCS has
no stop: the bubble lapses after about 20 s or when the reply arrives.

Outbound, text, notices and emotes go out as plain text (markdown flattened)
in chunks of at most 1,600 characters, recorded per chunk so a retried
`/send` resends only what did not go. An edit goes out as its new text,
prefixed `(edited) `. A reaction is accepted and dropped, and so is its
redaction: on RCS it would be a billed message saying nothing, and refusing
it would tell the agent its message was not sent. Everything else, and any
other `/redact`, is a 422. US RCS text is billed per 160-byte segment, so a long reply costs
several messages.
