# Matrix Bridge

*Part of Trentina's **Security** promise; see [Why Trentina](../README.md#why-trentina).*

Encrypted Matrix rooms are ciphertext at the perimeter, so a gateway that only
proxies `/sync` cannot read what it forwards. The bridge terminates the
encryption instead: Trentina's bridge process is the agent's Matrix client
upstream, and the agent talks plaintext to its own homeserver. Every message
crosses L1 ∥ L2 → L3 in both directions. Design and rationale: spec 015
(`.specify/specs/015-matrix-bridge/spec.md`), issue #162.

```
matrix.org ⇄ bridge-<profile>    network: egress only    holds the upstream login + crypto store
                 ⇅ HTTP, two tokens
             Trentina gateway     both networks           judges every event, sole writer below
                 ⇅ appservice (as_token / hs_token)
             conduit-<profile>    agent's internal net    plaintext, federation off
                 ⇅
               agent              agent's internal net
```

The bridge shares no network with Conduit and holds no token for it, so it
cannot deliver anything on its own. The gateway holds no upstream credential,
so it cannot speak to matrix.org without the bridge.

## Gateway: the `matrix_bridge` profile block

```yaml
profiles:
  agent1:
    auth:
      bearer_token_env: AGENT1_TOKEN
    matrix_bridge:
      enabled: true
      public_user_id: "@agent1-bot:matrix.org"   # the identity the bridge speaks as
      bridge_url: http://bridge-agent1:8471       # private host only
      # gateway -> bridge, then bridge -> gateway
      bridge_token_env: AGENT1_BRIDGE_TOKEN
      ingress_token_env: AGENT1_BRIDGE_INGRESS
      enforcement: block                          # or flag
      local:
        homeserver: http://10.0.10.3:6167        # private host only
        server_name: agent1.local
        agent_localpart: agent1                   # the agent's user on Conduit
        as_token_env: AGENT1_AS_TOKEN
        hs_token_env: AGENT1_HS_TOKEN
        sender_localpart: trentina                # the appservice's own user
        user_prefix: remote_                      # stand-ins for remote senders
```

Hosts must be loopback, a private address, or a single-label container name.
The four tokens are resolved (with `_FILE` support) only when `enabled`. Every
field is operator-only: an agent-scope `reload_profiles` holds the block, and
an operator reload reports that a restart applies it.

**Inbound**, each message, reaction and sticker is judged together with its
sender's display name and the room's name and topic. The event IDs its
relation points at are left out of what is judged, in both directions: each is
replaced from the mapping table or dropped, never delivered as written, and an
opaque ID reads to L2 as encoded text (one alone scored 0.79 MALICIOUS on
`prompt-injection-guard-small`, which withheld every reaction). A redaction is mirrored
without being judged, because it carries nothing across: its reason text is
dropped, and it only removes an event that was judged when it arrived. Under `block` a flagged or incompletely judged event becomes a
`[trentina] withheld: <reason>` notice from the appservice bot, keeping its
thread or reply through an allowlisted copy of its relation, never the
relation as sent (#296); a withheld reaction is dropped. Under `flag` it is delivered
with `_trentina_warning` in its content. **Outbound**, only the agent's own
events are carried; a refused one is not sent, and the agent gets a notice.

### Attachments (#491)

An `mxc://` URI names media on one homeserver, and neither side can resolve
the other's: the agent's homeserver does not federate. So no URI crosses,
in either direction; the bytes do, and they are judged with the event they
came in, as one document.

- **Inbound**, the bridge fetches the main media over the authenticated
  media API (`/_matrix/client/v1/media/download`, no redirects), decrypts an
  encrypted room's `file` (nio checks its sha256), and sends the bytes with
  the event. The gateway judges them with the message, uploads them to the
  agent's homeserver as the sender's stand-in, and delivers the event with
  that local `url` in place of the upstream `url` or `file`.
- **Outbound**, the gateway fetches the agent's media from its own
  homeserver. Only a `url` on that server is fetched; any other is refused.
  The gateway judges it, and the bridge uploads it upstream, encrypted for an
  encrypted room.
- **How it is read** goes by the bytes' signature first and the declared
  type second. An image is read by OCR (#370). Text that decodes as UTF-8 is
  read as text. Anything else is binary no layer read, the `binary_unread`
  gap: withheld under `block`, delivered with `_trentina_warning` under
  `flag`.
- **Limits:** 6 MiB per attachment, OCR's own cap, with a 60-second fetch.
  An attachment over the cap, or one that could not be fetched, is withheld
  without being judged and counted in `/health`'s `media_refused`. Inbound
  the agent gets the withheld notice; outbound it gets
  `your message was not sent`.
- **Thumbnails never cross.** Clients draw the picture from the main media.
  An `<img src="mxc://…">` inside `formatted_body` is text and is judged as
  such; it is not re-hosted.

Each carried event ends with one log line giving its outcome, its total time
and its stages: `wait` (behind the previous inbound event), `judge` (L1 ∥ L2 →
L3), and `deliver`, `send` or `notice`. It is INFO, and WARNING once an event
takes 5 seconds, so a slow turn shows where its time went at the production
log level.

Local rooms exist before anyone speaks in them. The bridge announces every
room it is in when it starts, and each room it joins later; the gateway judges
the room's name and topic, creates the local room, invites the agent, and
holds the announcement up to 30 seconds for the agent to join, so the room's
first messages are not written before the agent can read them. An agent that
has not joined by then does not stall the bridge: the room is used anyway,
and the delay is logged.

A direct message is a true DM: its local room is created by the other
person's stand-in and holds exactly two members, the stand-in and the agent.
Agents tell a DM from a group by member count, and a group is where they
answer only when mentioned. A DM made by 0.45.0, with the appservice bot in
it, is handed over when the next event arrives in it.

Remote senders appear as stand-ins, `@<user_prefix><escaped id>:<server_name>`,
where the escape is the spec's mapping (`@Scott_M:matrix.org` →
`@remote__scott___m=3amatrix.org:agent1.local`). The agent's own remote ID is
rewritten to its local ID inbound and back outbound, so mention detection still
works. The agent's allowlists must name the stand-ins and the appservice bot.

### No agent-to-agent channel (#264)

Anyone on matrix.org can invite a bridged account, and two bridged agents in
one room are a direct channel that only injection judging filters. Two rules
close it, one per process.

**The bridge's rule: who may open a room.** An invite is accepted only from a
user listed in `BRIDGE_ALLOWED_INVITERS`; any other invite is rejected and
forgotten. The inviter is the sender of the bridge's own `invite` membership
in the invite's stripped state; an invite that does not say who sent it is
rejected. The bridge records who invited it into each room it joins
(`BRIDGE_STORE_DIR/inviters.json`). On every start, once the first sync has
filled in room state, it leaves and forgets each joined room that fails the
rule: one whose recorded inviter is not allowed, and one with no record (a
room joined before #264) unless everyone else in it, joined or invited, is an
allowed inviter. nio keeps no trace of an inviter after the join, so the
audience is the only evidence left for those rooms; a stranger in the room is
enough to leave it. An audience changes, so such a room is checked again on
every sync, before anything from it is forwarded (#296). An allowed inviter gets a left room back by inviting the
bridge again, which records the inviter. Empty or unset, the list refuses
every invite and leaves every room, and the bridge logs a warning saying so
at startup. For a bridge that answers only Scott:
`BRIDGE_ALLOWED_INVITERS=@fatherlinux:matrix.org`.

**The gateway's rule: who may be on the other end.** Only the gateway knows
every agent: the `public_user_id` of every profile with a `matrix_bridge`
block, enabled or not, plus any agent it does not bridge, listed at the top
level of `profiles.yaml`:

```yaml
matrix:
  other_agent_user_ids:
    - "@ashigaru-crunchtools-bot:matrix.org"
```

Each entry must be a Matrix user ID or the file does not load; it binds at
startup, like the rest of `matrix`. An ID listed here is treated exactly like
another bridged profile's, and matching ignores case. The
bridge sends a room's members with its announcement, at every start and again
whenever they change, and the gateway records whether another agent is among
them (`room_audience` in the mapping store). Then:

- an inbound event whose sender is another agent is dropped before it is
  judged, and marks its room;
- a room announced with another agent in it is refused: no local room is
  made, the bridge is answered `refused`, and it leaves and forgets the room;
- every inbound event in a marked room is dropped;
- nothing is relayed upstream into a room that is marked, or whose members
  the bridge has never reported. The agent gets a
  `[trentina] your message was not sent: <reason>` notice instead.

This holds for a room an allowed inviter opened too: the inviter rule is the
bridge's, the agent rule the gateway's. Every drop is logged with the profile,
a redacted event ID and a fixed reason, never a Matrix ID, and audited in
`gateway_calls` as backend `matrix_bridge`, tool `inbound`, `outbound` or
`room`, outcome `denied_guard`, with the reason in `error_message`.

### A room the bridge leaves is retired (#317)

Whichever rule leaves a room, the bridge first tells the gateway
(`org.crunchtools.trentina.room_left`), and the gateway retires the agent's
mirror of it: a notice in the room saying it is no longer bridged, the name
prefixed `(unbridged)` (a DM keeps none), the agent kicked, and the bot or
the DM's stand-in leaving. The mapping, audience and member rows go with it,
so an invite back into the same upstream room gets a fresh mirror. The
agent's next send there fails at its own homeserver, where its runtime sees
it, instead of being dropped at the gateway with only a log line. The
gateway logs `retired <profile>'s room <local room id>`: that ID is minted by
the agent's homeserver, and it is what to re-point a delivery or home room
away from. A rejected invite has no mirror and is not reported.

### Monitoring outbound refusals

`GET /health` carries `{"matrix_bridge": {"outbound_refused": N, "media_refused": M}}` when a
bridge runs: the agents' events refused outbound since start, by the agent
rule or the judge, summed so the unauthenticated probe names no profile. Each
is a message the agent believes it sent, so alert when it rises. Which
profile is in `quarantine_stats` → `gateway_audit`, backend `matrix_bridge`,
tool `outbound`.

Endpoints, on the gateway's port:

| path | caller | auth |
|---|---|---|
| `POST /bridge/{profile}/event` | bridge process | `Bearer` ingress token |
| `PUT /bridge/as/{profile}/_matrix/app/v1/transactions/{txn}` | Conduit | `hs_token` |

Mapping state (rooms, stand-ins, event IDs, dedupe) is
`bridge-<profile>.db` beside the blocklist. Losing it costs duplicated rooms,
not a breach.

## Bridge process

Same image, its own container, on the egress network only:

```
python -m trentina.bridge.main run
```

| variable | meaning |
|---|---|
| `BRIDGE_PROFILE` | the gateway profile this bridge serves (required) |
| `BRIDGE_USER_ID` | upstream Matrix user (required) |
| `BRIDGE_HOMESERVER` | upstream base URL (default `https://matrix-client.matrix.org`) |
| `BRIDGE_GATEWAY_URL` | gateway base URL, e.g. `http://trentina:8019` (required) |
| `BRIDGE_INGRESS_TOKEN` | presented to the gateway; the profile's `ingress_token_env` value (required) |
| `BRIDGE_TOKEN` | required of the gateway; the profile's `bridge_token_env` value (required) |
| `BRIDGE_PICKLE_KEY` | encrypts the crypto store at rest (required) |
| `BRIDGE_STORE_DIR` | crypto store, session, sync position (default `/data`) |
| `BRIDGE_LISTEN_HOST` / `BRIDGE_LISTEN_PORT` | API bind (default `127.0.0.1:8471`; set `0.0.0.0` in a container) |
| `BRIDGE_DEVICE_ID` + `BRIDGE_ACCESS_TOKEN` | adopt an existing device |
| `BRIDGE_PASSWORD` | log in a new device (first boot only) |
| `BRIDGE_OLD_ACCESS_TOKEN` | `logout-device` only: the token of the device to prune |
| `BRIDGE_RECOVERY_KEY` | `sign-device` only: the account's secret-storage recovery key |
| `BRIDGE_DEVICE_NAME` | name for a new device (default `Trentina bridge`) |
| `BRIDGE_ALLOWED_INVITERS` | comma-separated Matrix user IDs whose invites are accepted; empty or unset accepts none and leaves every room (see above) |
| `BRIDGE_LOG_LEVEL` | default `WARNING`; an unknown name falls back to it. Same format and secret redaction as the gateway's log |

Every secret, and `BRIDGE_ALLOWED_INVITERS`, also reads from `<NAME>_FILE`.
A malformed entry in the list is fatal at startup. After the first start the session
in `BRIDGE_STORE_DIR/session.json` wins over the environment.

The first sync only establishes position; history is not replayed. The sync
position is written only after every event in the batch has been answered by
the gateway: taken, or refused for good. A 5xx, a connection failure, a 401,
403 or 429 is retried until it succeeds, since those are the gateway's state
rather than the event's; any other 4xx (a malformed or oversized event) is
logged at ERROR and dropped, so one bad event cannot stall the room. Events whose keys have not arrived are parked (`pending.json`), their
keys requested, and after ten minutes forwarded as a
`[trentina] could not be decrypted` notice. One parked in a room the bridge
has since left, or is leaving, is dropped instead (#296).

### Adopting a mautrix device

A device already in use keeps its identity and the room keys it holds, and
needs no password. Stop the agent for good first: two processes driving one
Olm account diverge immediately.

```
python -m trentina.bridge.main import-mautrix --crypto-db /import/crypto.db
```

Then start the bridge with `BRIDGE_DEVICE_ID` and `BRIDGE_ACCESS_TOKEN` set to
the agent's.

### Pruning the old device

```
python -m trentina.bridge.main logout-device
```

With `BRIDGE_OLD_ACCESS_TOKEN` set to the agent's old token, for this run
only. A homeserver behind MAS serves neither `/delete_devices` nor `DELETE /devices`;
logging a device out with its own token removes it. Afterwards the agent holds
no upstream credential, which is what makes the perimeter mandatory.

### Verifying a new device

A device the bridge logged in fresh is unsigned, and clients show it as
unverified. An adopted device is usually signed already.

```
python -m trentina.bridge.main sign-device
```

With `BRIDGE_RECOVERY_KEY` set to the account's recovery key, for this run
only. It reads the self-signing key from secret storage, checks it against
the published key, and signs the bridge's device, but only if the
homeserver's copy of the device's keys is exactly what the bridge's own crypto
store holds. No identity is reset, so nobody has to re-verify the account.

A recovery key opens only the secret storage it was made with. If storage was
set up again since, the old key is refused, and if nobody holds the current
one the self-signing key cannot be read at all. Then:

```
python -m trentina.bridge.main reset-identity
```

It generates new cross-signing keys, stores them in new secret storage, and
prints the new recovery key once, before anything is published. Keep it. Then
it uploads the identity; a homeserver behind MAS first asks the account owner
to approve the reset, so the command prints a link, to be opened while logged
in as the account, and waits up to ten minutes. Once it is published, the new
storage becomes the account's default and the bridge's device is signed. If
signing fails, `sign-device` with the printed key finishes it; if the reset is
never approved, nothing was published and the account's default storage is
unchanged; the new key and its copies stay unused beside it, and a rerun
starts again. Everyone who had verified the account sees its identity change and
verifies it again.

## The local homeserver

One per profile, on the agent's internal network only. It is
[tuwunel](https://github.com/matrix-construct/tuwunel) (Conduit until
#1533: Conduit never pushes ephemeral events to an appservice, so the agent's
typing never reached the gateway). Tuwunel still reads Conduit's `CONDUIT_*`
environment and takes over a Conduit RocksDB in place on first boot. The
containers and units keep the name `conduit-<profile>`.

```toml
[global]
server_name = "agent1.local"
database_path = "/var/lib/matrix-conduit/"
address = "0.0.0.0"
port = 6167
allow_registration = false
allow_federation = false
allow_check_for_updates = false
trusted_servers = []
```

Appservices are registered from the admin room. Once,
with a temporary `registration_token`: register the admin user (it joins
`#admins`), register the agent's user, then post

    !admin appservices register
    ```
    id: trentina
    url: http://<gateway ip on this network>:8019/bridge/as/agent1
    as_token: <AGENT1_AS_TOKEN>
    hs_token: <AGENT1_HS_TOKEN>
    sender_localpart: trentina
    rate_limited: false
    receive_ephemeral: true
    namespaces:
      users:
        - exclusive: true
          regex: '@remote_.*:agent1\.local'
      aliases: []
      rooms: []
    ```

and remove the registration token. `receive_ephemeral` is what carries the
agent's typing (see [channel-bridges.md](channel-bridges.md)); without it
everything else still works. Registering the same `id` again replaces it.
