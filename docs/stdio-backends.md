# Stdio Backends

Front an MCP server that only speaks stdio, without an HTTP wrapper and
without the gateway starting anything.

## Why it matters

Many MCP servers ship as a program that reads requests on stdin and writes
answers on stdout. Trentina reaches backends over a wire, and until #724 a
stdio server needed an adapter in front of it (supergateway, mcp-proxy) to
become an HTTP one first.

The gateway will not start the program itself. It is the one component that
has to stay the chokepoint, and it runs distroless, read-only, with every
capability dropped and no shell. Supervising processes is the init system's
job, and systemd already does it better.

So the host runs the server and the gateway connects to it. A systemd
`.socket` with `Accept=yes` and a `.service` with `StandardInput=socket` hand
each connection to a fresh server process as its stdin and stdout. The gateway
opens the socket and speaks what the server speaks on stdio. The `unix`
carrier ([plugins.md](plugins.md#carriers)) is that wire.

Nothing about judging changes. A `unix://` backend's tool list and tool
responses go through the same steps as an HTTP backend's: pinning, the guards,
L1, L2 and L3, and the audit row. The carrier only moves messages.

## The host side

One socket and one service template per server. The server's command line,
its environment and its credentials live here, never in `profiles.yaml`:

```ini
# /etc/systemd/system/mcp-hub.socket
[Socket]
ListenStream=/run/trentina-mcp/hub.sock
Accept=yes
SocketMode=0660
SocketUser=root
SocketGroup=trentina-mcp

[Install]
WantedBy=sockets.target
```

```ini
# /etc/systemd/system/mcp-hub@.service
[Service]
ExecStart=/usr/local/bin/hub-mcp-server
StandardInput=socket
StandardOutput=socket
StandardError=journal
User=mcp-hub
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
```

`systemctl enable --now mcp-hub.socket`. systemd creates the socket, and
starts `mcp-hub@<n>.service` for each connection.

Each tool call opens a new session (the gateway's rule for every backend), so
each call starts one process. That suits a server that starts in well under a
second. A server that is slow to start will spend its time there.

## The gateway side

Bind the socket directory into the gateway container and name it in
`TRENTINA_SOCKET_ROOTS`. Unset, no `unix://` backend loads:

```bash
podman run ... \
  -v /run/trentina-mcp:/sockets \
  -e TRENTINA_SOCKET_ROOTS=/sockets \
  quay.io/crunchtools/trentina
```

The gateway's user has to be able to connect to the socket: put it in the
socket's group, or set `SocketMode` accordingly. On an SELinux host a
container connecting to a host service's socket may be denied by policy. If the
backend reports the call failed and the socket is listening, look for an AVC
with `ausearch -m avc -ts recent` before anything else.

Then the profile:

```yaml
backends:
  hub:
    url: unix:///sockets/hub.sock
    tools_allow: ["search_*"]
```

The carrier follows from the URL; nothing names it. Everything a backend
takes applies (`tools_allow`, the literal and semantic guards,
`destination_params`, `l3_briefing`, `preprocess_tools`, the timeouts), except
what only HTTP carries. `headers`, `auth` and `federated` are refused at load
for a `unix://` backend: there is no header to send, OAuth and federation
reach a peer over https, and a credential header that would be silently
dropped is better refused.

## What is checked

At load:

- The URL is `unix:///<absolute path>`, already normalized, with no host,
  query, fragment or `%` escape. The socket's file name is at most 80 bytes.
- The path as written sits under a `TRENTINA_SOCKET_ROOTS` directory.

At every connect:

- The socket's directory resolves under a root and is opened one component at
  a time without following a link.
- The socket itself is a socket, not a link or a file.
- The connect goes through the opened directory
  (`/proc/self/fd/<n>/<name>`), so a link swapped in above the socket after
  the check cannot redirect it.

A refusal is one of `no_socket_roots`, `outside_socket_roots`, `not_found`,
`not_a_socket` and `changed_during_connect`, and never prints the path. A
refused or failed connect counts against the backend's circuit like any
unreachable backend. `reconnect_backend` resets it, keyed by the URL as
always.

What is not covered: the socket's own name in its directory can be replaced
by whoever can write that directory. Keep the directory owned by root and the
socket's group, as above.

## See also

- [Plugins: carriers](plugins.md#carriers): the contract the `unix` carrier
  implements, and how a third-party carrier is installed.
- [Deployment Hardening](deployment-hardening.md): the container flags this
  keeps intact.
