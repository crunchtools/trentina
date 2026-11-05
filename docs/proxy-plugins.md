# Proxies: the perimeter as config

Every way an agent's traffic leaves Trentina other than a tool call is a
**route**: an HTTP path under `/proxy/<type>/<instance>/`, or the CONNECT
listener. A deployment declares the routes it serves as named **instances** of
a **type** under `proxies:`, and grants each profile what it may do on each
instance. Adding a destination is a config change, not a code change.

`forward` and `dist:` route plugins are a [preview surface](stability.md)
(`proxy-plugins`, #535). The built-in types' configuration is stable.

## The grammar

```yaml
proxies:                                  # instances, each of one type
  github: {type: http,    upstream: https://api.github.com,
           credential: {header: Authorization, prefix: "Bearer "}}
  forge:  {type: git,     upstream: https://github.com}
  claude: {type: llm,     upstream: https://api.anthropic.com}
  matrix: {type: matrix,  upstream: https://matrix-client.matrix.org}
  egress: {type: connect}
  bench:  {type: forward, hosts: [aeb-fixture.test]}

profiles:
  agent1:
    auth:
      bearer_token_env: AGENT1_TOKEN
    proxies:                              # grants, each on one instance
      github:
        token_env: GH_TOKEN
        methods: [GET]
        paths: ["/repos/acme/*"]
      forge:
        token_env: GH_TOKEN
        fetch: ["acme/*"]
      egress: {source_networks: [10.0.0.0/24], hosts: [api.example.com]}
      bench:  {hosts: [aeb-fixture.test], enforcement: block}
```

An instance name is `[a-z][a-z0-9-]{0,31}`: a URL segment and an audit column.
Each built-in type takes the settings its older block took
([egress-http.md](egress-http.md), [git-transport.md](git-transport.md),
[llm-proxying.md](llm-proxying.md), [matrix-bridge.md](matrix-bridge.md),
[client-egress.md](client-egress.md)). There is one `matrix` and one `connect`
instance at most. An `llm` grant stays in the profile's `llm_keys` and a Matrix
caller in `matrix_ingress`, so neither takes a grant here.

### The older blocks

`egress_upstreams`, `git_remotes`, `llm_providers`, the proxy keys of `matrix:`,
and a profile's `egress_http`, `git` and `client_egress` still load, with one
deprecation warning each, and are removed at the next major. Both spellings
load to the same configuration. `config_tool get` lists the blocks still
written the older way under `deprecated_keys`. A file that writes one kind
both ways is refused. Rewriting a file into `proxies:` stages nothing for
approval, because it widens nothing.

### What a person approves

The same rules as the older blocks, read off the loaded configuration, so a
write cannot get around them by choosing a spelling:

- A new origin, a new host, or `*` on any instance or grant is an egress grant
  and is [staged for a person](approvals.md). `*` is shown as "ANY host".
- `enforcement: flag` on any grant is a defense downgrade (`flag_grants`) and
  is staged.
- `options:` are never dialled, so they are not a grant. A value in them that
  is shaped like a credential is refused at load.
- Removing a host, an origin or a grant applies at once.

An agent's reload holds its own `proxies:` grants. Which destinations it may
reach is the operator's decision.

## `forward`: an agent-chosen URL

```
GET|POST /proxy/forward/<instance>/fetch?url=<absolute http(s) URL>
```

The one type whose destination the agent chooses. It gives `fetch`'s reach on
a proxy route, with `/proxy/http`'s judging. This is the shape an egress
benchmark drives.

- **Hosts.** The host must be named in both the instance's `hosts` and the
  grant's, and is checked by name before it is resolved. A literal address is
  never a host.
- **Ports.** http on 80 and https on 443 only.
- **Redirects and addresses.** No redirect is followed. Every answer for the
  name is checked on every call and never cached.
- **Judging.** The request line, query, headers and body are judged before
  they leave (the layers, the credential detector, and the gatekeeper where
  configured). The response is judged before it is delivered.
- **Credentials.** None is ever injected. A `forward` instance or grant that
  names one is refused.
- **Refusals.** A refusal is JSON:
  `{"error": {"type": "trentina_refused", "reason": ...}}`.
  - Only when the gateway denied or blocked does it add
    `"blocked": true, "block_reason", "scanner": "trentina"`.
  - An unreachable upstream does not get that marker, so it never counts as
    containment.

`TRENTINA_FETCH_PRIVATE_NAMES` (comma-separated exact names, warned at startup)
lets those names resolve to a loopback or private address. It exists for a
benchmark's local fixtures. Every other name is still held to the address
rule.

## Route plugins (`dist:`)

A route plugin adds a **type**: an HTTP path shape that is not built in. You
install it like a transform plugin ([plugins.md](plugins.md)). It is named
`dist:name` under the entry-point group `trentina.transports.v1`, and declared
in `proxies:` with `type: "<dist>:<name>"`. It is served at
`/proxy/<name>/<instance>/{path}`.

```python
# acme_route/__init__.py
from dataclasses import dataclass
from typing import Any

from trentina.transports.base import (
    SPINE_REFUSALS, Admitted, Bearer, Context, Grant, Instance,
    OperatorOrigin, RefusedError, Route, Wire,
)

@dataclass(frozen=True)
class AcmeAdmitted(Admitted):
    path: str = ""

class Acme(Route[AcmeAdmitted, Context]):
    name = "acme"
    methods = ("GET",)
    auth = Bearer()
    refusals = SPINE_REFUSALS
    max_request_bytes = 4096

    async def admit(self, wire: Wire, grant: Grant, instance: Instance) -> AcmeAdmitted:
        if not wire.path.startswith("v1/"):
            raise RefusedError("not_found")
        return AcmeAdmitted(OperatorOrigin("api"), path=wire.path)

    async def deliver(self, admitted: AcmeAdmitted, ctx: Context) -> Any:
        return await ctx.upstream.send("GET", admitted.path, headers={})

    def render(self, refused: RefusedError) -> Any:
        return refused.reason        # your wire shape; never refused.detail

def make(options):                   # options: the instance's options:
    return Acme()
```

```toml
[project.entry-points."trentina.transports.v1"]
acme = "acme_route:make"
```

An instance of it, and a profile's grant:

```yaml
proxies:
  acme:
    type: "acme-route:acme"
    origins: {api: https://api.acme.example}         # https, no userinfo
    credential: {header: Authorization, prefix: "Bearer "}
    options: {region: eu}                            # handed to make(); never dialled
# under profiles.agent1:
#   proxies:
#     acme: {origins: [api], token_env: ACME_TOKEN}
```

### What the spine owns

A route decides two things: whether a request may go and to which origin
(`admit`), and its own wire shape (`deliver`, `render`). Everything else
belongs to the spine, and a plugin cannot reach it.

| The spine | The route |
|---|---|
| Authenticates the caller and resolves the instance and grant | Reads `Wire`: method, path, query and headers, with the caller's credential removed, and no body |
| Takes the profile's slot before a body byte is read | Reads `ctx.body` in `deliver`, capped at `max_request_bytes` |
| Dials the origin key `admit` named, at the operator's address, pinned and checked | Names an origin by **key**, never a host |
| Judges the request and the response under the grant's `enforcement` | Gets the delivered bytes or a refusal it can only render |
| Injects the grant's credential and scrubs any echo of it | Never holds the credential |
| Writes the one audit row, and spells each refusal's status and outcome | Renders the refusal in its own shape |

A plugin route may not use `Audit.ON_FINDING`, a `Listener`, `PeerAddress`
auth, a built-in's name, or a path outside `/proxy/<name>/`. A row records a
refusal's `reason`, never its `detail`.

### A `dist:` route is gateway code

The contract holds what a route does on the request path. It gets no socket,
no verdict, no audit row and no credential, and it cannot deliver anything
unjudged. **Nothing holds the Python process.** A route plugin runs in the
gateway with the gateway's permissions, as the operator who installed it is
root. Trentina does two things about that:

- **Before import.** At config load, the distribution's source is scanned and
  never imported. The scan refuses:
  - the network, process, file and introspection modules: `socket`, `ssl`,
    `httpx`, `anyio`, `os`, `sys`, `io`, `pathlib`, `importlib`, `inspect`,
    `pickle`, `threading`, `ctypes`, and more;
  - the builtins that read files or run strings: `open`, `exec`, `eval`,
    `compile`, `__import__`, `getattr`;
  - asyncio's dialers and executors, and frame attributes.

  A plugin that fails the scan is refused by name, and none of its code runs.
- **After the scan.** It is imported at startup, its factory is built, and the
  route it returns is held to the contract above.

The scan catches honest mistakes and obvious violations. It is not a sandbox.
Install a route plugin as you would install the gateway. Process isolation for
route plugins is planned.

### Testing it

```python
import asyncio
from trentina.testing import route_conformance

result = asyncio.run(route_conformance("acme-route:acme", make({})))
assert result.ok, result.failures
```

`route_conformance` checks four things and returns each failure by name:

- the import scan (`forbidden-import:socket`, ...);
- the declaration (`name`, `path`, `audit`, `api-version`);
- that `admit` answers a request it holds no grant for with a declared refusal
  and logs nothing the caller sent;
- that `render` answers every refusal without echoing its `detail`.

### Seeing what is served

`quarantine_stats` (operator) reports `routes.mounted`, the routes this gateway
serves. It also reports `routes.plugins`, each installed route plugin by
`dist:name` and version, read from metadata without importing any of them.
