# The Operator Profile

*Part of Trentina's **Architectural flexibility** promise; see [Why Trentina](../README.md#why-trentina).*

Trentina is meant to be run by an agent. It gets installed, configured, tuned
and kept healthy by an **Operator agent**, and humans set policy rather than
editing YAML. The operator profile (`role: operator`) is that agent's seat.
It is the one identity that owns the gateway.

Every other agent is a **tenant** (`role: agent`, the default). A tenant sees
its own tools, its own audit rows and its own section of the config, and
nothing about its neighbours. The operator sees the whole gateway, and the
gateway's own model work runs as the operator.

## What the seat is for

The operator holds two things.

**Administration.** The admin tools act on the whole gateway only from this
seat:

| Tool | As the operator |
|---|---|
| `quarantine_stats` | Every profile's calls, detections, destinations and fan-out, compression savings, and every federation link in both directions (`federation`) |
| `cache_flush` | Every cache, by exact name |
| `reconnect_backend` | Any backend, wherever it is configured, and which profiles share it |
| `reload_profiles` | Applies the whole `profiles.yaml`, gateway-wide settings included |
| `config_tool` | Reads and edits `profiles.yaml` itself, then applies it |
| `federation_keygen` | Mints an Ed25519 keypair for a federated edge, returning only its public half |

These are what an Operator agent's loop needs. It reads a section of
`profiles.yaml` with `config_tool`, writes the change back with the `hash` that
read returned, and gets told what applied and what needs a restart. It watches
`quarantine_stats` for false positives and calibration drift, and heals a
backend with `reconnect_backend` after a redeploy. None of this needs a shell.
See [Roles](profiles.md#roles) for how each tool narrows for a tenant.

Writing config is deliberately read-before-write. `expect_hash` is required, so
a change carries the hash of the version it was composed against: if a person
hand-edited the file in between, the write is refused instead of overwriting
them. The file is the source of truth, not a view over anything, and it stays a
file a person can read, diff and keep in git. Every successful write returns
the next hash, so a run of changes needs one read at the start.

Two things the operator can propose and cannot apply, and they are not about
authority — the operator *is* root on this gateway. They exist because the
operator is a model, so what matters is not whether it may but whether it can
be talked into it.

The first is the operator seat: who holds `role: operator`, and how a caller
becomes one. Minting a second root is the one change whose blast radius is
unbounded and permanent.

The second is `trust_verdict`, which makes this gateway serve another gateway's
response *without* running its own three layers over it. The project
constitution keeps trust administrator-set rather than agent-controlled, and
this is the setting that decides whether a layer runs at all. Everything else
about federation is the operator's, including `federation.peers`, which decides
who may authenticate: that is an access grant like any other, not a decision to
believe someone else's scan.

Both are written the way any other change is written. The gateway stages them
instead of applying them, tells you what a person will be shown, and waits. A
person approves at `/approve`; nothing moves until they do, and on a gateway
with no approval password set nothing can approve, so both stay refused. See
[Approvals](approvals.md) — including `approval_enrol`, which is how you ask a
person to set that password without anyone touching a shell.

Adding a profile no longer needs a restart. Its bearer token used to have to be
an environment variable, which the container carries, which made a brand-new
profile a deployment change — and worse than that, a profile naming a variable
that is not set fails validation, so the write was refused outright. Mint one
with `profile_token` and name it with `auth.bearer_token_name`: it is re-read on
every load, and a reload is a load.

Other things still do. The `llm_providers` and `matrix` sections, and adding an
alert or matrix ingress where no route was registered at startup, all bind when
the process starts. The result's `reload.not_applied` names anything it saw, so
read it rather than assuming.

Keeping the history is the host's job, not the gateway's: the image ships no
`git`, and the git transport carries a caller's client rather than authoring
commits. `contrib/quadlet/trentina-config-commit.{path,service}` commit the
file whenever it changes, which is what turns "the file is the record of what
is running" into a history of how it got there.

Setting up a federated edge needs no shell either: `federation_keygen` mints
the keypair and keeps the private half where no tool can read it, the public
half goes into the peer's config with `config_tool`, and a key referred to by
name is re-read on every reload, so a key minted after startup takes effect
without a restart. A writable config directory is what `config_tool` needs from
the deployment; see [Deployment Hardening](deployment-hardening.md#a-writable-config-directory).

**Service identity.** Some model calls belong to no tenant. Compressing a
shared tool description, and judging it at the perimeter before any profile
sees it, is done once for everyone. That work runs **as the operator**, on the
operator's `defense.provider`, `defense.model` and `llm_keys`, and it bills
the operator's key.

| Work | Runs as | Bills |
|---|---|---|
| L3 on a tool **response** | The calling tenant | The tenant's `llm_keys` |
| L3 on a tool **description** (perimeter, `tools/list`) | The operator | The operator's `llm_keys` |
| Description [compression](compression.md) | The operator | The operator's `llm_keys` |
| Any future gateway-initiated model call | The operator | The operator's `llm_keys` |

Thresholds are not part of the service identity. A shared description is
judged by the operator's model, but each tenant's own `l2_threshold` and
enforcement mode still decide what that tenant is shown. Verdicts are cached
per (thresholds, judging model, content), so a verdict reached by one model is
never served to a profile judged by another.

Before 0.36 there was no declared owner: compression used the first profile's
provider in file order, and the perimeter fell through to the env-global key.
Now, with **no operator declared**, both use the env-global provider, model and
key, and the gateway says so at startup:

```
service identity: no operator profile declared — centralized model calls (...) use the env-global key, ...
```

With an operator, the same line names it:

```
service identity: centralized model calls run as operator profile=ops provider=gemini model=...
```

## Declaring one

```yaml
llm_providers:              # every name under llm_keys must be one of these
  gemini:
    enabled: true
    upstream: https://generativelanguage.googleapis.com
    auth_header: x-goog-api-key
    api_key_env: GEMINI_API_KEY

profiles:
  ops:
    role: operator
    auth:
      bearer_token_env: TRENTINA_PROFILE_OPS_TOKEN
    llm_keys:
      gemini:
        api_key_env: TRENTINA_OPS_GEMINI_API_KEY
    backends:
      web:
        url: "internal://web"
        tools_allow: ["*"]
    # defense.provider / defense.model choose the service identity's model;
    # omitted, the env defaults (TRENTINA_MODEL_PROVIDER, QUARANTINE_MODEL).

  hermes:
    auth:
      bearer_token_env: TRENTINA_PROFILE_HERMES_TOKEN
    llm_keys:
      gemini:
        api_key_env: HERMES_GEMINI_API_KEY
    backends:
      web:
        url: "internal://web"
        tools_allow: ["fetch_tool", "search_tool"]
```

## Rules the loader enforces

- **At most one operator.** Two would make "whose identity" depend on file
  order again, so a second one refuses the whole file. On a reload the running
  config stays in force.
- **The operator pays for its own work.** It must hold `llm_keys` for the
  provider its service identity resolves to (Ollama excepted, which is
  keyless). Without that key, every description would come back
  `l3_unavailable`, and under `block` every tool would be quietly withheld from
  every profile. Failing at load is the better outcome.
- **No self-promotion.** A tenant's reload that finds its own `role` changed
  on disk refuses and applies nothing. A promotion takes effect only through an
  operator reload or a restart.

## Changing the operator

Moving the seat, or changing the operator's `defense.model`, moves every
centralized call to the new identity at the next reload. Descriptions are then
judged again under the new model: that's the verdict cache doing its job, not a
bug. Verdicts reached by the env-default model keep their cache keys, so an
operator that runs the default model inherits everything judged before
operators existed.
