# The Operator Profile

*Part of Trentina's **Architectural flexibility** promise; see [Why Trentina](../README.md#why-trentina).*

Trentina is meant to be run by an agent. It gets installed, configured, tuned
and kept healthy by an **Operator agent**, and humans set policy rather than
editing YAML. The operator profile (`role: operator`) is that agent's profile.
It owns the gateway. More than one profile may hold it — see
[More than one operator](#more-than-one-operator) — and one of them is named as
the identity the gateway reports as *itself*.

Every other agent is a **tenant** (`role: agent`, the default). A tenant sees
its own tools, its own audit rows and its own section of the config, and
nothing about its neighbours. The operator sees the whole gateway, and holds
what is left of the gateway's service identity — a short list, and since 6.1.0
no model call is on it.

## What the profile is for

The operator holds two things.

**Administration.** The admin tools act on the whole gateway only from this
profile:

| Tool | As the operator |
|---|---|
| `quarantine_stats` | Every profile's calls, detections, destinations and fan-out, compression savings, and every federation link in both directions (`federation`) |
| `cache_flush` | Every cache, by exact name |
| `reconnect_backend` | Any backend, wherever it is configured, and which profiles share it |
| `reload_profiles` | Applies the whole `profiles.yaml`, gateway-wide settings included |
| `config_tool` | Reads and edits `profiles.yaml` itself, then applies it |
| `federation_keygen` | Mints an Ed25519 keypair for a federated edge, returning only its public half |
| `federation_trust` | Asks a federated peer to sign its scanner and judge, verifies it against the key you supply, and stages the trust pin for a person |

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

> **`config_tool`'s shape is a preview surface** (`config-api`, #633). Its
> action names, its arguments and the keys in its result may change in a minor
> release — more of the gateway becomes configurable by tool call each time, and
> that shape has not finished settling. Which writes a person must approve is
> *not* in the surface: those rules are stable, and so is the approval flow
> below. See [stability.md](stability.md). Nothing else on this page is preview —
> the operator profile, `reload_profiles` and `cache_flush` are stable.

Two things the operator can propose and cannot apply, and they are not about
authority — the operator *is* root on this gateway. They exist because the
operator is a model, so what matters is not whether it may but whether it can
be talked into it.

The first is the operator profile: who holds `role: operator`, how a caller
becomes one, and which of them the gateway reports as itself
(`gateway.service_identity`). All three go to the same page, because they are
three spellings of one decision — who runs this gateway — and the blast radius
of getting it wrong is unbounded and permanent.

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
with no passkey or password set nothing can approve, so both stay refused. See
[Approvals](approvals.md) — including `approval_enrol`, which is how you bring
up the page where a person sets one, without anyone touching a shell.

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
without a restart. Trusting the peer's scan is `federation_trust`,
which reads the peer's scanner and judge off the link instead of taking them
from the agent; a person still approves it. A writable config directory is what `config_tool` needs from
the deployment; see [Deployment Hardening](deployment-hardening.md#a-writable-config-directory).

**Service identity.** A few model calls belong to no tenant, and those run
**as the operator** — the one `gateway.service_identity` names when more than
one profile holds the role — on that profile's `defense.provider`,
`defense.model` and `llm_keys`.

Since 6.1.0 that is a short list, and judging and compressing tool
descriptions are not on it. A tenant's tool list is a tenant's own: it is
judged and shortened on that tenant's key, and the results are cached where no
other tenant reads them. Both used to run as the operator, which meant one
tenant's key paid to read another's tool list, and the verdict and the
shortened text were shared by every profile whose thresholds and judge
matched.

| Work | Runs as | Bills |
|---|---|---|
| L3 on a tool **response** | The calling tenant | The tenant's `llm_keys` |
| L3 on a tool **description** (perimeter, `tools/list`) | The listing tenant | The tenant's `llm_keys` |
| Description [compression](compression.md) | The listing tenant | The tenant's `llm_keys` |
| Applying a config change a person approved | The operator | nothing — no model call |

The last row is what is left of the service identity on the request path, and
it spends nothing: an approval arrives from a browser with no bound caller at
all, and `reload_profiles` applies the whole file only for an operator, so
without one the change would be written and then refused by the reload.

**So every profile needs its own `llm_keys`.** A profile with none for the
provider its `defense` resolves to judges nothing — its responses and its tool
descriptions both report `l3_unavailable`, and under `enforcement: block` it is
served no tool list. The loader warns, and `config_tool` reports it in the
write result as `no_llm_key`, because a warning reaches the journal and the
thing writing configs is an agent. Ollama is the exception, being keyless.

Thresholds were never part of the service identity and still are not: each
tenant's own `l2_threshold` and enforcement mode decide what it is shown.
Verdicts are cached per (owner, thresholds, judging model, content) — the owner
being the `grant_owner`, so a derived federation ingress reads its source's
verdicts, since it spends the same credential and the same key.

Before 0.36 there was no declared owner at all: compression used the first
profile's provider in file order, and the perimeter fell through to the
env-global key. #138 gave that work to the operator; 6.1.0 gave it to the
tenant whose list it is, which is where it had been heading. With **no
operator declared** the remaining service-identity work uses the env-global
provider, model and key, and the gateway says so at startup:

```
service identity: no operator profile declared — an approved config write binds the env-global identity, provider=... model=... No model call runs as the service identity: ...
```

With an operator, the same line names it:

```
service identity: operator profile=ops, its own judge provider=gemini model=... It binds the approved-config apply; no model call runs as it
```

The judge in that line is the operator's **own** — what judges the operator's
own tool descriptions. It says nothing about any other profile's, and nothing
about who pays for them. With more than one operator, a line before it counts
the rest.

## More than one operator

Two agents can administer one gateway without sharing a login. Give each its
own profile with `role: operator`, and name the one the gateway binds and
reports as *itself*:

```yaml
gateway:
  service_identity: ops       # one of the operator profiles below
profiles:
  ops:
    role: operator
    auth:
      bearer_token_env: TRENTINA_PROFILE_OPS_TOKEN
    llm_keys:
      gemini:
        api_key_env: GEMINI_API_KEY
  ops-breetai:                # a second agent, its own login, its own key
    role: operator
    auth:
      bearer_token_env: TRENTINA_PROFILE_OPS_BREETAI_TOKEN
    llm_keys:
      gemini:
        api_key_env: GEMINI_API_KEY
```

With one operator the setting is unnecessary and may be left out, so no file
written before 6.4.0 changes meaning. With two or more and no setting, the file
is **refused** rather than resolved by whichever came first: file order
deciding an identity is the defect #138 removed.

Every operator is equal. Each administers the whole gateway on its own
credential, each judges its own tool descriptions on its own key, and each is
held to the keyless-operator rule below — a second operator with no key for its
provider is an admin seat that is served none of the admin tools under `block`.
What the named one gets is not authority but *attribution*: it is the profile in
an approved config write's audit row, and the `perimeter.judge` an operator's
`quarantine_stats` reports.

Because the file must validate at every step, adding the second operator takes
two writes, in this order:

```
config_tool set gateway.service_identity ops      # applies at once: nothing moved
config_tool set profiles.ops-breetai.role operator # stages for a person
```

Doing them the other way round is refused: the candidate would have two
operators and no name. That is deliberate — the choice is made before the
ambiguity exists, rather than after.

Going back the other way is the same two writes reversed, for the same reason:
taking the role off the profile the setting names leaves it pointing at a
profile that is not an operator, and the loader refuses that rather than
resolving it to whoever is left. Point the setting at the operator you are
keeping, then demote the other one.

Any operator may propose either write, including one that is not the named
identity. There is no privilege tier among operators: an operator is root here,
and one that can rewrite another's `auth` block could become it anyway, so a
restriction naming only the service identity would defend nothing while implying
a boundary the design does not have. A person decides instead.

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
- **The operator must hold a key for its own judge.** `llm_keys` for the
  provider its `defense` resolves to (Ollama excepted, which is keyless).
  Since 6.1.0 it pays for nobody else's judging, so a missing key costs only
  its own tools — but its tools are the **admin set**, served by `internal://`
  and judged like any other description. Under the default `block` a keyless
  operator would be served no `quarantine_stats`, no `config_tool` and no
  `reload_profiles`: a gateway nobody can repair through the API, which is how
  configs are written since #633. Every other keyless
  profile degrades to something its operator can still fix; this one degrades
  to a hand edit and a restart. So it fails at load, which on a reload keeps
  the running config.
- **No self-promotion.** A tenant's reload that finds its own `role` changed
  on disk refuses and applies nothing. A promotion takes effect only through an
  operator reload or a restart.
- **No profile may be NAMED after a role.** `agent` and `operator` are
  reserved, and so is any role added later — the rule reads the role enum
  rather than carrying its own list. `role: operator` says what a profile may
  do; a profile called `operator` says nothing and reads as though it did, and
  the two appear in the same sentences ("the operator profile", "an operator
  reload", `/gateway/operator/mcp`). The rule is equality, not a substring, so
  `operator-prime` and `agents` are fine. **This refuses the whole file**, so a
  deployment with such a profile must rename it before upgrading.
- **No duplicate key, anywhere in the file.** A key written twice in one
  mapping refuses the whole file, naming each repeat and its line. YAML keeps
  the LAST one and discards the earlier one silently, so the block a reader
  sees first is not the block that runs — and `config_tool`'s contract is that
  the file a person maintains and reviews in a diff is the file in force. One
  of these reached production: a profile carried `defense:` twice, the gateway
  ran the second, and the comment on the first explained a block that had
  already lost.

  A key that arrives through a `<<: *anchor` merge **and** is written
  explicitly is not a duplicate — that is the override merge keys exist for,
  and it keeps working. Only a key written twice in the same mapping counts.

  `python -m trentina.gateway.profile_lint <profiles.yaml>` reports it as
  `duplicate-key` before you deploy. Note that the lint checks posture over the
  raw YAML and does **not** call `load_profiles`, so a clean lint is not a
  guarantee the gateway will start; the pre-flight that is, is a real load
  inside the image you are deploying, with the unit's mounts and user.

## Changing the operator

Moving the role takes effect at the next reload, and from 6.1.0 it moves very
little: the admin scope, and the binding for an approved config write. No
model call and nobody's bill moves with it.

Changing the operator's `defense.model` re-judges **the operator's own**
descriptions and nobody else's — that's the verdict cache doing its job, not a
bug. Through 6.0.0 it re-judged every profile's, because the operator judged
for all of them; `reload_profiles` reported that as `service_identity_moved`,
a result key dropped in 6.1.1 along with the behaviour. A reload now
invalidates exactly the profiles it names in `changed`.

Verdicts reached by the env-default model keep their cache keys, so an
operator that runs the default model inherits everything judged before
operators existed.
