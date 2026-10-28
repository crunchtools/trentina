# Plugins

Trentina has two plugin registries, and nothing else is pluggable: **transforms**
(reshape content before the gate) and **transports** (speak a protocol). The
fail-closed verdict is not pluggable — sameness is the security property, so it
is one sealed function, never a plugin.

This page is the author and operator guide for **transform plugins**. A plugin
is Python code the operator installs into the image, so **review a plugin before
you install it, as you would any dependency**. Two boundaries hold regardless of
that review, and they are different in kind:

- **The type system bounds what a plugin can do to Trentina's decisions — in
  effect now, by construction, reviewed or not.** A transform returns
  `str`-shaped results; it cannot construct a verdict, skip or reorder the gate,
  dial an unchecked address, or forge a `_trentina_*` marker. Everything it
  emits crosses `defend()` as untrusted, exactly like a built-in transform's
  output. A buggy or hostile plugin cannot turn a *refuse* into a *deliver* or
  smuggle content past the scanner.
- **The process tier bounds a plugin's resources and environment.** By default a
  plugin runs in a child process with CPU, memory and wall-clock limits and no
  credential in its environment, so it cannot exhaust the gateway or read a
  secret from its own environment (see [Isolation](#isolation)).

The process tier is **not** a sandbox for hostile code: a plugin runs as the
gateway's OS user, so it can still read any file that user can read and reach
whatever the container's network allows. Bounding a plugin's filesystem and
network is the job of the deployment's container hardening (read-only rootfs,
network isolation; [Deployment Hardening](deployment-hardening.md)) — and even
hardened, running a plugin you have not reviewed is not something Trentina's
in-image tiers make safe on their own. Treat an installed plugin as code you
trust; the ecosystem is authors writing plugins, sharing them, and operators
reviewing and installing the ones they choose.

An operator who trusts a plugin fully can opt it down to the in-process tier
(`TRENTINA_PLUGIN_INLINE`) for speed; there the plugin runs in the gateway
process with full reach and no resource bound.

## The contract

A transform plugin is an ordinary Python distribution that:

1. depends on `trentina` only at development time, to import the public contract;
2. subclasses `trentina.transforms.base.Transform`; and
3. exposes a factory in the `trentina.transforms.v1` entry-point group.

```python
# my_plugin/__init__.py
from trentina.transforms.base import Applied, Declined, Transform, TransformContext, TransformResult


class Shout(Transform):
    name = "shout"                      # must equal the entry-point name

    async def run(self, payload: str, ctx: TransformContext, /) -> TransformResult:
        if not payload.strip():
            return Declined("empty")    # not my shape — a safe no-op
        return Applied(payload.upper(), {"chars": len(payload)})


def make(config) -> Transform:          # the entry-point factory
    return Shout()
```

```toml
# pyproject.toml
[project]
name = "acme-shout"
dependencies = []

[project.optional-dependencies]
dev = ["trentina @ git+https://github.com/crunchtools/trentina@v2.1.0"]

[project.entry-points."trentina.transforms.v1"]
shout = "acme_shout:make"
```

`run` returns one of three outcomes and the TYPE says which: `Applied` (rewrote
the payload), `Declined` (not this transform's shape — a safe no-op), or `Failed`
(tried and could not finish). A `required` transform that returns `Failed`
refuses the call; a non-required one passes the original through. `run` never
raises on hostile input, and its regexes must be linear-time — an attacker
choosing the input must not be able to buy quadratic work.

The dev dependency is a **git-tag**, not a published package: the gateway is
distributed only as a container image, so there is no `trentina` on PyPI. You
build and test against the tag; the operator installs your plugin into the image.

## `api_version` — the compatibility promise

`Transform.api_version` defaults to `1`. Within a major version, Trentina only
*adds* methods that carry defaults to the contract and never changes `run`'s
signature, so a plugin built against v1 keeps working. The entry-point group
carries the version (`…​.v1`); a future incompatible contract would be a new
group. A plugin declaring an `api_version` this build does not support is refused
**by name at config load**, never with an `AttributeError` at the first request.

## Testing your plugin

`trentina.testing` is public, alongside the two base contracts. Run it against
your plugin before you ship it:

```python
import asyncio
from trentina.testing import conformance, scan_imports
from my_plugin import make

# The load-bearing, synchronous check: the import boundary over your dist.
assert scan_imports("acme-shout") == []
# The full suite over a built instance: declines empty/binary, bounded
# amplification, roughly linear cost, logs no payload.
result = asyncio.run(conformance("acme-shout:shout", make({})))
assert result.ok, result.failures
```

The gateway runs the load-bearing half (`scan_imports`) at startup for every
plugin a profile names, so a plugin that imports a private `trentina` module or
a network/subprocess module is refused BY NAME at config load, never at the
first request.

## Installing (operator)

Nothing a verdict depends on is fetched at run time, and the container image is
the only distribution — so a plugin is installed INTO a derived image, pinned,
never loaded from a path or URL at run time:

```dockerfile
FROM quay.io/crunchtools/trentina:2.1.0 AS base

FROM python:3.13 AS build
RUN pip install --target=/plugins "acme-shout==1.2.3" --require-hashes -r hashes.txt

FROM base
COPY --from=build /plugins /usr/lib/python3.13/site-packages/
```

## Using it (profile)

Name the plugin `dist:name` anywhere a built-in transform is named, in a
processor chain — in a profile's `preprocess` (or a channel's):

```yaml
# under a profile in profiles.yaml, alongside the built-ins:
preprocess:
  processors: [detect, "acme-shout:shout"]
```

A bare name (no colon) is a built-in; a `dist:name` is a plugin. A plugin is
named only at the profile or channel level, never in a per-tool override, and a
processor chain is operator-only to change on reload — so a plugin is only ever
introduced by an operator, through the file, never by an agent reloading its own
section.

Version pinning (`plugin_versions: { acme-shout: "==1.2.3" }`, a mismatch refused
at load) is *planned for this release line and not yet available*.

## When it is refused

Plugin failures surface as **config-load** errors naming the operator-authored
thing (the distribution, the entry point) — read by an operator, not an agent:

- the distribution is not installed;
- the distribution exposes no such entry point;
- the factory did not return a `Transform`;
- the `Transform` declares an unsupported `api_version`;
- the factory raised while building (the real traceback is chained for you);
- the transform is named on a channel or kind it does not support.

Run-time refusals an agent sees stay closed reason codes, never these strings.

## Isolation

A plugin runs in one of two tiers:

- `process` (the default) — the plugin runs in a child process
  (`python -m trentina.plugins.worker`) that sets `RLIMIT_CPU`/`RLIMIT_AS` on
  itself, holds no credential in its environment, runs under a slot cap, and is
  killed at a wall-clock deadline — the same mechanism Trentina runs hostile
  document parsers in. The child rebuilds the plugin from its ref, so the plugin
  never runs in the gateway process. This bounds the plugin's TIME, CPU, MEMORY
  and ENVIRONMENT credentials; it does NOT by itself restrict the plugin's
  filesystem or network — those are bounded by the container's hardening (see
  [Deployment Hardening](deployment-hardening.md)). It is a resource and
  environment bound, not a sandbox for hostile code (review what you install).
- `inline` — set `TRENTINA_PLUGIN_INLINE=true`. The plugin runs in the gateway
  process. Faster, but with full import, environment and network reach and no
  time/CPU bound, so choose it only for a plugin you trust as you trust the
  gateway's own code.

Both tiers bound a plugin's OUTPUT: a result that is not one of the three
outcomes (or an `Applied` with non-string content) is a failure, and an
`Applied` far larger than its input is refused (a transform may not inflate).
The process tier adds the time, CPU, memory and host bounds the in-process tier
cannot enforce.

## Sharing and promotion

Publish your plugin repository on GitHub. A good one can be proposed as a PR into
Trentina's own in-tree transforms — the in-tree transforms implement this *same*
public contract (core code gets no privileged hook between transform and gate),
so there is nothing to rewrite.
