# Stability tiers

Trentina is one program with one version. Until 5.0.0 that meant a breaking
change anywhere forced a major bump for everything, so an operator reading a
version number could not tell whether the break was in the defense pipeline
they depend on or in a feature they do not use.

Stability tiers fix that. Most of the gateway is **stable**. A small, named set
of features is **preview**.

## What the tiers promise

**Stable** — the default, and everything not named below. Configuration keys,
wire formats and tool shapes change only in a major release, with upgrading
notes.

**Preview** — a named feature whose configuration and wire shape are not yet
frozen. A breaking change *confined to* a preview surface is a **minor** bump.

The tier is a promise about **blast radius**, not a licence for churn. A
preview surface carries the same test, lint, review and documentation bar as
the rest of the gateway. What it does not carry is a frozen shape.

Two rules keep the promise honest:

- A change reaching anything outside every declared preview surface is a
  **major**, exactly as before. "Mostly confined" is not confined.
- A surface is declared **before** the release that relies on it, never during
  one. Declaring a feature preview in the same release that breaks it would be
  re-characterising the break after the fact.

## The preview surfaces

| Surface | Issue | Shape that may change | Docs |
|---|---|---|---|
| `federation` | #592 | A seat's `federation` block, the derived ingress profile, the primary JWT, and the signed verdict assertion | [federation.md](federation.md) |

Nothing else is preview. In particular, API-driven configuration (#633) and
human approval (#637) are **stable** despite having churned recently.

That is a choice, not a consequence of the rules. 5.0.0 is a major release, so
the breaking changes it makes to either of them need no preview declaration;
declaring one here would only buy the freedom to break it again in a *minor*,
which is forward-looking and so is not the retroactive move the second rule
forbids. The reason to decline that freedom is what the declaration would say
to an operator. Human approval is a consent boundary: "we may change how a
person authorises a trust pin, in a minor" is the wrong promise to make about
the one mechanism here that a model cannot talk its way past. API-driven
configuration is the arguable one — it is young and its tool shape will move —
and we have simply not taken the freedom yet.

Adding a new `Kind` to human approval, or a new rule to `config_guard`, is a
TIGHTENING: something an operator could do alone now needs a person. It is not
a breaking change and does not need a preview surface to happen in a minor.

## How you know

Three places, and they agree:

- **At startup.** The gateway logs one `WARNING` per preview surface this
  deployment actually uses, naming the surface, its issue and its doc. A
  deployment that federates sees a federation line; one that does not sees
  nothing.
- **From the gateway.** `quarantine_stats` reports `preview_surfaces` in the
  operator slice — the surfaces in use, with their issues and docs. Empty is
  the common answer and the reassuring one.
- **In the changelog.** A release whose breaking changes are confined to a
  preview surface lists them under a `### Preview` heading naming the surface.
  A `### Preview` section is how a minor release is allowed to break something.

## Leaving preview

A surface leaves preview by a deliberate decision, not by surviving long
enough. Freezing one means: removing its row from the table above and its entry
from `stability.py`, and saying so in the changelog. From then on its
configuration and wire shape are major-release territory like everything else.

The reverse — moving a stable surface into preview — is not a thing. A shape
that has been promised cannot be un-promised; it can only be broken in a major
release.
