# Contributing

`CLAUDE.md` is context for an agent. This is the page for a person.

## Setup

```bash
git clone https://github.com/crunchtools/trentina
cd trentina
pre-commit install
```

That one command now wires three git hooks — `pre-commit`, `pre-merge-commit`
and `pre-push`. If you cloned this repo before November 2026 and ran
`pre-commit install` then, run it again: `pre-commit install` only wires the
hook types the config asked for on the day you ran it, so an older checkout has
no pre-push hook and the push tier silently does nothing. The commit tier
checks for exactly this and fails the commit if the pre-push hook is missing.

The host needs `git`, `podman`, `pre-commit` and `gh`, and nothing else. Every
gate runs from a container image, so there is no `uv`, `pytest`, `ruff`,
`semgrep`, `trivy` or `rpmbuild` to install. That is constitution XII's host
contract, and `validate-constitution.py` enforces it against every hook in
`.pre-commit-config.yaml`.

## The four tiers

`./scripts/gates.sh commit|push|pr|release` runs a tier by hand. `commit` and
`push` are the git hooks, so you normally meet them by committing and pushing.

| Tier | When | What runs | Roughly |
|---|---|---|---|
| commit | every commit | ruff (staged, and the whole tree as CI lints it), mypy, Gourmand, Gatehouse over the staged diff | under a minute, nearly all of it Gatehouse |
| push | every push | the full pytest suite, semgrep rule tests and scan, Gatehouse over `origin/main...HEAD` | two to four minutes |
| pr | by hand, before you open one | the container build, the verification CI runs inside the image, trivy, the constitution validator | eight to twelve minutes warm |
| release | by hand, before you tag | the constitution validator and `make rpm` | two to three minutes warm |

"Warm" matters. The first `pr` run on a machine pulls five base images, resolves
the locked dependency set, downloads the ONNX model and fetches Trivy's
vulnerability database, and can take half an hour. Everything after that reuses
the `crunchtools-hook-cache` volume and podman's image store. The image build
alone is about four minutes; a rebuild that touched only `src/` skips the
dependency install and saves about thirty seconds of it.

Two Gatehouse reviews is deliberate. The commit hook reads one staged diff, so
nothing looked at the branch as a whole until the push tier added
`origin/main...HEAD` — which is how findings used to arrive from CI after the
local hook had gone green.

## Exit codes

- `0` — the gate passed.
- `1` — the gate **ran and failed**. Fix the code.
- `2` — the gate **could not run**: no podman, an unreachable registry, a
  missing `~/.config/mcp-env/gatehouse.env`, an `origin/main` that does not
  resolve.

`2` is never a warning and never a pass, and the message never tells you to
install something on the host. A gate that cannot run is an incident, not a
nuisance: find out why it cannot run. Working around it defeats the only thing
it was there for.

## Skipping a gate

`SKIP=<hook> git commit …` is the sanctioned escape hatch and the only one. It
is for a false positive, which Gatehouse produces occasionally and the others
essentially never. Using it obliges you to answer the same finding on the pull
request, because CI will raise it again and a reviewer deserves to know you
already looked. Do not disable a hook, do not `--no-verify`, and do not
reach for `SKIP` because a gate is slow.

## Building the image

```bash
./scripts/gates.sh container-build     # then container-verify, trivy
```

Local builds are supported and need no credential. What causes drift is
*pushing* a hand-built image, which only `.github/workflows/container.yml`
does.

The published pipeline builds the image exactly once per run. A pull request
builds it in `Container Security Scan`, which also verifies it as production
runs it and gates on Trivy, and skips the build entirely when nothing the image
is built from changed. A merge to `main` builds and publishes. A release builds
nothing at all: it retags the digest `main` already verified, refusing unless
that digest carries the release commit's `revision` label, the version the tag
names, and a green `security.yml` run for that commit. So a red `main` is fixed
forward or reverted — it is never released around.

## Before you open a pull request

Run `./scripts/gates.sh pr`. Everything it runs is also a required check, so
anything it finds, CI finds four minutes later with a worse feedback loop.
