# Contributing

`CLAUDE.md` is context for an agent. This is the page for a person.

## Setup

```bash
git clone https://github.com/crunchtools/trentina
cd trentina
pre-commit install
```

That wires two git hooks, `pre-commit` and `pre-push`. If you cloned before
November 2026, run it again: `pre-commit install` only wires the hook types the
config asked for on the day you ran it, so an older checkout has no pre-push
hook and every verdict silently stops running. The commit hook checks for
exactly this and fails if the pre-push hook is missing.

The host needs `git`, `podman`, `pre-commit` and `gh`, and nothing else. Every
check runs from one image, [python-sdlc](https://github.com/crunchtools/python-sdlc),
pinned once in `.pre-commit-config.yaml`. CI runs the same image at the same
release, so a green push predicts a green CI.

## Three commands

| Command | When | What runs | Roughly |
|---|---|---|---|
| `sdlc commit` | every commit | ruff fixes, and that the push hook is installed | seconds, offline |
| `sdlc push` | every push | mypy, the full suite, Gourmand, Gatehouse over `origin/main...HEAD`, semgrep, pip-audit, the constitution validator, CodeQL | a few minutes |
| `sdlc ci` | in CI | push's checks except Gourmand and Gatehouse, plus building the image and running `tests/image/` and the L2, L3, OCR and PDF suites inside it | CI's business |

A push never builds the image; that is minutes, and a push you wait minutes for
is a push people stop making. You can run `sdlc ci` yourself before opening a
pull request if you want CI's verdict early. `sdlc tiers` prints exactly what
each command runs, and `sdlc <check>` runs one, for the inner loop:

```bash
sdlc mypy
sdlc image          # build the image
sdlc image-tests    # and test it from inside
```

`sdlc` is `bin/sdlc` in the python-sdlc checkout pre-commit keeps under
`~/.cache/pre-commit`; put it on your `PATH` or call it by path. What each
command runs is configured in `pyproject.toml` under `[tool.sdlc.commit]`,
`[tool.sdlc.push]` and `[tool.sdlc.ci]`.

Every check runs capped: half the cores the gate may actually use, an 8 GB
memory ceiling and a low CPU weight. `SDLC_CPUS` and `SDLC_MEMORY` override.

## Exit codes

- `0` — the check passed.
- `1` — the check **ran and failed**. Fix the code.
- `2` — the check **could not run**: no podman, an unreachable registry, a
  missing `~/.config/mcp-env/gatehouse.env`, an `origin/main` that does not
  resolve, a `uv.lock` out of date with `pyproject.toml`.

`2` is never a warning and never a pass. A check that cannot run is an incident,
not a nuisance: find out why. Working around it defeats the only thing it was
there for.

## Skipping a check

`SDLC_SKIP=gatehouse git push` skips one check, once. It is for a false
positive, which Gatehouse produces occasionally and the others essentially
never. Using it obliges you to answer the same finding on the pull request,
because CI will raise it again. Do not `--no-verify`, and do not reach for
`SDLC_SKIP` because a check is slow.

## CodeQL fails only on new findings

The push fails on a CodeQL finding that is not in `.sdlc/codeql-baseline.json`.
The baseline is the findings someone has already looked at; `sdlc
codeql-baseline` rewrites it from the current ones, and that change is reviewed
like any other.

## How the image is published

CI builds the image once per run, in the `sdlc ci` job, and tests it from
inside as production runs it. A merge to `main` publishes exactly those bytes. A
release builds nothing: it retags the digest `main` already verified, refusing
unless that digest carries the release commit's `revision` label, the version
the tag names, and a green `sdlc ci` for that commit. A red `main` is fixed
forward or reverted, never released around. Building locally is fine; what
causes drift is pushing a hand-built image, which only CI does.
