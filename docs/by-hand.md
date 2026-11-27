# Run by hand

Trentina's CI is `.github/workflows/ci.yml` alone, the fleet's shared copy
(crunchtools/sdlc `examples/ci.yml`). It never runs repo code with a secret in
reach, so everything below that needs a provider key, the RunPod key or the
signing key is run by a person on a seat that holds it. Each was a workflow
until a1788; the last revision with all of them is
`969113c40dc2beae4e8f63ebd6577d1ebcb0d690`, and `git show
969113c4:.github/workflows/<name>.yml` gives a job's exact steps and matrix.

Run from the repository root after `uv sync --all-extras --locked`. A run that
holds a key runs reviewed code: check out `main`, not a branch.

| Was | What it produced | By hand |
|---|---|---|
| `l2-export-lock.yml` | the exporter's lock installs | **In CI**: `sdlc l2-builder` and `sdlc l2-builder-imports`, part of `sdlc / check` on every pull request |
| `extra-tests.yml` `live-l3` | live L3 detection on OpenRouter | `OPENROUTER_API_KEY=… TRENTINA_LIVE_L3=1 TRENTINA_LIVE_L3_PROVIDER=openrouter QUARANTINE_MODEL=google/gemini-2.5-flash uv run pytest -n0 tests/test_l3_live.py -v` |
| `extra-tests.yml` `boundary-review-eval` | the boundary-review skill graded against `EVAL.yml` | `ANTHROPIC_API_KEY=… uv run python tests/boundary_review_eval.py --json-out boundary-review-eval.json`; its offline half is in the suite |
| `mutation-advisory.yml` | surviving mutants in the security modules (advisory) | `git diff --name-only origin/main... \| xargs -d '\n' uv run --with mutmut==3.8.1 python scripts/mutation_advisory.py --budget-minutes 40 --changed`, or `--budget-minutes 45 --all` |
| `benchmark-decoys.yml` | the decoy, detonation, venn, briefing, packs, corpora, paging, gatekeeper, egress-bench, agent-egress-bench and tune spikes | the job's script in `benchmarks/` with `OPENROUTER_API_KEY`, one matrix row per run, as the workflow lists them; see docs/benchmark.md for each |
| `collect-wild.yml` | a one-off wild-feed sample, judged | `uv run python benchmarks/wild_feed.py --limit 300 --json wild.json`, then `benchmarks/detonation.py --mode judge --documents wild.json` per judge and `--mode venn` over the results. The daily collection is crunchtools/data-collector |
| `demo.yml` | `docs/demo/trentina.gif` and `.mp4` | `ENGINE=podman OPENROUTER_API_KEY=… docs/demo/render.sh`, then commit the two files in a pull request |
| `l2-train.yml` | a fine-tuned L2 model, gated; on main, published | below |
| `publish.yml` | the Cockpit plugin RPM as a release asset | `make rpm` (docs/cockpit-plugin.md). The plugin has been 0.2.2 since October and installs from source |

## Training the L2 model

1. Build the training set: `uv pip install pandas pyarrow huggingface_hub`,
   then `uv run --no-sync python scripts/l2_train_data.py --out build/l2-train
   --per-envelope 120 --replay 1000`.
2. Build the exporter: `podman build -f scripts/l2-builder/Containerfile -t
   l2-builder .`
3. Train on RunPod with `RUNPOD_API_KEY` set. The driver keeps its keys in
   `$RUNNER_TEMP` and hands the pod's address on through `$GITHUB_ENV`, so
   point both at scratch: `export RUNNER_TEMP=$(mktemp -d)
   GITHUB_ENV=$(mktemp)`, then `python3 scripts/runpod_train.py create`,
   `set -a; . "$GITHUB_ENV"; set +a`, `python3 scripts/runpod_train.py run
   --host "$POD_HOST" --port "$POD_PORT" --epochs 2`, and always `terminate
   --pod "$POD_ID"`.
4. Export each blend in `l2-builder` with `scripts/export_l2_model.py`, and
   hold each to `benchmarks/l2_benign.py`, `l2_envelopes.py` and
   `l2_obfuscation.py` with `CLASSIFIER_MODEL_PATH` set. Step 4's exact
   arguments are in the old workflow's `Export` and `Gates` steps.

Publishing a model that passed is not done here: `quay.io/crunchtools/
trentina-l2-model` is signed with the fleet key, which no seat holds. Until it
has a CI route (crunchtools/trentina#954), hand the gated export to Josui
Prime. Shipping it is then a change to the model digest in `Containerfile` and
`scripts/l2-builder/Containerfile` (a test holds the two together).
