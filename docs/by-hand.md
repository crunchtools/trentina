# Run by hand

Trentina's CI is `.github/workflows/ci.yml` alone, the fleet's shared copy
(crunchtools/sdlc `examples/ci.yml`). It never runs repo code with a secret in
reach, so everything below that needs a provider key, the RunPod key or the
signing key is run by a person on a seat that holds it. Each was a workflow
until a1788; the last revision with all of them is
`969113c40dc2beae4e8f63ebd6577d1ebcb0d690`.

Run from the repository root after `uv sync --all-extras --locked`. A run that
holds a key runs reviewed code: check out `main`, not a branch.

| Was | What it produced | By hand |
|---|---|---|
| `l2-export-lock.yml` | the exporter's lock installs | **In CI**: `sdlc l2-builder` and `sdlc l2-builder-imports`, part of `sdlc / check` on every pull request |
| `extra-tests.yml` `live-l3` | live L3 detection on OpenRouter | `OPENROUTER_API_KEY=… TRENTINA_LIVE_L3=1 TRENTINA_LIVE_L3_PROVIDER=openrouter QUARANTINE_MODEL=google/gemini-2.5-flash uv run pytest -n0 tests/test_l3_live.py -v` |
| `extra-tests.yml` `boundary-review-eval` | the boundary-review skill graded against `EVAL.yml` | `ANTHROPIC_API_KEY=… uv run python tests/boundary_review_eval.py --json-out boundary-review-eval.json`; its offline half is in the suite |
| `mutation-advisory.yml` | surviving mutants in the security modules (advisory) | [below](#mutation-advisory) |
| `benchmark-decoys.yml` | the decoy, detonation, venn, briefing, packs, corpora, paging, gatekeeper, egress-bench, agent-egress-bench and tune spikes | [below](#benchmark-decoys), one block per job |
| `collect-wild.yml` | a one-off wild-feed sample, judged | [below](#collect-wild). The daily collection is crunchtools/data-collector |
| `demo.yml` | `docs/demo/trentina.gif` and `.mp4` | `ENGINE=podman OPENROUTER_API_KEY=… docs/demo/render.sh`, then commit the two files in a pull request |
| `l2-train.yml` | a fine-tuned L2 model, gated; on main, published | [below](#training-the-l2-model) |
| `publish.yml` | the Cockpit plugin RPM as a release asset | `make rpm` (docs/cockpit-plugin.md). The plugin has been 0.2.2 since October and installs from source |

The weekly L2 training canary and its `l2-canary` alert issue are gone with
`l2-train.yml`; the training round below is run when a model is wanted.

## Common setup

Run from the repository root on `main`. Keys are placeholders. The model-driven
jobs share these:

```bash
export OPENROUTER_API_KEY=…
effort() { [ "$1" = google/gemini-3.8-flash ] && echo minimal || echo ""; }
slug()   { echo "${1//\//-}"; }
JUDGES="google/gemini-2.5-flash-lite google/gemini-3.5-flash-lite anthropic/claude-haiku-4.5 google/gemini-3.8-flash"
mkdir -p build results
```

## mutation-advisory

Advisory, no key. Run the first form on the branch being judged, the second for
every module:

```bash
# PR form (run on the PR branch, not main, or the diff is empty)
mkdir -p build
git fetch origin main
BASE_SHA=$(git merge-base origin/main HEAD)
git diff --name-only "$BASE_SHA"...HEAD > build/changed
GEMINI_API_KEY=test_key_for_ci xargs -d '\n' -a build/changed \
  uv run --with mutmut==3.8.1 python scripts/mutation_advisory.py \
  --budget-minutes 40 --changed

# --all form (the weekly run)
GEMINI_API_KEY=test_key_for_ci \
  uv run --with mutmut==3.8.1 python scripts/mutation_advisory.py \
  --budget-minutes 45 --all
```

## collect-wild

Collecting holds no key. The judge and detonate legs write one directory per
model, and the last step lists what is worth reading:

```bash
LIMIT=300
REPLAY=false

# collect (no key needed)
set -o pipefail
uv run --no-sync python benchmarks/wild_feed.py --limit "$LIMIT" --json wild.json | tee build/wild-collect.md

# judge: the 4 shipped judges, three votes (reasoning only on gemini-3.8-flash)
mkdir -p results
for model in $JUDGES; do
  s=results/wild-judge-$(slug "$model"); mkdir -p "$s"
  QUARANTINE_MODEL="$model" QUARANTINE_REASONING_EFFORT="$(effort "$model")" \
    uv run --no-sync python benchmarks/detonation.py \
      --mode judge --documents wild.json --concurrency 6 --votes 3 \
      --json "$s/detonation.json" | tee "$s/summary.md"
done

# detonate: replay only (REPLAY=true), two decoy models, five draws
if [ "$REPLAY" = true ]; then
  for model in openai/gpt-oss-20b google/gemma-3-12b-it; do
    s=results/wild-detonate-$(slug "$model"); mkdir -p "$s"
    QUARANTINE_MODEL="$model" QUARANTINE_REASONING_EFFORT="" \
      uv run --no-sync python benchmarks/detonation.py \
        --mode detonate --documents wild.json --concurrency 6 --votes 5 --temperature 0.7 \
        --json "$s/detonation.json" | tee "$s/summary.md"
  done
fi

# what to read (flagged by any judge, split between judges, or tripped); no key needed
shopt -s nullglob
uv run --no-sync python benchmarks/detonation.py --mode venn \
  --judge-json results/wild-judge-*/detonation.json \
  --detonate-json results/wild-detonate-*/detonation.json | tee build/wild-reading-list.md
```

## benchmark-decoys

Defaults were `EXTERNAL=test`, `DESIGN=two-call` and `BENCH_REF=7339fef95630ce811f66aa39c7bab879d9f9e6e7`.
Each job below writes under `results/`.

### detonation

Ten decoy models and the four judges on the written corpus.

```bash
set -o pipefail
run_det() {  # mode model [effort]
  s=results/detonation-$1-$(slug "$2"); mkdir -p "$s"
  QUARANTINE_MODEL="$2" QUARANTINE_REASONING_EFFORT="$3" \
    uv run --no-sync python benchmarks/detonation.py --mode "$1" --json "$s/detonation.json" | tee "$s/summary.md"
}
for m in mistralai/mistral-nemo meta-llama/llama-3.1-8b-instruct qwen/qwen-2.5-7b-instruct amazon/nova-micro-v1 \
         google/gemma-3-12b-it mistralai/ministral-8b-2512 openai/gpt-oss-20b \
         google/gemini-2.5-flash-lite anthropic/claude-haiku-4.5; do run_det detonate "$m" ""; done
run_det detonate google/gemini-3.8-flash minimal
for m in $JUDGES; do run_det judge "$m" "$(effort "$m")"; done
```

### venn and venn-report

Every insert in every carrier, several draws a document, joined document by document.

```bash
set -o pipefail
run_venn() {  # mode model effort flags...
  mode=$1 model=$2 eff=$3; shift 3
  s=results/venn-$mode-$(slug "$model"); mkdir -p "$s"
  QUARANTINE_MODEL="$model" QUARANTINE_REASONING_EFFORT="$eff" \
    uv run --no-sync python benchmarks/detonation.py \
      --mode "$mode" --carriers all --tasks 0 --only clean,benign,attack \
      --concurrency 16 "$@" --json "$s/detonation.json" | tee "$s/summary.md"
}
for m in meta-llama/llama-3.1-8b-instruct openai/gpt-oss-20b qwen/qwen-2.5-7b-instruct google/gemma-3-12b-it; do
  run_venn detonate "$m" "" --votes 5 --temperature 0.7
done
for m in $JUDGES; do run_venn judge "$m" "$(effort "$m")" --votes 3; done

# venn-report (no key)
uv run --no-sync python benchmarks/detonation.py --mode venn \
  --judge-json results/venn-judge-*/detonation.json \
  --detonate-json results/venn-detonate-*/detonation.json | tee build/venn-report.md
```

### decoys

`benchmarks/decoy_tools.py` on every judge with a shipped pack.

```bash
EXTERNAL=test; DESIGN=two-call
for m in $JUDGES; do
  s=results/decoy-tools-$(slug "$m"); mkdir -p "$s"
  QUARANTINE_MODEL="$m" QUARANTINE_REASONING_EFFORT="$(effort "$m")" \
    uv run --no-sync python benchmarks/decoy_tools.py \
      --external "$EXTERNAL" --design "$DESIGN" --json "$s/decoy-tools.json" | tee "$s/summary.md"
done
```

### briefing

The judges on clean and benign-insert documents under each Layer 2 label.

```bash
for m in $JUDGES; do for arm in none benign malicious; do
  s=results/briefing-$arm-$(slug "$m"); mkdir -p "$s"
  QUARANTINE_MODEL="$m" QUARANTINE_REASONING_EFFORT="$(effort "$m")" \
    uv run --no-sync python benchmarks/detonation.py \
      --mode judge --briefing "$arm" --carriers all --tasks 0 \
      --only clean,benign,attack --no-injecagent --votes 3 --concurrency 16 \
      --json "$s/detonation.json" | tee "$s/summary.md"
done; done
```

### packs

Each shipped pack against the generic prompts, held out. The second run is the gate.

```bash
for m in $JUDGES; do
  pack=${m#*/}; s=results/pack-$pack; mkdir -p "$s"
  export QUARANTINE_MODEL="$m" QUARANTINE_REASONING_EFFORT="$(effort "$m")"
  PACK=src/trentina/quarantine/prompt_packs/$pack.json
  uv run --no-sync python benchmarks/prompt_pack.py --provider openrouter \
    --prompt-pack generic --votes 3 --concurrency 8 --out "$s/generic.json" | tee "$s/summary.md"
  uv run --no-sync python benchmarks/prompt_pack.py --provider openrouter \
    --prompt-pack "$PACK" --votes 3 --concurrency 8 --baseline "$s/generic.json" \
    --out "$s/pack.json" | tee -a "$s/summary.md"
done
```

### corpora

`provider_benchmark.py` on the internal, garak, disclosed and notes corpora.

```bash
for m in $JUDGES; do
  s=results/corpora-$(slug "$m")
  for corpus in internal garak disclosed notes; do
    TRENTINA_MODEL_PROVIDER=openrouter QUARANTINE_MODEL="$m" QUARANTINE_REASONING_EFFORT="$(effort "$m")" \
      uv run --no-sync python benchmarks/provider_benchmark.py \
        --providers openrouter --corpus "$corpus" --concurrency 8 --retries 3 --out "$s/$corpus"
    cat "$s/$corpus"/*.md | tee -a "$s/summary.md"
  done
done
```

### paging

An attack split across the parts of a paged response.

```bash
for m in $JUDGES; do
  s=results/paging-$(slug "$m"); mkdir -p "$s"
  TRENTINA_MODEL_PROVIDER=openrouter QUARANTINE_MODEL="$m" QUARANTINE_REASONING_EFFORT="$(effort "$m")" \
    uv run --no-sync python benchmarks/paging_l3.py --votes 3 --concurrency 8 \
      --json "$s/paging_l3.json" | tee "$s/summary.md"
done
```

### gatekeeper

Guarded execution, inside the image this checkout builds, so the arguments step includes L2.

```bash
podman build -f Containerfile -t trentina:bench .
for m in $JUDGES; do
  s=results/gatekeeper-$(slug "$m"); mkdir -p "$s" && chmod 777 "$s"
  QUARANTINE_MODEL="$m" QUARANTINE_REASONING_EFFORT="$(effort "$m")" \
  podman run --rm --security-opt label=disable \
    --read-only --tmpfs /tmp --cap-drop=all --security-opt no-new-privileges \
    --entrypoint python \
    -v "$PWD/benchmarks:/bench/benchmarks:ro" -v "$PWD/corpora:/bench/corpora:ro" \
    -v "$PWD/$s:/results" \
    -e OPENROUTER_API_KEY -e QUARANTINE_MODEL -e QUARANTINE_REASONING_EFFORT \
    -e TRENTINA_MODEL_PROVIDER=openrouter -e QUARANTINE_DB=/tmp/bench.db \
    trentina:bench \
    /bench/benchmarks/gatekeeper.py --require-l2 --votes 3 --concurrency 8 \
      --json /results/gatekeeper.json | tee "$s/summary.md"
done
```

### egress-bench

The terminating egress route, inside the image, so the response axis is L1/L2/L3 as production runs it.

```bash
podman build -f Containerfile -t trentina:bench .
m=google/gemini-3.5-flash-lite; s=results/egress-bench-$(slug "$m"); mkdir -p "$s" && chmod 777 "$s"
QUARANTINE_MODEL="$m" \
podman run --rm --security-opt label=disable \
  --read-only --tmpfs /tmp --cap-drop=all --security-opt no-new-privileges \
  --entrypoint python \
  -v "$PWD/benchmarks:/bench/benchmarks:ro" -v "$PWD/corpora:/bench/corpora:ro" \
  -v "$PWD/$s:/results" \
  -e OPENROUTER_API_KEY -e QUARANTINE_MODEL \
  -e TRENTINA_MODEL_PROVIDER=openrouter -e QUARANTINE_DB=/tmp/bench.db \
  trentina:bench \
  /bench/benchmarks/egress_bench.py --votes 3 --json /results/egress-bench.json | tee "$s/summary.md"
```

### agent-egress-bench

The third-party bench at a pinned commit, its Go runner holding no key and no socket, against the gateway behind the nginx shim, in `flag` then `block`. Ports 8000 and 18899 must be free. Export the provider key only after the Go build.

```bash
set -eu
export WS=$PWD MODEL=google/gemini-3.5-flash-lite
BENCH_REF=7339fef95630ce811f66aa39c7bab879d9f9e6e7
podman build -f Containerfile -t trentina:bench .

# The bench at the pinned commit, runner built in a Go container (no secret in scope: do not export the key here)
case "$BENCH_REF" in *[!0-9a-f]*|"") echo "bench_ref must be a SHA" >&2; exit 64 ;; esac
git init -q bench && cd bench
git fetch -q --depth 1 https://github.com/luckyPipewrench/agent-egress-bench "$BENCH_REF"
git checkout -q FETCH_HEAD
podman run --rm --security-opt label=disable --userns=keep-id --user "$(id -u):$(id -g)" -v "$PWD:/src" -w /src/runner \
  -e HOME=/tmp -e GOCACHE=/tmp/go-cache -e GOPATH=/tmp/go -e CGO_ENABLED=0 \
  -e GOFLAGS=-buildvcs=false docker.io/library/golang:1.26 go build -o /src/aeb-runner .
cd "$WS"

for AEB_TRENTINA_MODE in flag block; do
  export AEB_TRENTINA_MODE
  podman rm -f aeb-gateway aeb-shim >/dev/null 2>&1 || true

  # Start the gateway and the shim (only here is the provider key needed)
  export BENCH_TOKEN=$(openssl rand -hex 24)
  mkdir -p results kit-run && chmod 777 results kit-run
  cat > run-gateway.sh <<'EOF'
#!/bin/sh
exec podman run -d --name aeb-gateway --network host --security-opt label=disable \
  --add-host aeb-fixture.test:127.0.0.1 --add-host cdn.fixture.example.com:127.0.0.2 \
  --read-only --tmpfs /tmp --cap-drop=all --security-opt no-new-privileges \
  -v "$WS/kit-run:/cfg:ro" \
  -e TRENTINA_GATEWAY_ENABLED=1 -e TRENTINA_PROFILES_PATH=/cfg/profiles.yaml \
  -e BENCH_TOKEN -e OPENROUTER_API_KEY -e QUARANTINE_MODEL="$MODEL" \
  -e TRENTINA_MODEL_PROVIDER=openrouter -e QUARANTINE_DB=/tmp/trentina.db \
  -e 'TRENTINA_FETCH_PRIVATE_NAMES=aeb-fixture.test:*,cdn.fixture.example.com:*' \
  trentina:bench "$@"
EOF
  chmod +x run-gateway.sh
  AEB_TRENTINA_WORK="$WS/kit-run" AEB_TRENTINA_RUN="$WS/run-gateway.sh" \
    benchmarks/agent_egress/start-gateway.sh
  sed "s|@BENCH_TOKEN@|$BENCH_TOKEN|" benchmarks/agent_egress/shim.conf > shim.conf
  podman run -d --name aeb-shim --network host --security-opt label=disable \
    -v "$PWD/shim.conf:/etc/nginx/nginx.conf:ro" docker.io/library/nginx:1.27-alpine
  rm shim.conf run-gateway.sh
  for _ in $(seq 120); do curl -sf http://127.0.0.1:8000/health >/dev/null && break; sleep 5; done
  curl -sf http://127.0.0.1:8000/health

  # The bench runner: no key, no socket, read-only (do not pass OPENROUTER_API_KEY)
  podman run --rm --network host --read-only --tmpfs /tmp --cap-drop=all \
    --security-opt no-new-privileges --security-opt label=disable \
    --userns=keep-id --user "$(id -u):$(id -g)" -e HOME=/tmp \
    -v "$WS/bench:/bench:ro" -v "$WS/benchmarks/agent_egress:/kit:ro" \
    -v "$WS/kit-run:/kit-run:ro" -v "$WS/results:/results" -w /bench \
    docker.io/library/golang:1.26 /bench/aeb-runner \
      --cases /bench/cases --profile /kit/tool-profile.json --adapter proxy \
      --proxy-addr 127.0.0.1:18899 --fixtures --timeout 120s \
      --adapter-owner crunchtools --target-config /kit-run/profiles.yaml \
      --method-repository https://github.com/luckyPipewrench/agent-egress-bench \
      --method-commit "$BENCH_REF" --tool-version "$(git rev-parse HEAD)" \
      --output "/results/fetch-$AEB_TRENTINA_MODE.json" \
      > "results/fetch-$AEB_TRENTINA_MODE.log" 2>&1 || rc=$?
  grep -v '^{' "results/fetch-$AEB_TRENTINA_MODE.log" | tee "results/fetch-$AEB_TRENTINA_MODE.summary.md"
  echo "runner exit: ${rc:-0}"          # nonzero on an incomplete measurement is expected
  test -s "results/fetch-$AEB_TRENTINA_MODE.json"
  unset rc

  podman rm -f aeb-gateway aeb-shim >/dev/null 2>&1 || true
done
```

### tune

One judge on a candidate pack: `train` tunes, `held-out` gates it against generic and emits it if it passed.

```bash
MODEL=google/gemini-2.5-flash-lite SPLIT=train BRIEFING=benign
PACK_B64=$(base64 -w0 my-pack.json)     # the dispatch default was empty; supply a real pack
printf '%s' "$PACK_B64" | base64 --decode > candidate.json
python3 -c "import json; json.load(open('candidate.json'))"
export QUARANTINE_MODEL="$MODEL" QUARANTINE_REASONING_EFFORT="$(effort "$MODEL")"
set -o pipefail
if [ "$SPLIT" = train ]; then
  uv run --no-sync python benchmarks/prompt_pack.py --provider openrouter \
    --prompt-pack candidate.json --split train --concurrency 8 \
    --briefing "$BRIEFING" --out pack.json | tee build/tune-summary.md
else   # held-out; emitted.json exists only if the candidate passed
  uv run --no-sync python benchmarks/prompt_pack.py --provider openrouter \
    --prompt-pack generic --votes 3 --concurrency 8 --briefing "$BRIEFING" \
    --out generic.json | tee build/tune-summary.md
  uv run --no-sync python benchmarks/prompt_pack.py --provider openrouter \
    --prompt-pack candidate.json --votes 3 --concurrency 8 --briefing "$BRIEFING" \
    --baseline generic.json --emit emitted.json --out pack.json | tee -a build/tune-summary.md
fi
```

## Training the L2 model

Needs `RUNPOD_API_KEY`. The driver keeps its keys in `$RUNNER_TEMP` and hands
the pod's address on through `$GITHUB_ENV`, so both point at scratch:

```bash
export RUNPOD_API_KEY=…
PER_ENVELOPE=120 REPLAY=1000 EPOCHS=2
export RUNNER_TEMP=$(mktemp -d) GITHUB_ENV=$(mktemp)
GITHUB_SHA=$(git rev-parse HEAD)
```

1. The training set (pandas, pyarrow and huggingface_hub are not gateway dependencies):

```bash
uv pip install pandas pyarrow huggingface_hub
for size in "$PER_ENVELOPE" "$REPLAY"; do
  [[ "$size" =~ ^[1-9][0-9]+$ ]] || { echo "sizes must be whole numbers from 10" >&2; exit 1; }
done
uv run --no-sync python scripts/l2_train_data.py --out build/l2-train --per-envelope "$PER_ENVELOPE" --replay "$REPLAY"
```

2. The exporter image:

```bash
podman build -f scripts/l2-builder/Containerfile -t l2-builder .
```

3. The GPU pod. Terminate it whatever happened, even after a failed `create`:

```bash
python3 scripts/runpod_train.py create
set -a; . "$GITHUB_ENV"; set +a          # POD_ID, POD_HOST, POD_PORT

[[ "$EPOCHS" =~ ^[0-9]*[.]?[0-9]+$ && ! "$EPOCHS" =~ ^[0.]+$ ]] \
  || { echo "epochs must be a number above zero" >&2; exit 1; }
python3 scripts/runpod_train.py run --host "$POD_HOST" --port "$POD_PORT" --epochs "$EPOCHS" || run_failed=1

python3 scripts/runpod_train.py terminate --pod "${POD_ID:-}"
[ -z "${run_failed:-}" ]
```

4. Export each blend, with its `training.json` and NOTICE:

```bash
shopt -s nullglob
for src in build/l2-model build/l2-model/blend-*; do
  name=$(basename "$src"); [[ "$name" == l2-model ]] && name=blend-1
  podman run --rm --security-opt label=disable -v "$PWD:/w" -w /w l2-builder \
    python scripts/export_l2_model.py \
    --src "$src" --repo "crunchtools/trentina:l2-train" --revision "$GITHUB_SHA" \
    --out "build/l2-export/$name" --id prompt-injection-guard-small-ct --license Apache-2.0 \
    --threshold 0.5 --window-tokens 512 --malicious-labels INJECTION
  cp "$src/training.json" "build/l2-export/$name/"
  cp scripts/l2-model-NOTICE "build/l2-export/$name/NOTICE"
done
```

5. The gates. A round passes when one blend passes all three; only `blend-1`,
the full fine-tune, is published. Lower `CLASSIFIER_THREADS` on a seat with
fewer than 12 CPUs:

```bash
set -o pipefail
passed=0
for model in build/l2-export/blend-*; do
  [[ -d "$model" ]] || continue
  for gate in l2_benign l2_envelopes l2_obfuscation; do
    CLASSIFIER_THREADS=4 CLASSIFIER_MODEL_PATH="$model" uv run --no-sync \
      python "benchmarks/$gate.py" > "$model.$gate.log" 2>&1 &
  done
  status=0
  for job in $(jobs -p); do wait "$job" || status=1; done
  echo "# $(basename "$model")"
  for gate in l2_benign l2_envelopes l2_obfuscation; do
    echo "## $gate"; grep -v '^transform:' "$model.$gate.log"
  done
  echo "$(basename "$model"): $([[ $status == 0 ]] && echo pass || echo FAIL)"
  [[ $status == 0 ]] && passed=1 && touch "$model.passed"
done
[[ $passed == 1 ]]
```

Publishing a model that passed is not done here: `quay.io/crunchtools/
trentina-l2-model` is signed with the fleet key, which no seat holds. Until it
has a CI route (crunchtools/trentina#954), hand the gated export to Josui
Prime. Shipping it is then a change to the model digest in `Containerfile` and
`scripts/l2-builder/Containerfile` (a test holds the two together).
