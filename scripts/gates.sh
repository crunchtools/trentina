#!/bin/bash
# Trentina's local gates. Constitution XII.
#
#   ./scripts/gates.sh commit | push | pr | release    a tier
#   ./scripts/gates.sh <gate>                          one gate, as a pre-commit entry
#
# Every gate runs from a container image through podman. The host is assumed to
# have only git, podman, pre-commit and gh, so nothing here calls uv, pytest,
# ruff, semgrep, trivy or rpmbuild, and fixtures live in named volumes rather
# than in the worktree or in coreutils temp dirs.
#
# Exit codes are the point:
#   0  the gate passed
#   1  the gate RAN and FAILED -- fix the code
#   2  the gate COULD NOT RUN -- never 0, never a warning, and the message
#      never tells you to install something on the host
#
# `commit` and `push` delegate to pre-commit, so which gates belong to which
# tier is stated once, in .pre-commit-config.yaml, and never duplicated here.
set -euo pipefail

# Every path below is repo-relative (.semgrep/, .specify/, .gates/) and every
# mount is $PWD, so the gates must run from the root wherever they are invoked.
cd "$(git rev-parse --show-toplevel)" || { printf 'GATE CANNOT RUN: not a git checkout\n' >&2; exit 2; }

CACHE_VOLUME=crunchtools-hook-cache        # shared with the mypy hook
SCRATCH_VOLUME=crunchtools-gates-scratch   # fixtures; never the worktree
UV_IMAGE=ghcr.io/astral-sh/uv:python3.12-bookworm-slim
SEMGREP_IMAGE=docker.io/semgrep/semgrep:1.177.0
BUILDER_IMAGE=quay.io/hummingbird/python:3.14-builder
GATEHOUSE_IMAGE=quay.io/crunchtools/gatehouse:latest
# Keep aligned with whatever aquasecurity/trivy-action@v0.36.0 installs. Pinned
# rather than :latest so a local finding and a CI finding are the same finding.
TRIVY_IMAGE=docker.io/aquasec/trivy:0.58.1
CONSTITUTION_TAG=v1.28.0                   # with constitution.yml and `Inherits:`

IMAGE=localhost/trentina:gates
RUNNER=localhost/trentina:gates-runner
SERVER=trentina-gates-server
GATEHOUSE_ENV="$HOME/.config/mcp-env/gatehouse.env"

PODMAN=(podman --events-backend=none run --rm --log-driver=none)
RO_REPO=(-v "$PWD":/src:ro,Z -w /src)

die()  { printf 'GATE CANNOT RUN: %s\n' "$*" >&2; exit 2; }
fail() { printf 'GATE FAILED: %s\n'     "$*" >&2; exit 1; }
step() { printf '\n== %s\n' "$*"; }

need_podman() { command -v podman >/dev/null 2>&1 || die "podman is not on PATH"; }
need_file()   { [ -f "$1" ] || die "$1 is missing"; }
need_volume() { podman volume exists "$1" 2>/dev/null || podman volume create "$1" >/dev/null; }

guard_recursion() {
  [ "${TRENTINA_GATES_DEPTH:-0}" -eq 0 ] || die "gates.sh re-entered itself; a hook entry calls a tier"
  export TRENTINA_GATES_DEPTH=1
}

# ---------------------------------------------------------------- commit tier

# default_install_hook_types does nothing for a clone where `pre-commit install`
# already ran, so without this the whole push tier is a no-op nobody notices.
gate_hooks_installed() {
  # Asked of git, not assembled: in a linked worktree `.git` is a file, and
  # core.hooksPath moves the directory somewhere else entirely.
  local hook
  hook=$(git config --get core.hooksPath 2>/dev/null) && hook="$hook/pre-push" \
    || hook=$(git rev-parse --git-path hooks/pre-push) \
    || die "cannot ask git where its hooks live"
  [ -f "$hook" ] || fail "$hook is missing -- run: pre-commit install"
  grep -q "pre-commit" "$hook" 2>/dev/null \
    || fail "$hook is not pre-commit's -- run: pre-commit install"
}

# ------------------------------------------------------------------ push tier

gate_pytest() {
  need_podman; need_volume "$CACHE_VOLUME"
  # UV_PROJECT_ENVIRONMENT must differ from the mypy hook's: that one is 3.12,
  # this is production's 3.14, and one shared path makes uv rebuild the venv on
  # every commit and every push, in both directions, forever.
  #
  # -p no:cacheprovider because the tree is read-only and cacheprovider writes
  # into the rootdir. The tmpfs is sized and exec because tmp_path, the SQLite
  # databases and -n auto across every core will not fit the 64 MB default, and
  # uv may build the petit-plus path source there.
  "${PODMAN[@]}" "${RO_REPO[@]}" \
    -v "$CACHE_VOLUME":/cache \
    --tmpfs /tmp:rw,exec,size=4g,mode=1777 \
    -e HOME=/tmp \
    -e UV_CACHE_DIR=/cache/uv \
    -e UV_PYTHON_INSTALL_DIR=/cache/python \
    -e UV_PROJECT_ENVIRONMENT=/cache/venv/trentina-pytest-py314 \
    -e GEMINI_API_KEY=test_key_for_ci \
    "$UV_IMAGE" \
    uv run --locked --all-extras --python 3.14 \
      pytest -q -rfE -p no:cacheprovider \
    || fail "pytest"
}

gate_semgrep() {
  need_podman
  # HOME and the settings file go to the tmpfs: semgrep's only writes are its
  # own state, so the tree stays read-only.
  local semgrep=("${PODMAN[@]}" "${RO_REPO[@]}"
    --tmpfs /tmp:rw,size=256m -e HOME=/tmp -e SEMGREP_SETTINGS_FILE=/tmp/semgrep.yml
    "$SEMGREP_IMAGE")
  step "semgrep rule tests"
  "${semgrep[@]}" sh .semgrep/run-tests.sh || fail "semgrep rule tests"
  step "semgrep scan"
  "${semgrep[@]}" semgrep scan --config .semgrep/ --error --metrics=off src/ \
    || fail "semgrep scan"
}

# The pre-commit Gatehouse hook sees one staged diff, so nothing reviews the
# branch as a whole -- which is how a finding in the cumulative diff reaches CI
# after the local hook went green. This reviews what the PR will show.
gate_gatehouse_range() {
  need_podman
  need_file "$GATEHOUSE_ENV"
  git fetch --quiet origin main || die "cannot reach origin to read main; the cumulative diff is unknown"
  git rev-parse --verify --quiet origin/main >/dev/null || die "origin/main does not resolve"
  # 0 is no differences, 1 is differences, anything above is git failing -- which
  # is a gate that could not run, not a gate that found something.
  local rc=0
  git diff --quiet origin/main...HEAD || rc=$?
  case "$rc" in
    0) printf 'nothing to review: HEAD matches origin/main\n'; return 0 ;;
    1) ;;
    *) die "git could not compute origin/main...HEAD" ;;
  esac
  # The diff is written out first, so a failure to PRODUCE it is told apart from
  # a reviewer that read it and objected. Piping straight in reported the former
  # as the latter.
  local diff=/tmp/trentina-gates-range.diff
  git diff origin/main...HEAD > "$diff" || die "git could not write the cumulative diff"
  "${PODMAN[@]}" -i --env-file "$GATEHOUSE_ENV" "${RO_REPO[@]}" "$GATEHOUSE_IMAGE" --stdin \
    < "$diff" \
    || fail "Gatehouse found blocking findings in the cumulative diff"
}

# -------------------------------------------------------------------- pr tier

gate_container_build() {
  need_podman
  local version
  version=$(git show HEAD:pyproject.toml | grep -m1 '^version = ' | cut -d'"' -f2) \
    || die "cannot read pyproject.toml from HEAD"
  [ -n "$version" ] || die "pyproject.toml has no version line"
  step "build $IMAGE (VERSION=$version)"
  # Plain build, no buildx: the container driver the gha cache needs costs more
  # than the cache saves, and locally there is no gha cache at all.
  podman build -f Containerfile --build-arg "VERSION=$version" -t "$IMAGE" . \
    || fail "container build"
  local label
  label=$(podman image inspect "$IMAGE" --format '{{ index .Config.Labels "version" }}') \
    || die "cannot inspect the image just built"
  [ "$label" = "$version" ] \
    || fail "image version label is '$label', pyproject.toml says '$version'"
}

gate_container_verify() {
  need_podman; need_volume "$SCRATCH_VOLUME"
  podman image exists "$IMAGE" || die "$IMAGE is not built; run: ./scripts/gates.sh container-build"

  step "the gateway answers /health as production runs it"
  # Seeded from inside a container so no coreutils is assumed and nothing is
  # written into the worktree, where gourmand and the staged-diff hook would
  # see it.
  "${PODMAN[@]}" -v "$SCRATCH_VOLUME":/seed "$BUILDER_IMAGE" python -c '
import pathlib, secrets
seed = pathlib.Path("/seed")
(seed / "profiles.yaml").write_text(
    "profiles:\n  ci:\n    auth:\n      bearer_token_env: CI_TOKEN\n    backends: {}\n")
(seed / "token").write_text(secrets.token_hex(16))
' || die "cannot seed the gate fixture volume"

  podman rm -f "$SERVER" >/dev/null 2>&1 || true
  # shellcheck disable=SC2064
  trap "podman rm -f $SERVER >/dev/null 2>&1 || true" EXIT
  # No published port: 8019 is very likely a Trentina you are already running,
  # and probing that would pass while this image was broken.
  podman run -d --name "$SERVER" \
    --read-only --tmpfs /tmp --tmpfs /data:mode=1777 \
    --cap-drop=all --security-opt no-new-privileges \
    -v "$SCRATCH_VOLUME":/etc/trentina:ro \
    -e TRENTINA_GATEWAY_ENABLED=1 -e CI_TOKEN_FILE=/etc/trentina/token \
    "$IMAGE" --transport streamable-http --host 0.0.0.0 --port 8019 >/dev/null \
    || fail "the image did not start"
  # The probe shares the server's netns, so no curl on the host and no port.
  "${PODMAN[@]}" --network "container:$SERVER" --entrypoint python "$BUILDER_IMAGE" -c '
import time, urllib.request
for _ in range(30):
    try:
        print(urllib.request.urlopen("http://127.0.0.1:8019/health", timeout=5).read().decode())
        raise SystemExit(0)
    except Exception:
        time.sleep(2)
raise SystemExit("/health never answered")
' || { podman logs "$SERVER" 2>&1 | tail -20; fail "/health never answered"; }
  podman rm -f "$SERVER" >/dev/null 2>&1 || true
  trap - EXIT

  step "native extensions import in the distroless image"
  "${PODMAN[@]}" --entrypoint python "$IMAGE" -c '
import onnxruntime, vodozemac
print("onnxruntime", onnxruntime.__version__)
import cv2, PIL, pypdf, rapidocr, shapely, pyclipper
print("opencv", cv2.__version__, "pillow", PIL.__version__, "pypdf", pypdf.__version__)
' || fail "a native extension does not import in the distroless image"

  step "build the test runner (adds a shell and pytest to distroless)"
  podman build -f - -t "$RUNNER" . <<RUNNERFILE || fail "test runner build"
FROM $BUILDER_IMAGE AS test-deps
USER 0
RUN pip install --no-cache-dir --prefix=/usr pytest pytest-asyncio pytest-xdist

FROM $IMAGE
COPY --from=test-deps /usr/lib/python3.14/site-packages/ /usr/lib/python3.14/site-packages/
RUNNERFILE

  local in_image=("${PODMAN[@]}" --entrypoint python
    -v "$PWD/tests":/tests:ro -v "$PWD/corpora":/corpora:ro
    -e GEMINI_API_KEY=test_key_for_ci)

  step "L2 integration, against the model the image ships"
  "${in_image[@]}" \
    -e CLASSIFIER_MODEL=prompt-injection-guard-small-ct \
    -e TRENTINA_REQUIRE_L2_MODEL=1 -e CLASSIFIER_THREADS=1 \
    "$RUNNER" -m pytest -n 4 -q -rfE -p no:cacheprovider \
      /tests/test_l2_integration.py \
      "/tests/test_adversarial_corpus.py::TestLayer2Boundary" \
    || fail "L2 integration in the image"

  step "L3 integration (provider mocked)"
  "${in_image[@]}" "$RUNNER" \
    -m pytest -q -rfE -p no:cacheprovider /tests/test_l3_integration.py \
    || fail "L3 integration in the image"

  step "the OCR and PDF workers, as production runs them"
  "${PODMAN[@]}" --network none --read-only --tmpfs /tmp --cap-drop=all \
    --security-opt no-new-privileges --entrypoint python \
    -v "$PWD/tests":/tests:ro -v "$PWD/corpora":/corpora:ro \
    -e GEMINI_API_KEY=test_key_for_ci \
    "$RUNNER" -m pytest -q -rfE -p no:cacheprovider -m ocr /tests \
    || fail "the OCR or PDF worker does not run in the image"
}

gate_trivy() {
  need_podman; need_volume "$SCRATCH_VOLUME"; need_volume "$CACHE_VOLUME"
  podman image exists "$IMAGE" || die "$IMAGE is not built; run: ./scripts/gates.sh container-build"
  step "trivy"
  # Trivy cannot read podman's image store, so the image is streamed into the
  # scratch volume as an archive.
  podman save --format docker-archive "$IMAGE" \
    | "${PODMAN[@]}" -i -v "$SCRATCH_VOLUME":/scratch sh -c 'cat > /scratch/image.tar' \
    || die "cannot stage the image for trivy"
  "${PODMAN[@]}" -v "$SCRATCH_VOLUME":/scratch:ro "${RO_REPO[@]}" \
    -v "$CACHE_VOLUME":/cache -e TRIVY_CACHE_DIR=/cache/trivy \
    "$TRIVY_IMAGE" image --input /scratch/image.tar \
      --scanners vuln --severity CRITICAL,HIGH --ignore-unfixed \
      --ignorefile .trivyignore --exit-code 1 \
    || fail "trivy found CRITICAL or HIGH vulnerabilities"
}

# The one schema authority. Never hand-rolled: check_version_sync already holds
# pyproject.toml, src/*/__init__.py, server.json and the Containerfile label to
# the newest CHANGELOG heading, and a local copy of that rule would pass while
# one of the others was stale.
gate_constitution() {
  need_podman; need_volume "$CACHE_VOLUME"
  local checkout=.gates/constitution
  if [ -d "$checkout/.git" ]; then
    git -C "$checkout" fetch --quiet --depth 1 origin "$CONSTITUTION_TAG" \
      && git -C "$checkout" checkout --quiet FETCH_HEAD \
      || die "cannot update the constitution checkout to $CONSTITUTION_TAG"
  else
    git clone --quiet --depth 1 --branch "$CONSTITUTION_TAG" \
      https://github.com/crunchtools/constitution "$checkout" \
      || die "cannot clone the constitution at $CONSTITUTION_TAG"
  fi
  step "constitution validator ($CONSTITUTION_TAG)"
  "${PODMAN[@]}" "${RO_REPO[@]}" \
    -v "$CACHE_VOLUME":/cache --tmpfs /tmp:rw,size=256m \
    -e HOME=/tmp -e UV_CACHE_DIR=/cache/uv \
    "$UV_IMAGE" \
    uv run --no-project --with pyyaml python \
      "$checkout/validate-constitution.py" .specify/memory/constitution.md --pinned --verbose \
    || fail "constitution validation"
}

# The only gate that needs the tree writable: `make rpm` writes dist/, which is
# already gitignored.
gate_rpm() {
  need_podman; need_volume "$CACHE_VOLUME"
  step "cockpit RPM"
  "${PODMAN[@]}" -v "$PWD":/src:Z -w /src \
    -v "$CACHE_VOLUME":/var/cache/libdnf5 \
    registry.fedoraproject.org/fedora:43 \
    sh -c 'dnf -y --setopt=keepcache=1 install rpm-build make tar >/dev/null && make rpm' \
    || fail "make rpm"
}

# ----------------------------------------------------------------- dispatch

case "${1:-}" in
  commit)  guard_recursion; exec pre-commit run --hook-stage pre-commit --all-files ;;
  push)    guard_recursion; exec pre-commit run --hook-stage pre-push   --all-files ;;
  pr)      gate_container_build; gate_container_verify; gate_trivy; gate_constitution ;;
  release) gate_constitution; gate_rpm ;;

  hooks-installed)  gate_hooks_installed ;;
  pytest)           gate_pytest ;;
  semgrep)          gate_semgrep ;;
  gatehouse-range)  gate_gatehouse_range ;;
  container-build)  gate_container_build ;;
  container-verify) gate_container_verify ;;
  trivy)            gate_trivy ;;
  constitution)     gate_constitution ;;
  rpm)              gate_rpm ;;

  *) printf 'usage: %s commit|push|pr|release|<gate>\n' "$0" >&2; exit 2 ;;
esac
