# MCP Trentina CrunchTools Container
# Three-layer defense: deterministic checks + a local classifier (L2) + quarantined LLM
# Built entirely on Hummingbird Python images (Red Hat hardened, minimal)
#
# Publish: the GHA pipeline, and only the GHA pipeline. `sdlc ci` builds this
# file once per run (security.yml, pyproject.toml [tool.sdlc.ci]) and tests the
# image from inside; the `publish` job pushes exactly the image it tested.
# Drift comes from PUSHING a hand-built image, not from building one: build it
# locally whenever you like with `sdlc image` (or `sdlc ci` for the build and
# its tests).
#
# Layers are ordered by how often their input changes, least often first: the
# model, then the locked dependency set, then Trentina's own code, then the
# version label. A source edit rebuilds the project layer, the L2 gates and the
# runtime's last few layers; a release bump or a README edit does not reinstall
# a single dependency.
#
# No build secret is needed: the one L2 model the image ships is ungated.
# Until 0.59.0 it also shipped Meta's gated Prompt Guard 2, which took an
# HF_TOKEN build argument; that model fails the obfuscation gate below and
# was dropped (#362).
#
# Run (Streamable HTTP on port 8019):
#   podman run --rm \
#     --env-file ~/.config/mcp-env/trentina.env \
#     -v ~/.local/share/trentina:/data:Z \
#     -p 127.0.0.1:8019:8019 \
#     quay.io/crunchtools/trentina \
#     --transport streamable-http --host 0.0.0.0 --port 8019
#
# Optional D-Bus integration (for Cockpit plugin / mcp-assayer):
#   Add: -v /run/dbus/system_bus_socket:/run/dbus/system_bus_socket:z
#   D-Bus is optional — the server runs fine without it (--no-dbus is implicit
#   when the socket is not mounted).
#
# With Claude Code (stdio):
#   claude mcp add trentina \
#     -- podman run -i --rm \
#     --env-file ~/.config/mcp-env/trentina.env \
#     -v ~/.local/share/trentina:/data:Z \
#     quay.io/crunchtools/trentina

# The shipped L2 model: Horizon fine-tuned on benign tool replies (#17),
# trained and gated by .github/workflows/l2-train.yml (GHA run 40311268794,
# commit b7fd870) and published as a scratch image holding the ONNX export,
# its manifest, NOTICE and training.json. Pinned by digest: a new model is a
# new run and a change to this line.
FROM quay.io/crunchtools/trentina-l2-model@sha256:02c8a8ff165f1c133535f00523de68169c1c12c58632d415e2cd0e4c579ee4c6 AS l2-model

# ============================================================
# Stage 1: ONNX model conversion (Hummingbird builder — discarded)
# Builder variant includes DNF for installing libstdc++ and
# other native deps needed by PyTorch/numpy ONNX conversion.
# ============================================================
# Every stage is pinned to Python 3.14, not `latest`: the runtime stage copies
# /usr/lib*/python3.14/site-packages, and when `latest` moved to 3.15 the
# locked onnxruntime had no wheel for it and the build stopped. Moving to a new
# Python is a deliberate change to these tags, the lock and those COPY lines.
FROM quay.io/hummingbird/python:3.14-builder AS model-builder
USER 0

RUN pip install --no-cache-dir \
    torch --index-url https://download.pytorch.org/whl/cpu && \
    pip install --no-cache-dir \
    optimum[onnxruntime] \
    transformers \
    sentencepiece

# The exporter stays for l2-train, which builds this stage to export what it
# trains (scripts/export_l2_model.py); the image no longer exports a model
# itself. HORIZON_REVISION is the base the shipped fine-tune started from,
# the revision scripts/train_l2_model.py pins (tests/test_l2_envelopes.py
# holds the two together). Changing it is a new training run, not a rebuild.
COPY scripts/export_l2_model.py /usr/local/bin/export_l2_model.py
ARG HORIZON_REVISION=3215a27edd62c5ba0bd786c57a9d243b2158e70e

# The fine-tune as gated: export, manifest (threshold 0.5, window 512),
# NOTICE and training.json.
COPY --from=l2-model /model/ /models/prompt-injection-guard-small-ct/

# ============================================================
# Stage 2: the locked dependency set (builder variant -- has a shell)
# Hummingbird default is distroless (no /bin/sh), so installing must happen
# in builder stages. Installed packages are copied into the final distroless
# image.
#
# Three stages, by how often their input changes:
#   lock     pyproject.toml + uv.lock -> the exact, hashed requirements list
#   deps     installs that list         (reruns only when the LIST changes)
#   project  src/ -> Trentina itself    (reruns on every source edit; ~2 s)
#
# `lock` reruns on any pyproject.toml edit -- the version, the [tool.sdlc.*]
# config -- but it only exports, in about a second. `deps` copies the export,
# not pyproject.toml, so its cache is keyed on the resolved set: a release bump
# that changes no dependency reinstalls nothing. When one stage copied
# pyproject.toml and README.md and installed, every release bump and README
# edit reinstalled all ~263 packages.
#
# uv is pinned so a cold runner installs with the same uv a warm one cached.
# ============================================================
FROM quay.io/hummingbird/python:3.14-builder AS lock
USER 0
RUN pip install --no-cache-dir uv==0.13.7
WORKDIR /lock
COPY pyproject.toml uv.lock ./

# Dependencies come from uv.lock, not from a fresh resolve (issue #79). Every
# dependency in pyproject.toml is floor-pinned with no upper bound, so a plain
# `pip install .` here built the production image against whatever had been
# released that morning — the artifact that actually runs was the least pinned
# thing we owned, and it was resolved separately from the set CI tested.
#
# The `matrix` and `bridge` extras must appear in BOTH places below or the
# dependency is half-installed: `--extra matrix --extra bridge` puts vodozemac
# and matrix-nio in the exported, hash-pinned requirements, and
# `.[matrix,bridge]` on the final --no-deps install is what records
# it against the project. Exporting without installing gives you a verified
# wheel nobody imports; installing without exporting gives you an unpinned one.
#
# `uv export` emits hashes, so this is also a verified install, and `uv pip
# install` enforces them: with every hash in the exported file replaced by a
# wrong one it refuses with `Hash mismatch`, exactly as pip refuses with
# `THESE PACKAGES DO NOT MATCH THE HASHES`. It installs the same 263 entries
# pip did, and does it in 18.9 s against pip's 42.5 s (measured cold, same
# requirements file) -- which is why the installer here is uv and not the pip
# that is also present. Note that corrupting ONE hash of a package proves
# nothing either way: a requirements file lists a hash per artifact and both
# installers accept a download matching any of them.
#
# The project itself goes in second with --no-deps so nothing can re-resolve
# around the lock.
#
# The requirements go in with --no-deps too (#370). The export is the whole
# locked set, so there is nothing to resolve, and letting an installer try is
# what broke the build: rapidocr asks for `opencv-python`, the lock replaces
# that with `opencv-python-headless` (pyproject.toml, [tool.uv]), and pip,
# reading rapidocr's own metadata, went looking for the one the lock had
# removed.
#
# petit-log-crunchtools used to be held out of this export and installed from
# a hashed source archive, because it resolved from a git tag and pip refuses
# a VCS requirement under hash checking. It reached PyPI as of 4.1.1 (issue
# #96), so it is now an ordinary locked, hash-verified dependency like every
# other one and needs no special case here.
RUN uv export --frozen --no-dev --extra matrix --extra bridge --no-emit-project \
      --format requirements-txt -o /requirements.txt

FROM quay.io/hummingbird/python:3.14-builder AS deps
USER 0

# onnxruntime >= 1.29 reads /etc/machine-id during module init. When that file
# is absent it falls back to popen("blkid")/popen("hostname"), and popen returns
# NULL in a distroless image with no /bin/sh. The return value is not checked,
# so the following fclose(NULL) segfaults the interpreter on `import onnxruntime`.
# Providing the file short-circuits the fallback before popen is ever reached.
#
# First in the stage, before any COPY: it was after `COPY src/`, so every source
# edit minted a new random id and missed the runtime's cache for this file.
RUN tr -d - < /proc/sys/kernel/random/uuid > /etc/machine-id.seed

RUN pip install --no-cache-dir uv==0.13.7
COPY --from=lock /requirements.txt /tmp/requirements.txt
RUN uv pip install --no-cache --prefix=/usr --no-deps -r /tmp/requirements.txt

# The project itself, in its own stage so a source change costs only this one.
# --no-deps again: the locked set is already installed above, and letting the
# installer resolve here is what the comment above is about.
#
# Installed under its own prefix, /project, so the runtime copies it as one
# small layer of its own and the L2 gate below tests exactly those bytes.
# README.md is here, not in `lock`, because the build backend reads it for the
# project's metadata; nothing in the dependency set depends on it.
FROM deps AS project
WORKDIR /app
COPY pyproject.toml README.md ./
COPY src/ ./src/
RUN uv pip install --no-cache --prefix=/project --no-deps '.[matrix,bridge]'

# ============================================================
# Stage 2b: the L2 gates: obfuscation (#362), then benign content (#411)
# The Layer contract makes reading through obfuscation the model's job, so
# the build proves it: every corpus attack is classified plain and under six
# transforms by the classifier code this image runs, and the result is
# written into the model's manifest. A model that fails stops the build
# here. The gateway warns at startup about a model with no passing record
# and refuses to start on one under TRENTINA_REQUIRE_HARDENED.
# ============================================================
FROM deps AS l2-gate
# Straight from the digest-pinned stage, NOT through model-builder, which held
# the same bytes and nothing else this stage uses. Routed that way, nothing in
# the default target depends on model-builder, so the builder skips it and its
# torch + optimum + transformers + sentencepiece install (59 s measured cold,
# of a four-minute build) stops happening on every build. The stage stays in
# this file for `l2-train.yml --target model-builder`, which exports what it
# trains and does need them.
COPY --from=l2-model /model/ /models/prompt-injection-guard-small-ct/
COPY benchmarks/l2_obfuscation.py benchmarks/l2_benign.py /gate/benchmarks/
COPY corpora/internal.py corpora/benign_ops.py /gate/corpora/
# The project from the `project` stage's prefix: the same bytes the runtime
# ships, so the gate proves the classifier code this image runs by construction.
COPY --from=project /project/lib/python3.14/site-packages/ /usr/lib/python3.14/site-packages/
RUN cd /gate \
 && ORT_DISABLE_TELEMETRY=1 CLASSIFIER_MODEL_PATH=/models/prompt-injection-guard-small-ct \
    python benchmarks/l2_obfuscation.py --record

# The benign gate (#411), at the same threshold: the model must not refuse
# the operations output and forum replies of corpora/benign_ops.py, read
# through the default pre-processors as the gateway reads them. Its own layer,
# after the obfuscation gate's, so a change to one corpus re-runs one gate.
RUN cd /gate \
 && ORT_DISABLE_TELEMETRY=1 CLASSIFIER_MODEL_PATH=/models/prompt-injection-guard-small-ct \
    python benchmarks/l2_benign.py --record

# ============================================================
# Stage 3: Runtime image (distroless — no shell, no dnf)
# Constant settings first, then layers by how often they change: the base
# libraries, the dependency set, the model, Trentina, and the version label
# last -- declared first, a version change invalidated every layer after it.
# ============================================================
FROM quay.io/hummingbird/python:3.14

WORKDIR /app

ENV QUARANTINE_DB=/data/quarantine.db
ENV CLASSIFIER_MODEL=prompt-injection-guard-small-ct
# The OAuth proxy's DCR registrations and token metadata live under
# FASTMCP_HOME. Baked in so a deploy that forgets the operator env-file does
# not silently fall back to ephemeral storage and drop every web client's
# registration on the next restart. See docs/authentication.md.
ENV FASTMCP_HOME=/data/fastmcp

# Left on, onnxruntime's init reads /etc/machine-id and /proc/cpuinfo, reads
# /etc/os-release four times, writes /tmp/mat-debug-1.log and creates a session
# file at /tmp/.ses. Not appropriate in an image built to handle untrusted
# content. Disabling leaves the /sys/class/drm and /sys/class/accel probes it
# needs to pick an execution provider. The machine-id read that segfaults a
# shell-less image lives on this same path, so both fixes are kept: either one
# alone prevents the crash.
ENV ORT_DISABLE_TELEMETRY=1

# `python -m` puts the working directory first on sys.path, and onnxruntime
# and transformers are imported lazily, so a writable /app turned any file
# write into code execution at the next import (#268). PYTHONSAFEPATH drops
# that entry. No bytecode is written either: with --read-only it could not be,
# and without it a .pyc beside the package is one more file to plant.
ENV PYTHONSAFEPATH=1
ENV PYTHONDONTWRITEBYTECODE=1

EXPOSE 8019
# Client egress (CONNECT), bound only when a profile has client_egress.
EXPOSE 8021
ENTRYPOINT ["python", "-m", "trentina"]

# libstdc++, required by the onnxruntime and numpy C extensions. From
# deps, which has it: it ships in quay.io/hummingbird/python's own
# builder variant (libstdc++.so.6 -> libstdc++.so.6.0.36) rather than arriving
# with a pip install, so taking it from here depends on no extra stage.
COPY --from=deps /usr/lib64/libstdc++.so.6* /usr/lib64/

# Keeps onnxruntime off its shell-based fallback path — see the deps stage
COPY --from=deps /etc/machine-id.seed /etc/machine-id

# The ONNX model, from the gate stage: its manifest carries the gate record.
# No PyTorch in the final image.
COPY --from=l2-gate /models/prompt-injection-guard-small-ct/ /models/prompt-injection-guard-small-ct/

# The locked third-party set from deps (pure Python + native C extensions).
# It changes only with the lock, so a typical PR reuses both layers.
COPY --from=deps /usr/lib/python3.14/site-packages/ /usr/lib/python3.14/site-packages/
COPY --from=deps /usr/lib64/python3.14/site-packages/ /usr/lib64/python3.14/site-packages/

# Trentina itself, from the project stage: the one package layer a source
# edit changes.
COPY --from=project /project/lib/python3.14/site-packages/ /usr/lib/python3.14/site-packages/

# Supplied by CI from the release metadata. It was a hardcoded "0.4.0" that
# went unchanged through every release up to 0.7.0, so the image labelled
# itself with a version it had not been for a long time. A default is kept so
# a local build still works; CI always overrides it.
ARG VERSION=0.0.0-dev

LABEL name="trentina" \
      version="${VERSION}" \
      summary="MCP gateway for AI agents: injection defense, token savings, policy and auth" \
      description="MCP gateway between AI agents and their tools, the web and Matrix: three-layer prompt-injection defense, smaller tool lists and responses, gateway-enforced parameter and response guards, OAuth/DCR, and per-agent profiles" \
      maintainer="crunchtools.com" \
      url="https://github.com/crunchtools/trentina" \
      io.k8s.display-name="MCP Trentina CrunchTools" \
      io.openshift.tags="mcp,mcp-gateway,security,prompt-injection,oauth,token-efficiency" \
      org.opencontainers.image.source="https://github.com/crunchtools/trentina" \
      org.opencontainers.image.description="MCP gateway for AI agents: injection defense, token savings, policy and auth" \
      org.opencontainers.image.licenses="AGPL-3.0-or-later" \
      com.crunchtools.l2.default="prompt-injection-guard-small-ct: Horizon-Labs/prompt-injection-guard-small fine-tuned (Apache-2.0)"
