# MCP Trentina CrunchTools Container
# Three-layer defense: deterministic checks + a local classifier (L2) + quarantined LLM
# Built entirely on Hummingbird Python images (Red Hat hardened, minimal)
#
# Build: the GHA pipeline, and only the GHA pipeline.
# .github/workflows/container.yml builds and pushes quay.io/crunchtools/trentina.
# Do NOT build this image by hand — building outside the pipeline causes drift.
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
FROM ghcr.io/crunchtools/trentina-l2-model@sha256:02c8a8ff165f1c133535f00523de68169c1c12c58632d415e2cd0e4c579ee4c6 AS l2-model

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
# Stage 2: pip install (builder variant — has shell for RUN)
# Hummingbird default is distroless (no /bin/sh), so pip install
# must happen in a builder stage. Installed packages are copied
# into the final distroless image.
# ============================================================
FROM quay.io/hummingbird/python:3.14-builder AS pip-builder
USER 0

WORKDIR /app
COPY pyproject.toml README.md uv.lock ./
COPY src/ ./src/

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
# `uv export` emits hashes, so this is also a verified install. The project
# itself goes in second with --no-deps so pip cannot re-resolve around the lock.
#
# The requirements go in with --no-deps too (#370). The export is the whole
# locked set, so pip has nothing to resolve, and letting it try is what broke
# the build: rapidocr asks for `opencv-python`, the lock replaces that with
# `opencv-python-headless` (pyproject.toml, [tool.uv]), and pip, reading
# rapidocr's own metadata, went looking for the one the lock had removed.
#
# petit-log-crunchtools used to be held out of this export and installed from
# a hashed source archive, because it resolved from a git tag and pip refuses
# a VCS requirement under hash checking. It reached PyPI as of 4.1.1 (issue
# #96), so it is now an ordinary locked, hash-verified dependency like every
# other one and needs no special case here.
RUN pip install --no-cache-dir uv \
 && uv export --frozen --no-dev --extra matrix --extra bridge --no-emit-project \
      --format requirements-txt -o /tmp/requirements.txt \
 && pip install --no-cache-dir --prefix=/usr --no-deps -r /tmp/requirements.txt \
 && pip install --no-cache-dir --prefix=/usr --no-deps '.[matrix,bridge]'

# onnxruntime >= 1.29 reads /etc/machine-id during module init. When that file
# is absent it falls back to popen("blkid")/popen("hostname"), and popen returns
# NULL in a distroless image with no /bin/sh. The return value is not checked,
# so the following fclose(NULL) segfaults the interpreter on `import onnxruntime`.
# Providing the file short-circuits the fallback before popen is ever reached.
RUN tr -d - < /proc/sys/kernel/random/uuid > /etc/machine-id.seed

# ============================================================
# Stage 2b: the L2 gates: obfuscation (#362), then benign content (#411)
# The Layer contract makes reading through obfuscation the model's job, so
# the build proves it: every corpus attack is classified plain and under six
# transforms by the classifier code this image runs, and the result is
# written into the model's manifest. A model that fails stops the build
# here. The gateway warns at startup about a model with no passing record
# and refuses to start on one under TRENTINA_REQUIRE_HARDENED.
# ============================================================
FROM pip-builder AS l2-gate
COPY --from=model-builder /models/ /models/
COPY benchmarks/l2_obfuscation.py benchmarks/l2_benign.py /gate/benchmarks/
COPY corpora/internal.py corpora/benign_ops.py /gate/corpora/
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
# ============================================================
FROM quay.io/hummingbird/python:3.14

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

WORKDIR /app

# Copy libstdc++ from model-builder — required by onnxruntime/numpy C extensions
COPY --from=model-builder /usr/lib64/libstdc++.so.6* /usr/lib64/

# The ONNX model, from the gate stage: its manifest carries the gate record.
# No PyTorch in the final image.
COPY --from=l2-gate /models/prompt-injection-guard-small-ct/ /models/prompt-injection-guard-small-ct/

# Copy installed Python packages from pip-builder (pure Python + native C extensions)
COPY --from=pip-builder /usr/lib/python3.14/site-packages/ /usr/lib/python3.14/site-packages/
COPY --from=pip-builder /usr/lib64/python3.14/site-packages/ /usr/lib64/python3.14/site-packages/

# Keeps onnxruntime off its shell-based fallback path — see pip-builder stage
COPY --from=pip-builder /etc/machine-id.seed /etc/machine-id

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
