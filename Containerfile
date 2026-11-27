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
# trained and gated by the l2-train workflow (GHA run 40311268794, commit
# b7fd870) and published as a scratch image holding the ONNX export, its
# manifest, NOTICE and training.json. Pinned by digest: a new model is a new
# training round (docs/by-hand.md) and a change to this line, and to the same
# line in scripts/l2-builder/Containerfile.
FROM quay.io/crunchtools/trentina-l2-model@sha256:02c8a8ff165f1c133535f00523de68169c1c12c58632d415e2cd0e4c579ee4c6 AS l2-model

# ============================================================
# Stage 1: the locked dependency set (builder variant -- has a shell)
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
FROM quay.io/hummingbird/python:3.14-builder@sha256:df20744183ad6dcf65a5ff32409a2120892e3ce92c95bd736cb64ab66117f830 AS lock
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
#
# opencv-python-headless is the exception: it is built in the `opencv` stage
# below, so it is left out here, and numpy's locked entry is exported on its
# own (the `opencv-build` group) for that stage to build against.
RUN uv export --frozen --no-dev --extra matrix --extra bridge --no-emit-project \
      --no-emit-package opencv-python-headless \
      --format requirements-txt -o /requirements.txt \
 && uv export --frozen --only-group opencv-build --no-emit-project \
      --format requirements-txt -o /numpy.txt

# ============================================================
# OpenCV, built without video I/O. The opencv-python-headless wheel bundles
# FFmpeg, which the gateway never calls (cv2 is only rapidocr's image code,
# in unpack/ocr_worker.py) and which put FFmpeg's CVEs in this image's scan
# (9.0.2 in the 5.1.0.95 wheel). Only the modules rapidocr and the worker use
# are built: core, imgproc and imgcodecs (JPEG and PNG, from OpenCV's own
# copies), statically, so cv2 needs nothing from the runtime but libstdc++.
# The source is pinned by hash and should track the lock's
# opencv-python-headless version, which tests still run against.
# IPP is off because its configure step downloads a binary.
# ============================================================
FROM quay.io/hummingbird/python:3.14-builder@sha256:df20744183ad6dcf65a5ff32409a2120892e3ce92c95bd736cb64ab66117f830 AS opencv
USER 0
RUN dnf install -y gcc-c++ python3-devel cmake ninja-build tar gzip && dnf clean all
RUN pip install --no-cache-dir uv==0.13.7
COPY --from=lock /numpy.txt /tmp/numpy.txt
RUN uv pip install --no-cache --system --no-deps --require-hashes -r /tmp/numpy.txt
ARG OPENCV_VERSION=5.1.0
ARG OPENCV_SHA256=638c1dae7e37e45afea21aa217dc667ad7cf57acc66cdf652c074f1e0e5ad6d2
WORKDIR /src
RUN curl -fsSL -o opencv.tar.gz "https://github.com/opencv/opencv/archive/refs/tags/${OPENCV_VERSION}.tar.gz" \
 && echo "${OPENCV_SHA256}  opencv.tar.gz" | sha256sum -c - \
 && tar xzf opencv.tar.gz \
 && cmake -G Ninja -S "opencv-${OPENCV_VERSION}" -B build \
      -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=/opt/opencv \
      -DBUILD_LIST=core,imgproc,imgcodecs,python3 -DBUILD_SHARED_LIBS=OFF \
      -DOPENCV_FORCE_PYTHON_LIBS=ON -DBUILD_opencv_python3=ON \
      -DBUILD_JPEG=ON -DBUILD_PNG=ON -DBUILD_ZLIB=ON \
      -DWITH_FFMPEG=OFF -DWITH_GSTREAMER=OFF -DWITH_V4L=OFF -DWITH_1394=OFF \
      -DWITH_GTK=OFF -DWITH_QT=OFF -DWITH_OPENCL=OFF -DWITH_IPP=OFF \
      -DWITH_TIFF=OFF -DWITH_WEBP=OFF -DWITH_OPENJPEG=OFF -DWITH_JASPER=OFF \
      -DWITH_OPENEXR=OFF -DWITH_AVIF=OFF -DWITH_LAPACK=OFF -DWITH_EIGEN=OFF \
      -DWITH_PROTOBUF=OFF -DWITH_ADE=OFF \
      -DBUILD_TESTS=OFF -DBUILD_PERF_TESTS=OFF -DBUILD_EXAMPLES=OFF \
      -DBUILD_opencv_apps=OFF -DBUILD_DOCS=OFF -DBUILD_JAVA=OFF \
      -DPYTHON3_EXECUTABLE=/usr/bin/python3 -DOPENCV_PYTHON3_INSTALL_PATH=/usr/lib64/python3.14/site-packages \
 && cmake --build build --parallel 4 \
 && cmake --install build \
 && python3 -c "import cv2; print(cv2.__version__)"

FROM quay.io/hummingbird/python:3.14-builder@sha256:df20744183ad6dcf65a5ff32409a2120892e3ce92c95bd736cb64ab66117f830 AS deps
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
COPY --from=opencv /usr/lib64/python3.14/site-packages/cv2/ /usr/lib64/python3.14/site-packages/cv2/

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
# Stage 1b: the L2 gates: obfuscation (#362), then benign content (#411)
# The Layer contract makes reading through obfuscation the model's job, so
# the build proves it: every corpus attack is classified plain and under six
# transforms by the classifier code this image runs, and the result is
# written into the model's manifest. A model that fails stops the build
# here. The gateway warns at startup about a model with no passing record
# and refuses to start on one under TRENTINA_REQUIRE_HARDENED.
# ============================================================
FROM deps AS l2-gate
# Straight from the digest-pinned stage. The exporter's torch + optimum +
# transformers + sentencepiece stack is not in this file at all: it is
# scripts/l2-builder/Containerfile, which a training round exports with.
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
# Stage 2: Runtime image (distroless — no shell, no dnf)
# Constant settings first, then layers by how often they change: the base
# libraries, the dependency set, the model, Trentina, and the version label
# last -- declared first, a version change invalidated every layer after it.
# ============================================================
FROM quay.io/hummingbird/python:3.14@sha256:6f4fe5671e67d118d847a97804212da62f41ab380708a4df9e5f968f66507718

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
