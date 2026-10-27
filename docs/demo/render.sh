#!/usr/bin/env bash
# Render the README demo: docs/demo/trentina.gif and trentina.mp4.
#
#   OPENROUTER_API_KEY=... docs/demo/render.sh      # from the repository root
#
# Runs in GHA (.github/workflows/demo.yml); ENGINE=podman works locally.
# Starts the published gateway image with the fixture backend and the
# poisoned recipe page on a private network, records trentina.tape against
# it, renders flow.html frame by frame, and joins the two.
set -euo pipefail

ENGINE=${ENGINE:-docker}
IMAGE=${TRENTINA_IMAGE:-quay.io/crunchtools/trentina:latest}
DEMO=$(cd "$(dirname "$0")" && pwd)
OUT=${OUT:-$DEMO/out}
NET=trentina-demo
FPS=12
# L3 runs on OpenRouter, the key CI holds, on the supported judge,
# gemini-3.5-flash-lite. gemini-2.5-flash, the demo's judge before 2.0.0, is
# served only through Google AI Studio there now and answered 404.
: "${OPENROUTER_API_KEY:?OPENROUTER_API_KEY is required for L3}"
PROFILES=${PROFILES:-$DEMO/profiles.yaml}

mkdir -p "$OUT/frames"
cleanup() { $ENGINE rm -f td-workspace td-site td-gateway >/dev/null 2>&1 || true; $ENGINE network rm $NET >/dev/null 2>&1 || true; }
# A failed render prints the gateway's warnings and errors, not just an exit
# code; the wait loop's own session churn is left out.
trap 'rc=$?; [ $rc -ne 0 ] && $ENGINE logs td-gateway 2>&1 | grep -E "WARNING|ERROR|CRITICAL|Traceback" | grep -v "gateway.sessions" | tail -60 | sed "s/^/gateway: /"; cleanup' EXIT
cleanup
$ENGINE network create $NET >/dev/null

$ENGINE run -d --name td-workspace --network $NET --network-alias workspace \
    -v "$DEMO:/demo:ro,z" --entrypoint python "$IMAGE" /demo/backend.py >/dev/null
$ENGINE run -d --name td-site --network $NET --network-alias recipes.example \
    --sysctl net.ipv4.ip_unprivileged_port_start=0 -v "$DEMO/site:/site:ro,z" -w /site \
    --entrypoint python "$IMAGE" -m http.server 80 >/dev/null
# TRENTINA_FETCH_ALLOW_PRIVATE: the recipe page is on this private network.
$ENGINE run -d --name td-gateway --network $NET --network-alias trentina --tmpfs /data:mode=1777 \
    -v "$PROFILES:/config/profiles.yaml:ro,z" \
    -e TRENTINA_GATEWAY_ENABLED=true -e TRENTINA_PROFILES_PATH=/config/profiles.yaml \
    -e TRENTINA_PROFILE_ASSISTANT_TOKEN=demo-token -e TRENTINA_PROFILE_OPS_TOKEN=demo-ops-token \
    -e TRENTINA_FETCH_ALLOW_PRIVATE=true \
    -e OPENROUTER_API_KEY -e TRENTINA_MODEL_PROVIDER=openrouter \
    -e QUARANTINE_MODEL=google/gemini-3.5-flash-lite \
    "$IMAGE" --transport streamable-http --host 0.0.0.0 --port 8019 >/dev/null

$ENGINE build -q -f "$DEMO/Containerfile" -t trentina-demo-vhs "$DEMO" >/dev/null
VHS=( $ENGINE run --rm --network $NET -v "$DEMO:/demo:ro,z" -v "$OUT:/out:z"
      -e TQ_URL=http://trentina:8019/gateway/assistant/mcp -e TQ_TOKEN=demo-token )

OPS=( $ENGINE run --rm --network $NET -v "$DEMO:/demo:ro,z" --entrypoint python3
      -e TQ_URL=http://trentina:8019/gateway/ops/mcp -e TQ_TOKEN=demo-ops-token trentina-demo-vhs /demo/tq )

# The gateway judges every served tool description before its first
# tools/list answers, and on an empty store it holds every workspace tool
# until the operator approves it (#469): listing records the holds, the
# operator releases the four the tape uses. Wait for both, so the recording
# starts warm.
TAPE_TOOLS="search_gmail_messages get_gmail_message_content draft_gmail_message send_gmail_message"
missing() {
    local served; served=$("${VHS[@]}" --entrypoint python3 trentina-demo-vhs /demo/tq tools 2>/dev/null || true)
    for t in $TAPE_TOOLS; do grep -qx "$t" <<<"$served" || echo "$t"; done
}
for _ in $(seq 60); do
    need=$(missing)
    [ -z "$need" ] && break
    for t in $need; do
        "${OPS[@]}" call tool_pins action=approve backend=workspace tool="$t" >/dev/null 2>&1 || true
    done
    sleep 5
done
need=$(missing)
[ -z "$need" ] || { echo "not served after warm-up: $need" >&2; exit 1; }

"${VHS[@]}" -w /out trentina-demo-vhs /demo/trentina.tape

$ENGINE run --rm -v "$DEMO:/demo:ro,z" -v "$OUT:/out:z" mcr.microsoft.com/playwright/python:v1.55.0-noble \
    sh -c "pip install -q playwright==1.55.0 && python /demo/render_flow.py /out/frames $FPS"

FF=( $ENGINE run --rm -v "$OUT:/out:z" -v "$DEMO:/demo:z" --entrypoint ffmpeg trentina-demo-vhs -loglevel error -y )
"${FF[@]}" -framerate $FPS -i /out/frames/%05d.png -c:v libx264 -pix_fmt yuv420p -r 30 /out/flow.mp4
"${FF[@]}" -i /out/flow.mp4 -i /out/terminal.mp4 \
    -filter_complex "[0:v]scale=1200:720,setsar=1[a];[1:v]scale=1200:720,setsar=1,fps=30[b];[a][b]concat=n=2:v=1[v]" \
    -map "[v]" -c:v libx264 -pix_fmt yuv420p -movflags +faststart /demo/trentina.mp4
"${FF[@]}" -i /demo/trentina.mp4 \
    -vf "fps=10,split[s0][s1];[s0]palettegen=max_colors=128[p];[s1][p]paletteuse=dither=bayer" \
    /demo/trentina.gif
ls -l "$DEMO/trentina.gif" "$DEMO/trentina.mp4"
