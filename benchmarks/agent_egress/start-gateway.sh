#!/bin/sh
# Start Trentina for agent-egress-bench (#507). $1: "fetch" (port 8000, behind
# shim.conf) or "mcp" (the runner's $AEB_GATEWAY_ADDR, its fixture as backend).
# AEB_TRENTINA_RUN is the command that runs the gateway with the environment
# below, e.g. a `docker run --network host ... trentina:bench` prefix.
set -eu
kit=$(cd "$(dirname "$0")" && pwd)
work=${AEB_TRENTINA_WORK:-$kit/.run}
mkdir -p "$work"
case "$1" in
  fetch) listen=127.0.0.1:8000; fixture=http://127.0.0.1:9/unused ;;
  mcp) listen=$AEB_GATEWAY_ADDR; fixture=$AEB_MCP_HTTP_FIXTURE_URL ;;
  *) echo "usage: $0 fetch|mcp" >&2; exit 64 ;;
esac
sed -e "s|@MODE@|${AEB_TRENTINA_MODE:-block}|g" -e "s|@FIXTURE_URL@|$fixture|g" \
  "$kit/profiles.yaml.in" > "$work/profiles.yaml"
exec $AEB_TRENTINA_RUN --transport streamable-http \
  --host "${listen%:*}" --port "${listen##*:}" --no-dbus
