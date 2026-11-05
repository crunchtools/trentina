#!/bin/sh
# Start Trentina for agent-egress-bench (#507): write profiles.yaml from the
# template and run the gateway on 127.0.0.1:8000, behind shim.conf.
# AEB_TRENTINA_RUN is the command that runs the gateway with the environment it
# needs, e.g. a `docker run --network host ... trentina:bench` prefix; the
# arguments below are appended to it.
set -eu
kit=$(cd "$(dirname "$0")" && pwd)
work=${AEB_TRENTINA_WORK:-$kit/.run}
mode=${AEB_TRENTINA_MODE:-block}
case "$mode" in flag|block) ;; *) echo "AEB_TRENTINA_MODE must be flag or block" >&2; exit 64 ;; esac
mkdir -p "$work"
sed -e "s|@MODE@|$mode|g" "$kit/profiles.yaml.in" > "$work/profiles.yaml"
exec $AEB_TRENTINA_RUN --transport streamable-http --host 127.0.0.1 --port 8000 --no-dbus
