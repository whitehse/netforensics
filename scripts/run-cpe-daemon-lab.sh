#!/usr/bin/env bash
# Run cpe_agent as a daemon: NFLOG group 5 TCP stats → edgehost CH proxy → CH.
#
# Prerequisites:
#   1) edgehost running with plugins.clickhouse (telemetry_proxy + proxy_listen
#      18082, telemetry_user/password matching this YAML).
#   2) ClickHouse schema:
#        clickhouse-client --multiquery < ../edgehost/sql/clickhouse/002_cpe_tcp_stats.sql
#   3) Host NFLOG rules (CAP_NET_ADMIN) — see docs/guides/cpe-agent-tcp-stats.md
#
# Usage:
#   ./scripts/run-cpe-daemon-lab.sh
#   CONFIG=config/cpe_agent.field.yaml ROUTER_ID=cpe-42 ./scripts/run-cpe-daemon-lab.sh
#   FOREGROUND=0 ./scripts/run-cpe-daemon-lab.sh   # background
#
# Query on demand (another terminal):
#   ./build/cpe_ctl --socket /tmp/cpe_agent_lab.sock status
#   ./build/cpe_ctl --socket /tmp/cpe_agent_lab.sock --lua
#   ./build/cpe_ctl --socket /tmp/cpe_agent_lab.sock --lua-eval \
#     "local s=cpe.tcp_stats(); print(s.syn, s.rst, s.loss_hint)"
#   ./build/cpe_agent --config config/cpe_agent.lab-edgehost.yaml \
#     --lua-file examples/lua/tcp_stats_report.lua --no-ipc
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

CFG="${CONFIG:-$ROOT/config/cpe_agent.lab-edgehost.yaml}"
BIN="${CPE_AGENT_BIN:-$ROOT/build/cpe_agent}"
ROUTER_ID="${ROUTER_ID:-lab-cpe-1}"
LOG="${CPE_AGENT_LOG:-$ROOT/build/cpe_agent-lab.log}"
PID_FILE="${CPE_AGENT_PID:-$ROOT/build/cpe_agent-lab.pid}"
FOREGROUND="${FOREGROUND:-1}"
NO_BUILD="${NO_BUILD:-0}"
SOCK="${CPE_AGENT_SOCK:-/tmp/cpe_agent_lab.sock}"

die() { echo "error: $*" >&2; exit 1; }

if [[ ! -x "$BIN" ]]; then
  if [[ "$NO_BUILD" == "1" ]]; then
    die "missing $BIN (NO_BUILD=1)"
  fi
  echo "==> building cpe_agent + cpe_ctl"
  cmake -B build -S . >/dev/null
  cmake --build build --target cpe_agent cpe_ctl -j"$(nproc 2>/dev/null || echo 2)"
fi
[[ -x "$BIN" ]] || die "build/cpe_agent missing"
[[ -f "$CFG" ]] || die "missing config $CFG"

echo "==> cpe_agent daemon (NFLOG TCP stats → ClickHouse proxy)"
echo "    config:    $CFG"
echo "    router_id: $ROUTER_ID"
echo "    binary:    $BIN"
echo "    log:       $LOG"
echo "    ctl sock:  $SOCK  (override via ipc.socket in YAML)"
echo ""
echo "  Query:  ./build/cpe_ctl --socket $SOCK status"
echo "          ./build/cpe_ctl --socket $SOCK --lua-eval \"print(cpe.tcp_stats().loss_hint)\""
echo "  Stop:   kill \$(cat $PID_FILE)   # if FOREGROUND=0"
echo ""

if [[ "$FOREGROUND" == "1" ]]; then
  exec "$BIN" --config "$CFG" --router-id "$ROUTER_ID" 2>&1 | tee "$LOG"
else
  nohup "$BIN" --config "$CFG" --router-id "$ROUTER_ID" >"$LOG" 2>&1 &
  echo $! >"$PID_FILE"
  echo "cpe_agent pid $(cat "$PID_FILE") (FOREGROUND=0)"
fi
