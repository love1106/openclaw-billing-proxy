#!/usr/bin/env bash
# Start the OpenClaw billing proxy in the background.
# PID is written to scripts/proxy.pid; logs to scripts/proxy.log.
set -e
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PID_FILE="$ROOT/scripts/proxy.pid"
LOG_FILE="$ROOT/scripts/proxy.log"

if [ -f "$PID_FILE" ] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
  echo "proxy already running (pid $(cat "$PID_FILE"))"
  exit 0
fi

cd "$ROOT"
PROXY_HOST=0.0.0.0 nohup node -r ./proxy-logger.js proxy.js >> "$LOG_FILE" 2>&1 &
echo $! > "$PID_FILE"
echo "proxy started (pid $(cat "$PID_FILE")) -> $LOG_FILE"
