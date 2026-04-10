#!/usr/bin/env bash
# Stop the OpenClaw billing proxy started by start.sh.
set -e
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PID_FILE="$ROOT/scripts/proxy.pid"

if [ ! -f "$PID_FILE" ]; then
  echo "no pid file; proxy not running?"
  exit 0
fi

PID="$(cat "$PID_FILE")"
if kill -0 "$PID" 2>/dev/null; then
  kill "$PID"
  sleep 1
  kill -0 "$PID" 2>/dev/null && kill -9 "$PID" 2>/dev/null || true
  echo "proxy stopped (pid $PID)"
else
  echo "process $PID not running"
fi
rm -f "$PID_FILE"
