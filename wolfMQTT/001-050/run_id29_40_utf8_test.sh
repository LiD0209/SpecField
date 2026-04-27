#!/bin/sh
set -eu

BROKER="${BROKER:-/mnt/host/d/project/conditionFuzzing/build/wolfmqtt-id17-id20-test/bin/mqtt_broker}"
TESTPY="${TESTPY:-/mnt/host/d/project/conditionFuzzing/wolfMQTT/001-050/repro_id29_40_utf8_test.py}"
PORT="${PORT:-28984}"
LOG="${LOG:-/tmp/wolfmqtt_broker_id29_40.log}"

"$BROKER" -p "$PORT" >"$LOG" 2>&1 &
PID=$!

sleep 1
python3 "$TESTPY"
RC=$?

kill "$PID" >/dev/null 2>&1 || true
wait "$PID" >/dev/null 2>&1 || true

echo "--- broker log tail ---"
tail -n 120 "$LOG"

exit "$RC"
