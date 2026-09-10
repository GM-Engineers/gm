#!/usr/bin/env bash
# R-9.1 diagnostic wrapper — runs the gmssl interop test, samples both
# processes' syscalls once they're hung, captures the gmssl verbose log,
# and the gm-tlcp client stdout. Output to /tmp/r9-1-diagnostic/.
#
# Stops both processes after capture. Designed to run unattended.
set -uo pipefail

cd "$(dirname "$0")/.."  # gm-tlcp/

OUT=/tmp/r9-1-diagnostic
mkdir -p "$OUT"
rm -f "$OUT"/*

echo "[R-9.1] start: $(date '+%H:%M:%S')" > "$OUT/timeline.log"

# Launch the test (which spawns gmssl tlcp_server as a child).
export PATH="/Users/laozhang/Work/opensource/gmssl-master/build/bin:$PATH"

cargo test --test gmssl_interop --features tlcp-gmssl-compat \
    -- --ignored gmssl_tlcp_handshake_and_app_data \
    > "$OUT/test.stdout" 2> "$OUT/test.stderr" &
TEST_PID=$!
echo "[R-9.1] cargo test pid=$TEST_PID" >> "$OUT/timeline.log"

# Wait for gmssl server child to spawn (up to ~60s for cert generation).
GMSSL_PID=""
for i in $(seq 1 60); do
    GMSSL_PID=$(pgrep -P "$TEST_PID" -f 'tlcp_server' | head -1 || true)
    if [[ -n "$GMSSL_PID" ]]; then
        echo "[R-9.1] gmssl server pid=$GMSSL_PID (waited ${i}s)" >> "$OUT/timeline.log"
        break
    fi
    sleep 1
done

if [[ -z "$GMSSL_PID" ]]; then
    echo "[R-9.1] FAIL: gmssl server never spawned within 60s" >> "$OUT/timeline.log"
    cat "$OUT/test.stderr" >> "$OUT/timeline.log"
    kill -9 "$TEST_PID" 2>/dev/null
    exit 1
fi

# Wait ~30s for the handshake to complete + 500ms pre-write sleep + first
# write attempt, then for the server to hang. We've seen the hang stabilize
# within ~30s of the handshake finishing.
echo "[R-9.1] waiting 30s for server to enter hang state..." >> "$OUT/timeline.log"
sleep 30

# Sample the gmssl server (5s of stack traces — captures whatever syscall
# it's blocked on).
echo "[R-9.1] sampling gmssl server (5s)..." >> "$OUT/timeline.log"
sample "$GMSSL_PID" 5 -mayDie -file "$OUT/gmssl.sample.txt" \
    > "$OUT/gmssl.sample.stdout" 2> "$OUT/gmssl.sample.stderr" || true

# Sample the gm-tlcp test process too — it's likely blocked in
# client.read_application_data().
echo "[R-9.1] sampling gm-tlcp test (5s)..." >> "$OUT/timeline.log"
sample "$TEST_PID" 5 -mayDie -file "$OUT/test.sample.txt" \
    > "$OUT/test.sample.stdout" 2> "$OUT/test.sample.stderr" || true

# Capture process states.
ps -o pid,stat,time,wchan,command -p "$GMSSL_PID" 2>/dev/null \
    > "$OUT/gmssl.ps" || echo "gmssl gone" > "$OUT/gmssl.ps"
ps -o pid,stat,time,wchan,command -p "$TEST_PID" 2>/dev/null \
    > "$OUT/test.ps" || echo "test gone" > "$OUT/test.ps"

# Snapshot gmssl verbose log.
GMSSL_LOG="/tmp/gm-tlcp-server-$GMSSL_PID.log"
if [[ -f "$GMSSL_LOG" ]]; then
    cp "$GMSSL_LOG" "$OUT/gmssl-verbose.log"
    echo "[R-9.1] gmssl verbose log: $GMSSL_LOG ($(wc -l < "$GMSSL_LOG") lines)" \
        >> "$OUT/timeline.log"
fi

# Stop both.
echo "[R-9.1] stopping both processes..." >> "$OUT/timeline.log"
kill -INT "$TEST_PID" 2>/dev/null
sleep 1
kill -9 "$GMSSL_PID" 2>/dev/null
kill -9 "$TEST_PID" 2>/dev/null

echo "[R-9.1] done: $(date '+%H:%M:%S')" >> "$OUT/timeline.log"
echo "[R-9.1] outputs in: $OUT"
