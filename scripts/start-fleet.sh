#!/bin/bash
#
# start-fleet.sh — launch a securekit coordination SERVER plus N scanning
# CLIENTS (bots) on one machine, in one command.
#
# Each bot registers with the server, then claims batches of public-repo URLs
# from the server's queue and scans them. The server enumerates repositories
# centrally and hands out work; bots clone anonymously and never receive a
# credential. Only redacted findings are reported back; raw secret values never
# leave the bot.
#
# Usage:
#   ./scripts/start-fleet.sh [N_WORKERS]
#
# Examples:
#   ./scripts/start-fleet.sh            # 5 workers (default)
#   ./scripts/start-fleet.sh 10         # 10 workers
#
# Environment overrides:
#   SECUREKIT_BIND=127.0.0.1:8080   server bind address
#   SCAN_WORKERS=4                  repos scanned in parallel per bot
#   SECUREKIT_WORKER_TTL_SECS=60    heartbeat/liveness window
#   LOG_DIR=/tmp/securekit-fleet    where per-process logs are written

set -euo pipefail

# Run from the repo root regardless of where this script is invoked from.
cd "$(dirname "${BASH_SOURCE[0]}")/.." || exit 1

# ---- Configuration ----------------------------------------------------------
N_WORKERS="${1:-5}"
SERVER_URL="${SERVER_URL:-http://${SECUREKIT_BIND:-127.0.0.1:8080}}"
export SECUREKIT_BIND="${SECUREKIT_BIND:-127.0.0.1:8080}"
export SECUREKIT_WORKER_TTL_SECS="${SECUREKIT_WORKER_TTL_SECS:-60}"
# Scan concurrency is set on the SERVER and handed to every bot via /register.
export SECUREKIT_SCAN_WORKERS="${SCAN_WORKERS:-4}"
LOG_DIR="${LOG_DIR:-/tmp/securekit-fleet}"
ENV_FILE="${ENV_FILE:-.env}"

if ! [[ "$N_WORKERS" =~ ^[0-9]+$ ]] || (( N_WORKERS < 1 )); then
    echo "ERROR: N_WORKERS must be a positive integer (got '$N_WORKERS')." >&2
    exit 1
fi

mkdir -p "$LOG_DIR"

# ---- Build once -------------------------------------------------------------
echo "Building securekit (release)..."
cargo build --release

SERVER_BIN=./target/release/securekit-server
CLIENT_BIN=./target/release/securekit-client

# ---- Track children and clean up on exit ------------------------------------
PIDS=()

cleanup() {
    echo ""
    echo "Shutting down fleet..."
    for pid in "${PIDS[@]}"; do
        kill "$pid" 2>/dev/null || true
    done
    wait 2>/dev/null || true
    echo "Done."
}
trap cleanup INT TERM EXIT

# ---- Start the server -------------------------------------------------------
echo ""
echo "Starting server on $SERVER_URL (ttl ${SECUREKIT_WORKER_TTL_SECS}s)"
if [[ -f "$ENV_FILE" ]]; then
    "$SERVER_BIN" --env-file "$ENV_FILE" > "$LOG_DIR/server.log" 2>&1 &
else
    "$SERVER_BIN" > "$LOG_DIR/server.log" 2>&1 &
fi
SERVER_PID=$!
PIDS+=("$SERVER_PID")

# Wait for the server to accept connections.
for _ in $(seq 1 50); do
    if curl -sf "$SERVER_URL/health" >/dev/null 2>&1; then
        break
    fi
    if ! kill -0 "$SERVER_PID" 2>/dev/null; then
        echo "ERROR: server exited during startup. Last log lines:" >&2
        tail -n 20 "$LOG_DIR/server.log" >&2 || true
        exit 1
    fi
    sleep 0.2
done

# ---- Start the workers ------------------------------------------------------
echo "Starting $N_WORKERS worker(s) ($SECUREKIT_SCAN_WORKERS scan threads each)"
for i in $(seq 1 "$N_WORKERS"); do
    "$CLIENT_BIN" "$SERVER_URL" \
        --worker-id "bot-$i" \
        > "$LOG_DIR/bot-$i.log" 2>&1 &
    PIDS+=("$!")
done

echo ""
echo "Fleet is up. Logs in $LOG_DIR/"
echo "  server: $LOG_DIR/server.log"
echo "  bots:   $LOG_DIR/bot-<n>.log"
echo ""
echo "Live stats (Ctrl+C to stop the whole fleet):"

# ---- Poll stats until interrupted -------------------------------------------
while kill -0 "$SERVER_PID" 2>/dev/null; do
    stats="$(curl -sf "$SERVER_URL/stats" 2>/dev/null || echo '{}')"
    printf '\r  %s' "$stats"
    sleep 2
done
echo ""
