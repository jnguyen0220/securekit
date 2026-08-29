#!/bin/bash
#
# start-client.sh — run securekit as a CLIENT / scanning bot.
#
# On startup the bot REGISTERS with the coordination server, then repeatedly
# CLAIMS a batch of public-repo clone URLs from the server's queue, clones each
# one using the server-provided URL (authenticated when available), scans it
# locally, and reports back ONLY redacted findings (raw secret values never
# leave this machine).
# It exits when the server signals its queue is drained.
#
# A background heartbeat keeps the worker counted as alive.
#
# The bot is ZERO-CONFIG: it needs ONLY the server URL — no .env file, no
# credential, no environment settings. The server provides everything else —
# the repo URLs to scan, the ignore rules, and the scan/claim concurrency
# (set SECUREKIT_SCAN_WORKERS / SECUREKIT_CLAIM_BATCH on the SERVER to tune it).
#
# Run several of these in parallel (with distinct worker ids) to scan faster.
#
# Usage:
#   ./scripts/start-client.sh [SERVER_URL] [WORKER_ID]
#
# Examples:
#   ./scripts/start-client.sh                                   # defaults below
#   ./scripts/start-client.sh http://127.0.0.1:8080 bot-1

set -euo pipefail

# Run from the repo root regardless of where this script is invoked from.
cd "$(dirname "${BASH_SOURCE[0]}")/.." || exit 1

# ---- Configuration ----------------------------------------------------------
SERVER_URL="${1:-${SERVER_URL:-http://127.0.0.1:8080}}"
WORKER_ID="${2:-${WORKER_ID:-securekit-bot-$$}}"

# ---- Build ------------------------------------------------------------------
echo "Building securekit..."
cargo build --release

# ---- Run --------------------------------------------------------------------
echo ""
echo "Starting securekit CLIENT (public-repo scanning bot)"
echo "  server:    $SERVER_URL"
echo "  worker id: $WORKER_ID"
echo ""

exec ./target/release/securekit-client \
    "$SERVER_URL" \
    --worker-id "$WORKER_ID"
