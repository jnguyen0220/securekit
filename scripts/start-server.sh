#!/bin/bash
#
# start-server.sh — run securekit in coordination SERVER mode.
#
# The server enumerates public repositories centrally (using its own GitHub
# credential), hands clone URLs to connected bots via the claim queue,
# and collects the (redacted) findings the bots report back. Configuration is
# read from the environment; this script provides sensible defaults.
#
# Usage:
#   ./scripts/start-server.sh
#
# Override any setting via the environment, e.g.:
#   SECUREKIT_BIND=0.0.0.0:9000 ./scripts/start-server.sh
#   SECUREKIT_ENUM_SINCE=1000000 ./scripts/start-server.sh       # start after this repo id
#   SECUREKIT_CLAIM_BATCH=25 ./scripts/start-server.sh           # repos leased per claim
#   SECUREKIT_LIST_FILE=repos.txt ./scripts/start-server.sh      # scan a static list instead
#
# The server authenticates enumeration with a GitHub App (GITHUB_APP_ID +
# GITHUB_APP_INSTALLATION_ID + private key) or a personal token (GITHUB_TOKEN),
# read from the environment or a .env file. GitHub rate-limits anonymous access
# to 60 requests/hour, so a credential is strongly recommended.

set -euo pipefail

# Run from the repo root regardless of where this script is invoked from.
cd "$(dirname "${BASH_SOURCE[0]}")/.." || exit 1

# ---- Configuration (override via environment) -------------------------------
export SECUREKIT_BIND="${SECUREKIT_BIND:-127.0.0.1:8080}"
export SECUREKIT_RESULTS_FILE="${SECUREKIT_RESULTS_FILE:-results.jsonl}"
export SECUREKIT_LEASE_SECS="${SECUREKIT_LEASE_SECS:-300}"
export SECUREKIT_CLAIM_BATCH="${SECUREKIT_CLAIM_BATCH:-10}"
export SECUREKIT_ENUM_SINCE="${SECUREKIT_ENUM_SINCE:-0}"
export SECUREKIT_ENUM_CURSOR_FILE="${SECUREKIT_ENUM_CURSOR_FILE:-.enum-cursor.json}"
export SECUREKIT_VALIDATE_SECRETS="${SECUREKIT_VALIDATE_SECRETS:-1}"
export SECUREKIT_AZURE_ACTIVE_PROBE="${SECUREKIT_AZURE_ACTIVE_PROBE:-0}"

# ---- Build ------------------------------------------------------------------
echo "Building securekit..."
cargo build --release

# ---- Run --------------------------------------------------------------------
echo ""
echo "Starting securekit SERVER"
echo "  bind:        http://$SECUREKIT_BIND"
echo "  results:     $SECUREKIT_RESULTS_FILE"
echo "  lease:       ${SECUREKIT_LEASE_SECS}s"
echo "  claim batch: $SECUREKIT_CLAIM_BATCH"
if [[ -n "${SECUREKIT_LIST_FILE:-}" ]]; then
    echo "  mode:        static list ($SECUREKIT_LIST_FILE)"
else
    echo "  mode:        native enumeration (since id ${SECUREKIT_ENUM_SINCE})"
    echo "  enum cursor: ${SECUREKIT_ENUM_CURSOR_FILE}"
fi
echo ""

if [[ -f .env ]]; then
    exec ./target/release/securekit-server --env-file .env
else
    exec ./target/release/securekit-server
fi
