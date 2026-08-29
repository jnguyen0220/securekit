#!/bin/bash

# Start script for secret repository scanner

set -e

# Run from the repo root regardless of where this script is invoked from.
cd "$(dirname "${BASH_SOURCE[0]}")/.." || exit 1

echo "Building the secret repository scanner..."
cargo build --release

echo ""
echo "Build complete! Starting the application..."
echo ""

# Run the application with any arguments passed to this script
./target/release/securekit "$@"
