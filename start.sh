#!/bin/bash

# Start script for secret repository scanner

set -e

echo "Building the secret repository scanner..."
cargo build --release

echo ""
echo "Build complete! Starting the application..."
echo ""

# Run the application with any arguments passed to this script
./target/release/securekit "$@"
