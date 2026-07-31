#!/bin/bash
# Coverage analysis script
# Run locally with: cargo install cargo-tarpaulin && ./scripts/coverage.sh

set -e

echo "Running coverage analysis..."

# Check if tarpaulin is installed
if ! command -v cargo-tarpaulin &> /dev/null; then
    echo "Installing cargo-tarpaulin..."
    cargo install cargo-tarpaulin
fi

# Run coverage
echo "Building and running tarpaulin..."
cargo tarpaulin --out Html --output-dir ./target/coverage --workspace --tests --all-features

echo ""
echo "Coverage report generated at: ./target/coverage/index.html"
echo ""

# Print summary
cargo tarpaulin --out Text --workspace --tests --all-features 2>/dev/null | tail -20