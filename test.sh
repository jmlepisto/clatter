#!/bin/bash
set -e

TEST_FLAGS="--release -- --nocapture"
CRATES=("clatter" "clatter-tests" "clatter-test-vectors")

# Loop over crates
for crate in "${CRATES[@]}"; do
    echo "Testing crate: $crate"
    cargo test -p "$crate" $TEST_FLAGS
done

# Run all examples to verify they compile and run correctly
echo "Running examples..."
for example in examples/*.rs; do
    name=$(basename "$example" .rs)
    echo "  Running example: $name"
    cargo run --release --example "$name"
done
