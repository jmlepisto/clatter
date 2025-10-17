#!/bin/bash
set -e

TEST_FLAGS="--release -- --nocapture"
CRATES=("clatter" "clatter-tests" "clatter-test-vectors")

# Loop over crates
for crate in "${CRATES[@]}"; do
    echo "Testing crate: $crate"
    cargo test -p "$crate" $TEST_FLAGS
done
