#!/bin/bash
#
# Usage:
# fuzz.sh <t>
#
# t: How many seconds to fuzz
set -e

# Cleanup on exit
trap "trap - SIGTERM && kill -- -$$" SIGINT SIGTERM EXIT

# How many seconds to fuzz
T=${1?param missing - time to fuzz}

FUZZ="cargo +nightly fuzz"
$FUZZ build

# Fuzz all targets
targets=$($FUZZ list)
for target in $targets; do
    $FUZZ run $target -- -max_total_time=$T &
done

# Stop as soon as a fuzzer job fails
wait -n