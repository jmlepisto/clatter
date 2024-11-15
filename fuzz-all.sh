#!/bin/bash
set -e

if [ -z "$1" ]
  then
    echo "Please supply target fuzzing time in seconds as an argument"
fi

T="$1"
FUZZ="cargo +nightly fuzz"

targets=$($FUZZ list)

$FUZZ build --release
for t in $targets; do
    $FUZZ run --release $t -- -max_total_time=$T
done