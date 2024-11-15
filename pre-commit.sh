#!/bin/bash

cargo clippy --all-features -- -Dwarnings
cargo +nightly fmt --all
./test.sh