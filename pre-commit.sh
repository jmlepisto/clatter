#!/bin/bash

cargo clippy -- -Dwarnings
cargo +nightly fmt --all