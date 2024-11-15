# Without alloc
cargo test --release --all -- --nocapture
# With alloc
cargo test --release --all --features=alloc -- --nocapture