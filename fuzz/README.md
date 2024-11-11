# Fuzzing

**`cargo-fuzz` need to be run on a nightly compiler**

* Install [`cargo-fuzz`](https://rust-fuzz.github.io/book/cargo-fuzz/setup.html)
* In the repository root, run these commands:
    * `cargo fuzz list` to list fuzz targets
    * `cargo fuzz run <target>` to run a target

`cargo-fuzz` will not generate over 4096 byte inputs by default. To provide
longer fuzz data, provide `-max_len` option.