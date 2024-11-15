# Noise Test Vectors

This tester lib provides support for verifying Clatter with Noise test vectors.
Currently we have included vectors from Cacophony and Snow.

## Implementation

Due to our `no_std` approach we cannot parse protocol names and instantiate handshakes
based on those. This is why we generate a dispatch function in `build.rs` which matches
the protocol name in the test vector to a function call with the correct crypto primitives.

This also means that not all the test vectors are currently verified - only the patterns for
which we have pre-made support in the `handshakepattern` module.

## Testing

To execute the tests, simply run `cargo test`