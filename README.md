# Clatter 🔊

[![Crates.io Version](https://img.shields.io/crates/v/clatter?style=flat-square)](https://crates.io/crates/clatter)
[![docs.rs](https://img.shields.io/docsrs/clatter?style=flat-square)](https://docs.rs/clatter/latest/clatter/)

⚠️ **Work in progress** ⚠️

`no_std` compatible, pure Rust implementation of the [Noise protocol framework](https://noiseprotocol.org/noise.html)
with support for [**Post Quantum (PQ) extensions**](https://doi.org/10.1145/3548606.3560577) as presented by
Yawning Angel, Benjamin Dowling, Andreas Hülsing, Peter Schwabe, and Fiona Johanna Weber.

Main targets of this crate are correctness, extensibility, and strict `no_std` compatibility
and those come  with the small drawback of more verbose user experience with some boilerplate.
If you don't need PQ functionality and are developing for a regular target, you probably are better
off using these instead:

* [`snow`](https://github.com/mcginty/snow)
* [`noise-rust`](https://github.com/blckngm/noise-rust)

Basis of this implementation relies heavily on the abovementioned crates and I'm extending
huge thanks to the developers for their effort!

⚠️ **Warning** ⚠️ This library has not received any formal audit and is still in early phase

## Basics

From user perspective, everything in this crate is built around three types:

* `NqHandshake` - Classical, non-post-quantum Noise handshake
* `PqHandshake` - Post-quantum Noise handshake
* `DualLayerHandshake` - Dual layer handshake, which combines and pipes two Noise handshakes

Users will pick and instantiate the desired handshake state machine with the crypto primitives
they wish to use (supplied as generic parameters) and complete the handshake using the methods 
provided by the common `Handshaker` trait:

* `write_message(...)` - Write next handshake message
* `read_message(...)` - Read next handshake message
* `is_finished()` - Is the handshake ready?
* `finalize()` - Move to transport state

Once the handshake is complete, the handshake state machine can be moved to transport state
by calling `.finalize()`. This finishes the handshake and the returned `TransportState` can
be used for encrypting and decrypting communication with the peer. Voilà!

As already mentioned, this crate is quite verbose due to `no_std` compatibility requirements,
so it's a good idea to take a look at the [examples](/examples) for a better view of the
handshake process.

### Example

Simplified example with the most straightforward (and most unsecure) interactive PQ handshake 
pattern and no handshake payload data at all:

```rust
use clatter::crypto::cipher::ChaChaPoly;
use clatter::crypto::hash::Sha512;
use clatter::crypto::kem::rust_crypto_kyber::Kyber512;
use clatter::handshakepattern::noise_pqnn;
use clatter::traits::Handshaker;
use clatter::PqHandshake;

fn main() {
    let mut rng_alice = rand::thread_rng();

    // Instantiate initiator handshake
    let mut alice = PqHandshake::<Kyber512, Kyber512, ChaChaPoly, Sha512, _>::new(
        noise_pqnn(),   // Handshake pattern
        &[],            // Prologue data
        true,           // Are we the initiator
        None,           // Pre-shared keys..
        None,           // ..
        None,           // ..
        None,           // ..
        &mut rng_alice, // RNG instance
    ).unwrap();

    let mut buf_alice_send = [0u8; 4096];
    let mut buf_alice_receive = [0u8; 4096];

    // Write handshake message and deliver to peer
    let n = alice.write_message(&[], &mut buf_alice_send).unwrap();
    my_send_function(&buf_alice_send[..n]);

    // Receive handshake message and process it
    let n = my_receive_function(&mut buf_alice_receive);
    let _ = alice.read_message(&buf_alice_receive[..n], &mut[]).unwrap();

    assert!(alice.is_finished());

    // Move to transport state
    let mut alice = alice.finalize().unwrap();

    // All done! Use .send() and .receive() on the transport state to communicate
    // with the peer
    let n = alice.send(b"Hello from Alice", &mut buf_alice_send).unwrap();
    my_send_function(&buf_alice_send[..n]);   
}
```

## Differences to PQNoise paper

* PQNoise presents the possibility to use different KEMs for ephemeral, initiator, and responder.
With Clatter the same KEM is used for both initiator and responder operations, while it is still 
possible to configure a separate KEM for ephemeral use.
* PQNoise presents *SEEC*, a method for improving RNG security in bad randomness settings. Clatter
does not currently implement *SEEC*.

## Roadmap before first stable release

* ~~Add support for PSKs as defined by the Noise spec~~
* ~~Add support for all crypto algorithms listed in Noise spec~~, no compatible X448 implementation exists
* Add support for all fundamental Noise patterns (one-way patterns missing)
* More KEMs with ability to configure the desired vendor
* Proper testing and fuzzing
* Better documentation

