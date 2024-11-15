# Clatter 🔊

[![Crates.io Version](https://img.shields.io/crates/v/clatter?style=flat-square)](https://crates.io/crates/clatter)
[![docs.rs](https://img.shields.io/docsrs/clatter?style=flat-square)](https://docs.rs/clatter/latest/clatter/)
[![GitHub branch check runs](https://img.shields.io/github/check-runs/jmlepisto/clatter/main?style=flat-square)](https://github.com/jmlepisto/clatter/actions)


`no_std` compatible, pure Rust implementation of the [**Noise protocol framework**](https://noiseprotocol.org/noise.html)
with support for [**Post Quantum (PQ) extensions**](https://doi.org/10.1145/3548606.3560577) as presented by
Yawning Angel, Benjamin Dowling, Andreas Hülsing, Peter Schwabe, and Fiona Johanna Weber.

Main targets of this crate are **correctness**, extensibility, and strict `no_std` compatibility
and those come  with the small drawback of more verbose user experience with some boilerplate.
If you don't need PQ functionality and are developing for a regular target, you probably are better
off using these instead:

* [`snow`](https://github.com/mcginty/snow)
* [`noise-rust`](https://github.com/blckngm/noise-rust)

Basis of this implementation relies heavily on the abovementioned crates and I'm extending
huge thanks to the developers for their effort!

⚠️ **Warning** ⚠️ 

* This library has not received any formal audit
* While we enable some cryptographic providers by default, it is up to **you** to get familiar with those and decide if they meet your security and integrity requirements
* Post-Quantum cryptography generally is not as established and mature as classical cryptography. Users are encouraged to implement hybrid encryption schemes with classical
crypto primitives incorporated to provide additional security in case of a catastrophic flaw in the post-quantum algorithms.
Clatter provides [`DualLayerHandshake`](https://docs.rs/clatter/latest/clatter/struct.DualLayerHandshake.html) for this purpose.

## Noise Protocol

This crate tracks Noise protocol framework **revision 34**. As of now we omit support for the following features:

* Handshake pattern parsing support - Handshakes have to instantiated with the correct primitives compile-time
* Curve 448 DH support - No suitable Rust implementation exists for our requirements
* Deferred pattern support - can be implemented by the user
* Fallback pattern support - Can be implemented by the user

## Basics

From user perspective, everything in this crate is built around three types:

* [`NqHandshake`](https://docs.rs/clatter/latest/clatter/struct.NqHandshake.html) - Classical, non-post-quantum Noise handshake
* [`PqHandshake`](https://docs.rs/clatter/latest/clatter/struct.PqHandshake.html) - Post-quantum Noise handshake
* [`DualLayerHandshake`](https://docs.rs/clatter/latest/clatter/struct.DualLayerHandshake.html) - Dual layer handshake, which combines two Noise handshakes and allows a naive hybrid encryption approach

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

    // All done! Use .send() and .receive() on the transport state to encrypt
    // and decrypt communication with the peer
    let n = alice.send(b"Hello from Alice", &mut buf_alice_send).unwrap();
    my_send_function(&buf_alice_send[..n]);   
}
```

### Selectable Features

Clatter allows user to pick the crypto primitives they wish to use via feature flags. Below is a table
of all the configurable features supported by Clatter:

| Feature flag              | Description                                       | Default   | Details                                       |
| ---                       | ---                                               | ---       | ---                                           |
| `use-25519`               | Enable X25519 DH                                  | yes       |                                               |
| `use-aes-gcm`             | Enable AES-GCM cipher                             | yes       |                                               |
| `use-chacha20poly1305`    | Enable ChaCha20-Poly1305 cipher                   | yes       |                                               |
| `use-sha`                 | Enable SHA-256 and SHA-512 hashing                | yes       |                                               |
| `use-blake2`              | Enable BLAKE2 hashing                             | yes       |                                               |
| `use-rust-crypto-kyber`   | Enable Kyber KEMs by [RustCrypto][RustCrypto]     | yes       |                                               |
| `use-pqclean-kyber`       | Enable Kyber KEMs by [PQClean][PQClean]           | yes       |                                               |
| `std`                     | Enable standard library support                   | no        | Enables `std` for supported dependencies      |
| `alloc`                   | Enable allocator support                          | no        |                                               |

[RustCrypto]: https://github.com/RustCrypto/KEMs
[PQClean]: https://github.com/rustpq/pqcrypto

## PQ? NQ? Why should I care?

This crate refers to classical Noise handshakes as NQ handshakes (non-post-quantum). But what does a
PQ (post-quantum) handshake actually mean?

**Key encapsulation mechanism** or **KEM** is a public-key encryption system that allows a sender
to securely transmit a short shared secret to a receiver using the receivers public key. This shared
secret can then be used as a basis for further *symmetric* encrypted communication.

Classical Noise uses **Diffie-Hellman** or **DH** key exchanges to establish a shared secret between
the parties. During a DH key exchange the shared secret is generated by both parties through mutual
computations on the publicly transmitted data - whereas **KEMs** are used to transmit the shared 
secret directly.

The motivation to use KEMs lies in the fact that there are KEM algorithms that are currently though to
be secure against cryptoanalytic attacks by quantum computers. The DH algorithms used by Noise rely on
the difficulty of mathematical problems that can be easily solved on a powerful quantum computer.
Such quantum computers do not exist yet, but the world is already shifting towards quantum-safe
cryptography.

[**Post Quantum Noise**](https://doi.org/10.1145/3548606.3560577) by Yawning Angel et al. introduced
methods and rules for substituting DH key exchanges from classical Noise with KEMs, while maintaining a
similar level of secrecy. This crate provides a safe Rust based implementation for the post-quantum
handshakes proposed by PQNoise - so that we can keep on benefitting from the clarity and formal
security guarantees of Noise even in post-quantum era.

## PQ Handshake Notation

Noise uses a simple pattern language for defining the handshake patterns. PQ patterns follow these same
rules, only substituting DH tokens with `ekem` and `skem` operations, which indicate sending of a ciphertext
that was encapsulated to the ephemeral/static key of the receiving party.

## Differences to PQNoise paper

* PQNoise presents the possibility to use different KEMs for ephemeral, initiator, and responder.
With Clatter the same KEM is used for both initiator and responder operations, while it is still 
possible to configure a separate KEM for ephemeral use.
* PQNoise presents *SEEC*, a method for improving RNG security in bad randomness settings. Clatter
does not currently implement *SEEC*.

## Verification

Caltter is verified by:

* Unit tests
* [Integration tests](tests/)
* [Fuzzing](fuzz/)
* [Cacophony](https://github.com/haskell-cryptography/cacophony) and [Snow](https://github.com/mcginty/snow) test vectors
    * Supported pre-made handshake patterns verified
    * Test harness in [vectors/](vectors/)