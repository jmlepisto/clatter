#![cfg_attr(not(feature = "std"), no_std)]
#![warn(missing_docs)]
#![warn(clippy::missing_panics_doc)]
// only enables the `doc_cfg` feature when
// the `docsrs` configuration attribute is defined
#![cfg_attr(docsrs, feature(doc_cfg))]
//! # Clatter 🔊
//!
//! `no_std` compatible, pure Rust implementation of the [**Noise framework**](https://noiseprotocol.org/noise.html)
//! with support for [**Post Quantum (PQ) extensions**](https://doi.org/10.1145/3548606.3560577) as presented by
//! Yawning Angel, Benjamin Dowling, Andreas Hülsing, Peter Schwabe, and Fiona Johanna Weber.
//!
//! From user perspective, everything in this crate is built around three types:
//!
//! * [`NqHandshake`] - Classical, non-post-quantum Noise handshake
//! * [`PqHandshake`] - Post-quantum Noise handshake
//! * [`DualLayerHandshake`] - Dual layer handshake, which combines two Noise handshakes
//!
//! Users will pick and instantiate the desired handshake state machine with the crypto primitives
//! and [`handshakepattern::HandshakePattern`] they wish to use and complete the handshake using the
//! methods provided by the common [`Handshaker`] trait:
//!
//! * [`Handshaker::write_message`] - Write next handshake message
//! * [`Handshaker::read_message`]  - Read next handshake message
//! * [`Handshaker::is_finished`]   - Is the handshake ready?
//! * [`Handshaker::finalize`]      - Move to transport state
//!
//! Handshake messages are exchanged by the peers until the handshake is completed.
//! After completion, [`Handshaker::finalize`] is called and the handshake state machine
//! is consumed into a [`transportstate::TransportState`] instance, which can be used
//! to decrypt and encrypt communication between the peers.
//!
//! ## Handshake Patterns
//!
//! Selected fundamental Noise and PQNoise patterns are available pre-made in the [`handshakepattern`] module.
//! Utilities in that module can also be used to craft additional handshake patterns.
//!
//! ## Crypto Vendors
//!
//! Currently Clatter has frozen the vendor selection for DH, Cipher and Hash algorithms, but users
//! can select from multiple KEM vendors.
//!
//! Concrete implementations of the crypto algorithms are in the [`crypto`] module and it is even
//! possible to use custom implementations using the definitions in the [`traits`] module.
//!
//! ## Features
//!
//! To improve build times and produce more optimized binaries, Clatter can be heavily configured by
//! enabling and disabling crate features. Below is a listing of the available features:
//!
//! | Feature flag              | Description                               | Default   | Details                                   |
//! | ---                       | ---                                       | ---       | ---                                       |
//! | `use-25519`               | Enable X25519 DH                          | yes       |                                           |
//! | `use-aes-gcm`             | Enable AES-GCM cipher                     | yes       |                                           |
//! | `use-chacha20poly1305`    | Enable ChaCha20-Poly1305 cipher           | yes       |                                           |
//! | `use-sha`                 | Enable SHA-256 and SHA-512 hashing        | yes       |                                           |
//! | `use-blake2`              | Enable BLAKE2 hashing                     | yes       |                                           |
//! | `use-rust-crypto-ml-kem`  | Enable ML-KEM (Kyber) KEMs by RustCrypto  | yes       |                                           |
//! | `use-pqclean-kyber`       | Enable Kyber KEMs by PQClean              | yes       |                                           |
//! | `std`                     | Enable standard library support           | no        | Enables `std` for supported dependencies  |
//! | `alloc`                   | Enable allocator support                  | no        |                                           |
//!
//! ## Example
//!
//! Simplified example with the most straightforward (and unsecure) PQ handshake pattern and
//! no handshake payload data at all:
//!
//! ```no_run
//! use clatter::crypto::cipher::ChaChaPoly;
//! use clatter::crypto::hash::Sha512;
//! use clatter::crypto::kem::rust_crypto_ml_kem::MlKem512;
//! use clatter::handshakepattern::noise_pqnn;
//! use clatter::traits::Handshaker;
//! use clatter::PqHandshake;
//!
//! let mut rng_alice = rand::thread_rng();
//!
//! // Instantiate initiator handshake
//! let mut alice = PqHandshake::<MlKem512, MlKem512, ChaChaPoly, Sha512, _>::new(
//!     noise_pqnn(),   // Handshake pattern
//!     &[],            // Prologue data
//!     true,           // Are we the initiator
//!     None,           // Pre-shared keys..
//!     None,           // ..
//!     None,           // ..
//!     None,           // ..
//!     &mut rng_alice, // RNG instance
//! ).unwrap();
//!
//! let mut buf_alice_send = [0u8; 4096];
//!
//! // Send and receive handshake messages until the handshake is completed
//! loop {
//!     if alice.is_write_turn() {
//!         // Write handshake message to buf_alice_send
//!         let n = alice.write_message(&[], &mut buf_alice_send).unwrap();
//!         // --> Deliver buf_alice_send[..n] to peer
//!     } else {
//!         // <-- Receive message from peer to &buf_alice_receive
//!         let buf_alice_receive = [0u8];
//!         // Process received handshake message
//!         let _ = alice.read_message(&buf_alice_receive, &mut[]).unwrap();
//!     }
//!
//!     if alice.is_finished() {
//!         break;
//!     }
//! }
//!
//! // Move to transport state
//! let mut alice = alice.finalize().unwrap();
//!
//! // All done! Use .send() and .receive() on the transport state to encrypt
//! // and decrypt communication with the peer
//! let n = alice.send(b"Hello from Alice", &mut buf_alice_send).unwrap();
//! // --> Send &buf_alice_send[..n]) to peer
//! ```

#[cfg(feature = "alloc")]
extern crate alloc;

pub mod bytearray;
pub mod cipherstate;
pub mod constants;
mod crypto_impl;
pub mod error;
pub mod handshakepattern;
mod handshakestate;
mod symmetricstate;
pub mod traits;
pub mod transportstate;

pub use handshakestate::dual_layer::DualLayerHandshake;
pub use handshakestate::nq::NqHandshake;
pub use handshakestate::pq::PqHandshake;
pub use traits::Handshaker;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Concrete crypto implementations
pub mod crypto {

    /// Supported KEMs
    pub mod kem {
        #[cfg_attr(docsrs, doc(cfg(feature = "use-pqclean-kyber")))]
        #[cfg(feature = "use-pqclean-kyber")]
        pub use crate::crypto_impl::pqclean_kyber;
        #[cfg_attr(docsrs, doc(cfg(feature = "use-rust-crypto-ml-kem")))]
        #[cfg(feature = "use-rust-crypto-ml-kem")]
        pub use crate::crypto_impl::rust_crypto_ml_kem;
    }

    /// Supported DH algorithms
    pub mod dh {
        #[cfg_attr(docsrs, doc(cfg(feature = "use-25519")))]
        #[cfg(feature = "use-25519")]
        pub use crate::crypto_impl::x25519::X25519;
    }

    /// Supported cipher algorithms
    pub mod cipher {
        #[cfg_attr(docsrs, doc(cfg(feature = "use-aes-gcm")))]
        #[cfg(feature = "use-aes-gcm")]
        pub use crate::crypto_impl::aes::AesGcm;
        #[cfg_attr(docsrs, doc(cfg(feature = "use-chacha20poly1305")))]
        #[cfg(feature = "use-chacha20poly1305")]
        pub use crate::crypto_impl::chacha::ChaChaPoly;
    }

    /// Supported hash algorithms
    pub mod hash {
        #[cfg_attr(docsrs, doc(cfg(feature = "use-blake2")))]
        #[cfg(feature = "use-blake2")]
        pub use crate::crypto_impl::blake2::{Blake2b, Blake2s};
        #[cfg_attr(docsrs, doc(cfg(feature = "use-sha")))]
        #[cfg(feature = "use-sha")]
        pub use crate::crypto_impl::sha::{Sha256, Sha512};
    }
}

/// A zeroize-on-drop container for keys
#[derive(ZeroizeOnDrop, Clone)]
pub struct KeyPair<P: Zeroize, S: Zeroize> {
    /// Public key
    pub public: P,
    /// Secret (private) key
    pub secret: S,
}
