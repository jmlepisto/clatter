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
//! ⚠️ **Warning** ⚠️
//!
//! Clatter is a low-level crate that does not provide much guidance on the security aspects of the protocol(s)
//! you develop using it. Clatter itself is safe and sound but can easily be used in many unreliable ways.
//! Solid understanding of cryptography is required.
//!
//! From user perspective, everything in this crate is built around the available handshake types:
//!
//! * [`NqHandshake`] - Classical, non-post-quantum Noise handshake
//! * [`PqHandshake`] - Post-quantum Noise handshake
//! * [`HybridHandshake`] - *true hybrid* handshake which combines both NQ and PQ security in the same handshake messages
//! * [`HybridDualLayerHandshake`] - *outer-encrypts-inner* style piped handshake with cryptographic binding between the layers
//! * [`DualLayerHandshake`] - *outer-encrypts-inner* style piped handshake with fully independent layers
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
//! to encrypt and decrypt communication between the peers.
//!
//! ## Handshake Patterns
//!
//! Selected fundamental Noise and PQNoise patterns are available pre-made in the [`handshakepattern`] module.
//! Utilities in that module can also be used to craft additional handshake patterns.
//!
//! Pre-made hybrid patterns for the [`HybridHandshake`] type are also available. These patterns are constructed
//! by combining the classic Noise NQ patterns with PQNoise patterns in a way which preserves the relative ordering
//! of `DH`, `KEM` and key transmission operations.
//!
//! ## Crypto Vendors
//!
//! Currently Clatter has frozen the available selection of DH, Cipher and Hash algorithms, but users
//! of Clatter can select from multiple KEM vendors.
//!
//! Concrete implementations of the crypto algorithms are in the [`crypto`] module and it is even
//! possible to use custom implementations using the definitions in the [`traits`] module.
//!
//! ## Features
//!
//! To improve build times and produce more optimized binaries, Clatter can be heavily configured by
//! enabling and disabling crate features. Below is a listing of the available features:
//!
//! | Feature flag              | Description                                           | Default   | Details                                                           |
//! | ---                       | ---                                                   | ---       | ---                                                               |
//! | `use-25519`               | Enable X25519 DH                                      | yes       |                                                                   |
//! | `use-aes-gcm`             | Enable AES-GCM cipher                                 | yes       |                                                                   |
//! | `use-chacha20poly1305`    | Enable ChaCha20-Poly1305 cipher                       | yes       |                                                                   |
//! | `use-sha`                 | Enable SHA-256 and SHA-512 hashing                    | yes       |                                                                   |
//! | `use-blake2`              | Enable BLAKE2 hashing                                 | yes       |                                                                   |
//! | `use-rust-crypto-ml-kem`  | Enable ML-KEM (Kyber) KEMs by RustCrypto              | yes       |                                                                   |
//! | `use-pqclean-ml-kem`      | Enable ML-KEM (Kyber) KEMs by PQClean                 | yes       |                                                                   |
//! | `std`                     | Enable standard library support                       | yes       | Enables `std` for supported dependencies                          |
//! | `alloc`                   | Enable allocator support                              | yes       | Enables dynamically sized buffer types in [`crate::bytearray`]    |
//! | `getrandom`               | Enable automatic system RNG support via [`getrandom`] | yes       | Can be used without `std`                                         |
//!
//! ## Example
//!
//! Simplified example with the most straightforward (and unsecure) PQ handshake pattern and
//! no handshake payload data at all:
//!
//! ```rust
//! use clatter::crypto::cipher::ChaChaPoly;
//! use clatter::crypto::hash::Sha512;
//! use clatter::crypto::kem::pqclean_ml_kem::MlKem1024;
//! // We can mix and match KEMs from different vendors
//! use clatter::crypto::kem::rust_crypto_ml_kem::MlKem512;
//! use clatter::handshakepattern::noise_pqnn;
//! use clatter::traits::Handshaker;
//! use clatter::PqHandshake;
//!
//!
//! let mut alice = PqHandshake::<MlKem512, MlKem1024, ChaChaPoly, Sha512>::new(
//!     noise_pqnn(),
//!     &[],
//!     true,
//!     None,
//!     None,
//!     None,
//!     None,
//! )
//! .unwrap();
//!
//! let mut bob = PqHandshake::<MlKem512, MlKem1024, ChaChaPoly, Sha512>::new(
//!     noise_pqnn(),
//!     &[],
//!     false,
//!     None,
//!     None,
//!     None,
//!     None,
//! )
//! .unwrap();
//!
//! // Handshake message buffers
//! let mut buf_alice = [0u8; 4096];
//! let mut buf_bob = [0u8; 4096];
//!
//! // First handshake message from initiator to responder
//! // e -->
//! let n = alice.write_message(&[], &mut buf_alice).unwrap();
//! let _ = bob.read_message(&buf_alice[..n], &mut buf_bob).unwrap();
//!
//! // Second handshake message from responder to initiator
//! // <-- ekem
//! let n = bob.write_message(&[], &mut buf_bob).unwrap();
//! let _ = alice.read_message(&buf_bob[..n], &mut buf_alice).unwrap();
//!
//! // Handshake should be done
//! assert!(alice.is_finished() && bob.is_finished());
//!
//! // Finish handshakes and move to transport mode
//! let mut alice = alice.finalize().unwrap();
//! let mut bob = bob.finalize().unwrap();
//!
//! // Send a message from Alice to Bob
//! let msg = b"Hello from initiator";
//! let n = alice.send(msg, &mut buf_alice).unwrap();
//! let n = bob.receive(&buf_alice[..n], &mut buf_bob).unwrap();
//!
//! println!(
//!     "Bob received from Alice: {}",
//!     str::from_utf8(&buf_bob[..n]).unwrap()
//! );
//! ```
//!
//! ## `no_std` targets
//!
//! `std` feature is enabled by default. Disable default features and pick only the ones
//! you require when running on `no_std` targets.
//!
//! The only real platform service Clatter requires is the RNG. Clatter includes full
//! support for the [`getrandom`] crate (via the `getrandom` feature flag) which can be
//! enabled without `std` features. If your platform is not already supported by
//! `getrandom`, the most straightforward way to use Clatter is to create `getrandom`
//! bindings for your custom platform backend. Detailed instructions and examples can be
//! found in the [`getrandom`] crate documentation.
//!
//! If you do not add `getrandom` support, Clatter can still be used. In this case you
//! are restricted to the lower-level handshake core types, such as [`NqHandshakeCore`]
//! and [`PqHandshakeCore`] and must implement your own custom RNG provides that implements
//! the traits defined by [`crate::traits::Rng`].

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
pub use handshakestate::hybrid::{HybridHandshakeCore, HybridHandshakeParams};
pub use handshakestate::hybrid_dual_layer::HybridDualLayerHandshake;
pub use handshakestate::nq::NqHandshakeCore;
pub use handshakestate::pq::PqHandshakeCore;
pub use rand_core;
pub use traits::Handshaker;
use zeroize::{Zeroize, ZeroizeOnDrop};
#[cfg(feature = "getrandom")]
pub use {
    handshakestate::hybrid::HybridHandshake, handshakestate::nq::NqHandshake,
    handshakestate::pq::PqHandshake,
};

/// Concrete crypto implementations
pub mod crypto {

    /// Supported KEMs
    pub mod kem {
        #[cfg_attr(docsrs, doc(cfg(feature = "use-pqclean-ml-kem")))]
        #[cfg(feature = "use-pqclean-ml-kem")]
        pub use crate::crypto_impl::pqclean_ml_kem;
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

    /// Supported default random number generator(s)
    pub mod rng {
        #[cfg_attr(docsrs, doc(cfg(feature = "getrandom")))]
        #[cfg(feature = "getrandom")]
        pub use crate::crypto_impl::random::DefaultRng;
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

impl<P: Zeroize, S: Zeroize> KeyPair<P, S> {
    /// Initialize a keypair
    pub fn new(public: P, secret: S) -> KeyPair<P, S> {
        Self { public, secret }
    }
}
