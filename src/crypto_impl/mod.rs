//! Concrete implementations of crypto primitives

// Hashes
#[cfg(feature = "use-blake2")]
pub mod blake2;
#[cfg(feature = "use-sha")]
pub mod sha;

// KEMs
#[cfg(feature = "use-pqclean-ml-kem")]
pub mod pqclean_ml_kem;

#[cfg(feature = "use-rust-crypto-ml-kem")]
pub mod rust_crypto_ml_kem;

// Ciphers
#[cfg(feature = "use-aes-gcm")]
pub mod aes;
#[cfg(feature = "use-chacha20poly1305")]
pub mod chacha;

// DHs
#[cfg(feature = "use-25519")]
pub mod x25519;

// RNGs
#[cfg(feature = "getrandom")]
pub mod random;
