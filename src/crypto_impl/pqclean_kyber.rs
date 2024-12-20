//! Kyber implementation by PQClean: https://github.com/pqclean/pqclean/,
//! bindings generated by https://github.com/rustpq/pqcrypto.

use pqcrypto_kyber::{kyber1024, kyber512, kyber768};
use pqcrypto_traits::kem::{Ciphertext, PublicKey, SecretKey, SharedSecret};

use crate::bytearray::{ByteArray, SensitiveByteArray};
use crate::error::KemError;
use crate::traits::{CryptoComponent, Kem};
use crate::KeyPair;

/// Kyber512 KEM implementation
pub struct Kyber512;
/// Kyber768 KEM implementation
pub struct Kyber768;
/// Kyber1024 KEM implementation
pub struct Kyber1024;

impl CryptoComponent for Kyber512 {
    fn name() -> &'static str {
        "Kyber512"
    }
}

impl CryptoComponent for Kyber768 {
    fn name() -> &'static str {
        "Kyber768"
    }
}

impl CryptoComponent for Kyber1024 {
    fn name() -> &'static str {
        "Kyber1024"
    }
}

macro_rules! impl_kyber {
    ($kyber:ty, $module:ident) => {
        impl Kem for $kyber {
            #[cfg(feature = "alloc")]
            type SecretKey =
                SensitiveByteArray<crate::bytearray::HeapArray<{ $module::secret_key_bytes() }>>;
            #[cfg(not(feature = "alloc"))]
            type SecretKey = SensitiveByteArray<[u8; $module::secret_key_bytes()]>;

            #[cfg(feature = "alloc")]
            type PubKey = crate::bytearray::HeapArray<{ $module::public_key_bytes() }>;
            #[cfg(not(feature = "alloc"))]
            type PubKey = [u8; $module::public_key_bytes()];

            #[cfg(feature = "alloc")]
            type Ct = crate::bytearray::HeapArray<{ $module::ciphertext_bytes() }>;
            #[cfg(not(feature = "alloc"))]
            type Ct = [u8; $module::ciphertext_bytes()];

            type Ss = SensitiveByteArray<[u8; $module::shared_secret_bytes()]>;

            fn genkey<R: rand_core::RngCore + rand_core::CryptoRng>(
                _rng: &mut R,
            ) -> crate::error::KemResult<crate::KeyPair<Self::PubKey, Self::SecretKey>> {
                // PQClean uses their own RNG
                let (pk, sk) = $module::keypair();
                Ok(KeyPair {
                    public: ByteArray::from_slice(pk.as_bytes()),
                    secret: SensitiveByteArray::from_slice(sk.as_bytes()),
                })
            }

            fn encapsulate<R: rand_core::RngCore + rand_core::CryptoRng>(
                pk: &[u8],
                _rng: &mut R,
            ) -> crate::error::KemResult<(Self::Ct, Self::Ss)> {
                let pk = $module::PublicKey::from_bytes(pk).map_err(|_| KemError::Input)?;
                // PQClean uses their own RNG
                let (ss, ct) = $module::encapsulate(&pk);
                Ok((
                    Self::Ct::from_slice(ct.as_bytes()),
                    Self::Ss::from_slice(ss.as_bytes()),
                ))
            }

            fn decapsulate(ct: &[u8], sk: &[u8]) -> crate::error::KemResult<Self::Ss> {
                let sk = $module::SecretKey::from_bytes(sk).map_err(|_| KemError::Input)?;
                let ct = $module::Ciphertext::from_bytes(ct).map_err(|_| KemError::Input)?;
                let ss = $module::decapsulate(&ct, &sk);
                Ok(Self::Ss::from_slice(&ss.as_bytes()))
            }
        }
    };
}

impl_kyber!(Kyber512, kyber512);
impl_kyber!(Kyber768, kyber768);
impl_kyber!(Kyber1024, kyber1024);
