//! Kyber implementation by Argyle-Software: https://github.com/Argyle-Software/kyber
//!
//! The implementation crate is designed so that only one Kyber security level variant can
//! be active at a time.

use pqc_kyber::{
    decapsulate, encapsulate, keypair, KYBER_CIPHERTEXTBYTES, KYBER_PUBLICKEYBYTES,
    KYBER_SECRETKEYBYTES, KYBER_SSBYTES,
};
use zeroize::Zeroize;

use crate::bytearray::SensitiveByteArray;
use crate::error::KemError;
use crate::traits::{CryptoComponent, Kem};

/// Kyber512 KEM implementation
#[cfg(feature = "use-argyle-kyber512")]
pub struct Kyber512;
/// Kyber768 KEM implementation
#[cfg(feature = "use-argyle-kyber768")]
pub struct Kyber768;
/// Kyber1024 KEM implementation
#[cfg(feature = "use-argyle-kyber1024")]
pub struct Kyber1024;

#[cfg(feature = "use-argyle-kyber512")]
impl CryptoComponent for Kyber512 {
    fn name() -> &'static str {
        "Kyber512"
    }
}

#[cfg(feature = "use-argyle-kyber768")]
impl CryptoComponent for Kyber768 {
    fn name() -> &'static str {
        "Kyber768"
    }
}

#[cfg(feature = "use-argyle-kyber1024")]
impl CryptoComponent for Kyber1024 {
    fn name() -> &'static str {
        "Kyber1024"
    }
}

macro_rules! impl_kyber {
    ($kyber:ty) => {
        impl Kem for $kyber {
            type SecretKey = SensitiveByteArray<[u8; KYBER_SECRETKEYBYTES]>;
            type PubKey = [u8; KYBER_PUBLICKEYBYTES];
            type Ct = [u8; KYBER_CIPHERTEXTBYTES];
            type Ss = SensitiveByteArray<[u8; KYBER_SSBYTES]>;

            fn genkey<R: rand_core::RngCore + rand_core::CryptoRng>(
                rng: &mut R,
            ) -> crate::error::KemResult<crate::KeyPair<Self::PubKey, Self::SecretKey>> {
                let keys = keypair(rng).map_err(|_| KemError::KeyGeneration)?;

                Ok(crate::KeyPair {
                    public: keys.public,
                    secret: Self::SecretKey::new(keys.secret),
                })
            }

            fn encapsulate<R: rand_core::RngCore + rand_core::CryptoRng>(
                pk: &[u8],
                rng: &mut R,
            ) -> crate::error::KemResult<(Self::Ct, Self::Ss)> {
                let (ct, mut ss) = encapsulate(pk, rng).map_err(|_| KemError::Encapsulation)?;
                let res = Ok((ct, SensitiveByteArray::new(ss)));
                ss.zeroize();
                res
            }

            fn decapsulate(ct: &[u8], sk: &[u8]) -> crate::error::KemResult<Self::Ss> {
                Ok(SensitiveByteArray::new(
                    decapsulate(ct, sk).map_err(|_| KemError::Decapsulation)?,
                ))
            }
        }
    };
}

#[cfg(feature = "use-argyle-kyber512")]
impl_kyber!(Kyber512);
#[cfg(feature = "use-argyle-kyber768")]
impl_kyber!(Kyber768);
#[cfg(feature = "use-argyle-kyber1024")]
impl_kyber!(Kyber1024);
