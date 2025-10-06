//! ML-KEM implementation by RustCrypto: https://github.com/RustCrypto/KEMs

use ml_kem::kem::{Decapsulate, DecapsulationKey, Encapsulate, EncapsulationKey};
use ml_kem::{EncodedSizeUser, KemCore, MlKem1024Params, MlKem512Params, MlKem768Params};
use zeroize::Zeroize;

use crate::bytearray::{ByteArray, SensitiveByteArray};
use crate::error::KemError;
use crate::traits::{CryptoComponent, Kem, Rng};
use crate::KeyPair;

/// ML-KEM-512 KEM implementation
pub struct MlKem512;
/// ML-KEM-768 KEM implementation
pub struct MlKem768;
/// ML-KEM-1024 KEM implementation
pub struct MlKem1024;

impl CryptoComponent for MlKem512 {
    fn name() -> &'static str {
        "MLKEM512"
    }
}

impl CryptoComponent for MlKem768 {
    fn name() -> &'static str {
        "MLKEM768"
    }
}

impl CryptoComponent for MlKem1024 {
    fn name() -> &'static str {
        "MLKEM1024"
    }
}

macro_rules! impl_ml_kem {
    ($ml_kem:ty, $params:ty, $sk:expr, $pk:expr, $ct:expr) => {
        impl Kem for $ml_kem {
            #[cfg(feature = "alloc")]
            type SecretKey = SensitiveByteArray<crate::bytearray::HeapArray<$sk>>;
            #[cfg(not(feature = "alloc"))]
            type SecretKey = SensitiveByteArray<[u8; $sk]>;

            #[cfg(feature = "alloc")]
            type PubKey = crate::bytearray::HeapArray<$pk>;
            #[cfg(not(feature = "alloc"))]
            type PubKey = [u8; $pk];

            #[cfg(feature = "alloc")]
            type Ct = crate::bytearray::HeapArray<$ct>;
            #[cfg(not(feature = "alloc"))]
            type Ct = [u8; $ct];

            type Ss = SensitiveByteArray<[u8; 32]>;

            fn genkey_rng<R: Rng>(
                rng: &mut R,
            ) -> crate::error::KemResult<crate::KeyPair<Self::PubKey, Self::SecretKey>> {
                let (dk, ek) = ml_kem::kem::Kem::<$params>::generate(rng);
                Ok(KeyPair {
                    public: Self::PubKey::from_slice(&ek.as_bytes()),
                    secret: Self::SecretKey::from_slice(&dk.as_bytes()),
                })
            }

            fn encapsulate<R: Rng>(
                pk: &[u8],
                rng: &mut R,
            ) -> crate::error::KemResult<(Self::Ct, Self::Ss)> {
                let ek = EncapsulationKey::<$params>::from_bytes(
                    pk.try_into().map_err(|_| KemError::Input)?,
                );
                let (ct, mut ss) = ek.encapsulate(rng).map_err(|_| KemError::Encapsulation)?;
                let res = (
                    ByteArray::from_slice(ct.as_slice()),
                    SensitiveByteArray::from_slice(ss.as_slice()),
                );
                ss.zeroize();
                Ok(res)
            }

            fn decapsulate(ct: &[u8], sk: &[u8]) -> crate::error::KemResult<Self::Ss> {
                let dk = DecapsulationKey::<$params>::from_bytes(
                    sk.try_into().map_err(|_| KemError::Input)?,
                );
                let ct_arr = ct.try_into().map_err(|_| KemError::Input)?;
                Ok(SensitiveByteArray::from_slice(
                    dk.decapsulate(ct_arr)
                        .map_err(|_| KemError::Decapsulation)?
                        .as_slice(),
                ))
            }
        }
    };
}

impl_ml_kem!(MlKem512, MlKem512Params, 1632, 800, 768);
impl_ml_kem!(MlKem768, MlKem768Params, 2400, 1184, 1088);
impl_ml_kem!(MlKem1024, MlKem1024Params, 3168, 1568, 1568);
