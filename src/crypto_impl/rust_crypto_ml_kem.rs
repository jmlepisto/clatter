//! ML-KEM implementation by RustCrypto: https://github.com/RustCrypto/KEMs

use ml_kem::kem::{
    Decapsulate, DecapsulationKey, Encapsulate, EncapsulationKey, Generate, KeyExport,
};
use ml_kem::ml_kem_512::MlKem512 as MlKem512Params;
use ml_kem::ml_kem_768::MlKem768 as MlKem768Params;
use ml_kem::ml_kem_1024::MlKem1024 as MlKem1024Params;
use zeroize::Zeroize;

use crate::KeyPair;
use crate::bytearray::{ByteArray, SensitiveByteArray};
use crate::error::KemError;
use crate::traits::{CryptoComponent, Kem, Rng};

/// ML-KEM-512 KEM implementation
#[derive(Clone)]
pub struct MlKem512;
/// ML-KEM-768 KEM implementation
#[derive(Clone)]
pub struct MlKem768;
/// ML-KEM-1024 KEM implementation
#[derive(Clone)]
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
            type SecretKey = SensitiveByteArray<crate::bytearray::HeapArray<64>>;
            #[cfg(not(feature = "alloc"))]
            type SecretKey = SensitiveByteArray<[u8; 64]>;

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
                let dk = match <DecapsulationKey<$params> as Generate>::try_generate_from_rng(rng) {
                    Ok(dk) => dk,
                    Err(e) => match e {},
                };
                let ek = dk.encapsulation_key();
                let secret = dk.to_bytes();
                let public = ek.to_bytes();
                Ok(KeyPair {
                    public: Self::PubKey::from_slice(public.as_slice()),
                    secret: Self::SecretKey::from_slice(secret.as_slice()),
                })
            }

            fn encapsulate<R: Rng>(
                pk: &[u8],
                rng: &mut R,
            ) -> crate::error::KemResult<(Self::Ct, Self::Ss)> {
                let pk_arr: [u8; $pk] = pk.try_into().map_err(|_| KemError::Input)?;
                let ek_key = pk_arr.into();
                let ek = EncapsulationKey::<$params>::new(&ek_key).map_err(|_| KemError::Input)?;
                let (ct, mut ss) = ek.encapsulate_with_rng(rng);
                let res = (
                    ByteArray::from_slice(ct.as_slice()),
                    SensitiveByteArray::from_slice(ss.as_slice()),
                );
                ss.zeroize();
                Ok(res)
            }
            fn decapsulate(ct: &[u8], sk: &[u8]) -> crate::error::KemResult<Self::Ss> {
                let dk_seed: [u8; 64] = sk.try_into().map_err(|_| KemError::Input)?;
                let dk = DecapsulationKey::<$params>::from_seed(dk_seed.into());
                let ct_bytes: [u8; $ct] = ct.try_into().map_err(|_| KemError::Input)?;
                let ct_arr: ml_kem::kem::Ciphertext<$params> = ct_bytes.into();
                Ok(SensitiveByteArray::from_slice(
                    dk.decapsulate(&ct_arr).as_slice(),
                ))
            }
        }
    };
}

impl_ml_kem!(MlKem512, MlKem512Params, 1632, 800, 768);
impl_ml_kem!(MlKem768, MlKem768Params, 2400, 1184, 1088);
impl_ml_kem!(MlKem1024, MlKem1024Params, 3168, 1568, 1568);

#[cfg(all(test, any(feature = "getrandom", feature = "rand")))]
mod tests {
    use super::{MlKem512, MlKem768, MlKem1024};
    use crate::bytearray::ByteArray;
    use crate::crypto::rng::DefaultRng;
    use crate::traits::Kem;

    macro_rules! test_roundtrip {
        ($name:ident, $kem:ty) => {
            #[test]
            fn $name() {
                let mut rng = DefaultRng::default();
                let kp = <$kem>::genkey_rng(&mut rng).unwrap();
                let (ct, ss1) = <$kem>::encapsulate(kp.public.as_slice(), &mut rng).unwrap();
                let ss2 = <$kem>::decapsulate(ct.as_slice(), kp.secret.as_slice()).unwrap();
                assert_eq!(ss1.as_slice(), ss2.as_slice());
            }
        };
    }

    test_roundtrip!(roundtrip_ml_kem512, MlKem512);
    test_roundtrip!(roundtrip_ml_kem768, MlKem768);
    test_roundtrip!(roundtrip_ml_kem1024, MlKem1024);
}
