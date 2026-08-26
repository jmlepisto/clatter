//! HQC-KEM implementation by RustCrypto: https://github.com/RustCrypto/KEMs

use hqc_kem::{
    hqc128, hqc192, hqc256, Ciphertext as RustCryptoCiphertext,
    DecapsulationKey as RustCryptoDecapsulationKey, EncapsulationKey as RustCryptoEncapsulationKey,
    Hqc128Params, Hqc192Params, Hqc256Params, HqcKem as RustCryptoHqcKem,
};
use zeroize::Zeroize;

use crate::bytearray::{ByteArray, SensitiveByteArray};
use crate::error::KemError;
use crate::traits::{CryptoComponent, Kem, Rng};
use crate::KeyPair;

/// HQC-128 KEM implementation
/// 
/// ⚠️ Hazmat: HQC standard is not yet finalized.
#[derive(Clone)]
pub struct Hqc128;
/// HQC-192 KEM implementation
/// 
/// ⚠️ Hazmat: HQC standard is not yet finalized.
#[derive(Clone)]
pub struct Hqc192;
/// HQC-256 KEM implementation
/// 
/// ⚠️ Hazmat: HQC standard is not yet finalized.
#[derive(Clone)]
pub struct Hqc256;

impl CryptoComponent for Hqc128 {
    fn name() -> &'static str {
        "HQC128"
    }
}

impl CryptoComponent for Hqc192 {
    fn name() -> &'static str {
        "HQC192"
    }
}

impl CryptoComponent for Hqc256 {
    fn name() -> &'static str {
        "HQC256"
    }
}

macro_rules! impl_hqc_kem {
    ($hqc_kem:ty, $params:ty, $module:ident, $msg_len:expr) => {
        impl Kem for $hqc_kem {
            #[cfg(feature = "alloc")]
            type SecretKey =
                SensitiveByteArray<crate::bytearray::HeapArray<{ $module::SECRET_KEY_SIZE }>>;
            #[cfg(not(feature = "alloc"))]
            type SecretKey = SensitiveByteArray<[u8; { $module::SECRET_KEY_SIZE }]>;

            #[cfg(feature = "alloc")]
            type PubKey = crate::bytearray::HeapArray<{ $module::PUBLIC_KEY_SIZE }>;
            #[cfg(not(feature = "alloc"))]
            type PubKey = [u8; { $module::PUBLIC_KEY_SIZE }];

            #[cfg(feature = "alloc")]
            type Ct = crate::bytearray::HeapArray<{ $module::CIPHERTEXT_SIZE }>;
            #[cfg(not(feature = "alloc"))]
            type Ct = [u8; { $module::CIPHERTEXT_SIZE }];

            type Ss = SensitiveByteArray<[u8; { $module::SHARED_SECRET_SIZE }]>;

            fn genkey_rng<R: Rng>(
                rng: &mut R,
            ) -> crate::error::KemResult<KeyPair<Self::PubKey, Self::SecretKey>> {
                let mut seed = [0u8; 32];
                rng.fill_bytes(&mut seed);
                let (ek, dk) = RustCryptoHqcKem::<$params>::generate_key_deterministic(&seed);
                let res = KeyPair {
                    public: Self::PubKey::from_slice(ek.as_ref()),
                    secret: Self::SecretKey::from_slice(dk.as_ref()),
                };
                seed.zeroize();
                Ok(res)
            }

            fn encapsulate<R: Rng>(
                pk: &[u8],
                rng: &mut R,
            ) -> crate::error::KemResult<(Self::Ct, Self::Ss)> {
                let ek = RustCryptoEncapsulationKey::<$params>::try_from(pk)
                    .map_err(|_| KemError::Input)?;
                let mut message = [0u8; $msg_len];
                let mut salt = [0u8; 16];
                rng.fill_bytes(&mut message);
                rng.fill_bytes(&mut salt);
                let (ct, mut ss) = ek
                    .encapsulate_deterministic(&message, &salt)
                    .map_err(|_| KemError::Encapsulation)?;
                let res = (
                    ByteArray::from_slice(ct.as_ref()),
                    SensitiveByteArray::from_slice(ss.as_ref()),
                );
                message.zeroize();
                salt.zeroize();
                ss.zeroize();
                Ok(res)
            }

            fn decapsulate(ct: &[u8], sk: &[u8]) -> crate::error::KemResult<Self::Ss> {
                let ct =
                    RustCryptoCiphertext::<$params>::try_from(ct).map_err(|_| KemError::Input)?;
                let dk = RustCryptoDecapsulationKey::<$params>::try_from(sk)
                    .map_err(|_| KemError::Input)?;
                let mut ss = dk.decapsulate(&ct);
                let res = SensitiveByteArray::from_slice(ss.as_ref());
                ss.zeroize();
                Ok(res)
            }
        }
    };
}

impl_hqc_kem!(Hqc128, Hqc128Params, hqc128, 16);
impl_hqc_kem!(Hqc192, Hqc192Params, hqc192, 24);
impl_hqc_kem!(Hqc256, Hqc256Params, hqc256, 32);

#[cfg(test)]
mod tests {
    use super::{Hqc128, Hqc192, Hqc256};
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

    test_roundtrip!(roundtrip_hqc128, Hqc128);
    test_roundtrip!(roundtrip_hqc192, Hqc192);
    test_roundtrip!(roundtrip_hqc256, Hqc256);
}
