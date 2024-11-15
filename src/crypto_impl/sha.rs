use sha2::Digest;

use crate::bytearray::{ByteArray, SensitiveByteArray};
use crate::traits::{CryptoComponent, Hash};

/// SHA-512 hasher implementation
#[derive(Default)]
pub struct Sha512(sha2::Sha512);

/// SHA-256 hasher implementation
#[derive(Default)]
pub struct Sha256(sha2::Sha256);

impl CryptoComponent for Sha512 {
    fn name() -> &'static str {
        "SHA512"
    }
}

impl CryptoComponent for Sha256 {
    fn name() -> &'static str {
        "SHA256"
    }
}

macro_rules! impl_sha {
    ($sha:ty, $block:literal, $out:literal) => {
        impl Hash for $sha {
            type Block = [u8; $block];
            type Output = SensitiveByteArray<[u8; $out]>;

            fn input(&mut self, data: &[u8]) {
                self.0.update(data);
            }

            fn result(self) -> Self::Output {
                Self::Output::from_slice(&self.0.finalize())
            }
        }
    };
}

impl_sha!(Sha256, 64, 32);
impl_sha!(Sha512, 128, 64);
