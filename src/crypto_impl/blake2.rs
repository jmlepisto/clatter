use blake2::Digest;

use crate::bytearray::{ByteArray, SensitiveByteArray};
use crate::traits::{CryptoComponent, Hash};

/// BLAKE2b hash implementation
#[derive(Default)]
pub struct Blake2b(blake2::Blake2b512);

/// BLAKE2s hash implementation
#[derive(Default)]
pub struct Blake2s(blake2::Blake2s256);

impl CryptoComponent for Blake2b {
    fn name() -> &'static str {
        "BLAKE2b"
    }
}

impl CryptoComponent for Blake2s {
    fn name() -> &'static str {
        "BLAKE2s"
    }
}

macro_rules! impl_blake {
    ($blake:ty, $block:literal, $out:literal) => {
        impl Hash for $blake {
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

impl_blake!(Blake2b, 128, 64);
impl_blake!(Blake2s, 64, 32);
