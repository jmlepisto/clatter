use sha2::Digest;

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

impl Hash for Blake2b {
    type Block = [u8; 128];
    type Output = [u8; 64];

    fn input(&mut self, data: &[u8]) {
        self.0.update(data);
    }

    fn result(self) -> Self::Output {
        Self::Output::from(self.0.finalize())
    }
}

impl Hash for Blake2s {
    type Block = [u8; 64];
    type Output = [u8; 32];

    fn input(&mut self, data: &[u8]) {
        self.0.update(data);
    }

    fn result(self) -> Self::Output {
        Self::Output::from(self.0.finalize())
    }
}
