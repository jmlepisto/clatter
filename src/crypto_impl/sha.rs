use sha2::Digest;

use crate::traits::{CryptoComponent, Hash};

/// SHA-512 hasher implementation
#[derive(Default)]
pub struct Sha512(sha2::Sha512);

impl CryptoComponent for Sha512 {
    fn name() -> &'static str {
        "SHA512"
    }
}

impl Hash for Sha512 {
    type Block = [u8; 128];
    type Output = [u8; 64];

    fn input(&mut self, data: &[u8]) {
        self.0.update(data);
    }

    fn result(self) -> Self::Output {
        self.0.finalize().into()
    }
}

/// SHA-256 hasher implementation
#[derive(Default)]
pub struct Sha256(sha2::Sha256);

impl CryptoComponent for Sha256 {
    fn name() -> &'static str {
        "SHA256"
    }
}

impl Hash for Sha256 {
    type Block = [u8; 64];
    type Output = [u8; 32];

    fn input(&mut self, data: &[u8]) {
        self.0.update(data);
    }

    fn result(self) -> Self::Output {
        self.0.finalize().into()
    }
}
