use x25519_dalek::{PublicKey, StaticSecret};

use crate::bytearray::{ByteArray, SensitiveByteArray};
use crate::traits::{CryptoComponent, Dh};
use crate::KeyPair;

/// X25519 DH implementation
pub struct X25519;

impl CryptoComponent for X25519 {
    fn name() -> &'static str {
        "25519"
    }
}

impl Dh for X25519 {
    type Key = SensitiveByteArray<[u8; 32]>;
    type PubKey = [u8; 32];
    type Output = SensitiveByteArray<[u8; 32]>;

    fn genkey<R: rand_core::RngCore + rand_core::CryptoRng>(
        rng: &mut R,
    ) -> crate::error::DhResult<KeyPair<Self::PubKey, Self::Key>> {
        let s = StaticSecret::random_from_rng(rng);
        let p = PublicKey::from(&s);

        Ok(KeyPair {
            public: Self::PubKey::from_slice(p.as_bytes()),
            secret: Self::Key::from_slice(s.as_bytes()),
        })
    }

    fn dh(k: &Self::Key, pk: &Self::PubKey) -> crate::error::DhResult<Self::Output> {
        let k = StaticSecret::from(**k);
        let pk = PublicKey::from(*pk);
        Ok(Self::Output::from_slice(k.diffie_hellman(&pk).as_bytes()))
    }
}
