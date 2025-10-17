use x25519_dalek::{PublicKey, StaticSecret};

use crate::bytearray::{ByteArray, SensitiveByteArray};
use crate::traits::{CryptoComponent, Dh, Rng};
use crate::KeyPair;

/// X25519 DH implementation
#[derive(Clone)]
pub struct X25519;

impl CryptoComponent for X25519 {
    fn name() -> &'static str {
        "25519"
    }
}

impl Dh for X25519 {
    type PrivateKey = SensitiveByteArray<[u8; 32]>;
    type PubKey = [u8; 32];
    type Output = SensitiveByteArray<[u8; 32]>;

    fn genkey_rng<R: Rng>(
        rng: &mut R,
    ) -> crate::error::DhResult<KeyPair<Self::PubKey, Self::PrivateKey>> {
        let s = StaticSecret::random_from_rng(rng);
        let p = PublicKey::from(&s);

        Ok(KeyPair {
            public: Self::PubKey::from_slice(p.as_bytes()),
            secret: Self::PrivateKey::from_slice(s.as_bytes()),
        })
    }

    fn pubkey(k: &Self::PrivateKey) -> Self::PubKey {
        let public = PublicKey::from(&StaticSecret::from(**k));
        Self::PubKey::from_slice(public.as_bytes())
    }

    fn dh(k: &Self::PrivateKey, pk: &Self::PubKey) -> crate::error::DhResult<Self::Output> {
        let k = StaticSecret::from(**k);
        let pk = PublicKey::from(*pk);
        Ok(Self::Output::from_slice(k.diffie_hellman(&pk).as_bytes()))
    }
}
