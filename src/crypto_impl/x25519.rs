use x25519_dalek::{PublicKey, StaticSecret};

use crate::bytearray::{ByteArray, SensitiveByteArray};
use crate::traits::{CryptoComponent, Dh, ExtractPubKey};

/// X25519 DH implementation
pub struct X25519;

impl CryptoComponent for X25519 {
    fn name() -> &'static str {
        "25519"
    }
}

impl<S, P> ExtractPubKey<S, P> for X25519
where
    S: ByteArray,
    P: ByteArray,
{
    fn pubkey(secret: &S) -> P {
        let mut s = [0; 32];
        s.copy_from_slice(secret.as_slice());
        let s = StaticSecret::from(s);
        P::from_slice(PublicKey::from(&s).as_bytes())
    }
}

impl Dh for X25519 {
    type Key = SensitiveByteArray<[u8; 32]>;
    type PubKey = [u8; 32];
    type Output = SensitiveByteArray<[u8; 32]>;

    fn genkey<R: rand_core::RngCore + rand_core::CryptoRng>(
        rng: &mut R,
    ) -> crate::error::DhResult<Self::Key> {
        Ok(SensitiveByteArray::from_slice(
            StaticSecret::random_from_rng(rng).as_bytes(),
        ))
    }

    fn dh(k: &Self::Key, pk: &Self::PubKey) -> crate::error::DhResult<Self::Output> {
        let k = StaticSecret::from(**k);
        let pk = PublicKey::from(*pk);
        Ok(Self::Output::from_slice(k.diffie_hellman(&pk).as_bytes()))
    }
}
