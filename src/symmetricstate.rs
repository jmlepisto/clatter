//! Symmetric state implementation
//!
//! [`SymmetricState`] is used during the handshake process to establish a cryptographic
//! state for deriving transport keys once the handshake is completed.

use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::bytearray::ByteArray;
use crate::cipherstate::{CipherState, CipherStates};
use crate::error::CipherResult;
use crate::traits::{Cipher, Hash};

/// Symmetric state used during handshakes to establish session hash and chaining key
#[derive(ZeroizeOnDrop, Zeroize)]
pub struct SymmetricState<C, H>
where
    C: Cipher,
    H: Hash,
{
    cipherstate: Option<CipherState<C>>,
    h: H::Output,
    ck: H::Output,
}

impl<C, H> SymmetricState<C, H>
where
    C: Cipher,
    H: Hash,
{
    /// Initialize new symmetric state for the given Noise protocol type
    pub(crate) fn new(noise_pattern_name: &str) -> Self {
        let pattern_bytes = noise_pattern_name.as_bytes();
        let mut h = H::Output::new_zero();

        // "If protocol_name is less than or equal to HASHLEN bytes in length, sets h equal to protocol_name
        // with zero bytes appended to make HASHLEN bytes. Otherwise sets h = HASH(protocol_name)"
        if pattern_bytes.len() <= H::hash_len() {
            h.as_mut()[..pattern_bytes.len()].copy_from_slice(pattern_bytes);
        } else {
            h = H::hash(pattern_bytes);
        }
        Self {
            cipherstate: None,
            ck: h.clone(),
            h,
        }
    }

    /// # Protocol
    /// ```text
    /// Sets h = HASH(h || data)
    /// ```
    pub(crate) fn mix_hash(&mut self, bytes: &[u8]) {
        let mut h = H::default();
        h.input(self.h.as_slice());
        h.input(bytes);
        self.h = h.result();
    }

    /// # Protocol
    /// ```text
    /// * Sets ck, temp_k = HKDF(ck, input_key_material, 2).
    /// * If HASHLEN is 64, then truncates temp_k to 32 bytes.
    /// * Calls InitializeKey(temp_k).
    /// ```
    pub(crate) fn mix_key(&mut self, input_key_material: &[u8]) {
        let (ck, temp_k) = H::hkdf(self.ck.as_slice(), input_key_material);
        self.ck = ck;
        self.cipherstate = Some(CipherState::new(&temp_k.as_slice()[..C::key_len()], 0));
    }

    /// # Protocol
    /// ```text
    /// * Sets ck, temp_h, temp_k = HKDF(ck, input_key_material, 3).
    /// * Calls MixHash(temp_h).
    /// * If HASHLEN is 64, then truncates temp_k to 32 bytes.
    /// * Calls InitializeKey(temp_k).
    /// ```
    pub(crate) fn mix_key_and_hash(&mut self, input_key_material: &[u8]) {
        let (ck, temp_h, temp_k) = H::hkdf3(self.ck.as_slice(), input_key_material);
        self.ck = ck;
        self.mix_hash(temp_h.as_slice());
        self.cipherstate = Some(CipherState::new(&temp_k.as_slice()[..C::key_len()], 0));
    }

    /// Encrypt data with currently established key material and update hash
    ///
    /// # Warning
    /// If no key material is available, `plaintext` is simply copied to the `out` buffer
    pub(crate) fn encrypt_and_hash(
        &mut self,
        plaintext: &[u8],
        out: &mut [u8],
    ) -> CipherResult<()> {
        if let Some(ref mut c) = self.cipherstate {
            c.encrypt_with_ad(self.h.as_slice(), plaintext, out)?;
        } else {
            out.copy_from_slice(plaintext);
        };
        self.mix_hash(out);
        Ok(())
    }

    /// Decrypt data with currently established key material and update hash
    ///
    /// # Warning
    /// If no key material is available, `data` is simply copied to the `out` buffer
    pub(crate) fn decrypt_and_hash(&mut self, data: &[u8], out: &mut [u8]) -> CipherResult<()> {
        if let Some(ref mut c) = self.cipherstate {
            c.decrypt_with_ad(self.h.as_slice(), data, out)?;
        } else {
            out.copy_from_slice(data)
        }
        self.mix_hash(data);
        Ok(())
    }

    /// Return [`CipherStates`] for encrypting and decrypting transport messages
    ///
    /// # Panics
    /// * If no key material has been established
    pub(crate) fn split(&self) -> CipherStates<C> {
        // This means that we are still in the initial state
        if self.ck == self.h {
            panic!("No key material")
        }

        let (mut temp_k1, mut temp_k2) = H::hkdf(self.ck.as_slice(), &[]);

        let ct = CipherStates {
            initiator_to_responder: CipherState::new(&temp_k1.as_slice()[..C::key_len()], 0),
            responder_to_initiator: CipherState::new(&temp_k2.as_slice()[..C::key_len()], 0),
        };

        temp_k1.zeroize();
        temp_k2.zeroize();
        ct
    }

    /// Get handshake hash
    pub(crate) fn get_hash(&self) -> H::Output {
        self.h.clone()
    }

    /// Check if have already established key material
    pub(crate) fn has_key(&self) -> bool {
        self.cipherstate.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::SymmetricState;
    use crate::crypto::cipher::{AesGcm, ChaChaPoly};
    use crate::crypto::hash::{Blake2b, Blake2s, Sha256, Sha512};
    use crate::traits::{Cipher, Hash};

    impl<C: Cipher, H: Hash> PartialEq for SymmetricState<C, H> {
        fn eq(&self, other: &Self) -> bool {
            self.h == other.h && self.ck == other.ck
        }
    }

    fn symmetric_suite<C: Cipher, H: Hash>() {
        let mut s1 = SymmetricState::<C, H>::new("complex delirium");
        let mut s2 = SymmetricState::<C, H>::new("complex delirium");

        // Don't have keys yet
        assert!(!s1.has_key());
        assert!(!s2.has_key());

        // Identical at start
        assert!(s1 == s2);

        // Mix hash
        s1.mix_hash(b"all wound up");
        s2.mix_hash(b"all wound up");
        assert!(s1 == s2);
        assert!(!s1.has_key() && !s2.has_key());

        // Mix key
        s1.mix_key(b"sleep disturbed");
        s2.mix_key(b"sleep disturbed");
        assert!(s1 == s2);
        assert!(s1.has_key() && s2.has_key());

        // Mix key and hash
        s1.mix_key_and_hash(b"sleep disturbed");
        s2.mix_key_and_hash(b"sleep disturbed");
        assert!(s1 == s2);

        // Mix key and hash empty
        s1.mix_key_and_hash(&[]);
        s2.mix_key_and_hash(&[]);
        assert!(s1 == s2);

        // Encrypt and hash
        let mut buf1 = [0; 4096];
        let mut buf2 = [0; 4096];
        let msg = b"caught off guard";
        s1.encrypt_and_hash(msg, &mut buf1[..msg.len() + C::tag_len()])
            .unwrap();
        assert!(s1 != s2);
        assert!(msg != &buf1[..msg.len()]);

        // Decrypt and hash
        s2.decrypt_and_hash(&buf1[..msg.len() + C::tag_len()], &mut buf2[..msg.len()])
            .unwrap();
        assert_eq!(*msg, buf2[..msg.len()]);
        assert!(s1 == s2);

        // Split
        let s1_c = s1.split();
        let s2_c = s2.split();

        assert!(s1_c.initiator_to_responder.take() == s2_c.initiator_to_responder.take());
        assert!(s1_c.responder_to_initiator.take() == s2_c.responder_to_initiator.take());

        // Mix in different material
        s1.mix_key_and_hash(b"run");
        s2.mix_key_and_hash(b"try to hide");
        assert!(s1 != s2);

        // Encrypt and hash with wrong hashes
        s1.encrypt_and_hash(msg, &mut buf1[..msg.len() + C::tag_len()])
            .unwrap();
        assert!(s1 != s2);
        assert!(msg != &buf1[..msg.len()]);

        // Decrypt should fail
        assert!(s2
            .decrypt_and_hash(&buf1[..msg.len() + C::tag_len()], &mut buf2[..msg.len()])
            .is_err());

        // Verify that we panic if no key material is available
        cant_split_without_key::<C, H>();
    }

    #[should_panic]
    fn cant_split_without_key<C: Cipher, H: Hash>() {
        let mut s1 = SymmetricState::<C, H>::new("complex delirium");
        s1.mix_hash(b"all wound up");
        s1.split();
    }

    #[test]
    fn symmetric_suites() {
        // ChaChaPoly
        symmetric_suite::<ChaChaPoly, Sha256>();
        symmetric_suite::<ChaChaPoly, Sha512>();
        symmetric_suite::<ChaChaPoly, Blake2b>();
        symmetric_suite::<ChaChaPoly, Blake2s>();

        // AES-GCM
        symmetric_suite::<AesGcm, Sha256>();
        symmetric_suite::<AesGcm, Sha512>();
        symmetric_suite::<AesGcm, Blake2b>();
        symmetric_suite::<AesGcm, Blake2s>();
    }
}
