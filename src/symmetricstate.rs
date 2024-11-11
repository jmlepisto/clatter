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

    /// # Protocol:
    /// ```text
    /// Sets h = HASH(h || data)
    /// ```
    pub(crate) fn mix_hash(&mut self, bytes: &[u8]) {
        let mut h = H::default();
        h.input(self.h.as_slice());
        h.input(bytes);
        self.h = h.result();
    }

    /// # Protocol:
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

    /// # Protocol:
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

    /// Return [`CipherStates`] for encrypting transport messages
    pub(crate) fn split(&self) -> CipherStates<C> {
        let (temp_k1, temp_k2) = H::hkdf(self.ck.as_slice(), &[]);

        CipherStates {
            initiator_to_responder: CipherState::new(&temp_k1.as_slice()[..C::key_len()], 0),
            responder_to_initiator: CipherState::new(&temp_k2.as_slice()[..C::key_len()], 0),
        }
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
