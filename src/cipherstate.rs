//! Cipherstate implementation

use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::bytearray::ByteArray;
use crate::error::{CipherError, CipherResult};
use crate::traits::{Cipher, CryptoComponent};

/// Pair of [`CipherState`] instances for encrypting and decrypting transport messages
pub struct CipherStates<C: Cipher> {
    /// Cipher for initiator -> responder communication
    pub initiator_to_responder: CipherState<C>,
    /// Cipher for responder -> initiator communication
    pub responder_to_initiator: CipherState<C>,
}

/// Cipherstate for encrypting and decrypting messages
///
/// Contains the encryption key and nonce and provides
/// methods for encrypting and decrypting data.
/// Will automatically increment the nonce and return an
/// error if that overflows.
#[derive(ZeroizeOnDrop, Zeroize, Clone)]
pub struct CipherState<C: Cipher> {
    k: C::Key,
    n: u64,
    overflowed: bool,
}

impl<C: Cipher> CryptoComponent for CipherState<C> {
    fn name() -> &'static str {
        C::name()
    }
}

impl<C: Cipher> CipherState<C> {
    /// Initialize with given key and nonce
    ///
    /// # Panics
    /// Panics if key data has incorrect length
    pub fn new(k: &[u8], n: u64) -> Self {
        Self {
            k: C::Key::from_slice(k),
            n,
            overflowed: false,
        }
    }

    fn nonce_inc_check(&mut self) {
        // "If incrementing n results in 2^(64)-1, then any further EncryptWithAd()
        // or DecryptWithAd() calls will signal an error to the caller"
        match self.n.checked_add(1) {
            None => self.overflowed = true,
            Some(n) => {
                self.n = n;
            }
        }
    }

    /// AEAD encryption
    pub fn encrypt_with_ad(
        &mut self,
        ad: &[u8],
        plaintext: &[u8],
        out: &mut [u8],
    ) -> CipherResult<()> {
        if self.overflowed {
            return Err(CipherError::NonceOverflow);
        }

        C::encrypt(&self.k, self.n, ad, plaintext, out);
        self.nonce_inc_check();

        Ok(())
    }

    /// AEAD encryption in place
    pub fn encrypt_with_ad_in_place(
        &mut self,
        ad: &[u8],
        in_out: &mut [u8],
        plaintext_len: usize,
    ) -> CipherResult<usize> {
        if self.overflowed {
            return Err(CipherError::NonceOverflow);
        }

        let size = C::encrypt_in_place(&self.k, self.n, ad, in_out, plaintext_len);
        self.nonce_inc_check();

        Ok(size)
    }

    /// AEAD decryption
    pub fn decrypt_with_ad(
        &mut self,
        ad: &[u8],
        ciphertext: &[u8],
        out: &mut [u8],
    ) -> CipherResult<()> {
        if self.overflowed {
            return Err(CipherError::NonceOverflow);
        }

        C::decrypt(&self.k, self.n, ad, ciphertext, out)?;
        self.nonce_inc_check();

        Ok(())
    }

    /// AEAD decryption in place
    pub fn decrypt_with_ad_in_place(
        &mut self,
        ad: &[u8],
        in_out: &mut [u8],
        ciphertext_len: usize,
    ) -> CipherResult<usize> {
        if self.overflowed {
            return Err(CipherError::NonceOverflow);
        }

        let size = C::decrypt_in_place(&self.k, self.n, ad, in_out, ciphertext_len)?;
        self.nonce_inc_check();
        Ok(size)
    }

    /// Get current nonce value
    pub fn get_nonce(&self) -> u64 {
        self.n
    }

    /// Set nonce value
    ///
    /// # Warning
    /// **Do not reuse nonces.** Doing so WILL LEAD to a
    /// catastrophic crypto failure.
    pub fn set_nonce(&mut self, nonce: u64) {
        self.n = nonce;
    }

    /// Take ownership of key and nonce of this state
    ///
    /// # Warning
    /// **Use with care**
    pub fn take(self) -> (C::Key, u64) {
        (self.k.clone(), self.n)
    }

    /// Rekey
    ///
    /// Rekeys as per Noise spec parts 4.2 and 11.3
    pub fn rekey(&mut self) {
        self.k = C::rekey(&self.k)
    }
}

#[cfg(test)]
mod tests {
    use core::u64;

    use super::CipherState;
    use crate::crypto::cipher::{AesGcm, ChaChaPoly};
    use crate::traits::Cipher;

    const K: &[u8] = b"Back home.... where I belong....";

    fn cipher_suite<C: Cipher>() {
        let mut c1 = CipherState::<C>::new(K, 0);
        let mut c2 = CipherState::<C>::new(K, 0);

        let mut c1_buf = [0u8; 4069];
        let mut c2_buf = [0u8; 4069];

        let msg = b"Decadent scenes from my memory";
        let cipher_len = msg.len() + C::tag_len();

        // Normal encrypt-decrypt
        c1.encrypt_with_ad(&[], msg, &mut c1_buf[..cipher_len])
            .unwrap();
        c2.decrypt_with_ad(&[], &c1_buf[..cipher_len], &mut c2_buf[..msg.len()])
            .unwrap();
        assert_eq!(*msg, c2_buf[..msg.len()]);
        assert!(c1_buf[..msg.len()] != c2_buf[..msg.len()]);

        // With AD
        c1.encrypt_with_ad(b"Close your eyes", msg, &mut c1_buf[..cipher_len])
            .unwrap();
        c2.decrypt_with_ad(
            b"Close your eyes",
            &c1_buf[..cipher_len],
            &mut c2_buf[..msg.len()],
        )
        .unwrap();
        assert_eq!(*msg, c2_buf[..msg.len()]);

        // Wrong AD
        c1.encrypt_with_ad(b"Close your eyes", msg, &mut c1_buf[..cipher_len])
            .unwrap();
        assert!(c2
            .decrypt_with_ad(
                b"Close your eyes and relax",
                &c1_buf[..cipher_len],
                &mut c2_buf[..msg.len()]
            )
            .is_err());

        // Nonce is now desynchronized
        assert!(c1.get_nonce() != c2.get_nonce());
        c1.encrypt_with_ad(&[], msg, &mut c1_buf[..cipher_len])
            .unwrap();
        assert!(c2
            .decrypt_with_ad(&[], &c1_buf[..cipher_len], &mut c2_buf[..msg.len()])
            .is_err());

        // Restore nonce
        c2.set_nonce(c1.get_nonce());
        c1.encrypt_with_ad(&[], msg, &mut c1_buf[..cipher_len])
            .unwrap();
        c2.decrypt_with_ad(&[], &c1_buf[..cipher_len], &mut c2_buf[..msg.len()])
            .unwrap();
        assert_eq!(*msg, c2_buf[..msg.len()]);

        // Rekey responder
        c2.rekey();
        c1.encrypt_with_ad(&[], msg, &mut c1_buf[..cipher_len])
            .unwrap();
        assert!(c2
            .decrypt_with_ad(
                b"Close your eyes and relax",
                &c1_buf[..cipher_len],
                &mut c2_buf[..msg.len()]
            )
            .is_err());

        // Rekey sender (and restore nonce...)
        c1.rekey();
        c2.set_nonce(c1.get_nonce());
        c1.encrypt_with_ad(&[], msg, &mut c1_buf[..cipher_len])
            .unwrap();
        c2.decrypt_with_ad(&[], &c1_buf[..cipher_len], &mut c2_buf[..msg.len()])
            .unwrap();
        assert_eq!(*msg, c2_buf[..msg.len()]);

        // Rekey a lot
        for _ in 0..10000 {
            c1.rekey();
            c2.rekey();
        }
        c1.encrypt_with_ad(&[], msg, &mut c1_buf[..cipher_len])
            .unwrap();
        c2.decrypt_with_ad(&[], &c1_buf[..cipher_len], &mut c2_buf[..msg.len()])
            .unwrap();
        assert_eq!(*msg, c2_buf[..msg.len()]);

        // Nonce overflow
        c1.set_nonce(u64::MAX);
        // This should be ok
        c1.encrypt_with_ad(&[], msg, &mut c1_buf[..cipher_len])
            .unwrap();
        // This and all following calls should result in an error
        assert!(c1
            .encrypt_with_ad(&[], msg, &mut c1_buf[..cipher_len])
            .is_err());
        assert!(c1
            .encrypt_with_ad(&[], msg, &mut c1_buf[..cipher_len])
            .is_err());
    }

    #[test]
    fn cipher_suite_chacha() {
        cipher_suite::<ChaChaPoly>();
    }

    #[test]
    fn cipher_suite_aes_gcm() {
        cipher_suite::<AesGcm>();
    }
}
