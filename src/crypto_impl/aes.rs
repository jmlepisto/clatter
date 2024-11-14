use core::ops::Deref;

use aes_gcm::{AeadInPlace, KeyInit};

use crate::bytearray::SensitiveByteArray;
use crate::error::CipherError;
use crate::traits::{Cipher, CryptoComponent};

/// AES-GCM cipher implementation
pub struct AesGcm;

impl CryptoComponent for AesGcm {
    fn name() -> &'static str {
        "AESGCM"
    }
}

impl Cipher for AesGcm {
    type Key = SensitiveByteArray<[u8; 32]>;

    fn tag_len() -> usize {
        16
    }

    fn encrypt(k: &Self::Key, nonce: u64, ad: &[u8], plaintext: &[u8], out: &mut [u8]) {
        assert!(plaintext.len().checked_add(Self::tag_len()) == Some(out.len()));
        out[..plaintext.len()].copy_from_slice(plaintext);
        Self::encrypt_in_place(k, nonce, ad, out, plaintext.len());
    }

    fn encrypt_in_place(
        k: &Self::Key,
        nonce: u64,
        ad: &[u8],
        in_out: &mut [u8],
        plaintext_len: usize,
    ) -> usize {
        assert!(plaintext_len
            .checked_add(Self::tag_len())
            .map_or(false, |len| len <= in_out.len()));

        let mut full_nonce = [0u8; 12];
        full_nonce[4..].copy_from_slice(&nonce.to_be_bytes());

        let out_len = plaintext_len + Self::tag_len();
        let (buffer, tag_out) = in_out[..out_len].split_at_mut(plaintext_len);

        let tag = aes_gcm::Aes256Gcm::new(k.deref().into())
            .encrypt_in_place_detached(&full_nonce.into(), ad, buffer)
            .unwrap();

        tag_out.copy_from_slice(&tag);
        out_len
    }

    fn decrypt(
        k: &Self::Key,
        nonce: u64,
        ad: &[u8],
        ciphertext: &[u8],
        out: &mut [u8],
    ) -> crate::error::CipherResult<()> {
        assert!(ciphertext.len().checked_sub(Self::tag_len()) == Some(out.len()));

        let mut full_nonce = [0u8; 12];
        full_nonce[4..].copy_from_slice(&nonce.to_be_bytes());

        out.copy_from_slice(&ciphertext[..out.len()]);
        let tag = &ciphertext[out.len()..];

        aes_gcm::Aes256Gcm::new(k.deref().into())
            .decrypt_in_place_detached(&full_nonce.into(), ad, out, tag.into())
            .map_err(|_| CipherError::Decrypt)?;

        Ok(())
    }

    fn decrypt_in_place(
        k: &Self::Key,
        nonce: u64,
        ad: &[u8],
        in_out: &mut [u8],
        ciphertext_len: usize,
    ) -> crate::error::CipherResult<usize> {
        assert!(ciphertext_len <= in_out.len());
        assert!(ciphertext_len >= Self::tag_len());

        let mut full_nonce = [0u8; 12];
        full_nonce[4..].copy_from_slice(&nonce.to_be_bytes());

        let (buffer, tag) = in_out[..ciphertext_len].split_at_mut(ciphertext_len - 16);

        aes_gcm::Aes256Gcm::new(k.deref().into())
            .decrypt_in_place_detached(&full_nonce.into(), ad, buffer, tag.as_ref().into())
            .map_err(|_| CipherError::Decrypt)?;

        Ok(buffer.len())
    }
}
