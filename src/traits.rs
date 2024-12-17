//! Common traits used throughout the crate

use arrayvec::ArrayString;
pub use rand_core::{CryptoRng, RngCore};
use zeroize::Zeroize;

use crate::bytearray::ByteArray;
use crate::cipherstate::CipherStates;
use crate::constants::{MAX_KEY_LEN, MAX_MESSAGE_LEN, MAX_TAG_LEN};
use crate::error::{CipherResult, DhResult, HandshakeError, HandshakeResult, KemResult};
use crate::handshakepattern::HandshakePattern;
use crate::handshakestate::HandshakeStatus;
use crate::transportstate::TransportState;
use crate::KeyPair;

/// Common trait for all crypto components
pub trait CryptoComponent {
    /// Name of this algorithm
    fn name() -> &'static str;
}

/// Common trait for compatible RNG sources
///
/// Automatically implemented for all types that implement:
/// * [`RngCore`]
/// * [`CryptoRng`]
pub trait Rng: RngCore + CryptoRng {}

/// Automatic implementation for all supported types
impl<T: RngCore + CryptoRng> Rng for T {}

/// Common trait for all Diffie-Hellman algorithms
pub trait Dh: CryptoComponent {
    /// Private key type
    type PrivateKey: ByteArray;
    /// Public key type
    type PubKey: ByteArray;
    /// DH output type
    type Output: ByteArray;

    /// Generate a keypair
    fn genkey<R: Rng>(rng: &mut R) -> DhResult<KeyPair<Self::PubKey, Self::PrivateKey>>;

    /// Extract public key from given private key
    fn pubkey(k: &Self::PrivateKey) -> Self::PubKey;

    /// Perform DH key exchange
    fn dh(_: &Self::PrivateKey, _: &Self::PubKey) -> DhResult<Self::Output>;
}

/// Common trait for all key encapsulation mechanisms
pub trait Kem: CryptoComponent {
    /// Secret key type
    type SecretKey: ByteArray;
    /// Public key type
    type PubKey: ByteArray;
    /// Ciphertext type
    type Ct: ByteArray;
    /// Shared secret type
    type Ss: ByteArray;

    /// Generate a keypair
    fn genkey<R: Rng>(rng: &mut R) -> KemResult<KeyPair<Self::PubKey, Self::SecretKey>>;

    /// Encapsulate a public key and return the ciphertext and shared secret
    fn encapsulate<R: Rng>(pk: &[u8], rng: &mut R) -> KemResult<(Self::Ct, Self::Ss)>;

    /// Decapsulate ciphertext with secret key and return the shared secret
    fn decapsulate(ct: &[u8], sk: &[u8]) -> KemResult<Self::Ss>;
}

/// Common trait for all hash algorithms
pub trait Hash: CryptoComponent + Default {
    /// Hash block type
    type Block: ByteArray;
    /// Hash output type
    type Output: ByteArray;

    /// Hash block length
    fn block_len() -> usize {
        Self::Block::len()
    }

    /// Hash output length in bytes
    fn hash_len() -> usize {
        Self::Output::len()
    }

    /// Update hash state with bytes
    fn input(&mut self, data: &[u8]);

    /// Calculate hash result
    fn result(self) -> Self::Output;

    /// Calculate hash result for bytes
    fn hash(data: &[u8]) -> Self::Output {
        let mut h = Self::default();
        h.input(data);
        h.result()
    }

    /// Calculate HMAC with the given key and messages
    fn hmac_many(key: &[u8], data: &[&[u8]]) -> Self::Output {
        assert!(key.len() <= Self::block_len());

        // Initialize to maximize Hamming distance:
        // https://cseweb.ucsd.edu/~mihir/papers/kmd5.pdf
        let mut ipad = Self::Block::new_with(0x36);
        let mut opad = Self::Block::new_with(0x5c);

        let ipad = ipad.as_mut();
        let opad = opad.as_mut();

        for (i, b) in key.iter().enumerate() {
            ipad[i] ^= b;
            opad[i] ^= b;
        }

        let mut hasher = Self::default();
        hasher.input(ipad);
        for d in data {
            hasher.input(d);
        }
        let inner_output = hasher.result();

        let mut hasher = Self::default();
        hasher.input(opad);
        hasher.input(inner_output.as_slice());
        hasher.result()
    }

    /// Calculate HMAC with the given key and message
    fn hmac(key: &[u8], data: &[u8]) -> Self::Output {
        Self::hmac_many(key, &[data])
    }

    /// Calculate HKDF
    fn hkdf(chaining_key: &[u8], input_key_material: &[u8]) -> (Self::Output, Self::Output) {
        let temp_key = Self::hmac(chaining_key, input_key_material);
        let out1 = Self::hmac(temp_key.as_slice(), &[1u8]);
        let out2 = Self::hmac_many(temp_key.as_slice(), &[out1.as_slice(), &[2u8]]);
        (out1, out2)
    }

    /// Calculate triple output HKDF
    fn hkdf3(
        chaining_key: &[u8],
        input_key_material: &[u8],
    ) -> (Self::Output, Self::Output, Self::Output) {
        let temp_key = Self::hmac(chaining_key, input_key_material);
        let out1 = Self::hmac(temp_key.as_slice(), &[1u8]);
        let out2 = Self::hmac_many(temp_key.as_slice(), &[out1.as_slice(), &[2u8]]);
        let out3 = Self::hmac_many(temp_key.as_slice(), &[out2.as_slice(), &[3u8]]);
        (out1, out2, out3)
    }
}

/// Common trait for all cipher algorithms
pub trait Cipher: CryptoComponent {
    /// Cipher key type
    type Key: ByteArray;

    /// Key length
    fn key_len() -> usize {
        Self::Key::len()
    }

    /// Cipher tag length
    ///
    /// # Warning
    /// Noise specification only support 16 byte tags!
    fn tag_len() -> usize;

    /// AEAD encrypt
    ///
    /// Encrypts given plaintext using the supplied nonce and
    /// additional data and places the result in the given buffer.
    ///
    /// # Panics
    ///
    /// If `out.len()` < `plaintext.len()` + `Self::tag_len()`
    fn encrypt(k: &Self::Key, nonce: u64, ad: &[u8], plaintext: &[u8], out: &mut [u8]);

    /// In-place AEAD encrypt
    ///
    /// Encrypts given plaintext using the supplied nonce and
    /// additional data in-place.
    ///
    /// # Panics
    ///
    /// If `in_out.len()` < `plaintext_len` + `Self::tag_len()`
    fn encrypt_in_place(
        k: &Self::Key,
        nonce: u64,
        ad: &[u8],
        in_out: &mut [u8],
        plaintext_len: usize,
    ) -> usize;

    /// AEAD decrypt
    ///
    /// Decrypts given plaintext using the supplied nonce and
    /// additional data and places the result in the given buffer.
    ///
    /// # Panics
    ///
    /// If `out.len()` < `ciphertext.len()` - `Self::tag_len()`
    fn decrypt(
        k: &Self::Key,
        nonce: u64,
        ad: &[u8],
        ciphertext: &[u8],
        out: &mut [u8],
    ) -> CipherResult<()>;

    /// In-place AEAD decrypt
    ///
    /// Decrypts given ciphertext using the supplied nonce and
    /// additional data in-place
    ///
    /// # Panics
    ///
    /// If `in_out.len()` < `ciphertext_len`
    fn decrypt_in_place(
        k: &Self::Key,
        nonce: u64,
        ad: &[u8],
        in_out: &mut [u8],
        ciphertext_len: usize,
    ) -> CipherResult<usize>;

    /// Rekey according to noise spec part 4.2
    fn rekey(k: &Self::Key) -> Self::Key {
        let mut k_new = [0u8; MAX_KEY_LEN + MAX_TAG_LEN];
        let plaintext = [0u8; MAX_KEY_LEN];
        Self::encrypt(
            k,
            u64::MAX,
            &[],
            &plaintext[..Self::key_len()],
            &mut k_new[..Self::key_len() + Self::tag_len()],
        );
        let k_out = Self::Key::from_slice(&k_new[..Self::key_len()]);
        k_new.zeroize();

        k_out
    }
}

/// Common internal operations for all types of handshakes
pub(crate) trait HandshakerInternal<C, H>
where
    C: Cipher,
    H: Hash,
{
    /// Get current handshake status
    fn status(&self) -> HandshakeStatus;
    /// Set the handshaker to error status
    fn set_error(&mut self);
    /// Write next handshake message
    fn write_message_impl(&mut self, payload: &[u8], out: &mut [u8]) -> HandshakeResult<usize>;
    /// Read next handshake message
    fn read_message_impl(&mut self, message: &[u8], out: &mut [u8]) -> HandshakeResult<usize>;
    /// Extract ciphers
    fn get_ciphers(&self) -> CipherStates<C>;
    /// Get handshake hash
    fn get_hash(&self) -> H::Output;
    /// Get handshake pattern
    fn get_pattern(&self) -> HandshakePattern;
}

/// Common operations for all types of handshakes
#[allow(private_bounds)] // We want to define a dedicated internal API as crate-private
pub trait Handshaker<C, H>: HandshakerInternal<C, H>
where
    C: Cipher,
    H: Hash,
{
    /// Ephemeral public key type
    type E: ByteArray;
    /// Static public key type
    type S: ByteArray;

    /// Write next handshake message to the given buffer
    ///
    /// # Arguments
    /// * `payload` - payload to include in the handshake message
    /// * `out` - destination buffer to write the handshake message to
    ///
    /// # Returns
    /// Number of bytes written to destination buffer
    ///
    /// # Errors
    /// * [`HandshakeError::ErrorState`] - Handshaker encountered an error before and cannot be used anymore
    /// * [`HandshakeError::InvalidState`] - Handshaker is not in receive state
    /// * [`HandshakeError::BufferTooSmall`] - Message does not fit into provided destination buffer
    /// * [`HandshakeError::Dh`] - DH error
    /// * [`HandshakeError::Cipher`] - Encryption error
    ///
    /// # Panics
    /// If resulting message length is larger than [`crate::constants::MAX_MESSAGE_LEN`]
    fn write_message(&mut self, payload: &[u8], out: &mut [u8]) -> HandshakeResult<usize> {
        if self.status() == HandshakeStatus::Error {
            return Err(HandshakeError::ErrorState);
        }

        if !self.is_write_turn() {
            return Err(HandshakeError::InvalidState);
        }

        let out_len = payload.len() + self.get_next_message_overhead().unwrap();

        if out_len > MAX_MESSAGE_LEN {
            panic!("Maximum Noise message length exceeded");
        }

        if out.len() < out_len {
            return Err(HandshakeError::BufferTooSmall);
        }

        let res = self.write_message_impl(payload, out);

        if res.is_err() {
            self.set_error();
        }

        res
    }

    /// Read and process next handshake message from given buffer
    ///
    /// # Arguments
    /// * `message` - handshake message
    /// * `out` - destination buffer to write the handshake payload
    ///
    /// # Returns
    /// Number of payload bytes written to destination buffer
    ///
    /// # Errors
    /// * [`HandshakeError::ErrorState`] - Handshaker encountered an error before and cannot be used anymore
    /// * [`HandshakeError::InvalidState`] - Handshaker is not in receive state
    /// * [`HandshakeError::InvalidMessage`] - Input does not match the next expected message
    /// * [`HandshakeError::BufferTooSmall`] - Payload does not fit into provided destination buffer
    /// * [`HandshakeError::Dh`] - DH error
    /// * [`HandshakeError::Cipher`] - Decryption error
    ///
    /// # Panics
    /// * If message length is larger than [`crate::constants::MAX_MESSAGE_LEN`]
    fn read_message(&mut self, message: &[u8], out: &mut [u8]) -> HandshakeResult<usize> {
        if message.len() > MAX_MESSAGE_LEN {
            panic!("Maximum Noise message length exceeded");
        }

        if self.status() == HandshakeStatus::Error {
            return Err(HandshakeError::ErrorState);
        }

        if self.is_write_turn() {
            return Err(HandshakeError::InvalidState);
        }

        let overhead = self.get_next_message_overhead().unwrap();
        if message.len() < overhead {
            return Err(HandshakeError::InvalidMessage);
        }

        let out_len = message.len() - overhead;
        if out.len() < out_len {
            return Err(HandshakeError::BufferTooSmall);
        }

        let res = self.read_message_impl(message, out);

        if res.is_err() {
            self.set_error();
        }

        res
    }

    /// Push a PSK to the PSK queue
    ///
    /// # Panics
    ///  * If the PSK is not [`crate::constants::PSK_LEN`] bytes
    ///  * If the PSK queue becomes larger than [`crate::constants::MAX_PSKS`]
    fn push_psk(&mut self, psk: &[u8]);

    /// Is the handshake finished
    fn is_finished(&self) -> bool {
        self.status() == HandshakeStatus::Ready
    }

    /// Is it our turn to send
    fn is_write_turn(&self) -> bool;

    /// Are we the initiator
    fn is_initiator(&self) -> bool;

    /// Get next message overhead in bytes
    fn get_next_message_overhead(&self) -> HandshakeResult<usize>;

    /// Build full name of the protocol with the given pattern
    fn build_name(pattern: &HandshakePattern) -> ArrayString<128>;

    /// Get full name of the selected protocol
    fn get_name(&self) -> ArrayString<128> {
        Self::build_name(&self.get_pattern())
    }

    /// Get remote static key (if available)
    fn get_remote_static(&self) -> Option<Self::S>;

    /// Get remote ephemeral key (if available)
    fn get_remote_ephemeral(&self) -> Option<Self::E>;

    /// Transition into transport mode
    ///
    /// Handshake must be finished before calling this.
    /// use [`Handshaker::is_finished`] to check the status.
    fn finalize(self) -> HandshakeResult<TransportState<C, H>>
    where
        Self: Sized,
    {
        TransportState::new(self)
    }
}
