use crate::bytearray::ByteArray;
use crate::cipherstate::CipherStates;
use crate::constants::MAX_MESSAGE_LEN;
use crate::error::{HandshakeError, HandshakeResult, TransportError, TransportResult};
use crate::handshakepattern::HandshakePattern;
use crate::traits::{Cipher, Handshaker, Hash};

/// Transport state used after a successful handshake
///
/// Contains session keys for secure communication in the
/// form of a [`CipherStates`] struct. Users have raw access
/// to the keys if needed using the [`Self::take`] method.
///
/// # Sending and receiving messages
/// * [`Self::send`]
/// * [`Self::receive`]
/// * [`Self::send_in_place`]
/// * [`Self::receive_in_place`]
pub struct TransportState<C: Cipher, H: Hash> {
    pattern: HandshakePattern,
    cipherstates: CipherStates<C>,
    h: H::Output,
    initiator: bool,
}

impl<C: Cipher, H: Hash> TransportState<C, H> {
    /// Consume a [`Handshaker`] to initialize a new transport state
    pub fn new<Hs: Handshaker<C, H>>(hs: Hs) -> HandshakeResult<TransportState<C, H>> {
        if !hs.is_finished() {
            return Err(HandshakeError::InvalidState);
        }

        Ok(TransportState {
            pattern: hs.get_pattern(),
            cipherstates: hs.get_ciphers(),
            h: hs.get_hash(),
            initiator: hs.is_initiator(),
        })
    }

    /// Encrypt a message for remote peer
    ///
    /// Encrypts data from `msg` and places the resulting ciphertext
    /// in `buf`, returning the total number of bytes written.
    ///
    /// # Arguments
    /// * `msg` - Message buffer to encrypt
    /// * `buf` - Destination buffer to store the encrypted message
    ///
    /// # Returns
    /// * Encrypted ytes written to `buf`
    ///
    /// # Errors
    /// * [`TransportError::BufferTooSmall`] - Resulting message does not fit in `buf`
    /// * [`TransportError::Cipher`] - Encryption error
    /// * [`TransportError::OneWayViolation`] - Tried to send data as responder after a one-way handshake
    ///
    /// # Panics
    /// * If resulting message length exceeds [`MAX_MESSAGE_LEN`]
    pub fn send(&mut self, msg: &[u8], buf: &mut [u8]) -> TransportResult<usize> {
        let out_len = msg.len() + C::tag_len();

        if out_len > MAX_MESSAGE_LEN {
            panic!("Maximum Noise message length exceeded");
        }

        if buf.len() < out_len {
            return Err(TransportError::BufferTooSmall);
        }

        if self.pattern.is_one_way() && !self.initiator {
            return Err(TransportError::OneWayViolation);
        }

        let c = if self.initiator {
            &mut self.cipherstates.initiator_to_responder
        } else {
            &mut self.cipherstates.responder_to_initiator
        };

        c.encrypt_with_ad(&[], msg, &mut buf[..out_len])?;
        Ok(out_len)
    }

    /// Encrypt a message for remote peer in-place
    ///
    /// Encrypts `msg_len` bytes in `msg` in-place,
    /// returning the total number of bytes the resulting
    /// ciphertext takes.
    ///
    /// # Arguments
    /// * `msg` - Message buffer
    /// * `msg_len` - How many bytes from the beginning of `msg` will be encrypted in-place
    ///
    /// # Returns
    /// * Encrypted bytes written to `msg`
    ///
    /// # Errors
    /// * [`TransportError::BufferTooSmall`] - Resulting message does not fit in `buf`
    /// * [`TransportError::Cipher`] - Encryption error
    /// * [`TransportError::OneWayViolation`] - Tried to send data as responder after a one-way handshake
    ///
    /// # Panics
    /// * If resulting message length exceeds [`MAX_MESSAGE_LEN`]
    pub fn send_in_place(&mut self, msg: &mut [u8], msg_len: usize) -> TransportResult<usize> {
        let out_len = msg_len + C::tag_len();

        if out_len > MAX_MESSAGE_LEN {
            panic!("Maximum Noise message length exceeded");
        }

        if msg.len() < out_len {
            return Err(TransportError::BufferTooSmall);
        }

        if self.pattern.is_one_way() && !self.initiator {
            return Err(TransportError::OneWayViolation);
        }

        let c = if self.initiator {
            &mut self.cipherstates.initiator_to_responder
        } else {
            &mut self.cipherstates.responder_to_initiator
        };

        c.encrypt_with_ad_in_place(&[], msg, msg_len)?;
        Ok(out_len)
    }

    /// Decrypt a message from remote peer
    ///
    /// Decrypts data from `msg` and places the resulting plaintext
    /// in `buf`, returning the total number of bytes written.
    ///
    /// # Arguments
    /// * `msg` - Received message buffer
    /// * `buf` - Destination buffer to store the decrypted message
    ///
    /// # Returns
    /// * Decrypted bytes written to `buf`
    ///
    /// # Errors
    /// * [`TransportError::TooShort`] - Provided message `msg` is too short for decryption
    /// * [`TransportError::BufferTooSmall`] - Resulting message does not fit in `buf`
    /// * [`TransportError::Cipher`] - Decryption error
    /// * [`TransportError::OneWayViolation`] - Tried to receive data as initiator after a one-way handshake
    ///
    /// # Panics
    /// * If message length exceeds [`MAX_MESSAGE_LEN`]
    pub fn receive(&mut self, msg: &[u8], buf: &mut [u8]) -> TransportResult<usize> {
        if msg.len() < C::tag_len() {
            return Err(TransportError::TooShort);
        }

        if msg.len() > MAX_MESSAGE_LEN {
            panic!("Maximum Noise message length exceeded");
        }

        let out_len = msg.len() - C::tag_len();
        if buf.len() < out_len {
            return Err(TransportError::BufferTooSmall);
        }

        if self.pattern.is_one_way() && self.initiator {
            return Err(TransportError::OneWayViolation);
        }

        let c = if self.initiator {
            &mut self.cipherstates.responder_to_initiator
        } else {
            &mut self.cipherstates.initiator_to_responder
        };

        c.decrypt_with_ad(&[], msg, &mut buf[..out_len])?;
        Ok(out_len)
    }

    /// Decrypt a message from remote peer in-place
    ///
    /// Decrypts `msg_len` bytes in `msg` in-place,
    /// returning the total number of byte the resulting
    /// plaintext takes.
    ///
    /// # Arguments
    /// * `msg` - Message buffer
    /// * `msg_len` - How many bytes from the beginning of `msg` will be decrypted in-place
    ///
    /// # Returns
    /// * Decrypted bytes written to `msg`
    ///
    /// # Errors
    /// * [`TransportError::TooShort`] - Provided message `msg` is too short for decryption
    /// * [`TransportError::BufferTooSmall`] - Resulting message does not fit in `buf`
    /// * [`TransportError::Cipher`] - Decryption error
    /// * [`TransportError::OneWayViolation`] - Tried to receive data as initiator after a one-way handshake
    ///
    /// # Panics
    /// * If message length exceeds [`MAX_MESSAGE_LEN`]
    pub fn receive_in_place(&mut self, msg: &mut [u8], msg_len: usize) -> TransportResult<usize> {
        if msg_len < C::tag_len() {
            return Err(TransportError::TooShort);
        }

        if msg_len > MAX_MESSAGE_LEN {
            panic!("Maximum Noise message length exceeded");
        }

        if msg_len > msg.len() {
            return Err(TransportError::BufferTooSmall);
        }

        if self.pattern.is_one_way() && self.initiator {
            return Err(TransportError::OneWayViolation);
        }

        let c = if self.initiator {
            &mut self.cipherstates.responder_to_initiator
        } else {
            &mut self.cipherstates.initiator_to_responder
        };

        c.decrypt_with_ad_in_place(&[], msg, msg_len)?;
        Ok(msg_len - C::tag_len())
    }

    /// Get forthcoming inbound nonce value
    #[must_use]
    pub fn receiving_nonce(&self) -> u64 {
        if self.initiator {
            self.cipherstates.responder_to_initiator.get_nonce()
        } else {
            self.cipherstates.initiator_to_responder.get_nonce()
        }
    }

    /// Get forthcoming outbound nonce value
    #[must_use]
    pub fn sending_nonce(&self) -> u64 {
        if self.initiator {
            self.cipherstates.initiator_to_responder.get_nonce()
        } else {
            self.cipherstates.responder_to_initiator.get_nonce()
        }
    }

    /// Set forthcoming inbound nonce value
    pub fn set_receiving_nonce(&mut self, nonce: u64) {
        if self.initiator {
            self.cipherstates.responder_to_initiator.set_nonce(nonce);
        } else {
            self.cipherstates.initiator_to_responder.set_nonce(nonce);
        }
    }

    /// Get session handshake hash value
    #[must_use]
    pub fn get_handshake_hash(&self) -> H::Output {
        self.h.clone()
    }

    /// Rekey outbound cipher
    pub fn rekey_sender(&mut self) {
        if self.initiator {
            self.cipherstates.initiator_to_responder.rekey();
        } else {
            self.cipherstates.responder_to_initiator.rekey();
        }
    }

    /// Rekey inbound cipher
    pub fn rekey_receiver(&mut self) {
        if self.initiator {
            self.cipherstates.responder_to_initiator.rekey();
        } else {
            self.cipherstates.initiator_to_responder.rekey();
        }
    }

    /// Take ownership of internal cipherstates
    ///
    /// # Warning
    /// **Handle with care!**
    pub fn take(self) -> CipherStates<C> {
        self.cipherstates
    }
}
