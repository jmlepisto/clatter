//! Transport state implementation
//!
//! [`TransportState`] is constructed from a [`Handshaker`] once the handshake
//! is completed and it can be used for encrypting and decrypting transport
//! communication with the peer.
//!
//! Methods for rekeying and configuring the encryption nonce are also provided
//! so that the user can easily implement higher level protocol features.

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
/// * [`Self::send_vec`] (requires `alloc`)
/// * [`Self::receive_vec`] (requires `alloc`)
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
            cipherstates: hs.get_ciphers()?,
            h: hs.get_hash(),
            initiator: hs.is_initiator(),
        })
    }

    /// Encrypt a message for remote peer
    ///
    /// Encrypts data from `msg` and places the resulting ciphertext
    /// in a vector.
    ///
    /// # Arguments
    /// * `msg` - Message buffer to encrypt
    ///
    /// # Returns
    /// * Encrypted bytes written to a `Vec<u8>`
    ///
    /// # Errors
    /// * [`TransportError::Cipher`] - Encryption error
    /// * [`TransportError::OneWayViolation`] - Tried to send data as responder after a one-way handshake
    ///
    /// # Panics
    /// * If message length exceeds [`MAX_MESSAGE_LEN`]
    #[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
    #[cfg(feature = "alloc")]
    pub fn send_vec(&mut self, msg: &[u8]) -> TransportResult<alloc::vec::Vec<u8>> {
        let mut buf = alloc::vec![0; msg.len() + C::tag_len()];
        let n = self.send(msg, &mut buf)?;
        assert_eq!(buf.len(), n);
        Ok(buf)
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
    /// * Encrypted bytes written to `buf`
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
    /// in a vector.
    ///
    /// # Arguments
    /// * `msg` - Received message buffer
    ///
    /// # Returns
    /// * Decrypted bytes written to `Vec<u8>`
    ///
    /// # Errors
    /// * [`TransportError::TooShort`] - Provided message `msg` is too short for decryption
    /// * [`TransportError::Cipher`] - Decryption error
    /// * [`TransportError::OneWayViolation`] - Tried to receive data as initiator after a one-way handshake
    ///
    /// # Panics
    /// * If message length exceeds [`MAX_MESSAGE_LEN`]
    #[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
    #[cfg(feature = "alloc")]
    pub fn receive_vec(&mut self, msg: &[u8]) -> TransportResult<alloc::vec::Vec<u8>> {
        let mut buf = alloc::vec![0; msg.len() - C::tag_len()];
        let n = self.receive(msg, &mut buf)?;
        assert_eq!(buf.len(), n);
        Ok(buf)
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
    pub fn rekey_sender(&mut self) -> TransportResult<()> {
        if self.initiator {
            self.cipherstates.initiator_to_responder.rekey()?;
        } else {
            self.cipherstates.responder_to_initiator.rekey()?;
        }

        Ok(())
    }

    /// Rekey inbound cipher
    pub fn rekey_receiver(&mut self) -> TransportResult<()> {
        if self.initiator {
            self.cipherstates.responder_to_initiator.rekey()?;
        } else {
            self.cipherstates.initiator_to_responder.rekey()?;
        }

        Ok(())
    }

    /// Take ownership of internal cipherstates
    ///
    /// # Warning
    /// **Handle with care!**
    pub fn take(self) -> CipherStates<C> {
        self.cipherstates
    }
}

#[cfg(test)]
mod tests {
    use super::TransportState;
    use crate::crypto::cipher::ChaChaPoly;
    use crate::crypto::hash::Sha256;
    use crate::error::{HandshakeError, TransportError};
    use crate::handshakepattern::noise_nn;
    use crate::handshakestate::nq::NqHandshakeCore;
    use crate::traits::{Dh, Handshaker};

    fn create_transport_states() -> (
        TransportState<ChaChaPoly, Sha256>,
        TransportState<ChaChaPoly, Sha256>,
    ) {
        let pattern = noise_nn();
        let mut alice = NqHandshakeCore::<
            crate::crypto::dh::X25519,
            ChaChaPoly,
            Sha256,
            crate::crypto::rng::DefaultRng,
        >::new(pattern.clone(), &[], true, None, None, None, None)
        .unwrap();
        let mut bob = NqHandshakeCore::<
            crate::crypto::dh::X25519,
            ChaChaPoly,
            Sha256,
            crate::crypto::rng::DefaultRng,
        >::new(pattern, &[], false, None, None, None, None)
        .unwrap();

        let mut alice_buf = [0u8; 2048];
        let mut bob_buf = [0u8; 2048];

        // Complete handshake
        let n = alice.write_message(&[], &mut alice_buf).unwrap();
        let _ = bob.read_message(&alice_buf[..n], &mut bob_buf).unwrap();
        let n = bob.write_message(&[], &mut bob_buf).unwrap();
        let _ = alice.read_message(&bob_buf[..n], &mut alice_buf).unwrap();

        let alice_transport = alice.finalize().unwrap();
        let bob_transport = bob.finalize().unwrap();

        (alice_transport, bob_transport)
    }

    #[test]
    fn transport_basic_send_receive() {
        let (mut alice, mut bob) = create_transport_states();

        let msg = b"Hello, world!";
        let mut send_buf = [0u8; 2048];
        let mut recv_buf = [0u8; 2048];

        // Alice sends to Bob
        let n = alice.send(msg, &mut send_buf).unwrap();
        let m = bob.receive(&send_buf[..n], &mut recv_buf).unwrap();
        assert_eq!(&recv_buf[..m], msg);

        // Bob sends to Alice
        let n = bob.send(msg, &mut send_buf).unwrap();
        let m = alice.receive(&send_buf[..n], &mut recv_buf).unwrap();
        assert_eq!(&recv_buf[..m], msg);
    }

    #[test]
    fn transport_buffer_too_small_send() {
        let (mut alice, _) = create_transport_states();

        let msg = b"test message";
        let mut buf = [0u8; 5]; // Too small

        let result = alice.send(msg, &mut buf);
        assert!(matches!(result, Err(TransportError::BufferTooSmall)));
    }

    #[test]
    fn transport_buffer_too_small_receive() {
        let (mut alice, mut bob) = create_transport_states();

        let msg = b"test message";
        let mut send_buf = [0u8; 2048];
        let mut recv_buf = [0u8; 5]; // Too small

        let n = alice.send(msg, &mut send_buf).unwrap();
        let result = bob.receive(&send_buf[..n], &mut recv_buf);
        assert!(matches!(result, Err(TransportError::BufferTooSmall)));
    }

    #[test]
    fn transport_too_short_receive() {
        let (_, mut bob) = create_transport_states();

        let mut recv_buf = [0u8; 2048];
        let short_msg = [0u8; 10]; // Too short (less than tag_len)

        let result = bob.receive(&short_msg, &mut recv_buf);
        assert!(matches!(result, Err(TransportError::TooShort)));
    }

    #[test]
    fn transport_invalid_state_from_unfinished_handshake() {
        let pattern = noise_nn();
        let alice = NqHandshakeCore::<
            crate::crypto::dh::X25519,
            ChaChaPoly,
            Sha256,
            crate::crypto::rng::DefaultRng,
        >::new(pattern, &[], true, None, None, None, None)
        .unwrap();

        // Try to finalize before handshake is complete
        let result = alice.finalize();
        assert!(matches!(result, Err(HandshakeError::InvalidState)));
    }

    #[test]
    fn transport_one_way_violation_responder_send() {
        // Create a one-way handshake (N pattern)
        // N pattern: <- s (responder's static key is known to initiator)
        let pattern = crate::handshakepattern::noise_n();
        let mut rng = crate::crypto::rng::DefaultRng::default();
        let bob_static = crate::crypto::dh::X25519::genkey_rng(&mut rng).unwrap();
        let bob_static_pub = bob_static.public.clone();
        let mut alice = NqHandshakeCore::<
            crate::crypto::dh::X25519,
            ChaChaPoly,
            Sha256,
            crate::crypto::rng::DefaultRng,
        >::new(
            pattern.clone(),
            &[],
            true,
            None,
            None,
            Some(bob_static_pub),
            None,
        )
        .unwrap();
        let mut bob = NqHandshakeCore::<
            crate::crypto::dh::X25519,
            ChaChaPoly,
            Sha256,
            crate::crypto::rng::DefaultRng,
        >::new(pattern, &[], false, Some(bob_static), None, None, None)
        .unwrap();

        let mut alice_buf = [0u8; 2048];
        let mut bob_buf = [0u8; 2048];

        // Complete one-way handshake
        let n = alice.write_message(&[], &mut alice_buf).unwrap();
        let _ = bob.read_message(&alice_buf[..n], &mut bob_buf).unwrap();

        let mut bob_transport = bob.finalize().unwrap();

        // Bob (responder) should not be able to send in one-way handshake
        let msg = b"test";
        let mut buf = [0u8; 2048];
        let result = bob_transport.send(msg, &mut buf);
        assert!(matches!(result, Err(TransportError::OneWayViolation)));
    }

    #[test]
    fn transport_one_way_violation_initiator_receive() {
        // Create a one-way handshake (N pattern)
        // N pattern: <- s (responder's static key is known to initiator)
        let pattern = crate::handshakepattern::noise_n();
        let mut rng = crate::crypto::rng::DefaultRng::default();
        let bob_static = crate::crypto::dh::X25519::genkey_rng(&mut rng).unwrap();
        let bob_static_pub = bob_static.public.clone();
        let mut alice = NqHandshakeCore::<
            crate::crypto::dh::X25519,
            ChaChaPoly,
            Sha256,
            crate::crypto::rng::DefaultRng,
        >::new(
            pattern.clone(),
            &[],
            true,
            None,
            None,
            Some(bob_static_pub),
            None,
        )
        .unwrap();
        let mut bob = NqHandshakeCore::<
            crate::crypto::dh::X25519,
            ChaChaPoly,
            Sha256,
            crate::crypto::rng::DefaultRng,
        >::new(pattern, &[], false, Some(bob_static), None, None, None)
        .unwrap();

        let mut alice_buf = [0u8; 2048];
        let mut bob_buf = [0u8; 2048];

        // Complete one-way handshake
        let n = alice.write_message(&[], &mut alice_buf).unwrap();
        let _ = bob.read_message(&alice_buf[..n], &mut bob_buf).unwrap();

        let mut alice_transport = alice.finalize().unwrap();

        // Alice (initiator) should not be able to receive in one-way handshake
        let mut buf = [0u8; 2048];
        let fake_msg = [0u8; 32]; // Fake encrypted message
        let result = alice_transport.receive(&fake_msg, &mut buf);
        assert!(matches!(result, Err(TransportError::OneWayViolation)));
    }

    #[test]
    fn transport_nonce_management() {
        let (mut alice, mut bob) = create_transport_states();

        // Check initial nonces
        assert_eq!(alice.sending_nonce(), 0);
        assert_eq!(alice.receiving_nonce(), 0);
        assert_eq!(bob.sending_nonce(), 0);
        assert_eq!(bob.receiving_nonce(), 0);

        // Send/receive messages to increment nonces
        let msg = b"test";
        let mut send_buf = [0u8; 2048];
        let mut recv_buf = [0u8; 2048];

        let n = alice.send(msg, &mut send_buf).unwrap();
        bob.receive(&send_buf[..n], &mut recv_buf).unwrap();

        // Nonces should have incremented
        assert_eq!(alice.sending_nonce(), 1);
        assert_eq!(bob.receiving_nonce(), 1);

        // Test nonce setting
        alice.set_receiving_nonce(42);
        assert_eq!(alice.receiving_nonce(), 42);
    }

    #[test]
    fn transport_rekey() {
        let (mut alice, mut bob) = create_transport_states();

        let msg = b"test";
        let mut send_buf = [0u8; 2048];
        let mut recv_buf = [0u8; 2048];

        // Send a message
        let n = alice.send(msg, &mut send_buf).unwrap();
        bob.receive(&send_buf[..n], &mut recv_buf).unwrap();

        // Rekey sender
        alice.rekey_sender().unwrap();
        bob.rekey_receiver().unwrap();

        // Should still be able to communicate after rekey
        let n = alice.send(msg, &mut send_buf).unwrap();
        let m = bob.receive(&send_buf[..n], &mut recv_buf).unwrap();
        assert_eq!(&recv_buf[..m], msg);
    }

    #[test]
    fn transport_send_in_place() {
        let (mut alice, mut bob) = create_transport_states();

        let mut msg = [0u8; 2048];
        msg[..13].copy_from_slice(b"Hello, world!");
        let msg_len = 13;

        let mut recv_buf = [0u8; 2048];

        // Send in-place
        let n = alice.send_in_place(&mut msg, msg_len).unwrap();
        let m = bob.receive(&msg[..n], &mut recv_buf).unwrap();
        assert_eq!(&recv_buf[..m], b"Hello, world!");
    }

    #[test]
    fn transport_receive_in_place() {
        let (mut alice, mut bob) = create_transport_states();

        let msg = b"Hello, world!";
        let mut send_buf = [0u8; 2048];
        let mut recv_buf = [0u8; 2048];

        // Send normally
        let n = alice.send(msg, &mut send_buf).unwrap();
        recv_buf[..n].copy_from_slice(&send_buf[..n]);

        // Receive in-place
        let m = bob.receive_in_place(&mut recv_buf, n).unwrap();
        assert_eq!(&recv_buf[..m], msg);
    }
}
