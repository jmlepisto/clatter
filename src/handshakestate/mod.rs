use arrayvec::ArrayVec;
use zeroize::Zeroize;

use crate::bytearray::ByteArray;
use crate::cipherstate::CipherStates;
use crate::constants::{MAX_PSKS, PSK_LEN};
use crate::error::{HandshakeError, HandshakeResult};
use crate::handshakepattern::{HandshakePattern, Token};
use crate::symmetricstate::SymmetricState;
use crate::traits::{Cipher, Hash, Rng};
use crate::KeyPair;

pub mod dual_layer;
pub mod hybrid;
pub mod hybrid_dual_layer;
pub mod nq;
pub mod pq;

/// Handshake status
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum HandshakeStatus {
    // Our turn to send
    Send,
    // Our turn to receive
    Receive,
    // Handshake ready
    Ready,
    // Handshake error - can't continue
    Error,
}

#[derive(Clone)]
pub(crate) struct HandshakeInternals<C, H, RNG, K, P, EK, EP>
where
    C: Cipher,
    H: Hash,
    RNG: Rng,
    K: ByteArray,
    P: ByteArray,
    EK: ByteArray,
    EP: ByteArray,
{
    symmetricstate: SymmetricState<C, H>,
    s: Option<KeyPair<P, K>>,
    e: Option<KeyPair<EP, EK>>,
    rs: Option<P>,
    re: Option<EP>,
    pattern: HandshakePattern,
    initiator: bool,
    status: HandshakeStatus,
    initiator_pattern_index: usize,
    responder_pattern_index: usize,
    psks: ArrayVec<[u8; PSK_LEN], MAX_PSKS>,
    rng: RNG,
}

impl<C, H, RNG, K, P, EK, EP> HandshakeInternals<C, H, RNG, K, P, EK, EP>
where
    C: Cipher,
    H: Hash,
    RNG: Rng,
    K: ByteArray,
    P: ByteArray,
    EK: ByteArray,
    EP: ByteArray,
{
    fn set_error(&mut self) {
        self.status = HandshakeStatus::Error;
        self.symmetricstate.zeroize();
    }

    fn status(&self) -> HandshakeStatus {
        self.status
    }

    /// Get next message we are about to send or receive
    fn get_next_message(&self) -> HandshakeResult<&[Token]> {
        let message = match (self.initiator, self.status) {
            (true, HandshakeStatus::Send) | (false, HandshakeStatus::Receive) => self
                .pattern
                .get_initiator_pattern(self.initiator_pattern_index),
            (true, HandshakeStatus::Receive) | (false, HandshakeStatus::Send) => self
                .pattern
                .get_responder_pattern(self.responder_pattern_index),
            _ => return Err(HandshakeError::InvalidState),
        };

        Ok(message)
    }

    fn has_key(&self) -> bool {
        self.symmetricstate.has_key()
    }

    /// Check if we have already completed the handshake pattern and if so, update internal state.
    fn update_hs_status(&mut self) {
        if self.initiator_pattern_index == self.pattern.get_initiator_pattern_len()
            && self.responder_pattern_index == self.pattern.get_responder_pattern_len()
        {
            self.status = HandshakeStatus::Ready;
        } else if self.status == HandshakeStatus::Receive {
            self.status = HandshakeStatus::Send
        } else {
            self.status = HandshakeStatus::Receive
        }
    }

    pub(crate) fn is_write_turn(&self) -> bool {
        self.status == HandshakeStatus::Send
    }

    pub(crate) fn get_hash(&self) -> H::Output {
        self.symmetricstate.get_hash()
    }

    pub(crate) fn get_ciphers(&self) -> CipherStates<C> {
        self.symmetricstate.split()
    }

    fn push_psk(&mut self, psk: &[u8]) {
        self.psks.push(ByteArray::from_slice(psk));
    }
}
