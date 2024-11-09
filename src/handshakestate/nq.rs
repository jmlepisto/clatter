//! Non-post-quantum Noise handshake implementation

use core::fmt::Write;

use arrayvec::ArrayString;
use rand_core::{CryptoRng, RngCore};

use super::HandshakeInternals;
use crate::bytearray::ByteArray;
use crate::error::{HandshakeError, HandshakeResult};
use crate::handshakepattern::{HandshakePattern, Token};
use crate::handshakestate::HandshakeStatus;
use crate::symmetricstate::SymmetricState;
use crate::traits::{Cipher, Dh, Handshaker, HandshakerInternal, Hash};

/// Non-post-quantum Noise handshake
pub struct NqHandshake<'a, DH, C, H, RNG>
where
    DH: Dh,
    C: Cipher,
    H: Hash,
    RNG: RngCore + CryptoRng,
{
    // Internal, we can live with this
    #[allow(clippy::type_complexity)]
    internals: HandshakeInternals<'a, C, H, RNG, DH::Key, DH::PubKey, DH::Key, DH::PubKey>,
}

impl<'a, DH, C, H, RNG> NqHandshake<'a, DH, C, H, RNG>
where
    DH: Dh,
    C: Cipher,
    H: Hash,
    RNG: RngCore + CryptoRng,
{
    /// Initialize new non-post-quantum handshake
    ///
    /// # Arguments:
    /// * `pattern` - Handshake pattern
    /// * `prolopgue` - Optional prologue data for the handshake
    /// * `initiator` - True if we are the initiator
    /// * `s` - Our static secret key
    /// * `e` - Our ephemeral secret key - Shouldn't usually be provided manually
    /// * `rs` - Peer public static key
    /// * `re` - Peer public ephemeral key - Shouldn't usually be provided manually
    /// * `rng` - RNG to use during the handshake
    ///
    /// # Generic parameters:
    /// * `DH` - DH algorithm to use
    /// * `C` - Cipher algorithm to use
    /// * `H` - Hashing algorithm to use
    #[allow(clippy::too_many_arguments)] // Okay for now
    pub fn new(
        pattern: HandshakePattern,
        prologue: &[u8],
        initiator: bool,
        s: Option<DH::Key>,
        e: Option<DH::Key>,
        rs: Option<DH::PubKey>,
        re: Option<DH::PubKey>,
        rng: &'a mut RNG,
    ) -> Result<NqHandshake<'a, DH, C, H, RNG>, HandshakeError> {
        // No KEMs tolerated here
        assert!(!pattern.is_kem());

        // Initialize symmetric state and mix in prologue
        let mut ss = SymmetricState::new(&Self::build_name(&pattern));
        ss.mix_hash(prologue);

        // Mix in possible initiator pre-shared keys
        for pre_shared in pattern.get_initiator_pre_shared() {
            match pre_shared {
                Token::S => {
                    if initiator {
                        ss.mix_hash(
                            DH::pubkey(s.as_ref().ok_or(HandshakeError::MissingMaterial)?)
                                .as_slice(),
                        );
                    } else {
                        ss.mix_hash(
                            rs.as_ref()
                                .ok_or(HandshakeError::MissingMaterial)?
                                .as_slice(),
                        );
                    };
                }
                _ => {
                    panic!("Invalid pre-shared token in pattern");
                }
            }
        }

        // Mix in possible responder pre-shared keys
        for pre_shared in pattern.get_responder_pre_shared() {
            match pre_shared {
                Token::S => {
                    if initiator {
                        ss.mix_hash(
                            rs.as_ref()
                                .ok_or(HandshakeError::MissingMaterial)?
                                .as_slice(),
                        );
                    } else {
                        ss.mix_hash(
                            DH::pubkey(s.as_ref().ok_or(HandshakeError::MissingMaterial)?)
                                .as_slice(),
                        );
                    };
                }
                Token::E => {
                    if initiator {
                        ss.mix_hash(
                            re.as_ref()
                                .ok_or(HandshakeError::MissingMaterial)?
                                .as_slice(),
                        );
                    } else {
                        ss.mix_hash(
                            DH::pubkey(e.as_ref().ok_or(HandshakeError::MissingMaterial)?)
                                .as_slice(),
                        );
                    };
                }
                _ => {
                    panic!("Invalid pre-shared token in pattern");
                }
            }
        }

        let status = if initiator {
            HandshakeStatus::Send
        } else {
            HandshakeStatus::Receive
        };

        let internals = HandshakeInternals {
            symmetricstate: ss,
            s,
            e,
            rs,
            re,
            pattern,
            initiator,
            status,
            initiator_pattern_index: 0,
            responder_pattern_index: 0,
            rng,
        };

        let this = Self { internals };

        Ok(this)
    }

    fn dh(a: Option<&DH::Key>, b: Option<&DH::PubKey>) -> HandshakeResult<DH::Output> {
        let a = a.ok_or(HandshakeError::MissingMaterial)?;
        let b = b.ok_or(HandshakeError::MissingMaterial)?;
        let out = DH::dh(a, b)?;
        Ok(out)
    }

    fn map_dh(&self, t: Token) -> HandshakeResult<DH::Output> {
        let out = match t {
            Token::EE => Self::dh(self.internals.e.as_ref(), self.internals.re.as_ref())?,
            Token::ES => {
                if self.is_initiator() {
                    Self::dh(self.internals.e.as_ref(), self.internals.rs.as_ref())?
                } else {
                    Self::dh(self.internals.s.as_ref(), self.internals.re.as_ref())?
                }
            }
            Token::SE => {
                if self.is_initiator() {
                    Self::dh(self.internals.s.as_ref(), self.internals.re.as_ref())?
                } else {
                    Self::dh(self.internals.e.as_ref(), self.internals.rs.as_ref())?
                }
            }
            Token::SS => Self::dh(self.internals.s.as_ref(), self.internals.rs.as_ref())?,
            _ => unreachable!(),
        };

        Ok(out)
    }
}

impl<'a, DH, C, H, RNG> HandshakerInternal<C, H> for NqHandshake<'a, DH, C, H, RNG>
where
    DH: Dh,
    C: Cipher,
    H: Hash,
    RNG: RngCore + CryptoRng,
{
    fn status(&self) -> HandshakeStatus {
        self.internals.status()
    }

    fn set_error(&mut self) {
        self.internals.set_error();
    }

    fn write_message_impl(
        &mut self,
        payload: &[u8],
        out: &mut [u8],
    ) -> crate::error::HandshakeResult<usize> {
        let out_len = payload.len() + self.get_next_message_overhead().unwrap();

        let message = if self.is_initiator() {
            let p = self
                .internals
                .pattern
                .get_initiator_pattern(self.internals.initiator_pattern_index);
            self.internals.initiator_pattern_index += 1;
            p
        } else {
            let p = self
                .internals
                .pattern
                .get_responder_pattern(self.internals.responder_pattern_index);
            self.internals.responder_pattern_index += 1;
            p
        };

        let mut cur = 0_usize;
        for token in message {
            match *token {
                Token::E => {
                    if self.internals.e.is_none() {
                        self.internals.e = Some(DH::genkey(&mut self.internals.rng)?);
                    }

                    let e_pub = DH::pubkey(self.internals.e.as_ref().unwrap());
                    self.internals.symmetricstate.mix_hash(e_pub.as_slice());
                    out[cur..cur + DH::PubKey::len()].copy_from_slice(e_pub.as_slice());
                    cur += DH::PubKey::len();
                }
                Token::S => {
                    if self.internals.s.is_none() {
                        return Err(HandshakeError::MissingMaterial);
                    }

                    let len = if self.internals.symmetricstate.has_key() {
                        DH::PubKey::len() + C::tag_len()
                    } else {
                        DH::PubKey::len()
                    };

                    let encrypted_s_out = &mut out[cur..cur + len];
                    self.internals.symmetricstate.encrypt_and_hash(
                        DH::pubkey(self.internals.s.as_ref().unwrap()).as_slice(),
                        encrypted_s_out,
                    )?;
                    cur += len;
                }
                t @ (Token::EE | Token::ES | Token::SE | Token::SS) => {
                    let dh_result = self.map_dh(t)?;
                    self.internals.symmetricstate.mix_key(dh_result.as_slice());
                }
                _ => panic!("Incompatible pattern"),
            }
        }

        self.internals
            .symmetricstate
            .encrypt_and_hash(payload, &mut out[cur..out_len])?;

        self.internals.update_hs_status();
        Ok(out_len)
    }

    fn read_message_impl(
        &mut self,
        message: &[u8],
        out: &mut [u8],
    ) -> crate::error::HandshakeResult<usize> {
        let out_len = message.len() - self.get_next_message_overhead().unwrap();

        // Consume the next `n` bytes of message data
        let mut message = message;
        let mut get = |n| {
            let ret;
            (ret, message) = message.split_at(n);
            ret
        };

        let message_pattern = if self.internals.initiator {
            let p = self
                .internals
                .pattern
                .get_responder_pattern(self.internals.responder_pattern_index);
            self.internals.responder_pattern_index += 1;
            p
        } else {
            let p = self
                .internals
                .pattern
                .get_initiator_pattern(self.internals.initiator_pattern_index);
            self.internals.initiator_pattern_index += 1;
            p
        };

        for token in message_pattern {
            match *token {
                Token::E => {
                    let re = DH::PubKey::from_slice(get(DH::PubKey::len()));
                    self.internals.symmetricstate.mix_hash(re.as_slice());
                    self.internals.re = Some(re);
                }
                Token::S => {
                    let len = if self.internals.symmetricstate.has_key() {
                        DH::PubKey::len() + C::tag_len()
                    } else {
                        DH::PubKey::len()
                    };

                    let mut rs = DH::PubKey::new_zero();
                    self.internals
                        .symmetricstate
                        .decrypt_and_hash(get(len), rs.as_mut())?;
                    self.internals.rs = Some(rs);
                }
                t @ (Token::EE | Token::ES | Token::SE | Token::SS) => {
                    let dh_result = self.map_dh(t)?;
                    self.internals.symmetricstate.mix_key(dh_result.as_slice());
                }
                _ => panic!("Incompatible pattern"),
            }
        }

        self.internals
            .symmetricstate
            .decrypt_and_hash(message, &mut out[..out_len])?;

        self.internals.update_hs_status();

        Ok(out_len)
    }

    fn get_ciphers(&self) -> crate::cipherstate::CipherStates<C> {
        self.internals.get_ciphers()
    }

    fn get_hash(&self) -> H::Output {
        self.internals.get_hash()
    }

    fn get_pattern(&self) -> HandshakePattern {
        self.internals.pattern.clone()
    }
}

impl<'a, DH, C, H, RNG> Handshaker<C, H> for NqHandshake<'a, DH, C, H, RNG>
where
    DH: Dh,
    C: Cipher,
    H: Hash,
    RNG: RngCore + CryptoRng,
{
    fn is_write_turn(&self) -> bool {
        self.internals.is_write_turn()
    }

    fn is_initiator(&self) -> bool {
        self.internals.initiator
    }

    fn get_next_message_overhead(&self) -> crate::error::HandshakeResult<usize> {
        let message = self.internals.get_next_message()?;

        let mut overhead = 0;
        let mut has_key = self.internals.has_key();

        for &token in message {
            match token {
                Token::E => {
                    overhead += DH::PubKey::len();
                }
                Token::S => {
                    overhead += DH::PubKey::len();
                    if has_key {
                        overhead += C::tag_len();
                    }
                }
                Token::EE | Token::ES | Token::SE | Token::SS => {
                    has_key = true;
                }
                _ => panic!("Incompatible pattern"),
            }
        }

        if has_key {
            overhead += C::tag_len();
        }

        Ok(overhead)
    }

    fn build_name(pattern: &HandshakePattern) -> ArrayString<128> {
        let mut ret = ArrayString::new();
        write!(
            &mut ret,
            "Noise_{}_{}_{}_{}",
            pattern.get_name(),
            DH::name(),
            C::name(),
            H::name()
        )
        .unwrap();
        ret
    }
}
