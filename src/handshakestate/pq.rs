//! Post-quantum Noise handshake implementation

use core::fmt::Write;

use arrayvec::{ArrayString, ArrayVec};

use super::HandshakeInternals;
use crate::bytearray::ByteArray;
use crate::cipherstate::CipherStates;
use crate::constants::{MAX_PSKS, PSK_LEN};
use crate::error::{HandshakeError, HandshakeResult};
use crate::handshakepattern::{HandshakePattern, Token};
use crate::handshakestate::HandshakeStatus;
use crate::symmetricstate::SymmetricState;
use crate::traits::{Cipher, Handshaker, HandshakerInternal, Hash, Kem, Rng};
use crate::KeyPair;

/// Post-quantum Noise handshake
#[cfg(feature = "getrandom")]
pub type PqHandshake<EKEM, SKEM, C, H> =
    PqHandshakeCore<EKEM, SKEM, C, H, crate::crypto::rng::DefaultRng>;

/// Post-quantum Noise handshake core with a generic RNG provider
#[derive(Clone)]
pub struct PqHandshakeCore<EKEM, SKEM, C, H, RNG>
where
    EKEM: Kem,
    SKEM: Kem,
    C: Cipher,
    H: Hash,
    RNG: Rng,
{
    // Internal, we can live with this
    #[allow(clippy::type_complexity)]
    internals:
        HandshakeInternals<C, H, RNG, SKEM::SecretKey, SKEM::PubKey, EKEM::SecretKey, EKEM::PubKey>,
}

impl<EKEM, SKEM, CIPHER, HASH, RNG> PqHandshakeCore<EKEM, SKEM, CIPHER, HASH, RNG>
where
    EKEM: Kem,
    SKEM: Kem,
    CIPHER: Cipher,
    HASH: Hash,
    RNG: Rng,
{
    /// Initialize new post-quantum handshake
    ///
    /// # Arguments
    /// * `pattern` - Handshake pattern
    /// * `prologue` - Optional prologue data for the handshake
    /// * `initiator` - True if we are the initiator
    /// * `s` - Our static keys
    /// * `e` - Our ephemeral keys - Shouldn't usually be provided manually
    /// * `rs` - Peer public static key
    /// * `re` - Peer public ephemeral key - Shouldn't usually be provided manually
    ///
    /// # Generic parameters
    /// * `EKEM` - KEM algorithm to use for ephemeral key encapsulation
    /// * `SKEM` - KEM algorithm to use for static key encapsulation
    /// * `CIPHER` - Cipher algorithm to use
    /// * `HASH` - Hashing algorithm to use
    /// * `RNG` - RNG to use
    ///
    /// # Panics
    /// * Panics if initialized with a NQ pattern
    #[allow(clippy::too_many_arguments)] // Okay for now
    pub fn new(
        pattern: HandshakePattern,
        prologue: &[u8],
        initiator: bool,
        s: Option<KeyPair<SKEM::PubKey, SKEM::SecretKey>>,
        e: Option<KeyPair<EKEM::PubKey, EKEM::SecretKey>>,
        rs: Option<SKEM::PubKey>,
        re: Option<EKEM::PubKey>,
    ) -> Result<PqHandshakeCore<EKEM, SKEM, CIPHER, HASH, RNG>, HandshakeError> {
        // Can't KEM without KEM, right
        assert!(pattern.is_kem());

        // Initialize symmetric state and mix in prologue
        let mut ss = SymmetricState::new(&Self::build_name(&pattern));
        ss.mix_hash(prologue);

        // Mix in possible initiator pre-shared keys
        for pre_shared in pattern.get_initiator_pre_shared() {
            match pre_shared {
                Token::S => {
                    if initiator {
                        ss.mix_hash(
                            s.as_ref()
                                .ok_or(HandshakeError::MissingMaterial)?
                                .public
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
                            s.as_ref()
                                .ok_or(HandshakeError::MissingMaterial)?
                                .public
                                .as_slice(),
                        );
                    };
                }
                Token::E => {
                    if initiator {
                        let re_bytes = re
                            .as_ref()
                            .ok_or(HandshakeError::MissingMaterial)?
                            .as_slice();
                        ss.mix_hash(re_bytes);
                        if pattern.has_psk() {
                            ss.mix_key(re_bytes);
                        }
                    } else {
                        let e_bytes = e
                            .as_ref()
                            .ok_or(HandshakeError::MissingMaterial)?
                            .public
                            .as_slice();
                        ss.mix_hash(e_bytes);
                        if pattern.has_psk() {
                            ss.mix_key(e_bytes);
                        }
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
            initiator,
            pattern,
            status,
            initiator_pattern_index: 0,
            responder_pattern_index: 0,
            psks: ArrayVec::<[u8; PSK_LEN], MAX_PSKS>::new(),
            rng: RNG::default(),
        };

        let this = Self { internals };

        Ok(this)
    }
}

impl<EKEM, SKEM, C, H, RNG> HandshakerInternal<C, H> for PqHandshakeCore<EKEM, SKEM, C, H, RNG>
where
    EKEM: Kem,
    SKEM: Kem,
    C: Cipher,
    H: Hash,
    RNG: Rng,
{
    fn status(&self) -> HandshakeStatus {
        self.internals.status()
    }

    fn set_error(&mut self) {
        self.internals.set_error();
    }

    fn write_message_impl(&mut self, payload: &[u8], out: &mut [u8]) -> HandshakeResult<usize> {
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
                        self.internals.e = Some(EKEM::genkey_rng(&mut self.internals.rng)?);
                    }

                    let e_pub = &self.internals.e.as_ref().unwrap().public;
                    self.internals.symmetricstate.mix_hash(e_pub.as_slice());
                    if self.get_pattern().has_psk() {
                        self.internals.symmetricstate.mix_key(e_pub.as_slice());
                    }
                    out[cur..cur + EKEM::PubKey::len()].copy_from_slice(e_pub.as_slice());
                    cur += EKEM::PubKey::len();
                }
                Token::S => {
                    if self.internals.s.is_none() {
                        return Err(HandshakeError::MissingMaterial);
                    }

                    let len = if self.internals.symmetricstate.has_key() {
                        SKEM::PubKey::len() + C::tag_len()
                    } else {
                        SKEM::PubKey::len()
                    };

                    let encrypted_s_out = &mut out[cur..cur + len];
                    self.internals.symmetricstate.encrypt_and_hash(
                        self.internals
                            .s
                            .as_ref()
                            .ok_or(HandshakeError::MissingMaterial)?
                            .public
                            .as_slice(),
                        encrypted_s_out,
                    )?;
                    cur += len;
                }
                Token::Psk => {
                    if let Some(psk) = self.internals.psks.pop_at(0) {
                        self.internals.symmetricstate.mix_key_and_hash(&psk);
                    } else {
                        return Err(HandshakeError::PskMissing);
                    }
                }
                Token::Ekem => {
                    // Should have peer e
                    if self.internals.re.is_none() {
                        return Err(HandshakeError::MissingMaterial);
                    }

                    let (ct, ss) = EKEM::encapsulate(
                        self.internals.re.as_ref().unwrap().as_slice(),
                        &mut self.internals.rng,
                    )?;
                    self.internals.symmetricstate.mix_hash(ct.as_slice());
                    self.internals.symmetricstate.mix_key(ss.as_slice());
                    out[cur..cur + EKEM::Ct::len()].copy_from_slice(ct.as_slice());
                    cur += EKEM::Ct::len();
                }
                Token::Skem => {
                    // Should have peer s
                    if self.internals.rs.is_none() {
                        return Err(HandshakeError::MissingMaterial);
                    }

                    let len = if self.internals.symmetricstate.has_key() {
                        SKEM::Ct::len() + C::tag_len()
                    } else {
                        SKEM::Ct::len()
                    };

                    let encrypt_out = &mut out[cur..cur + len];
                    let (ct, ss) = SKEM::encapsulate(
                        self.internals.rs.as_ref().unwrap().as_slice(),
                        &mut self.internals.rng,
                    )?;
                    self.internals
                        .symmetricstate
                        .encrypt_and_hash(ct.as_slice(), encrypt_out)?;
                    self.internals
                        .symmetricstate
                        .mix_key_and_hash(ss.as_slice());
                    cur += len;
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

    fn read_message_impl(&mut self, message: &[u8], out: &mut [u8]) -> HandshakeResult<usize> {
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
                    let re = EKEM::PubKey::from_slice(get(EKEM::PubKey::len()));
                    self.internals.symmetricstate.mix_hash(re.as_slice());
                    if self.get_pattern().has_psk() {
                        self.internals.symmetricstate.mix_key(re.as_slice());
                    }
                    self.internals.re = Some(re);
                }
                Token::S => {
                    let len = if self.internals.symmetricstate.has_key() {
                        SKEM::PubKey::len() + C::tag_len()
                    } else {
                        SKEM::PubKey::len()
                    };

                    let mut rs = SKEM::PubKey::new_zero();
                    self.internals
                        .symmetricstate
                        .decrypt_and_hash(get(len), rs.as_mut())?;
                    self.internals.rs = Some(rs);
                }
                Token::Psk => {
                    if let Some(psk) = self.internals.psks.pop_at(0) {
                        self.internals.symmetricstate.mix_key_and_hash(&psk);
                    } else {
                        return Err(HandshakeError::PskMissing);
                    }
                }
                Token::Ekem => {
                    let ct = get(EKEM::Ct::len());
                    self.internals.symmetricstate.mix_hash(ct);
                    let ss = EKEM::decapsulate(
                        ct,
                        self.internals.e.as_ref().unwrap().secret.as_slice(),
                    )?;
                    self.internals.symmetricstate.mix_key(ss.as_slice());
                }
                Token::Skem => {
                    let len = if self.internals.symmetricstate.has_key() {
                        SKEM::Ct::len() + C::tag_len()
                    } else {
                        SKEM::Ct::len()
                    };

                    let ct_enc = get(len);
                    let mut ct = SKEM::Ct::new_zero();
                    self.internals
                        .symmetricstate
                        .decrypt_and_hash(ct_enc, ct.as_mut())?;
                    let ss = SKEM::decapsulate(
                        ct.as_slice(),
                        self.internals.s.as_ref().unwrap().secret.as_slice(),
                    )?;
                    self.internals
                        .symmetricstate
                        .mix_key_and_hash(ss.as_slice());
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

    fn get_ciphers(&self) -> CipherStates<C> {
        self.internals.get_ciphers()
    }

    fn get_hash(&self) -> H::Output {
        self.internals.get_hash()
    }

    fn mix_hash(&mut self, data: &[u8]) {
        self.internals.symmetricstate.mix_hash(data)
    }

    fn mix_key_and_hash(&mut self, data: &[u8]) {
        self.internals.symmetricstate.mix_key_and_hash(data)
    }

    fn get_pattern(&self) -> HandshakePattern {
        self.internals.pattern.clone()
    }
}

impl<EKEM, SKEM, C, H, RNG> Handshaker<C, H> for PqHandshakeCore<EKEM, SKEM, C, H, RNG>
where
    EKEM: Kem,
    SKEM: Kem,
    C: Cipher,
    H: Hash,
    RNG: Rng,
{
    type E = EKEM::PubKey;
    type S = SKEM::PubKey;

    fn push_psk(&mut self, psk: &[u8]) {
        self.internals.push_psk(psk);
    }

    fn is_write_turn(&self) -> bool {
        self.internals.is_write_turn()
    }

    fn is_initiator(&self) -> bool {
        self.internals.initiator
    }

    fn get_next_message_overhead(&self) -> HandshakeResult<usize> {
        let message = self.internals.get_next_message()?;

        let mut overhead = 0;
        let mut has_key = self.internals.has_key();
        let has_psk = self.get_pattern().has_psk();

        for &token in message {
            match token {
                Token::E => {
                    overhead += EKEM::PubKey::len();
                    if has_psk {
                        has_key = true;
                    }
                }
                Token::S => {
                    overhead += SKEM::PubKey::len();
                    if has_key {
                        overhead += C::tag_len();
                    }
                }
                Token::Ekem => {
                    overhead += EKEM::Ct::len();
                    has_key = true;
                }
                Token::Skem => {
                    overhead += SKEM::Ct::len();
                    if has_key {
                        overhead += C::tag_len();
                    }
                    has_key = true;
                }
                Token::Psk => {
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

        if SKEM::name() == EKEM::name() {
            // If SKEM and EKEM are the same, we can build the pattern name as usual.
            // This is compatible with Nyquist.
            write!(
                &mut ret,
                "Noise_{}_{}_{}_{}",
                pattern.get_name(),
                EKEM::name(),
                C::name(),
                H::name()
            )
            .unwrap();
        } else {
            // If SKEM and EKEM are different, we will use our own custom naming.
            // Both KEMs are included in the pattern name, separated by a "+" sign.
            write!(
                &mut ret,
                "Noise_{}_{}+{}_{}_{}",
                pattern.get_name(),
                EKEM::name(),
                SKEM::name(),
                C::name(),
                H::name()
            )
            .unwrap();
        }
        ret
    }

    fn get_remote_static(&self) -> Option<Self::S> {
        self.internals.rs.clone()
    }

    fn get_remote_ephemeral(&self) -> Option<Self::E> {
        self.internals.re.clone()
    }
}
