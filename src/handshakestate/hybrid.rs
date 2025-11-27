//! Hybrid (DH + PQ KEM) Noise handshake implementation

use core::fmt::Write;

use arrayvec::{ArrayString, ArrayVec};

use super::HandshakeInternals;
use crate::bytearray::ByteArray;
use crate::cipherstate::CipherStates;
use crate::constants::{MAX_PSKS, PSK_LEN};
use crate::error::{HandshakeError, HandshakeResult};
use crate::handshakepattern::{HandshakePattern, HandshakeType, Token};
use crate::handshakestate::HandshakeStatus;
use crate::symmetricstate::SymmetricState;
use crate::traits::{Cipher, Dh, Handshaker, HandshakerInternal, Hash, Kem, Rng};
use crate::KeyPair;

/// Parameters for initializing a [`HybridHandshake`]
pub struct HybridHandshakeParams<'a, DH, EKEM, SKEM>
where
    DH: Dh,
    EKEM: Kem,
    SKEM: Kem,
{
    /// Handshake pattern (must be a hybrid pattern)
    pub pattern: HandshakePattern,
    /// True if we are the initiator
    pub initiator: bool,
    /// Optional prologue data for the handshake
    pub prologue: Option<&'a [u8]>,
    /// Our static DH keys
    pub s: Option<KeyPair<DH::PubKey, DH::PrivateKey>>,
    /// Our ephemeral DH keys - Shouldn't usually be provided manually
    pub e: Option<KeyPair<DH::PubKey, DH::PrivateKey>>,
    /// Peer public static DH key
    pub rs: Option<DH::PubKey>,
    /// Peer public ephemeral DH key - Shouldn't usually be provided manually
    pub re: Option<DH::PubKey>,
    /// Our static KEM keys
    pub s_kem: Option<KeyPair<SKEM::PubKey, SKEM::SecretKey>>,
    /// Our ephemeral KEM keys - Shouldn't usually be provided manually
    pub e_kem: Option<KeyPair<EKEM::PubKey, EKEM::SecretKey>>,
    /// Peer public static KEM key
    pub rs_kem: Option<SKEM::PubKey>,
    /// Peer public ephemeral KEM key - Shouldn't usually be provided manually
    pub re_kem: Option<EKEM::PubKey>,
}

impl<'a, DH, EKEM, SKEM> HybridHandshakeParams<'a, DH, EKEM, SKEM>
where
    DH: Dh,
    EKEM: Kem,
    SKEM: Kem,
{
    /// Create new handshake parameters
    ///
    /// # Arguments
    /// * `pattern` - Handshake pattern
    /// * `initiator` - True if we are the initiating party
    pub fn new(pattern: HandshakePattern, initiator: bool) -> Self {
        Self {
            pattern,
            initiator,
            prologue: None,
            s: None,
            e: None,
            rs: None,
            re: None,
            s_kem: None,
            e_kem: None,
            rs_kem: None,
            re_kem: None,
        }
    }

    /// Set handshake prologue bytes
    pub fn with_prologue(mut self, prologue: &'a [u8]) -> Self {
        self.prologue = Some(prologue);
        self
    }

    /// Set our static DH keys
    pub fn with_s(mut self, s: KeyPair<DH::PubKey, DH::PrivateKey>) -> Self {
        self.s = Some(s);
        self
    }

    /// Set our ephemeral DH keys
    pub fn with_e(mut self, e: KeyPair<DH::PubKey, DH::PrivateKey>) -> Self {
        self.e = Some(e);
        self
    }

    /// Set peer public static DH key
    pub fn with_rs(mut self, rs: DH::PubKey) -> Self {
        self.rs = Some(rs);
        self
    }

    /// Set peer public ephemeral DH key
    pub fn with_re(mut self, re: DH::PubKey) -> Self {
        self.re = Some(re);
        self
    }

    /// Set our static KEM keys
    pub fn with_s_kem(mut self, s_kem: KeyPair<SKEM::PubKey, SKEM::SecretKey>) -> Self {
        self.s_kem = Some(s_kem);
        self
    }

    /// Set our ephemeral KEM keys
    pub fn with_e_kem(mut self, e_kem: KeyPair<EKEM::PubKey, EKEM::SecretKey>) -> Self {
        self.e_kem = Some(e_kem);
        self
    }

    /// Set peer public static KEM key
    pub fn with_rs_kem(mut self, rs_kem: SKEM::PubKey) -> Self {
        self.rs_kem = Some(rs_kem);
        self
    }

    /// Set peer public ephemeral KEM key
    pub fn with_re_kem(mut self, re_kem: EKEM::PubKey) -> Self {
        self.re_kem = Some(re_kem);
        self
    }
}

/// Container for a pair of public keys used by the hybrid handshake
pub struct HybridPubKeyPair<D, K> {
    dh: D,
    kem: K,
}

impl<D, K> HybridPubKeyPair<D, K> {
    pub fn new(dh: D, kem: K) -> HybridPubKeyPair<D, K> {
        Self { dh, kem }
    }

    pub fn dh(&self) -> &D {
        &self.dh
    }

    pub fn kem(&self) -> &K {
        &self.kem
    }
}

/// True hybrid (NQ + PQ) Noise handshake
#[cfg(feature = "getrandom")]
pub type HybridHandshake<DH, EKEM, SKEM, C, H> =
    HybridHandshakeCore<DH, EKEM, SKEM, C, H, crate::crypto::rng::DefaultRng>;

/// True hybrid Noise handhsake core with a generic RNG provider
///
/// A handshake which combines both DH and KEM operations. This handshake type accepts handshake patterns with
/// both DH and KEM operations and mixes the results of both exchanges in a single *symmetric state* containing
/// the session keys and hash, achieving true hybrid security against quantum threats while preserving the
/// established safety guarantees of classic algorithms.
///
/// This handshake type accepts handshake patterns with both DH and KEM operations.
/// [`Token::E`]/[`Token::S`] will send/receive both DH and KEM ephemeral/static public keys.
#[derive(Clone)]
pub struct HybridHandshakeCore<DH, EKEM, SKEM, C, H, RNG>
where
    DH: Dh,
    EKEM: Kem,
    SKEM: Kem,
    C: Cipher,
    H: Hash,
    RNG: Rng,
{
    #[allow(clippy::type_complexity)]
    dh_internals:
        HandshakeInternals<C, H, RNG, DH::PrivateKey, DH::PubKey, DH::PrivateKey, DH::PubKey>,
    kem_s: Option<KeyPair<SKEM::PubKey, SKEM::SecretKey>>,
    kem_e: Option<KeyPair<EKEM::PubKey, EKEM::SecretKey>>,
    kem_rs: Option<SKEM::PubKey>,
    kem_re: Option<EKEM::PubKey>,
}

impl<DH, EKEM, SKEM, CIPHER, HASH, RNG> HybridHandshakeCore<DH, EKEM, SKEM, CIPHER, HASH, RNG>
where
    DH: Dh,
    EKEM: Kem,
    SKEM: Kem,
    CIPHER: Cipher,
    HASH: Hash,
    RNG: Rng,
{
    /// Initialize new hybrid handshake
    ///
    /// # Arguments
    /// * `params` - Handshake parameters
    ///
    /// # Generic parameters
    /// * `DH` - DH algorithm to use
    /// * `EKEM` - Ephemeral KEM algorithm to use
    /// * `SKEM` - Static KEM algorithm to use
    /// * `CIPHER` - Cipher algorithm to use
    /// * `HASH` - Hashing algorithm to use
    /// * `RNG` - RNG to use
    ///
    /// # Errors
    /// * [`HandshakeError::InvalidPattern`] if initialized with a non-hybrid pattern
    ///
    /// # Panics
    /// * If the handshake pattern contains invalid pre-shared keys
    pub fn new(params: HybridHandshakeParams<DH, EKEM, SKEM>) -> Result<Self, HandshakeError> {
        let HybridHandshakeParams {
            pattern,
            prologue,
            initiator,
            s,
            e,
            rs,
            re,
            s_kem,
            e_kem,
            rs_kem,
            re_kem,
        } = params;

        // Must be a hybrid pattern (has both DH and KEM)
        if pattern.get_type() != HandshakeType::HYBRID {
            return Err(HandshakeError::InvalidPattern(
                HandshakeType::HYBRID,
                pattern.get_type(),
            ));
        }

        // Initialize symmetric state and mix in prologue
        let mut ss = SymmetricState::new(&Self::build_name(&pattern));

        // Mix in prologue bytes if available
        if let Some(prologue_bytes) = prologue {
            ss.mix_hash(prologue_bytes);
        }

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
                        ss.mix_hash(
                            s_kem
                                .as_ref()
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
                        ss.mix_hash(
                            rs_kem
                                .as_ref()
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
                        ss.mix_hash(
                            rs_kem
                                .as_ref()
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
                        ss.mix_hash(
                            s_kem
                                .as_ref()
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
                        let re_kem_bytes = re_kem
                            .as_ref()
                            .ok_or(HandshakeError::MissingMaterial)?
                            .as_slice();
                        ss.mix_hash(re_bytes);
                        ss.mix_hash(re_kem_bytes);
                        if pattern.has_psk() {
                            ss.mix_key(re_bytes);
                            ss.mix_key(re_kem_bytes);
                        }
                    } else {
                        let e_bytes = e
                            .as_ref()
                            .ok_or(HandshakeError::MissingMaterial)?
                            .public
                            .as_slice();
                        let e_kem_bytes = e_kem
                            .as_ref()
                            .ok_or(HandshakeError::MissingMaterial)?
                            .public
                            .as_slice();
                        ss.mix_hash(e_bytes);
                        ss.mix_hash(e_kem_bytes);
                        if pattern.has_psk() {
                            ss.mix_key(e_bytes);
                            ss.mix_key(e_kem_bytes);
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

        let dh_internals = HandshakeInternals {
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
            psks: ArrayVec::<[u8; PSK_LEN], MAX_PSKS>::new(),
            rng: RNG::default(),
        };

        Ok(Self {
            dh_internals,
            kem_s: s_kem,
            kem_e: e_kem,
            kem_rs: rs_kem,
            kem_re: re_kem,
        })
    }

    fn dh(
        a: Option<&KeyPair<DH::PubKey, DH::PrivateKey>>,
        b: Option<&DH::PubKey>,
    ) -> HandshakeResult<DH::Output> {
        let a = a.ok_or(HandshakeError::MissingMaterial)?;
        let b = b.ok_or(HandshakeError::MissingMaterial)?;
        let out = DH::dh(&a.secret, b)?;
        Ok(out)
    }

    fn map_dh(&self, t: Token) -> HandshakeResult<DH::Output> {
        let out = match t {
            Token::EE => Self::dh(self.dh_internals.e.as_ref(), self.dh_internals.re.as_ref())?,
            Token::ES => {
                if self.is_initiator() {
                    Self::dh(self.dh_internals.e.as_ref(), self.dh_internals.rs.as_ref())?
                } else {
                    Self::dh(self.dh_internals.s.as_ref(), self.dh_internals.re.as_ref())?
                }
            }
            Token::SE => {
                if self.is_initiator() {
                    Self::dh(self.dh_internals.s.as_ref(), self.dh_internals.re.as_ref())?
                } else {
                    Self::dh(self.dh_internals.e.as_ref(), self.dh_internals.rs.as_ref())?
                }
            }
            Token::SS => Self::dh(self.dh_internals.s.as_ref(), self.dh_internals.rs.as_ref())?,
            _ => unreachable!(),
        };

        Ok(out)
    }
}

impl<DH, EKEM, SKEM, C, H, RNG> HandshakerInternal<C, H>
    for HybridHandshakeCore<DH, EKEM, SKEM, C, H, RNG>
where
    DH: Dh,
    EKEM: Kem,
    SKEM: Kem,
    C: Cipher,
    H: Hash,
    RNG: Rng,
{
    fn status(&self) -> HandshakeStatus {
        self.dh_internals.status()
    }

    fn set_error(&mut self) {
        self.dh_internals.set_error();
    }

    fn write_message_impl(&mut self, payload: &[u8], out: &mut [u8]) -> HandshakeResult<usize> {
        let out_len = payload.len() + self.get_next_message_overhead()?;

        let message = if self.is_initiator() {
            let p = self
                .dh_internals
                .pattern
                .get_initiator_pattern(self.dh_internals.initiator_pattern_index);
            self.dh_internals.initiator_pattern_index += 1;
            p
        } else {
            let p = self
                .dh_internals
                .pattern
                .get_responder_pattern(self.dh_internals.responder_pattern_index);
            self.dh_internals.responder_pattern_index += 1;
            p
        };

        let mut cur = 0_usize;
        for token in message {
            match *token {
                Token::E => {
                    // Generate both DH and KEM ephemeral keys if not present
                    if self.dh_internals.e.is_none() {
                        self.dh_internals.e = Some(DH::genkey_rng(&mut self.dh_internals.rng)?);
                    }
                    if self.kem_e.is_none() {
                        self.kem_e = Some(EKEM::genkey_rng(&mut self.dh_internals.rng)?);
                    }

                    // Send DH public key
                    let e_pub = &self.dh_internals.e.as_ref().unwrap().public;
                    self.dh_internals.symmetricstate.mix_hash(e_pub.as_slice());
                    if self.get_pattern().has_psk() {
                        self.dh_internals.symmetricstate.mix_key(e_pub.as_slice());
                    }
                    out[cur..cur + DH::PubKey::len()].copy_from_slice(e_pub.as_slice());
                    cur += DH::PubKey::len();

                    // Send KEM public key
                    let e_kem_pub = &self.kem_e.as_ref().unwrap().public;
                    self.dh_internals
                        .symmetricstate
                        .mix_hash(e_kem_pub.as_slice());
                    if self.get_pattern().has_psk() {
                        self.dh_internals
                            .symmetricstate
                            .mix_key(e_kem_pub.as_slice());
                    }
                    out[cur..cur + EKEM::PubKey::len()].copy_from_slice(e_kem_pub.as_slice());
                    cur += EKEM::PubKey::len();
                }
                Token::S => {
                    if self.dh_internals.s.is_none() || self.kem_s.is_none() {
                        return Err(HandshakeError::MissingMaterial);
                    }

                    let has_key = self.dh_internals.symmetricstate.has_key();

                    // Send DH static key
                    let dh_len = if has_key {
                        DH::PubKey::len() + C::tag_len()
                    } else {
                        DH::PubKey::len()
                    };
                    self.dh_internals.symmetricstate.encrypt_and_hash(
                        self.dh_internals.s.as_ref().unwrap().public.as_slice(),
                        &mut out[cur..cur + dh_len],
                    )?;
                    cur += dh_len;

                    // Send KEM static key
                    let kem_len = if has_key {
                        SKEM::PubKey::len() + C::tag_len()
                    } else {
                        SKEM::PubKey::len()
                    };
                    self.dh_internals.symmetricstate.encrypt_and_hash(
                        self.kem_s.as_ref().unwrap().public.as_slice(),
                        &mut out[cur..cur + kem_len],
                    )?;
                    cur += kem_len;
                }
                Token::Psk => {
                    if let Some(psk) = self.dh_internals.psks.pop_at(0) {
                        self.dh_internals.symmetricstate.mix_key_and_hash(&psk);
                    } else {
                        return Err(HandshakeError::PskMissing);
                    }
                }
                t @ (Token::EE | Token::ES | Token::SE | Token::SS) => {
                    // Perform DH
                    let dh_result = self.map_dh(t)?;
                    self.dh_internals
                        .symmetricstate
                        .mix_key(dh_result.as_slice());
                }
                Token::Ekem => {
                    // Should have peer e
                    if self.kem_re.is_none() {
                        return Err(HandshakeError::MissingMaterial);
                    }

                    let re_kem_pk = self.kem_re.as_ref().unwrap();
                    let (ct, ss) =
                        EKEM::encapsulate(re_kem_pk.as_slice(), &mut self.dh_internals.rng)?;
                    self.dh_internals.symmetricstate.mix_hash(ct.as_slice());
                    self.dh_internals.symmetricstate.mix_key(ss.as_slice());
                    out[cur..cur + EKEM::Ct::len()].copy_from_slice(ct.as_slice());
                    cur += EKEM::Ct::len();
                }
                Token::Skem => {
                    // Should have peer s
                    if self.kem_rs.is_none() {
                        return Err(HandshakeError::MissingMaterial);
                    }

                    let rs_kem_pk = self.kem_rs.as_ref().unwrap();
                    let len = if self.dh_internals.symmetricstate.has_key() {
                        SKEM::Ct::len() + C::tag_len()
                    } else {
                        SKEM::Ct::len()
                    };

                    let encrypt_out = &mut out[cur..cur + len];
                    let (ct, ss) =
                        SKEM::encapsulate(rs_kem_pk.as_slice(), &mut self.dh_internals.rng)?;
                    self.dh_internals
                        .symmetricstate
                        .encrypt_and_hash(ct.as_slice(), encrypt_out)?;
                    self.dh_internals
                        .symmetricstate
                        .mix_key_and_hash(ss.as_slice());
                    cur += len;
                }
            }
        }

        self.dh_internals
            .symmetricstate
            .encrypt_and_hash(payload, &mut out[cur..out_len])?;

        self.dh_internals.update_hs_status();
        Ok(out_len)
    }

    fn read_message_impl(&mut self, message: &[u8], out: &mut [u8]) -> HandshakeResult<usize> {
        let out_len = message.len() - self.get_next_message_overhead()?;

        // Consume the next `n` bytes of message data
        let mut message = message;
        let mut get = |n| {
            let ret;
            (ret, message) = message.split_at(n);
            ret
        };

        let message_pattern = if self.dh_internals.initiator {
            let p = self
                .dh_internals
                .pattern
                .get_responder_pattern(self.dh_internals.responder_pattern_index);
            self.dh_internals.responder_pattern_index += 1;
            p
        } else {
            let p = self
                .dh_internals
                .pattern
                .get_initiator_pattern(self.dh_internals.initiator_pattern_index);
            self.dh_internals.initiator_pattern_index += 1;
            p
        };

        for token in message_pattern {
            match *token {
                Token::E => {
                    // Receive DH public key
                    let re = DH::PubKey::from_slice(get(DH::PubKey::len()));
                    self.dh_internals.symmetricstate.mix_hash(re.as_slice());
                    if self.get_pattern().has_psk() {
                        self.dh_internals.symmetricstate.mix_key(re.as_slice());
                    }
                    self.dh_internals.re = Some(re);

                    // Receive KEM public key
                    let re_kem = EKEM::PubKey::from_slice(get(EKEM::PubKey::len()));
                    self.dh_internals.symmetricstate.mix_hash(re_kem.as_slice());
                    if self.get_pattern().has_psk() {
                        self.dh_internals.symmetricstate.mix_key(re_kem.as_slice());
                    }
                    self.kem_re = Some(re_kem);
                }
                Token::S => {
                    let has_key = self.dh_internals.symmetricstate.has_key();

                    // Receive DH static key
                    let dh_len = if has_key {
                        DH::PubKey::len() + C::tag_len()
                    } else {
                        DH::PubKey::len()
                    };
                    let mut rs = DH::PubKey::new_zero();
                    self.dh_internals
                        .symmetricstate
                        .decrypt_and_hash(get(dh_len), rs.as_mut())?;
                    self.dh_internals.rs = Some(rs);

                    // Receive KEM static key
                    let kem_len = if has_key {
                        SKEM::PubKey::len() + C::tag_len()
                    } else {
                        SKEM::PubKey::len()
                    };
                    let mut rs_kem = SKEM::PubKey::new_zero();
                    self.dh_internals
                        .symmetricstate
                        .decrypt_and_hash(get(kem_len), rs_kem.as_mut())?;
                    self.kem_rs = Some(rs_kem);
                }
                Token::Psk => {
                    if let Some(psk) = self.dh_internals.psks.pop_at(0) {
                        self.dh_internals.symmetricstate.mix_key_and_hash(&psk);
                    } else {
                        return Err(HandshakeError::PskMissing);
                    }
                }
                t @ (Token::EE | Token::ES | Token::SE | Token::SS) => {
                    // Perform DH
                    let dh_result = self.map_dh(t)?;
                    self.dh_internals
                        .symmetricstate
                        .mix_key(dh_result.as_slice());
                }
                Token::Ekem => {
                    let ct = get(EKEM::Ct::len());
                    self.dh_internals.symmetricstate.mix_hash(ct);
                    let ss = EKEM::decapsulate(ct, self.kem_e.as_ref().unwrap().secret.as_slice())?;
                    self.dh_internals.symmetricstate.mix_key(ss.as_slice());
                }
                Token::Skem => {
                    let len = if self.dh_internals.symmetricstate.has_key() {
                        SKEM::Ct::len() + C::tag_len()
                    } else {
                        SKEM::Ct::len()
                    };

                    let ct_enc = get(len);
                    let mut ct = SKEM::Ct::new_zero();
                    self.dh_internals
                        .symmetricstate
                        .decrypt_and_hash(ct_enc, ct.as_mut())?;
                    let ss = SKEM::decapsulate(
                        ct.as_slice(),
                        self.kem_s.as_ref().unwrap().secret.as_slice(),
                    )?;
                    self.dh_internals
                        .symmetricstate
                        .mix_key_and_hash(ss.as_slice());
                }
            }
        }

        self.dh_internals
            .symmetricstate
            .decrypt_and_hash(message, &mut out[..out_len])?;
        self.dh_internals.update_hs_status();

        Ok(out_len)
    }

    fn get_ciphers(&self) -> CipherStates<C> {
        self.dh_internals.get_ciphers()
    }

    fn get_hash(&self) -> H::Output {
        self.dh_internals.get_hash()
    }

    fn mix_hash(&mut self, data: &[u8]) {
        self.dh_internals.symmetricstate.mix_hash(data)
    }

    fn mix_key_and_hash(&mut self, data: &[u8]) {
        self.dh_internals.symmetricstate.mix_key_and_hash(data)
    }

    fn get_pattern(&self) -> HandshakePattern {
        self.dh_internals.pattern.clone()
    }
}

impl<DH, EKEM, SKEM, C, H, RNG> Handshaker<C, H> for HybridHandshakeCore<DH, EKEM, SKEM, C, H, RNG>
where
    DH: Dh,
    EKEM: Kem,
    SKEM: Kem,
    C: Cipher,
    H: Hash,
    RNG: Rng,
{
    type E = HybridPubKeyPair<DH::PubKey, EKEM::PubKey>;
    type S = HybridPubKeyPair<DH::PubKey, SKEM::PubKey>;

    fn push_psk(&mut self, psk: &[u8]) {
        self.dh_internals.push_psk(psk);
    }

    fn is_write_turn(&self) -> bool {
        self.dh_internals.is_write_turn()
    }

    fn is_initiator(&self) -> bool {
        self.dh_internals.initiator
    }

    fn get_next_message_overhead(&self) -> HandshakeResult<usize> {
        let message = self.dh_internals.get_next_message()?;

        let mut overhead = 0;
        let mut has_key = self.dh_internals.has_key();
        let has_psk = self.get_pattern().has_psk();

        for &token in message {
            match token {
                Token::E => {
                    overhead += DH::PubKey::len();
                    overhead += EKEM::PubKey::len();
                    if has_psk {
                        has_key = true;
                    }
                }
                Token::S => {
                    overhead += DH::PubKey::len();
                    overhead += SKEM::PubKey::len();
                    if has_key {
                        overhead += C::tag_len() * 2; // One tag per key
                    }
                }
                Token::EE | Token::ES | Token::SE | Token::SS => {
                    has_key = true;
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
            }
        }

        if has_key {
            overhead += C::tag_len();
        }

        Ok(overhead)
    }

    fn build_name(pattern: &HandshakePattern) -> ArrayString<128> {
        let mut ret = ArrayString::new();

        if EKEM::name() == SKEM::name() {
            // If EKEM and SKEM are the same, use simpler naming
            write!(
                &mut ret,
                "Noise_{}_{}+{}_{}_{}",
                pattern.get_name(),
                DH::name(),
                EKEM::name(),
                C::name(),
                H::name()
            )
            .unwrap();
        } else {
            // If EKEM and SKEM are different, include both
            write!(
                &mut ret,
                "Noise_{}_{}+{}+{}_{}_{}",
                pattern.get_name(),
                DH::name(),
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
        match (self.dh_internals.rs.as_ref(), self.kem_rs.as_ref()) {
            (Some(dh), Some(kem)) => Some(HybridPubKeyPair::new(dh.clone(), kem.clone())),
            _ => None,
        }
    }

    fn get_remote_ephemeral(&self) -> Option<Self::E> {
        match (self.dh_internals.re.as_ref(), self.kem_re.as_ref()) {
            (Some(dh), Some(kem)) => Some(HybridPubKeyPair::new(dh.clone(), kem.clone())),
            _ => None,
        }
    }
}
