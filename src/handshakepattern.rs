//! Pre-made Noise handshake patterns and tools for defining new ones

use arrayvec::ArrayVec;

use crate::constants::{MAX_HS_MESSAGES_PER_ROLE, MAX_TOKENS_PER_HS_MESSAGE};
use crate::error::{PatternError, PatternResult};

/// Handshake pattern type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeType {
    /// Classical Noise DH handshake
    DH,
    /// PQNoise KEM handshake
    KEM,
    /// Hybrid handshake combining both DH and KEM
    HYBRID,
}

/// Handshake tokens as defined by the Noise spec and PQNoise paper.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Token {
    /// Initiator ephemeral key
    E,
    /// Initiator static key
    S,
    /// Ephemeral-ephemeral DH
    EE,
    /// Ephemeral-static DH
    ES,
    /// Static-ephemeral DH
    SE,
    /// Static-static DH
    SS,
    /// Ephemeral KEM
    Ekem,
    /// Static KEM
    Skem,
    /// Pre-shared key
    Psk,
}

/// Noise handshake pattern
///
/// Contains token sequences for pre-shared information
/// as well as actual handshake messages.
#[derive(Clone, Debug)]
pub struct HandshakePattern {
    name: &'static str,
    pre_initiator: ArrayVec<Token, 4>,
    pre_responder: ArrayVec<Token, 4>,
    message_pattern: MessagePattern,
    has_psk: bool,
    hs_type: HandshakeType,
}

/// Handshake message pattern
///
/// Does not include pre-message patterns
#[derive(Clone, Debug)]
pub struct MessagePattern {
    /// Messages sent by the initiator
    pub initiator: ArrayVec<ArrayVec<Token, MAX_TOKENS_PER_HS_MESSAGE>, MAX_HS_MESSAGES_PER_ROLE>,
    /// Messages sent by the responder
    pub responder: ArrayVec<ArrayVec<Token, MAX_TOKENS_PER_HS_MESSAGE>, MAX_HS_MESSAGES_PER_ROLE>,
}

impl MessagePattern {
    /// Check if the pattern includes pre-shared keys
    pub fn has_psk(&self) -> bool {
        self.initiator.iter().flatten().any(|t| *t == Token::Psk)
            || self.responder.iter().flatten().any(|t| *t == Token::Psk)
    }

    /// Check if the pattern includes `KEM` tokens
    pub fn has_kem(&self) -> bool {
        self.initiator
            .iter()
            .flatten()
            .any(|t| *t == Token::Ekem || *t == Token::Skem)
            || self
                .responder
                .iter()
                .flatten()
                .any(|t| *t == Token::Ekem || *t == Token::Skem)
    }

    /// Check if the pattern includes `DH` tokens
    pub fn has_dh(&self) -> bool {
        self.initiator
            .iter()
            .flatten()
            .any(|t| matches!(t, Token::EE | Token::ES | Token::SE | Token::SS))
            || self
                .responder
                .iter()
                .flatten()
                .any(|t| matches!(t, Token::EE | Token::ES | Token::SE | Token::SS))
    }
}

impl HandshakePattern {
    /// Initialize a new handshake pattern
    ///
    /// # Arguments
    /// * `name` - Pattern name
    /// * `pre_initiator` - Tokens shared by initiator pre handshake
    /// * `pre_responder` - Tokens shared by responder pre handshake
    /// * `initiator` - Initiator messages
    /// * `responder` - Responder messages
    ///
    /// # Panics
    /// * If the pattern is invalid (empty pattern, no DH or KEM operations at all)
    /// * If the message sequences are too long, limits in [`crate::constants`]
    ///
    /// # Errors
    /// * [`PatternError::PskValidityViolation`] - If the pattern violates the PSK validity rule (Noise Protocol Framework Specification section 9.3)
    /// * [`PatternError::PqTokenOrderViolation`] - If the pattern violates the PQ token ordering rule (PQNoise paper section 2.4)
    pub fn try_new(
        name: &'static str,
        pre_initiator: &[Token],
        pre_responder: &[Token],
        initiator: &[&[Token]],
        responder: &[&[Token]],
    ) -> PatternResult<Self> {
        let message_pattern = MessagePattern {
            initiator: initiator
                .iter()
                .map(|p| p.iter().copied().collect())
                .collect(),
            responder: responder
                .iter()
                .map(|p| p.iter().copied().collect())
                .collect(),
        };

        let has_kem = message_pattern.has_kem();
        let has_dh = message_pattern.has_dh();

        let hs_type = match (has_kem, has_dh) {
            (true, true) => HandshakeType::HYBRID,
            (true, false) => HandshakeType::KEM,
            (false, true) => HandshakeType::DH,
            (false, false) => unreachable!("Invalid handshake pattern"),
        };

        // Validate PSK validity rule if pattern has PSK
        if message_pattern.has_psk() {
            Self::validate_psk_rule(&message_pattern.initiator)?;
            Self::validate_psk_rule(&message_pattern.responder)?;
        }

        if has_kem {
            Self::validate_pq_token_order_rule(&message_pattern.initiator)?;
            Self::validate_pq_token_order_rule(&message_pattern.responder)?;
        }

        Ok(Self {
            name,
            hs_type,
            has_psk: message_pattern.has_psk(),
            message_pattern,
            pre_initiator: pre_initiator.iter().copied().collect(),
            pre_responder: pre_responder.iter().copied().collect(),
        })
    }

    /// Initialize a new handshake pattern
    ///
    /// # Arguments
    /// * `name` - Pattern name
    /// * `pre_initiator` - Tokens shared by initiator pre handshake
    /// * `pre_responder` - Tokens shared by responder pre handshake
    /// * `initiator` - Initiator messages
    /// * `responder` - Responder messages
    ///
    /// # Panics
    /// * If the pattern is invalid (empty pattern, no DH or KEM operations at all)
    /// * If the message sequences are too long, limits in [`crate::constants`]
    /// * If the pattern violates the PSK validity rule (Noise Protocol Framework Specification section 9.3)
    /// * If the pattern violates the PQ token ordering rule (PQNoise paper section 2.4)
    pub fn new(
        name: &'static str,
        pre_initiator: &[Token],
        pre_responder: &[Token],
        initiator: &[&[Token]],
        responder: &[&[Token]],
    ) -> Self {
        Self::try_new(name, pre_initiator, pre_responder, initiator, responder)
            .unwrap_or_else(|e| panic!("Handshake pattern error: {}", e))
    }

    /// Validate PQ token ordering rule for a party's message pattern
    ///
    /// The validity rule expressed by PQNoise authors is as follows:
    ///
    /// > Within a message ekem always precedes skem which
    /// > always precedes all public keys and the payload
    ///
    /// # Errors
    /// * [`PatternError::PqTokenOrderViolation`] if the rule is violated
    pub fn validate_pq_token_order_rule(
        messages: &[ArrayVec<Token, MAX_TOKENS_PER_HS_MESSAGE>],
    ) -> PatternResult<()> {
        for message in messages.iter() {
            let mut skem_seen = false;
            let mut public_key_seen = false;
            for token in message.iter() {
                match token {
                    Token::Ekem => {
                        if public_key_seen {
                            return Err(PatternError::PqTokenOrderViolation);
                        }

                        if skem_seen {
                            return Err(PatternError::PqTokenOrderViolation);
                        }
                    }
                    Token::Skem => {
                        skem_seen = true;
                        if public_key_seen {
                            return Err(PatternError::PqTokenOrderViolation);
                        }
                    }
                    Token::E | Token::S => {
                        public_key_seen = true;
                    }
                    _ => {}
                }
            }
        }

        Ok(())
    }

    /// Validate PSK validity rule for a party's message pattern
    ///
    /// The relaxed rule applied by Clatter: A party may not send any encrypted data after it processes a "psk" token
    /// unless it has previously sent an "e" token or "ekem" token, either before or after the "psk" token.
    ///
    /// Encrypted data includes:
    /// - `skem` token (encrypts its ciphertext if a key exists, then applies randomness)
    /// - `s` token (encrypts static public key if a key exists)
    ///
    /// # Errors
    /// * [`PatternError::PskValidityViolation`] if the rule is violated
    pub fn validate_psk_rule(
        messages: &[ArrayVec<Token, MAX_TOKENS_PER_HS_MESSAGE>],
    ) -> PatternResult<()> {
        let mut psk_sent = false;
        for message in messages.iter() {
            for token in message.iter() {
                match token {
                    Token::Psk => {
                        psk_sent = true;
                    }
                    Token::E | Token::Ekem => {
                        // E or Ekem token applies randomness before any encryption, safe to early return
                        return Ok(());
                    }
                    Token::Skem => {
                        if psk_sent {
                            return Err(PatternError::PskValidityViolation);
                        } else {
                            // If Skem comes before PSK, it satisfies the requirement of applying randomness before any encryption
                            return Ok(());
                        }
                    }
                    Token::S => {
                        if psk_sent {
                            return Err(PatternError::PskValidityViolation);
                        }

                        // S does not apply randomness, continue validation...
                    }
                    _ => {}
                }
            }
        }

        Ok(())
    }

    /// Get initiator message pattern length
    pub fn get_initiator_pattern_len(&self) -> usize {
        self.message_pattern.initiator.len()
    }

    /// Get responder message pattern length
    pub fn get_responder_pattern_len(&self) -> usize {
        self.message_pattern.responder.len()
    }

    /// Get initiators pre shared data
    pub(crate) fn get_initiator_pre_shared(&self) -> &[Token] {
        &self.pre_initiator
    }

    /// Get responders pre shared data
    pub(crate) fn get_responder_pre_shared(&self) -> &[Token] {
        &self.pre_responder
    }

    /// Get initiator message pattern based on message index
    ///
    /// # Panics
    /// Panics if message index is larger than the pattern length
    pub fn get_initiator_pattern(&self, index: usize) -> &[Token] {
        &self.message_pattern.initiator[index]
    }

    /// Get responder message pattern based on message index
    ///
    /// # Panics
    /// Panics if message index is larger than the pattern length
    pub fn get_responder_pattern(&self, index: usize) -> &[Token] {
        &self.message_pattern.responder[index]
    }

    /// Check if the pattern includes PSKs
    pub fn has_psk(&self) -> bool {
        self.has_psk
    }

    /// Get name of the pattern
    pub fn get_name(&self) -> &'static str {
        self.name
    }

    /// Check if the pattern is one way
    pub fn is_one_way(&self) -> bool {
        self.message_pattern.responder.is_empty()
    }

    /// Get the handshake type
    pub fn get_type(&self) -> HandshakeType {
        self.hs_type
    }

    /// Insert PSK's to the message pattern at given positions, `psks`
    ///
    /// PSK placement is identical to the one defined in the Noise spec. To
    /// include PSK0 and PSK2 in a pattern, pass in `psks = [0, 2]`.
    ///
    /// # Panics
    /// * If the resulting pattern violates the PSK validity rule (Noise Protocol Framework Specification section 9.3)
    /// * If the resulting pattern violates the PQ token ordering rule (PQNoise paper section 2.4)
    pub fn add_psks(&self, psks: &[usize], name: &'static str) -> Self {
        let mut initiator = self.message_pattern.initiator.clone();
        let mut responder = self.message_pattern.responder.clone();
        for pos in psks {
            if *pos == 0 {
                initiator[0].insert(0, Token::Psk);
            } else if *pos % 2 == 0 {
                // Even, responder pattern
                let responder_psk = (*pos / 2) - 1;
                responder[responder_psk].push(Token::Psk);
            } else {
                // Odd, initiator pattern
                let initiator_psk = *pos / 2;
                initiator[initiator_psk].push(Token::Psk);
            }
        }

        let initiator_slices: ArrayVec<&[Token], MAX_HS_MESSAGES_PER_ROLE> =
            initiator.iter().map(|v| v.as_slice()).collect();
        let responder_slices: ArrayVec<&[Token], MAX_HS_MESSAGES_PER_ROLE> =
            responder.iter().map(|v| v.as_slice()).collect();

        Self::try_new(
            name,
            self.pre_initiator.as_slice(),
            self.pre_responder.as_slice(),
            &initiator_slices,
            &responder_slices,
        )
        .unwrap_or_else(|e| panic!("Handshake pattern error in add_psks: {}", e))
    }
}

// PQ patterns:

/// ```text
/// -> e
/// <- ekem
/// ```
pub fn noise_pqnn() -> HandshakePattern {
    HandshakePattern::new("pqNN", &[], &[], &[&[Token::E]], &[&[Token::Ekem]])
}

/// ```text
/// <- s
/// ...
/// -> skem, e
/// <- ekem
/// ```
pub fn noise_pqnk() -> HandshakePattern {
    HandshakePattern::new(
        "pqNK",
        &[],
        &[Token::S],
        &[&[Token::Skem, Token::E]],
        &[&[Token::Ekem]],
    )
}

/// ```text
/// -> e
/// <- ekem, s
/// -> skem
/// ```
pub fn noise_pqnx() -> HandshakePattern {
    HandshakePattern::new(
        "pqNX",
        &[],
        &[],
        &[&[Token::E], &[Token::Skem]],
        &[&[Token::Ekem, Token::S]],
    )
}

/// ```text
/// -> s
/// ...
/// -> e
/// <- ekem, skem
/// ```
pub fn noise_pqkn() -> HandshakePattern {
    HandshakePattern::new(
        "pqNK",
        &[Token::S],
        &[],
        &[&[Token::E]],
        &[&[Token::Ekem, Token::Skem]],
    )
}

/// ```text
/// -> s
/// <- s
/// ...
/// -> skem, e
/// <- ekem, skem
/// ```
pub fn noise_pqkk() -> HandshakePattern {
    HandshakePattern::new(
        "pqKK",
        &[Token::S],
        &[Token::S],
        &[&[Token::Skem, Token::E]],
        &[&[Token::Ekem, Token::Skem]],
    )
}

/// ```text
/// -> s
/// ...
/// -> e
/// <- ekem, skem, s
/// -> skem
/// ```
pub fn noise_pqkx() -> HandshakePattern {
    HandshakePattern::new(
        "pqKX",
        &[Token::S],
        &[],
        &[&[Token::E], &[Token::Skem]],
        &[&[Token::Ekem, Token::Skem, Token::S]],
    )
}

/// ```text
/// -> e
/// <- ekem
/// -> s
/// <- skem
/// ```
pub fn noise_pqxn() -> HandshakePattern {
    HandshakePattern::new(
        "pqXN",
        &[],
        &[],
        &[&[Token::E], &[Token::S]],
        &[&[Token::Ekem], &[Token::Skem]],
    )
}

/// ```text
/// <- s
/// ...
/// -> skem, e
/// <- ekem
/// -> s
/// <- skem
/// ```
pub fn noise_pqxk() -> HandshakePattern {
    HandshakePattern::new(
        "pqXK",
        &[],
        &[Token::S],
        &[&[Token::Skem, Token::E], &[Token::S]],
        &[&[Token::Ekem], &[Token::Skem]],
    )
}

/// ```text
/// -> e
/// <- ekem, s
/// -> skem, s
/// <- skem
/// ```
pub fn noise_pqxx() -> HandshakePattern {
    HandshakePattern::new(
        "pqXX",
        &[],
        &[],
        &[&[Token::E], &[Token::Skem, Token::S]],
        &[&[Token::Ekem, Token::S], &[Token::Skem]],
    )
}

/// ```text
/// -> e, s
/// <- ekem, skem
/// ```
pub fn noise_pqin() -> HandshakePattern {
    HandshakePattern::new(
        "pqIN",
        &[],
        &[],
        &[&[Token::E, Token::S]],
        &[&[Token::Ekem, Token::Skem]],
    )
}

/// ```text
/// <- s
/// ...
/// -> skem, e, s
/// <- ekem, skem
/// ```
pub fn noise_pqik() -> HandshakePattern {
    HandshakePattern::new(
        "pqIK",
        &[],
        &[Token::S],
        &[&[Token::Skem, Token::E, Token::S]],
        &[&[Token::Ekem, Token::Skem]],
    )
}

/// ```text
/// -> e, s
/// <- ekem, skem, s
/// -> skem
/// ```
pub fn noise_pqix() -> HandshakePattern {
    HandshakePattern::new(
        "pqIX",
        &[],
        &[],
        &[&[Token::E, Token::S], &[Token::Skem]],
        &[&[Token::Ekem, Token::Skem, Token::S]],
    )
}

// PQ patterns with PSKs:

/// ```text
/// -> e
/// <- ekem, psk
/// ```
pub fn noise_pqnn_psk2() -> HandshakePattern {
    noise_pqnn().add_psks(&[2], "pqNNpsk2")
}

/// ```text
/// <- s
/// ...
/// -> skem, e
/// <- ekem, psk
/// ```
pub fn noise_pqnk_psk2() -> HandshakePattern {
    noise_pqnk().add_psks(&[2], "pqNKpsk2")
}

/// ```text
/// -> e
/// <- ekem, s, psk
/// -> skem
/// ```
pub fn noise_pqnx_psk2() -> HandshakePattern {
    noise_pqnx().add_psks(&[2], "pqNXpsk2")
}

/// ```text
/// -> e
/// <- ekem, s
/// -> skem, psk
/// ```
pub fn noise_pqxn_psk3() -> HandshakePattern {
    noise_pqxn().add_psks(&[3], "pqXNpsk3")
}

/// ```text
/// <- s
/// ...
/// -> skem, e
/// <- ekem
/// -> s, psk
/// <- skem
/// ```
pub fn noise_pqxk_psk3() -> HandshakePattern {
    noise_pqxk().add_psks(&[3], "pqXKpsk3")
}

/// ```text
/// -> e
/// <- ekem, s
/// -> skem, s, psk
/// <- skem
/// ```
pub fn noise_pqxx_psk3() -> HandshakePattern {
    noise_pqxx().add_psks(&[3], "pqXXpsk3")
}

/// ```text
/// -> s
/// ...
/// -> e
/// <- ekem, skem, psk
/// ```
pub fn noise_pqkn_psk2() -> HandshakePattern {
    noise_pqkn().add_psks(&[2], "pqKNpsk2")
}

/// ```text
/// -> s
/// <- s
/// ...
/// -> skem, e
/// <- ekem, skem, psk
/// ```
pub fn noise_pqkk_psk2() -> HandshakePattern {
    noise_pqkk().add_psks(&[2], "pqKKpsk2")
}

/// ```text
/// -> s
/// ...
/// -> e
/// <- ekem, skem, s, psk
/// -> skem
/// ```
pub fn noise_pqkx_psk2() -> HandshakePattern {
    noise_pqkx().add_psks(&[2], "pqKXpsk2")
}

/// ```text
/// -> e, s, psk
/// <- ekem, skem
/// ```
pub fn noise_pqin_psk1() -> HandshakePattern {
    noise_pqin().add_psks(&[1], "pqINpsk1")
}

/// ```text
/// -> e, s
/// <- ekem, skem, psk
/// ```
pub fn noise_pqin_psk2() -> HandshakePattern {
    noise_pqin().add_psks(&[2], "pqINpsk2")
}

/// ```text
/// <- s
/// ...
/// -> skem, e, s, psk
/// <- ekem, skem
/// ```
pub fn noise_pqik_psk1() -> HandshakePattern {
    noise_pqik().add_psks(&[1], "pqIKpsk1")
}

/// ```text
/// <- s
/// ...
/// -> skem, e, s
/// <- ekem, skem, psk
/// ```
pub fn noise_pqik_psk2() -> HandshakePattern {
    noise_pqik().add_psks(&[2], "pqIKpsk2")
}

/// ```text
/// -> e, s
/// <- ekem, skem, s, psk
/// -> skem
/// ```
pub fn noise_pqix_psk2() -> HandshakePattern {
    noise_pqix().add_psks(&[2], "pqIXpsk2")
}

// NQ patterns:

/// ```text
/// <- s
/// ...
/// -> e, es
/// ```
pub fn noise_n() -> HandshakePattern {
    HandshakePattern::new("N", &[], &[Token::S], &[&[Token::E, Token::ES]], &[])
}

/// ```text
/// -> s
/// <- s
/// ...
/// -> e, es, ss
/// ```
pub fn noise_k() -> HandshakePattern {
    HandshakePattern::new(
        "K",
        &[Token::S],
        &[Token::S],
        &[&[Token::E, Token::ES, Token::SS]],
        &[],
    )
}

/// ```text
/// <- s
/// ...
/// -> e, es, s, ss
/// ```
pub fn noise_x() -> HandshakePattern {
    HandshakePattern::new(
        "X",
        &[],
        &[Token::S],
        &[&[Token::E, Token::ES, Token::S, Token::SS]],
        &[],
    )
}

/// ```text
/// -> e
/// <- e, ee
/// ```
pub fn noise_nn() -> HandshakePattern {
    HandshakePattern::new("NN", &[], &[], &[&[Token::E]], &[&[Token::E, Token::EE]])
}

/// ```text
/// <- s
/// ...
/// -> e, es
/// <- e, ee
/// ```
pub fn noise_nk() -> HandshakePattern {
    HandshakePattern::new(
        "NK",
        &[],
        &[Token::S],
        &[&[Token::E, Token::ES]],
        &[&[Token::E, Token::EE]],
    )
}

/// ```text
/// -> e
/// <- e, ee, s, es
/// ```
pub fn noise_nx() -> HandshakePattern {
    HandshakePattern::new(
        "NX",
        &[],
        &[],
        &[&[Token::E]],
        &[&[Token::E, Token::EE, Token::S, Token::ES]],
    )
}

/// ```text
/// -> s
/// ...
/// -> e
/// <- e, ee, se
/// ```
pub fn noise_kn() -> HandshakePattern {
    HandshakePattern::new(
        "KN",
        &[Token::S],
        &[],
        &[&[Token::E]],
        &[&[Token::E, Token::EE, Token::SE]],
    )
}

/// ```text
/// -> s
/// <- s
/// ...
/// -> e, es, ss
/// <- e, ee, se
/// ```
pub fn noise_kk() -> HandshakePattern {
    HandshakePattern::new(
        "KK",
        &[Token::S],
        &[Token::S],
        &[&[Token::E, Token::ES, Token::SS]],
        &[&[Token::E, Token::EE, Token::SE]],
    )
}

/// ```text
/// -> s
/// ...
/// -> e
/// <- e, ee, se, s, es
/// ```
pub fn noise_kx() -> HandshakePattern {
    HandshakePattern::new(
        "KX",
        &[Token::S],
        &[],
        &[&[Token::E]],
        &[&[Token::E, Token::EE, Token::SE, Token::S, Token::ES]],
    )
}

/// ```text
/// -> e
/// <- e, ee
/// -> s, se
/// ```
pub fn noise_xn() -> HandshakePattern {
    HandshakePattern::new(
        "XN",
        &[],
        &[],
        &[&[Token::E], &[Token::S, Token::SE]],
        &[&[Token::E, Token::EE]],
    )
}

/// ```text
/// <- s
/// ...
/// -> e, es
/// <- e, ee
/// -> s, se
/// ```
pub fn noise_xk() -> HandshakePattern {
    HandshakePattern::new(
        "XK",
        &[],
        &[Token::S],
        &[&[Token::E, Token::ES], &[Token::S, Token::SE]],
        &[&[Token::E, Token::EE]],
    )
}

/// ```text
/// -> e
/// <- e, ee, s, es
/// -> s, se
/// ```
pub fn noise_xx() -> HandshakePattern {
    HandshakePattern::new(
        "XX",
        &[],
        &[],
        &[&[Token::E], &[Token::S, Token::SE]],
        &[&[Token::E, Token::EE, Token::S, Token::ES]],
    )
}

/// ```text
/// -> e, s
/// <- e, ee, se
/// ```
pub fn noise_in() -> HandshakePattern {
    HandshakePattern::new(
        "IN",
        &[],
        &[],
        &[&[Token::E, Token::S]],
        &[&[Token::E, Token::EE, Token::SE]],
    )
}

/// ```text
/// <- s
/// ...
/// -> e, es, s, ss
/// <- e, ee, se
/// ```
pub fn noise_ik() -> HandshakePattern {
    HandshakePattern::new(
        "IK",
        &[],
        &[Token::S],
        &[&[Token::E, Token::ES, Token::S, Token::SS]],
        &[&[Token::E, Token::EE, Token::SE]],
    )
}

/// ```text
/// -> e, s
/// <- e, ee, se, s, es
/// ```
pub fn noise_ix() -> HandshakePattern {
    HandshakePattern::new(
        "IX",
        &[],
        &[],
        &[&[Token::E, Token::S]],
        &[&[Token::E, Token::EE, Token::SE, Token::S, Token::ES]],
    )
}

// NQ patterns with PSKs:

/// ```text
/// <- s
/// ...
/// -> psk, e, es
/// ```
pub fn noise_n_psk0() -> HandshakePattern {
    noise_n().add_psks(&[0], "Npsk0")
}

/// ```text
/// -> s
/// <- s
/// ...
/// -> psk, e, es, ss
/// ```
pub fn noise_k_psk0() -> HandshakePattern {
    noise_k().add_psks(&[0], "Kpsk0")
}

/// ```text
/// <- s
/// ...
/// -> e, es, s, ss, psk
/// ```
pub fn noise_x_psk1() -> HandshakePattern {
    noise_x().add_psks(&[1], "Xpsk1")
}

/// ```text
/// -> psk, e
/// <- e, ee
/// ```
pub fn noise_nn_psk0() -> HandshakePattern {
    noise_nn().add_psks(&[0], "NNpsk0")
}

/// ```text
/// -> e
/// <- e, ee, psk
/// ```
pub fn noise_nn_psk2() -> HandshakePattern {
    noise_nn().add_psks(&[2], "NNpsk2")
}

/// ```text
/// <- s
/// ...
/// -> psk, e, es
/// <- e, ee
/// ```
pub fn noise_nk_psk0() -> HandshakePattern {
    noise_nk().add_psks(&[0], "NKpsk0")
}

/// ```text
/// <- s
/// ...
/// -> e, es
/// <- e, ee, psk
/// ```
pub fn noise_nk_psk2() -> HandshakePattern {
    noise_nk().add_psks(&[2], "NKpsk2")
}

/// ```text
/// -> e
/// <- e, ee, s, es, psk
/// ```
pub fn noise_nx_psk2() -> HandshakePattern {
    noise_nx().add_psks(&[2], "NXpsk2")
}

/// ```text
/// -> e
/// <- e, ee
/// -> s, se, psk
/// ```
pub fn noise_xn_psk3() -> HandshakePattern {
    noise_xn().add_psks(&[3], "XNpsk3")
}

/// ```text
/// <- s
/// ...
/// -> e, es
/// <- e, ee
/// -> s, se, psk
/// ```
pub fn noise_xk_psk3() -> HandshakePattern {
    noise_xk().add_psks(&[3], "XKpsk3")
}

/// ```text
/// -> e
/// <- e, ee, s, es
/// -> s, se, psk
/// ```
pub fn noise_xx_psk3() -> HandshakePattern {
    noise_xx().add_psks(&[3], "XXpsk3")
}

/// ```text
/// -> s
/// ...
/// -> psk, e
/// <- e, ee, se
/// ```
pub fn noise_kn_psk0() -> HandshakePattern {
    noise_kn().add_psks(&[0], "KNpsk0")
}

/// ```text
/// -> s
/// ...
/// -> e
/// <- e, ee, se, psk
/// ```
pub fn noise_kn_psk2() -> HandshakePattern {
    noise_kn().add_psks(&[2], "KNpsk2")
}

/// ```text
/// -> s
/// <- s
/// ...
/// -> psk, e, es, ss
/// <- e, ee, se
/// ```
pub fn noise_kk_psk0() -> HandshakePattern {
    noise_kk().add_psks(&[0], "KKpsk0")
}

/// ```text
/// -> s
/// <- s
/// ...
/// -> e, es, ss
/// <- e, ee, se, psk
/// ```
pub fn noise_kk_psk2() -> HandshakePattern {
    noise_kk().add_psks(&[2], "KKpsk2")
}

/// ```text
/// -> s
/// ...
/// -> e
/// <- e, ee, se, s, es, psk
/// ```
pub fn noise_kx_psk2() -> HandshakePattern {
    noise_kx().add_psks(&[2], "KXpsk2")
}

/// ```text
/// -> e, s, psk
/// <- e, ee, se
/// ```
pub fn noise_in_psk1() -> HandshakePattern {
    noise_in().add_psks(&[1], "INpsk1")
}

/// ```text
/// -> e, s
/// <- e, ee, se, psk
/// ```
pub fn noise_in_psk2() -> HandshakePattern {
    noise_in().add_psks(&[2], "INpsk2")
}

/// ```text
/// <- s
/// ...
/// -> e, es, s, ss, psk
/// <- e, ee, se
/// ```
pub fn noise_ik_psk1() -> HandshakePattern {
    noise_ik().add_psks(&[1], "IKpsk1")
}

/// ```text
/// <- s
/// ...
/// -> e, es, s, ss
/// <- e, ee, se, psk
/// ```
pub fn noise_ik_psk2() -> HandshakePattern {
    noise_ik().add_psks(&[2], "IKpsk2")
}

/// ```text
/// -> e, s
/// <- e, ee, se, s, es, psk
/// ```
pub fn noise_ix_psk2() -> HandshakePattern {
    noise_ix().add_psks(&[2], "IXpsk2")
}

// Hybrid patterns (combining classical DH and PQ KEM):

/// ```text
/// -> e
/// <- ekem, e, ee
/// ```
pub fn noise_hybrid_nn() -> HandshakePattern {
    HandshakePattern::new(
        "hybridNN",
        &[],
        &[],
        &[&[Token::E]],
        &[&[Token::Ekem, Token::E, Token::EE]],
    )
}

/// ```text
/// <- s
/// ...
/// -> skem, e, es
/// <- ekem, e, ee
/// ```
pub fn noise_hybrid_nk() -> HandshakePattern {
    HandshakePattern::new(
        "hybridNK",
        &[],
        &[Token::S],
        &[&[Token::Skem, Token::E, Token::ES]],
        &[&[Token::Ekem, Token::E, Token::EE]],
    )
}

/// ```text
/// -> e
/// <- ekem, e, ee, s, es
/// -> skem
/// ```
pub fn noise_hybrid_nx() -> HandshakePattern {
    HandshakePattern::new(
        "hybridNX",
        &[],
        &[],
        &[&[Token::E], &[Token::Skem]],
        &[&[Token::Ekem, Token::E, Token::EE, Token::S, Token::ES]],
    )
}

/// ```text
/// -> s
/// ...
/// -> e
/// <- ekem, skem, e, ee, se
/// ```
pub fn noise_hybrid_kn() -> HandshakePattern {
    HandshakePattern::new(
        "hybridKN",
        &[Token::S],
        &[],
        &[&[Token::E]],
        &[&[Token::Ekem, Token::Skem, Token::E, Token::EE, Token::SE]],
    )
}

/// ```text
/// -> s
/// <- s
/// ...
/// -> skem, e, es, ss
/// <- ekem, skem, e, ee, se
/// ```
pub fn noise_hybrid_kk() -> HandshakePattern {
    HandshakePattern::new(
        "hybridKK",
        &[Token::S],
        &[Token::S],
        &[&[Token::Skem, Token::E, Token::ES, Token::SS]],
        &[&[Token::Ekem, Token::Skem, Token::E, Token::EE, Token::SE]],
    )
}

/// ```text
/// -> s
/// ...
/// -> e
/// <- ekem, skem, e, ee, se, s, es
/// -> skem
/// ```
pub fn noise_hybrid_kx() -> HandshakePattern {
    HandshakePattern::new(
        "hybridKX",
        &[Token::S],
        &[],
        &[&[Token::E], &[Token::Skem]],
        &[&[
            Token::Ekem,
            Token::Skem,
            Token::E,
            Token::EE,
            Token::SE,
            Token::S,
            Token::ES,
        ]],
    )
}

/// ```text
/// -> e
/// <- ekem, e, ee
/// -> s, se
/// <- skem
/// ```
pub fn noise_hybrid_xn() -> HandshakePattern {
    HandshakePattern::new(
        "hybridXN",
        &[],
        &[],
        &[&[Token::E], &[Token::S, Token::SE]],
        &[&[Token::Ekem, Token::E, Token::EE], &[Token::Skem]],
    )
}

/// ```text
/// <- s
/// ...
/// -> skem, e, es
/// <- ekem, e, ee
/// -> s, se
/// <- skem
/// ```
pub fn noise_hybrid_xk() -> HandshakePattern {
    HandshakePattern::new(
        "hybridXK",
        &[],
        &[Token::S],
        &[&[Token::Skem, Token::E, Token::ES], &[Token::S, Token::SE]],
        &[&[Token::Ekem, Token::E, Token::EE], &[Token::Skem]],
    )
}

/// ```text
/// -> e
/// <- ekem, e, ee, s, es
/// -> skem, s, se
/// <- skem
/// ```
pub fn noise_hybrid_xx() -> HandshakePattern {
    HandshakePattern::new(
        "hybridXX",
        &[],
        &[],
        &[&[Token::E], &[Token::Skem, Token::S, Token::SE]],
        &[
            &[Token::Ekem, Token::E, Token::EE, Token::S, Token::ES],
            &[Token::Skem],
        ],
    )
}

/// ```text
/// -> e, s
/// <- ekem, skem, e, ee, se
/// ```
pub fn noise_hybrid_in() -> HandshakePattern {
    HandshakePattern::new(
        "hybridIN",
        &[],
        &[],
        &[&[Token::E, Token::S]],
        &[&[Token::Ekem, Token::Skem, Token::E, Token::EE, Token::SE]],
    )
}

/// ```text
/// <- s
/// ...
/// -> skem, e, es, s, ss
/// <- ekem, skem, e, ee, se
/// ```
pub fn noise_hybrid_ik() -> HandshakePattern {
    HandshakePattern::new(
        "hybridIK",
        &[],
        &[Token::S],
        &[&[Token::Skem, Token::E, Token::ES, Token::S, Token::SS]],
        &[&[Token::Ekem, Token::Skem, Token::E, Token::EE, Token::SE]],
    )
}

/// ```text
/// -> e, s
/// <- ekem, skem, e, ee, se, s, es
/// -> skem
/// ```
pub fn noise_hybrid_ix() -> HandshakePattern {
    HandshakePattern::new(
        "hybridIX",
        &[],
        &[],
        &[&[Token::E, Token::S], &[Token::Skem]],
        &[&[
            Token::Ekem,
            Token::Skem,
            Token::E,
            Token::EE,
            Token::SE,
            Token::S,
            Token::ES,
        ]],
    )
}

// Hybrid patterns with PSKs:

/// ```text
/// -> psk, e
/// <- ekem, e, ee
/// ```
pub fn noise_hybrid_nn_psk0() -> HandshakePattern {
    noise_hybrid_nn().add_psks(&[0], "hybridNNpsk0")
}

/// ```text
/// -> e
/// <- ekem, e, ee, psk
/// ```
pub fn noise_hybrid_nn_psk2() -> HandshakePattern {
    noise_hybrid_nn().add_psks(&[2], "hybridNNpsk2")
}

/// ```text
/// <- s
/// ...
/// -> skem, e, es
/// <- ekem, e, ee, psk
/// ```
pub fn noise_hybrid_nk_psk2() -> HandshakePattern {
    noise_hybrid_nk().add_psks(&[2], "hybridNKpsk2")
}

/// ```text
/// -> e
/// <- ekem, e, ee, s, es, psk
/// -> skem
/// ```
pub fn noise_hybrid_nx_psk2() -> HandshakePattern {
    noise_hybrid_nx().add_psks(&[2], "hybridNXpsk2")
}

/// ```text
/// -> e
/// <- ekem, e, ee, s, es
/// -> skem, psk
/// ```
pub fn noise_hybrid_xn_psk3() -> HandshakePattern {
    noise_hybrid_xn().add_psks(&[3], "hybridXNpsk3")
}

/// ```text
/// <- s
/// ...
/// -> skem, e, es
/// <- ekem, e, ee
/// -> s, se, psk
/// <- skem
/// ```
pub fn noise_hybrid_xk_psk3() -> HandshakePattern {
    noise_hybrid_xk().add_psks(&[3], "hybridXKpsk3")
}

/// ```text
/// -> e
/// <- ekem, e, ee, s, es
/// -> skem, s, se, psk
/// <- skem
/// ```
pub fn noise_hybrid_xx_psk3() -> HandshakePattern {
    noise_hybrid_xx().add_psks(&[3], "hybridXXpsk3")
}

/// ```text
/// -> s
/// ...
/// -> psk, e
/// <- ekem, skem, e, ee, se
/// ```
pub fn noise_hybrid_kn_psk0() -> HandshakePattern {
    noise_hybrid_kn().add_psks(&[0], "hybridKNpsk0")
}

/// ```text
/// -> s
/// ...
/// -> e
/// <- ekem, skem, e, ee, se, psk
/// ```
pub fn noise_hybrid_kn_psk2() -> HandshakePattern {
    noise_hybrid_kn().add_psks(&[2], "hybridKNpsk2")
}

/// ```text
/// -> s
/// <- s
/// ...
/// -> skem, e, es, ss
/// <- ekem, skem, e, ee, se, psk
/// ```
pub fn noise_hybrid_kk_psk2() -> HandshakePattern {
    noise_hybrid_kk().add_psks(&[2], "hybridKKpsk2")
}

/// ```text
/// -> s
/// ...
/// -> e
/// <- ekem, skem, e, ee, se, s, es, psk
/// -> skem
/// ```
pub fn noise_hybrid_kx_psk2() -> HandshakePattern {
    noise_hybrid_kx().add_psks(&[2], "hybridKXpsk2")
}

/// ```text
/// -> e, s, psk
/// <- ekem, skem, e, ee, se
/// ```
pub fn noise_hybrid_in_psk1() -> HandshakePattern {
    noise_hybrid_in().add_psks(&[1], "hybridINpsk1")
}

/// ```text
/// -> e, s
/// <- ekem, skem, e, ee, se, psk
/// ```
pub fn noise_hybrid_in_psk2() -> HandshakePattern {
    noise_hybrid_in().add_psks(&[2], "hybridINpsk2")
}

/// ```text
/// <- s
/// ...
/// -> skem, e, es, s, ss, psk
/// <- ekem, skem, e, ee, se
/// ```
pub fn noise_hybrid_ik_psk1() -> HandshakePattern {
    noise_hybrid_ik().add_psks(&[1], "hybridIKpsk1")
}

/// ```text
/// <- s
/// ...
/// -> skem, e, es, s, ss
/// <- ekem, skem, e, ee, se, psk
/// ```
pub fn noise_hybrid_ik_psk2() -> HandshakePattern {
    noise_hybrid_ik().add_psks(&[2], "hybridIKpsk2")
}

/// ```text
/// -> e, s
/// <- ekem, skem, e, ee, se, s, es, psk
/// -> skem
/// ```
pub fn noise_hybrid_ix_psk2() -> HandshakePattern {
    noise_hybrid_ix().add_psks(&[2], "hybridIXpsk2")
}

#[cfg(test)]
mod tests {
    use crate::handshakepattern::{HandshakePattern, HandshakeType, Token};

    #[test]
    fn resolve_dh() {
        let pattern = HandshakePattern::new("dh", &[], &[], &[&[Token::EE]], &[&[Token::SE]]);
        assert_eq!(pattern.get_type(), HandshakeType::DH);
    }

    #[test]
    fn resolve_kem() {
        let pattern = HandshakePattern::new("dh", &[], &[], &[&[Token::Ekem]], &[&[Token::Skem]]);
        assert_eq!(pattern.get_type(), HandshakeType::KEM);
    }

    #[test]
    fn resolve_hybrid() {
        let pattern = HandshakePattern::new(
            "dh",
            &[],
            &[],
            &[&[Token::Ekem, Token::SE]],
            &[&[Token::Skem]],
        );
        assert_eq!(pattern.get_type(), HandshakeType::HYBRID);
    }

    #[test]
    #[should_panic]
    fn invalid_pattern_empty() {
        let _ = HandshakePattern::new("dh", &[], &[], &[], &[]);
    }

    #[test]
    #[should_panic]
    fn invalid_pattern_no_ops() {
        let _ = HandshakePattern::new("dh", &[], &[], &[&[Token::E, Token::S]], &[]);
    }

    #[test]
    #[should_panic]
    fn too_many_tokens() {
        let _ = HandshakePattern::new(
            "dh",
            &[],
            &[],
            &[&[
                Token::E,
                Token::E,
                Token::E,
                Token::E,
                Token::E,
                Token::E,
                Token::E,
                Token::E,
                Token::E,
                Token::E,
                Token::E,
                Token::E,
            ]],
            &[],
        );
    }

    // PSK validity rule tests
    #[test]
    fn psk_validity_e_before_psk() {
        // E before PSK is valid
        let result = HandshakePattern::try_new(
            "test",
            &[],
            &[],
            &[&[Token::E, Token::Psk]],
            &[&[Token::E, Token::EE]],
        );
        assert!(result.is_ok());
    }

    #[test]
    fn psk_validity_e_after_psk() {
        // E after PSK is valid
        let result = HandshakePattern::try_new(
            "test",
            &[],
            &[],
            &[&[Token::Psk, Token::E]],
            &[&[Token::E, Token::EE]],
        );
        assert!(result.is_ok());
    }

    #[test]
    fn psk_validity_ekem_after_psk() {
        // Ekem after PSK is valid
        let result = HandshakePattern::try_new(
            "test",
            &[],
            &[],
            &[&[Token::Psk, Token::Ekem]],
            &[&[Token::Ekem]],
        );
        assert!(result.is_ok());
    }

    #[test]
    fn psk_validity_skem_before_psk() {
        // Skem before PSK is valid (applies randomness before encryption)
        let result = HandshakePattern::try_new(
            "test",
            &[],
            &[],
            &[&[Token::Skem, Token::Psk]],
            &[&[Token::Ekem]],
        );
        assert!(result.is_ok());
    }

    #[test]
    fn psk_validity_violation_s_after_psk() {
        // S after PSK without E/Ekem is invalid
        let result = HandshakePattern::try_new(
            "test",
            &[],
            &[],
            &[&[Token::Psk, Token::S]],
            &[&[Token::E, Token::EE]],
        );
        assert!(matches!(
            result,
            Err(crate::error::PatternError::PskValidityViolation)
        ));
    }

    #[test]
    fn psk_validity_violation_skem_after_psk() {
        // Skem after PSK is invalid (encrypts before applying randomness)
        let result = HandshakePattern::try_new(
            "test",
            &[],
            &[],
            &[&[Token::Psk, Token::Skem]],
            &[&[Token::Ekem]],
        );
        assert!(matches!(
            result,
            Err(crate::error::PatternError::PskValidityViolation)
        ));
    }

    // PQ token ordering rule tests
    #[test]
    fn pq_token_order_valid() {
        // Valid: ekem before skem before public keys
        let result = HandshakePattern::try_new(
            "test",
            &[],
            &[],
            &[&[Token::Ekem, Token::Skem, Token::E]],
            &[&[Token::Ekem]],
        );
        assert!(result.is_ok());
    }

    #[test]
    fn pq_token_order_violation_ekem_after_skem() {
        // Invalid: ekem must come before skem
        let result = HandshakePattern::try_new(
            "test",
            &[],
            &[],
            &[&[Token::Skem, Token::Ekem]],
            &[&[Token::Ekem]],
        );
        assert!(matches!(
            result,
            Err(crate::error::PatternError::PqTokenOrderViolation)
        ));
    }

    #[test]
    fn pq_token_order_violation_ekem_after_public_key() {
        // Invalid: ekem must come before public keys
        let result = HandshakePattern::try_new(
            "test",
            &[],
            &[],
            &[&[Token::E, Token::Ekem]],
            &[&[Token::Ekem]],
        );
        assert!(matches!(
            result,
            Err(crate::error::PatternError::PqTokenOrderViolation)
        ));
    }

    #[test]
    fn pq_token_order_violation_skem_after_public_key() {
        // Invalid: skem must come before public keys
        let result = HandshakePattern::try_new(
            "test",
            &[],
            &[],
            &[&[Token::E, Token::Skem]],
            &[&[Token::Ekem]],
        );
        assert!(matches!(
            result,
            Err(crate::error::PatternError::PqTokenOrderViolation)
        ));
    }

    // Tests for add_psks validation
    #[test]
    #[should_panic(expected = "PSK validity rule violation")]
    fn add_psks_psk_validity_violation_skem_after_psk() {
        // This test verifies that add_psks validates PSK validity rule
        // Creating a pattern with Skem, then adding PSK at position 0
        // should fail because PSK comes before Skem without E/Ekem
        let pattern = HandshakePattern::new("test", &[], &[], &[&[Token::Skem]], &[&[Token::Ekem]]);
        // Adding PSK at position 0 (first message, first token) creates [Psk, Skem]
        // which violates PSK validity rule: Skem encrypts data after PSK without E/Ekem
        let _ = pattern.add_psks(&[0], "invalid");
    }

    #[test]
    #[should_panic(expected = "PSK validity rule violation")]
    fn add_psks_psk_validity_violation_s_after_psk() {
        // This test verifies that add_psks validates PSK validity rule
        // Creating a pattern with S, then adding PSK at position 0
        // should fail because PSK comes before S without E/Ekem
        let pattern =
            HandshakePattern::new("test", &[], &[], &[&[Token::S]], &[&[Token::E, Token::EE]]);
        // Adding PSK at position 0 creates [Psk, S]
        // which violates PSK validity rule: S encrypts data after PSK without E/Ekem
        let _ = pattern.add_psks(&[0], "invalid");
    }

    #[test]
    fn add_psks_psk_validity_ok_with_e_before() {
        // Valid: E before PSK
        let pattern =
            HandshakePattern::new("test", &[], &[], &[&[Token::E]], &[&[Token::E, Token::EE]]);
        // Adding PSK at position 1 (after E) creates [E, Psk] which is valid
        let result = pattern.add_psks(&[1], "valid");
        assert!(result.has_psk());
    }

    #[test]
    fn add_psks_psk_validity_ok_with_e_after() {
        // Valid: E after PSK
        let pattern =
            HandshakePattern::new("test", &[], &[], &[&[Token::E]], &[&[Token::E, Token::EE]]);
        // Adding PSK at position 0 (before E) creates [Psk, E] which is valid
        let result = pattern.add_psks(&[0], "valid");
        assert!(result.has_psk());
    }

    #[test]
    fn add_psks_validates_full_pattern() {
        // This test verifies that add_psks calls try_new which validates
        // the entire pattern, including PQ token ordering if applicable.
        // Since PSK placement doesn't typically affect ekem/skem ordering,
        // we verify that add_psks works correctly on valid patterns.
        let pattern = HandshakePattern::new("test", &[], &[], &[&[Token::Ekem]], &[&[Token::Ekem]]);
        // Adding PSK should work and the resulting pattern should be valid
        let result = pattern.add_psks(&[0], "valid");
        assert!(result.has_psk());
        assert_eq!(result.get_type(), HandshakeType::KEM);
    }
}
