//! Pre-made Noise handshake patterns and tools for defining new ones

use arrayvec::ArrayVec;

use crate::constants::{MAX_HS_MESSAGES_PER_ROLE, MAX_TOKENS_PER_HS_MESSAGE};

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
    pub fn new(
        name: &'static str,
        pre_initiator: &[Token],
        pre_responder: &[Token],
        initiator: &[&[Token]],
        responder: &[&[Token]],
    ) -> Self {
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

        Self {
            name,
            hs_type,
            has_psk: message_pattern.has_psk(),
            message_pattern,
            pre_initiator: pre_initiator.iter().copied().collect(),
            pre_responder: pre_responder.iter().copied().collect(),
        }
    }

    pub(crate) fn get_initiator_pattern_len(&self) -> usize {
        self.message_pattern.initiator.len()
    }

    pub(crate) fn get_responder_pattern_len(&self) -> usize {
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
    pub(crate) fn get_initiator_pattern(&self, index: usize) -> &[Token] {
        &self.message_pattern.initiator[index]
    }

    /// Get responder message pattern based on message index
    ///
    /// # Panics
    /// Panics if message index is larger than the pattern length
    pub(crate) fn get_responder_pattern(&self, index: usize) -> &[Token] {
        &self.message_pattern.responder[index]
    }

    /// Check if the pattern includes PSKs
    pub(crate) fn has_psk(&self) -> bool {
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

        Self {
            name,
            hs_type: self.hs_type,
            has_psk: true,
            pre_initiator: self.pre_initiator.clone(),
            pre_responder: self.pre_responder.clone(),
            message_pattern: MessagePattern {
                initiator,
                responder,
            },
        }
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
/// -> psk, e
/// <- ekem
/// ```
pub fn noise_pqnn_psk0() -> HandshakePattern {
    noise_pqnn().add_psks(&[0], "pqNNpsk0")
}

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
/// -> psk, skem, e
/// <- ekem
/// ```
pub fn noise_pqnk_psk0() -> HandshakePattern {
    noise_pqnk().add_psks(&[0], "pqNKpsk0")
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
/// -> psk, e
/// <- ekem, skem
/// ```
pub fn noise_pqkn_psk0() -> HandshakePattern {
    noise_pqkn().add_psks(&[0], "pqKNpsk0")
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
/// -> psk, skem, e
/// <- ekem, skem
/// ```
pub fn noise_pqkk_psk0() -> HandshakePattern {
    noise_pqkk().add_psks(&[0], "pqKKpsk0")
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
/// <- e, ee, ekem
/// ```
pub fn noise_hybrid_nn() -> HandshakePattern {
    HandshakePattern::new(
        "hybridNN",
        &[],
        &[],
        &[&[Token::E]],
        &[&[Token::E, Token::EE, Token::Ekem]],
    )
}

/// ```text
/// <- s
/// ...
/// -> skem, e, es
/// <- e, ee, ekem
/// ```
pub fn noise_hybrid_nk() -> HandshakePattern {
    HandshakePattern::new(
        "hybridNK",
        &[],
        &[Token::S],
        &[&[Token::Skem, Token::E, Token::ES]],
        &[&[Token::E, Token::EE, Token::Ekem]],
    )
}

/// ```text
/// -> e
/// <- e, ee, ekem, s, es
/// -> skem
/// ```
pub fn noise_hybrid_nx() -> HandshakePattern {
    HandshakePattern::new(
        "hybridNX",
        &[],
        &[],
        &[&[Token::E], &[Token::Skem]],
        &[&[Token::E, Token::EE, Token::Ekem, Token::S, Token::ES]],
    )
}

/// ```text
/// -> s
/// ...
/// -> e
/// <- e, ee, se, ekem, skem
/// ```
pub fn noise_hybrid_kn() -> HandshakePattern {
    HandshakePattern::new(
        "hybridKN",
        &[Token::S],
        &[],
        &[&[Token::E]],
        &[&[Token::E, Token::EE, Token::SE, Token::Ekem, Token::Skem]],
    )
}

/// ```text
/// -> s
/// <- s
/// ...
/// -> skem, e, es, ss
/// <- e, ee, se, ekem, skem
/// ```
pub fn noise_hybrid_kk() -> HandshakePattern {
    HandshakePattern::new(
        "hybridKK",
        &[Token::S],
        &[Token::S],
        &[&[Token::Skem, Token::E, Token::ES, Token::SS]],
        &[&[Token::E, Token::EE, Token::SE, Token::Ekem, Token::Skem]],
    )
}

/// ```text
/// -> s
/// ...
/// -> e
/// <- e, ee, se, ekem, skem, s, es
/// -> skem
/// ```
pub fn noise_hybrid_kx() -> HandshakePattern {
    HandshakePattern::new(
        "hybridKX",
        &[Token::S],
        &[],
        &[&[Token::E], &[Token::Skem]],
        &[&[
            Token::E,
            Token::EE,
            Token::SE,
            Token::Ekem,
            Token::Skem,
            Token::S,
            Token::ES,
        ]],
    )
}

/// ```text
/// -> e
/// <- e, ee, ekem
/// -> s, se
/// <- skem
/// ```
pub fn noise_hybrid_xn() -> HandshakePattern {
    HandshakePattern::new(
        "hybridXN",
        &[],
        &[],
        &[&[Token::E], &[Token::S, Token::SE]],
        &[&[Token::E, Token::EE, Token::Ekem], &[Token::Skem]],
    )
}

/// ```text
/// <- s
/// ...
/// -> skem, e, es
/// <- e, ee, ekem
/// -> s, se
/// <- skem
/// ```
pub fn noise_hybrid_xk() -> HandshakePattern {
    HandshakePattern::new(
        "hybridXK",
        &[],
        &[Token::S],
        &[&[Token::Skem, Token::E, Token::ES], &[Token::S, Token::SE]],
        &[&[Token::E, Token::EE, Token::Ekem], &[Token::Skem]],
    )
}

/// ```text
/// -> e
/// <- e, ee, ekem, s, es
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
            &[Token::E, Token::EE, Token::Ekem, Token::S, Token::ES],
            &[Token::Skem],
        ],
    )
}

/// ```text
/// -> e, s
/// <- e, ee, se, ekem, skem
/// ```
pub fn noise_hybrid_in() -> HandshakePattern {
    HandshakePattern::new(
        "hybridIN",
        &[],
        &[],
        &[&[Token::E, Token::S]],
        &[&[Token::E, Token::EE, Token::SE, Token::Ekem, Token::Skem]],
    )
}

/// ```text
/// <- s
/// ...
/// -> skem, e, es, s, ss
/// <- e, ee, se, ekem, skem
/// ```
pub fn noise_hybrid_ik() -> HandshakePattern {
    HandshakePattern::new(
        "hybridIK",
        &[],
        &[Token::S],
        &[&[Token::Skem, Token::E, Token::ES, Token::S, Token::SS]],
        &[&[Token::E, Token::EE, Token::SE, Token::Ekem, Token::Skem]],
    )
}

/// ```text
/// -> e, s
/// <- e, ee, se, ekem, skem, s, es
/// -> skem
/// ```
pub fn noise_hybrid_ix() -> HandshakePattern {
    HandshakePattern::new(
        "hybridIX",
        &[],
        &[],
        &[&[Token::E, Token::S], &[Token::Skem]],
        &[&[
            Token::E,
            Token::EE,
            Token::SE,
            Token::Ekem,
            Token::Skem,
            Token::S,
            Token::ES,
        ]],
    )
}

// Hybrid patterns with PSKs:

/// ```text
/// -> psk, e
/// <- e, ee, ekem
/// ```
pub fn noise_hybrid_nn_psk0() -> HandshakePattern {
    noise_hybrid_nn().add_psks(&[0], "hybridNNpsk0")
}

/// ```text
/// -> e
/// <- e, ee, ekem, psk
/// ```
pub fn noise_hybrid_nn_psk2() -> HandshakePattern {
    noise_hybrid_nn().add_psks(&[2], "hybridNNpsk2")
}

/// ```text
/// <- s
/// ...
/// -> psk, e, es, skem
/// <- e, ee, ekem
/// ```
pub fn noise_hybrid_nk_psk0() -> HandshakePattern {
    noise_hybrid_nk().add_psks(&[0], "hybridNKpsk0")
}

/// ```text
/// <- s
/// ...
/// -> e, es, skem
/// <- e, ee, ekem, psk
/// ```
pub fn noise_hybrid_nk_psk2() -> HandshakePattern {
    noise_hybrid_nk().add_psks(&[2], "hybridNKpsk2")
}

/// ```text
/// -> e
/// <- e, ee, ekem, s, es, psk
/// -> se, skem
/// ```
pub fn noise_hybrid_nx_psk2() -> HandshakePattern {
    noise_hybrid_nx().add_psks(&[2], "hybridNXpsk2")
}

/// ```text
/// -> e
/// <- e, ee, ekem
/// -> s, se, skem, psk
/// <- skem
/// ```
pub fn noise_hybrid_xn_psk3() -> HandshakePattern {
    noise_hybrid_xn().add_psks(&[3], "hybridXNpsk3")
}

/// ```text
/// <- s
/// ...
/// -> e, es, skem
/// <- e, ee, ekem
/// -> s, se, skem, psk
/// <- skem
/// ```
pub fn noise_hybrid_xk_psk3() -> HandshakePattern {
    noise_hybrid_xk().add_psks(&[3], "hybridXKpsk3")
}

/// ```text
/// -> e
/// <- e, ee, ekem, s, es
/// -> se, skem, s, ss, psk
/// <- skem
/// ```
pub fn noise_hybrid_xx_psk3() -> HandshakePattern {
    noise_hybrid_xx().add_psks(&[3], "hybridXXpsk3")
}

/// ```text
/// -> s
/// ...
/// -> psk, e
/// <- e, ee, ekem, se, skem
/// ```
pub fn noise_hybrid_kn_psk0() -> HandshakePattern {
    noise_hybrid_kn().add_psks(&[0], "hybridKNpsk0")
}

/// ```text
/// -> s
/// ...
/// -> e
/// <- e, ee, ekem, se, skem, psk
/// ```
pub fn noise_hybrid_kn_psk2() -> HandshakePattern {
    noise_hybrid_kn().add_psks(&[2], "hybridKNpsk2")
}

/// ```text
/// -> s
/// <- s
/// ...
/// -> psk, e, es, ss, skem
/// <- e, ee, ekem, se, skem
/// ```
pub fn noise_hybrid_kk_psk0() -> HandshakePattern {
    noise_hybrid_kk().add_psks(&[0], "hybridKKpsk0")
}

/// ```text
/// -> s
/// <- s
/// ...
/// -> e, es, ss, skem
/// <- e, ee, ekem, se, skem, psk
/// ```
pub fn noise_hybrid_kk_psk2() -> HandshakePattern {
    noise_hybrid_kk().add_psks(&[2], "hybridKKpsk2")
}

/// ```text
/// -> s
/// ...
/// -> e
/// <- e, ee, ekem, se, skem, s, es, psk
/// -> ss, skem
/// ```
pub fn noise_hybrid_kx_psk2() -> HandshakePattern {
    noise_hybrid_kx().add_psks(&[2], "hybridKXpsk2")
}

/// ```text
/// -> e, s, psk
/// <- e, ee, ekem, se, skem
/// ```
pub fn noise_hybrid_in_psk1() -> HandshakePattern {
    noise_hybrid_in().add_psks(&[1], "hybridINpsk1")
}

/// ```text
/// -> e, s
/// <- e, ee, ekem, se, skem, psk
/// ```
pub fn noise_hybrid_in_psk2() -> HandshakePattern {
    noise_hybrid_in().add_psks(&[2], "hybridINpsk2")
}

/// ```text
/// <- s
/// ...
/// -> e, es, s, ss, skem, psk
/// <- e, ee, ekem, se, skem
/// ```
pub fn noise_hybrid_ik_psk1() -> HandshakePattern {
    noise_hybrid_ik().add_psks(&[1], "hybridIKpsk1")
}

/// ```text
/// <- s
/// ...
/// -> e, es, s, ss, skem
/// <- e, ee, ekem, se, skem, psk
/// ```
pub fn noise_hybrid_ik_psk2() -> HandshakePattern {
    noise_hybrid_ik().add_psks(&[2], "hybridIKpsk2")
}

/// ```text
/// -> e, s
/// <- e, ee, ekem, se, skem, s, es, psk
/// -> ss, skem
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
}
