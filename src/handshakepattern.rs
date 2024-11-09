//! Pre-made Noise handshake patterns and tools for defining new ones

use arrayvec::ArrayVec;

/// Handshake tokens as defined by the Noise spec and PQNoise paper.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Token {
    E,
    S,
    EE,
    ES,
    SE,
    SS,
    Ekem,
    Skem,
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
    is_kem: bool,
}

#[derive(Clone, Debug)]
pub struct MessagePattern {
    pub initiator: ArrayVec<ArrayVec<Token, 8>, 4>,
    pub responder: ArrayVec<ArrayVec<Token, 8>, 4>,
}

impl HandshakePattern {
    /// Initialize a new handshake pattern
    ///
    /// # Arguments:
    /// * `name` - Pattern name
    /// * `pre_initiator` - Tokens shared by initiator pre handshake
    /// * `pre_responder` - Tokens shared by responder pre handshake
    /// * `initiator` - Initiator messages
    /// * `responder` - Responder messages
    /// * `ìs_kem` - True if this pattern is a PQ Noise pattern with KEMs
    pub fn new(
        name: &'static str,
        pre_initiator: &[Token],
        pre_responder: &[Token],
        initiator: &[&[Token]],
        responder: &[&[Token]],
        is_kem: bool,
    ) -> Self {
        Self {
            name,
            is_kem,
            pre_initiator: pre_initiator.iter().copied().collect(),
            pre_responder: pre_responder.iter().copied().collect(),
            message_pattern: MessagePattern {
                initiator: initiator
                    .iter()
                    .map(|p| p.iter().copied().collect())
                    .collect(),
                responder: responder
                    .iter()
                    .map(|p| p.iter().copied().collect())
                    .collect(),
            },
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

    /// Get name of the pattern
    pub(crate) fn get_name(&self) -> &'static str {
        self.name
    }

    /// Check if the pattern includes KEM
    pub(crate) fn is_kem(&self) -> bool {
        self.is_kem
    }
}

// PQ patterns:

/// ```text
/// -> e
/// <- ekem
/// ```
pub fn noise_pqnn() -> HandshakePattern {
    HandshakePattern::new("pqNN", &[], &[], &[&[Token::E]], &[&[Token::Ekem]], true)
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
        true,
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
        true,
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
        true,
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
        true,
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
        true,
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
        true,
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
        true,
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
        true,
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
        true,
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
        true,
    )
}

/// ```text
/// pqIX:
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
        true,
    )
}

// NQ patterns:

/// ```text
/// -> e
/// <- e, ee
/// ```
pub fn noise_nn() -> HandshakePattern {
    HandshakePattern::new(
        "NN",
        &[],
        &[],
        &[&[Token::E]],
        &[&[Token::E, Token::EE]],
        false,
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
        false,
    )
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
        false,
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
        false,
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
        false,
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
        false,
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
        false,
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
        false,
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
        false,
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
        false,
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
        false,
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
        false,
    )
}
