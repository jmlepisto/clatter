//! Error types used by Clatter

use displaydoc::Display;
use thiserror_no_std::Error;

use crate::handshakepattern::HandshakeType;

/// Errors that can happen during handshake operations
#[derive(Debug, Error, Display)]
pub enum HandshakeError {
    /// Missing key material for selected pattern
    MissingMaterial,
    /// Requested an operation in invalid state
    InvalidState,
    /// Provided buffer too small for next message
    BufferTooSmall,
    /// Received invalid message
    InvalidMessage,
    /// Handshaker encountered an error earlier and has been disabled
    ErrorState,
    /// Required PSKs were not supplied
    PskMissing,
    /// Invalid handshake pattern: expected {0:?}, got {1:?}
    InvalidPattern(HandshakeType, HandshakeType),
    /// KEM error: {0}
    Kem(#[from] KemError),
    /// DH error: {0}
    Dh(#[from] DhError),
    /// Cipher error: {0}
    Cipher(#[from] CipherError),
    /// Transport error: {0}
    Transport(#[from] TransportError),
}

/// Handshake operation result type
pub type HandshakeResult<T> = Result<T, HandshakeError>;

/// Errors that can happen during transport operations
#[derive(Debug, Error, Display)]
pub enum TransportError {
    /// Provided buffer too small for given message
    BufferTooSmall,
    /// Received too short message for decryption
    TooShort,
    /// Tried to encrypt/decrypt data in the wrong direction after a one-way handshake
    OneWayViolation,
    /// Cipher error: {0}
    Cipher(#[from] CipherError),
}

/// Transport operation result type
pub type TransportResult<T> = Result<T, TransportError>;

/// Errors that can happen during KEM operations
#[derive(Debug, Error, Display)]
pub enum KemError {
    /// Invalid input
    Input,
    /// Decapsulation error
    Decapsulation,
    /// Encapsulation error
    Encapsulation,
    /// Error generating keys
    KeyGeneration,
}

/// KEM operation result type
pub type KemResult<T> = Result<T, KemError>;

/// Errors that can happen during DH operations
#[derive(Debug, Error, Display)]
pub enum DhError {
    /// Error generating keys
    KeyGeneration,
}

/// DH operation result type
pub type DhResult<T> = Result<T, DhError>;

/// Errors that can happen during Cipher operations
#[derive(Debug, Error, Display)]
pub enum CipherError {
    /// Nonce overflow
    NonceOverflow,
    /// Decrypt error
    Decrypt,
}

/// Cipher operation result type
pub type CipherResult<T> = Result<T, CipherError>;
