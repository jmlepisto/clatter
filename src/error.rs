//! Error types used by Clatter

use displaydoc::Display;
use thiserror_no_std::Error;

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
    /// KEM error: {0}
    Kem(#[from] KemError),
    /// DH error: {0}
    Dh(#[from] DhError),
    /// Cipher error: {0}
    Cipher(#[from] CipherError),
    /// Transport error: {0}
    Transport(#[from] TransportError),
}

pub type HandshakeResult<T> = Result<T, HandshakeError>;

/// Errors that can happen during transport operations
#[derive(Debug, Error, Display)]
pub enum TransportError {
    /// Provided buffer too small for given message
    BufferTooSmall,
    /// Received too short message for decryption
    TooShort,
    /// Cipher error: {0}
    Cipher(#[from] CipherError),
}

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

pub type KemResult<T> = Result<T, KemError>;

/// Errors that can happen during DH operations
#[derive(Debug, Error, Display)]
pub enum DhError {
    /// Error generating keys
    KeyGeneration,
}

pub type DhResult<T> = Result<T, DhError>;

/// Errors that can happen during Cipher operations
#[derive(Debug, Error, Display)]
pub enum CipherError {
    /// Nonce overflow
    NonceOverflow,
    /// Decrypt error
    Decrypt,
}

pub type CipherResult<T> = Result<T, CipherError>;
