use thiserror_no_std::Error;

/// Errors that can happen during handshake operations
#[derive(Debug, Error)]
pub enum HandshakeError {
    #[error("Missing key material for selected pattern")]
    MissingMaterial,
    #[error("Requested an operation in invalid state")]
    InvalidState,
    #[error("Provided buffer too small for next message")]
    BufferTooSmall,
    #[error("Handshaker encountered an error earlier and has been disabled")]
    ErrorState,
    #[error("Required PSKs were not supplied")]
    PskMissing,
    #[error("KEM error: {0}")]
    Kem(#[from] KemError),
    #[error("DH error: {0}")]
    Dh(#[from] DhError),
    #[error("Cipher error: {0}")]
    Cipher(#[from] CipherError),
    #[error("Transport error: {0}")]
    Transport(#[from] TransportError),
}

pub type HandshakeResult<T> = Result<T, HandshakeError>;

/// Errors that can happen during transport operations
#[derive(Debug, Error)]
pub enum TransportError {
    #[error("Provided buffer too small for given message")]
    BufferTooSmall,
    #[error("Cipher error: {0}")]
    Cipher(#[from] CipherError),
}

pub type TransportResult<T> = Result<T, TransportError>;

/// Errors that can happen during KEM operations
#[derive(Debug, Error)]
pub enum KemError {
    #[error("Invalid input")]
    Input,
    #[error("Decapsulation error")]
    Decapsulation,
    #[error("Encapsulation error")]
    Encapsulation,
    #[error("Error generating keys")]
    KeyGeneration,
}

pub type KemResult<T> = Result<T, KemError>;

// Errors that can happen during DH operations
#[derive(Debug, Error)]
pub enum DhError {
    #[error("Error generating keys")]
    KeyGeneration,
}

pub type DhResult<T> = Result<T, DhError>;

/// Errors that can happen during Cipher operations
#[derive(Debug, Error)]
pub enum CipherError {
    #[error("Nonce overflow")]
    NonceOverflow,
    #[error("Decrypt error")]
    Decrypt,
}

pub type CipherResult<T> = Result<T, CipherError>;
