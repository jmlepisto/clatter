use displaydoc::Display;
use embedded_io::{Error, ErrorKind, ReadExactError};
use thiserror_no_std::Error;

use crate::error::{HandshakeError, TransportError};

#[derive(Debug, Error, Display)]
/// Errors that can happen during handshake or transport
pub enum NoiseError {
    /// Error during handshake
    Handshake(#[from] HandshakeError),
    /// Error during transport
    Transport(#[from] TransportError),
}

impl Error for NoiseError {
    fn kind(&self) -> ErrorKind {
        ErrorKind::Other
    }
}

#[derive(Debug, Error, Display)]
/// Errors that can occur while using the read adapter
pub enum ReadAdapterError<RE: Error> {
    /// Error while using the underlying reader
    Read(#[from] RE),
    /// Error while using the underlying reader using `read_exact`
    ReadExact(#[from] ReadExactError<RE>),
    /// MTU too small to handle an incoming message
    Mtu(u16),
    /// Error in the handshake or transport
    Noise(NoiseError),
}

impl<RE: Error> Error for ReadAdapterError<RE> {
    fn kind(&self) -> ErrorKind {
        match self {
            ReadAdapterError::Read(e) => e.kind(),
            ReadAdapterError::Noise(e) => e.kind(),
            ReadAdapterError::ReadExact(e) => match e {
                ReadExactError::UnexpectedEof => ErrorKind::ConnectionAborted,
                ReadExactError::Other(e) => e.kind(),
            },
            ReadAdapterError::Mtu(_) => ErrorKind::InvalidData,
        }
    }
}

#[derive(Debug, Error, Display)]
/// Errors that can occur while using the read adapter
pub enum WriteAdapterError<WE: Error> {
    /// Error while using the underlying writer
    Write(WE),
    /// Error in the handshake or transport
    Noise(NoiseError),
}

impl<WE: Error> Error for WriteAdapterError<WE> {
    fn kind(&self) -> ErrorKind {
        match self {
            WriteAdapterError::Noise(e) => e.kind(),
            WriteAdapterError::Write(e) => e.kind(),
        }
    }
}

#[derive(Debug, Error, Display)]
pub enum ReadWriteAdapterError<RE: Error, WE: Error> {
    /// Error in the read adapter
    ReadAdapter(#[from] ReadAdapterError<RE>),
    /// Error in the write adapter
    WriteAdapter(#[from] WriteAdapterError<WE>),
    /// Error during the creation of the transport state
    Handshake(#[from] HandshakeError),
}

impl<RE: Error, WE: Error> Error for ReadWriteAdapterError<RE, WE> {
    fn kind(&self) -> ErrorKind {
        match self {
            ReadWriteAdapterError::ReadAdapter(e) => e.kind(),
            ReadWriteAdapterError::WriteAdapter(e) => e.kind(),
            ReadWriteAdapterError::Handshake(_) => ErrorKind::Other,
        }
    }
}
