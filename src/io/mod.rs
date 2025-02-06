//! Implementation of no-std [`embedded_io::Read`] and [`embedded_io::Write`] from the Embedded Working Group
//!
//! Provide a way to build an object that is [`embedded_io::Read`] and [`embedded_io::Write`] with a transport state
//! set up, from another [`embedded_io::Read`] and [`embedded_io::Write`] object (eg. a TCP socket).

use embedded_io::{ErrorType, Read, Write};
use error::{ReadAdapterError, ReadWriteAdapterError, WriteAdapterError};
use read::ReadAdapterInner;
use write::WriteAdapterInner;

use crate::error::HandshakeError;
use crate::traits::{Cipher, Handshaker, Hash};
use crate::transportstate::TransportState;

mod error;
mod read;
pub use read::ReadAdapter;
mod write;
pub use write::WriteAdapter;

/// Try to construct a new transport state
///
/// Perform a handshake using the given [`crate::traits::Handshaker`] using the provided
/// `reader` and `writer`. To perform the handshake, this needs an additional
/// `handshake_buffer` big enough to hold the biggest message during the handshake.
/// We assume no handshake payload is ever transmitted.
///
/// # Arguments
/// * `mut hs` - A handshaker implementing [`crate::traits::Handshaker`], to be performed
/// * `reader` - A reader implementing [`embedded_io::Read`], to receive the messages
/// * `writer` - A writer implementing [`embedded_io::Write`] to send the messages
/// * `handshake_buffer` - A buffer big enough to hold the biggest message during the handshake.
///
/// # Errors
/// * [`AdapterError::ReadError`] or [`AdapterError::WriteError`] - The underlying reader or writer failed.
/// * [`AdapterError::HandshakeError`] - There was a problem during the handshake (eg. the provided buffer is too small).
// TODO: Add marker traits for: {OneWay,Interactive}Handshake (for single {Reader,Writer}Adapter), and {PQ,NQ}Handshake (instead of is_oneway and is_kem)
// TODO: Statically computed size (to avoid manipulating buffer)
// TODO: Implement Split from the Noise Specification
fn try_new_transport<C: Cipher, H: Hash, R: Read, W: Write, HS: Handshaker<C, H>>(
    mut hs: HS,
    reader: &mut R,
    writer: &mut W,
    handshake_buffer: &mut [u8],
) -> Result<TransportState<C, H>, ReadWriteAdapterError<R::Error, W::Error>> {
    // First, perform handshake with empty payload data.
    while !hs.is_finished() {
        if hs.is_write_turn() {
            let n = hs.write_message(&[], handshake_buffer)?;
            writer
                .write_all(&handshake_buffer[..n])
                .map_err(WriteAdapterError::Write)?;
        } else {
            // Expects empty payload data. Will eventually return an error if there are some handshake payload data
            let message_len = hs.get_next_message_overhead()?;
            if message_len > handshake_buffer.len() {
                return Err(HandshakeError::BufferTooSmall.into());
            }
            reader
                .read_exact(&mut handshake_buffer[..message_len])
                .map_err(ReadAdapterError::ReadExact)?;
            let _ = hs.read_message(&handshake_buffer[..message_len], &mut [])?;
        }
    }

    hs.finalize().map_err(ReadWriteAdapterError::Handshake)
}

/// Adapter type to use a given reader and writer with a Noise protocol.
///
/// Since [`embedded_io::Read`] and [`embedded_io::Write`] interfaces do not provide a way to know message
/// boundaries, message length is encoded as recommended in Section 13 of the Noise specification:
/// with a 16-bits big-endian length field prior to each transport message.
pub struct IoAdapter<C: Cipher, H: Hash, R: Read, W: Write, const BUF: usize> {
    transport_state: TransportState<C, H>,
    inner_read: ReadAdapterInner<C, H, R, BUF>,
    inner_write: WriteAdapterInner<C, H, W, BUF>,
}

// TODO: Typestate every message pattern, this would allow easier read
// TODO: Implement Async{Read,Write) from embedded-io-async
impl<C: Cipher, H: Hash, R: Read, W: Write, const BUF: usize> IoAdapter<C, H, R, W, BUF> {
    /// Try to construct a new read and write adapter by performing a handshake.
    ///
    /// Perform a handshake using the given [`crate::traits::Handshaker`] using the provided
    /// `reader` and `writer`. To perform the handshake, this needs an additional
    /// `handshake_buffer` big enough to hold the biggest message during the handshake.
    /// We assume no handshake payload is ever transmitted.
    ///
    /// This function voluntarily takes ownership of the reader and writer to limit
    /// possible misuses.
    ///
    /// # Arguments
    /// * `mut hs` - A handshaker implementing [`crate::traits::Handshaker`], to be performed
    /// * `reader` - A reader implementing [`embedded_io::Read`], to receive the messages
    /// * `writer` - A writer implementing [`embedded_io::Write`] to send the messages
    /// * `handshake_buffer` - A buffer big enough to hold the biggest message during the handshake.
    ///
    /// # Errors
    /// * [`ReadWriteAdapter::ReadAdapterError`] or [`ReadWriteAdapter::WriteAdapterError`] - The underlying reader or writer failed.
    /// * [`ReadWriteAdapterError::HandshakeError`] - There was a problem during the handshake (eg. the provided buffer is too small).
    pub fn try_with_handshake<HS: Handshaker<C, H>>(
        hs: HS,
        mut reader: R,
        mut writer: W,
        handshake_buffer: &mut [u8],
    ) -> Result<Self, ReadWriteAdapterError<R::Error, W::Error>> {
        Ok(Self {
            transport_state: try_new_transport(hs, &mut reader, &mut writer, handshake_buffer)?,
            inner_read: ReadAdapterInner::new(reader),
            inner_write: WriteAdapterInner::new(writer),
        })
    }

    /// Construct a new read and write adapter from a provided transport state.
    ///
    /// # Arguments
    /// * `transport_state` - A transport state (handshake already done)
    /// * `reader` - A reader implementing [`embedded_io::Read`], to receive the messages
    /// * `writer` - A writer implementing [`embedded_io::Write`] to send the messages
    pub fn new_with_transport_state(
        transport_state: TransportState<C, H>,
        reader: R,
        writer: W,
    ) -> Self {
        Self {
            transport_state,
            inner_read: ReadAdapterInner::new(reader),
            inner_write: WriteAdapterInner::new(writer),
        }
    }
}

impl<C: Cipher, H: Hash, R: Read, W: Write, const BUF: usize> ErrorType
    for IoAdapter<C, H, R, W, BUF>
{
    type Error = ReadWriteAdapterError<R::Error, W::Error>;
}

impl<C: Cipher, H: Hash, R: Read, W: Write, const BUF: usize> Read for IoAdapter<C, H, R, W, BUF> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        self.inner_read
            .read_with_transport_state(buf, &mut self.transport_state)
            .map_err(ReadWriteAdapterError::ReadAdapter)
    }
}
impl<C: Cipher, H: Hash, R: Read, W: Write, const BUF: usize> Write for IoAdapter<C, H, R, W, BUF> {
    fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
        self.inner_write
            .write_with_transport_state(buf, &mut self.transport_state)
            .map_err(ReadWriteAdapterError::WriteAdapter)
    }

    fn flush(&mut self) -> Result<(), Self::Error> {
        self.inner_write
            .flush()
            .map_err(ReadWriteAdapterError::WriteAdapter)
    }
}

// TODO: Test combination of:
// TODO: * small capacity channel with bufread
// TODO: * big buf to read or write
// TODO: * small io_buffer
