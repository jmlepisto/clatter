//! Implementation of no-std [`Read`] and [`Write`] from the Embedded Working Group
//!
//! Provide a way to build an object that is [`Read`] and [`Write`] with a transport state
//! set up, from another [`Read`] and [`Write`] object (eg. a TCP socket).

use core::marker::PhantomData;

use displaydoc::Display;
use embedded_io::{Error, ErrorKind, ErrorType, Read, ReadExactError, Write};
use thiserror_no_std::Error;

use crate::constants::{MAX_MESSAGE_LEN, MAX_TAG_LEN};
use crate::error::{HandshakeError, TransportError};
use crate::traits::{Cipher, Handshaker, Hash};
use crate::transportstate::TransportState;

#[derive(Debug, Error, Display)]
/// Errors that can happen during handshake or transport with the io adapter
pub enum AdapterError<RE: Error, WE: Error> {
    /// Error during handshake
    HandshakeError(#[from] HandshakeError),
    /// Error during transport
    TransportError(#[from] TransportError),
    /// Error while using the underlying reader
    ReadError(RE),
    /// Error while using the underlying reader using `read_exact`
    ReadExactError(#[from] ReadExactError<RE>),
    /// Error while using the underlying writer
    WriteError(WE),
    /// MTU too small to handle an incoming message
    MTUError(u16),
}

impl<RE: Error, WE: Error> Error for AdapterError<RE, WE> {
    fn kind(&self) -> ErrorKind {
        match self {
            AdapterError::HandshakeError(_) | AdapterError::TransportError(_) => ErrorKind::Other,
            AdapterError::ReadError(e) => e.kind(),
            AdapterError::ReadExactError(e) => match e {
                ReadExactError::UnexpectedEof => ErrorKind::ConnectionAborted,
                ReadExactError::Other(e) => e.kind(),
            },
            AdapterError::WriteError(e) => e.kind(),
            AdapterError::MTUError(_) => ErrorKind::InvalidData,
        }
    }
}

/// Adapter type to use a given reader and writer.
///
/// Since `Read` and `Write` interface does not provide a way to know message
/// boundaries, we encode the length of message as recommend in Section 13 of the Noise specification:
/// with a 16-bits big-endian length field prior to each transport message.
// TODO: Split reader and writer into two different objects.
pub struct IoAdapter<C: Cipher, H: Hash, R: Read, W: Write, HS: Handshaker<C, H>, const BUF: usize>
{
    transport_state: TransportState<C, H>,
    reader: R,
    writer: W,
    read_buffer: [u8; BUF],
    available_to_read: usize,
    write_buffer: [u8; BUF],
    _phantom: PhantomData<HS>,
}

// TODO: Add marker traits for: {OneWay,Interactive}Handshake (for single {Reader,Writer}Adapter, {PQ,NQ}Handshake (instead of is_oneway and is_kem)
// TODO: Statically computed size (to avoid manipulating buffer)
// TODO: Typestate every message pattern, this would allow easier read
// TODO: Implement Async{Read,Write) from embedded-io-async
// TODO: MAX_TAG_LEN needs to be just TAG_LEN
// TODO: Implement Split from the Noise Specification instead of runtime checks
impl<C: Cipher, H: Hash, R: Read, W: Write, HS: Handshaker<C, H>, const BUF: usize>
    IoAdapter<C, H, R, W, HS, BUF>
{
    /// MTU is equal to the size of the buffer minus MAX_TAG_LEN for the tag
    const MTU: usize = BUF - MAX_TAG_LEN;

    // This fails to compile if BUF is too big.
    // Thus, it is a compile time check that BUF is reasonable.
    const _CHECK: usize = MAX_MESSAGE_LEN - BUF;

    /// Try to construct a new adapter
    ///
    /// Perform a handshake using the given [`crate::traits::Handshaker`] using the provided
    /// `reader` and `writer`. To perform the handshake, it needs an additional
    /// `handshake_buffer` big enough to hold the biggest message during the handshake.
    /// We assume no handshake payload is ever transmitted.
    ///
    /// # Arguments
    /// * `mut hs` - A handshaker implementing [`crate::traits::Handshaker`], to execute
    /// * `mut reader` - A reader implementing [`embedded_io::Read`], to receive the messages
    /// * `mut writer` - A writer implementing [`embedded_io::Write`] to send the messages
    /// * `handshake_buffer` - A buffer big enough to hold the biggest message during the handshake.
    ///
    /// # Errors
    /// * [`AdapterError::ReadError`] or [`AdapterError::WriteError`] - The underlying reader or writer failed.
    /// * [`AdapterError::HandshakeError`] - There was a problem during the handshake (eg. the provided buffer is too small).
    pub fn try_new(
        mut hs: HS,
        mut reader: R,
        mut writer: W,
        handshake_buffer: &mut [u8],
    ) -> Result<Self, <Self as ErrorType>::Error> {
        // First, perform handshake with empty payload data.
        while !hs.is_finished() {
            if hs.is_write_turn() {
                let n = hs.write_message(&[], handshake_buffer)?;
                writer
                    .write_all(&handshake_buffer[..n])
                    .map_err(AdapterError::WriteError)?;
            } else {
                // Expects empty payload data. Will eventually return an error if there are some handshake payload data
                let message_len = hs.get_next_message_overhead()?;
                if message_len > handshake_buffer.len() {
                    return Err(AdapterError::HandshakeError(HandshakeError::BufferTooSmall));
                }
                reader.read_exact(&mut handshake_buffer[..message_len])?;
                let _ = hs.read_message(&handshake_buffer[..message_len], &mut [])?;
            }
        }

        Ok(IoAdapter {
            transport_state: hs.finalize()?,
            reader,
            writer,
            read_buffer: [0u8; BUF],
            available_to_read: 0,
            write_buffer: [0u8; BUF],
            _phantom: PhantomData,
        })
    }
}

impl<C: Cipher, H: Hash, R: Read, W: Write, HS: Handshaker<C, H>, const BUF: usize> ErrorType
    for IoAdapter<C, H, R, W, HS, BUF>
{
    type Error = AdapterError<R::Error, W::Error>; // Wrap the underlying error
}

impl<C: Cipher, H: Hash, R: Read, W: Write, HS: Handshaker<C, H>, const BUF: usize> Read
    for IoAdapter<C, H, R, W, HS, BUF>
{
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        if buf.is_empty() {
            return Ok(0);
        }

        // If bytes are available from a previous read, return them instantly.
        if self.available_to_read != 0 {
            // Infallible
            let n_read = (&self.read_buffer[..self.available_to_read])
                .read(buf)
                .unwrap();
            // Cannot underflow
            self.available_to_read -= n_read;
            return Ok(n_read);
        }

        // Read the size of the next message
        let mut msg_len_buf = [0u8; 2];
        match self.reader.read_exact(&mut msg_len_buf) {
            Ok(_) => {}
            Err(e) => match e {
                ReadExactError::UnexpectedEof => return Ok(0),
                ReadExactError::Other(inner_e) => return Err(AdapterError::ReadError(inner_e)),
            },
        };
        let msg_len = u16::from_be_bytes(msg_len_buf) as usize;

        if msg_len > BUF {
            return Err(AdapterError::MTUError(msg_len as u16));
        }

        // At this point, self.available_to_read is guaranteed to be zero
        // and read_buffer only contains useless bytes.
        self.reader.read_exact(&mut self.read_buffer[..msg_len])?;
        let plain_len = self
            .transport_state
            .receive_in_place(&mut self.read_buffer[..msg_len], msg_len)?;

        // Copy as much plaintext bytes to the destination buffer.
        // Every slice ranges are valid in every branches.
        if plain_len > buf.len() {
            buf.copy_from_slice(&self.read_buffer[..buf.len()]);
            // Store the remaining plaintext bytes for a later read
            // by copying at the start of the buffer and updating self.available_to_read
            self.read_buffer.copy_within(buf.len()..plain_len, 0);
            self.available_to_read = plain_len - buf.len();

            Ok(buf.len())
        } else {
            buf[..plain_len].copy_from_slice(&self.read_buffer[..plain_len]);
            Ok(plain_len)
        }
    }
}

impl<C: Cipher, H: Hash, R: Read, W: Write, HS: Handshaker<C, H>, const BUF: usize> Write
    for IoAdapter<C, H, R, W, HS, BUF>
{
    fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
        let to_send = &buf[..buf.len().min(Self::MTU)];

        // Encrypt the part of the input buffer we will actually send.
        let msg_len = self.transport_state.send(to_send, &mut self.write_buffer)?;

        // First, send the message length.
        self.writer
            // try_from is infallible since msg_len is guaranteed to be < MAX_MESSAGE_LEN = 2**16
            .write_all(&u16::try_from(msg_len).unwrap().to_le_bytes())
            .map_err(AdapterError::WriteError)?;

        // Finally, send the actual message.
        self.writer
            .write_all(&self.write_buffer[..msg_len])
            .map_err(AdapterError::WriteError)?;

        Ok(msg_len)
    }

    fn flush(&mut self) -> Result<(), Self::Error> {
        self.writer.flush().map_err(AdapterError::WriteError)
    }
}

// TODO: Test combination of:
// TODO: * small capacity channel with bufread
// TODO: * big buf to read or write
// TODO: * small io_buffer
