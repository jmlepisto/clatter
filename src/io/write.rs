//! Implementation of the [`embedded_io::Write`] adapter.

use embedded_io::{ErrorType, Read, Write};

use crate::{
    constants::{MAX_MESSAGE_LEN, MAX_TAG_LEN},
    traits::{Cipher, Handshaker, Hash},
    transportstate::TransportState,
};

use super::{
    error::{ReadWriteAdapterError, WriteAdapterError},
    try_new_transport,
};

pub(crate) struct WriteAdapterInner<W: Write, const BUF: usize> {
    writer: W,
    write_buffer: [u8; BUF],
}

impl<W: Write, const BUF: usize> ErrorType for WriteAdapterInner<W, BUF> {
    type Error = WriteAdapterError<W::Error>;
}

impl<W: Write, const BUF: usize> WriteAdapterInner<W, BUF> {
    // This fails to compile if BUF is too big.
    // Thus, it is a compile time check that BUF is reasonable.
    const _CHECK: usize = MAX_MESSAGE_LEN.checked_sub(BUF).unwrap();

    /// MTU is equal to the size of the buffer minus MAX_TAG_LEN for the tag
    // TODO: MAX_TAG_LEN needs to be just TAG_LEN since the Noise framework force it to be 16 bytes
    const MTU: usize = BUF.checked_sub(MAX_TAG_LEN).unwrap();

    pub(crate) fn new(writer: W) -> Self {
        Self {
            writer,
            write_buffer: [0u8; BUF],
        }
    }

    pub(crate) fn write_with_transport_state<C: Cipher, H: Hash>(
        &mut self,
        buf: &[u8],
        transport_state: &mut TransportState<C, H>,
    ) -> Result<usize, <Self as ErrorType>::Error> {
        let to_send = &buf[..buf.len().min(Self::MTU)];

        // Encrypt the part of the input buffer we will actually send.
        let msg_len = transport_state
            .send(to_send, &mut self.write_buffer)
            .map_err(|e| WriteAdapterError::Noise(e.into()))?;

        // First, send the message length.
        self.writer
            // try_from is infallible since msg_len is guaranteed to be < MAX_MESSAGE_LEN = 2**16
            .write_all(&u16::try_from(msg_len).unwrap().to_be_bytes())
            .map_err(WriteAdapterError::Write)?;

        // Finally, send the actual message.
        self.writer
            .write_all(&self.write_buffer[..msg_len])
            .map_err(WriteAdapterError::Write)?;

        Ok(to_send.len())
    }

    pub(crate) fn flush(&mut self) -> Result<(), <Self as ErrorType>::Error> {
        self.writer.flush().map_err(WriteAdapterError::Write)
    }
}

/// Adapter type to use a given writer with a Noise protocol.
///
/// Since [`embedded_io::Write`] interface do not provide a way to set message
/// boundaries, message length is encoded as recommended in Section 13 of the Noise specification:
/// with a 16-bits big-endian length field prior to each transport message.
pub struct WriteAdapter<C: Cipher, H: Hash, W: Write, const BUF: usize> {
    transport_state: TransportState<C, H>,
    inner: WriteAdapterInner<W, BUF>,
}

impl<C: Cipher, H: Hash, W: Write, const BUF: usize> WriteAdapter<C, H, W, BUF> {
    /// Try to construct a new write adapter
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
    /// * `hs` - A handshaker implementing [`crate::traits::Handshaker`], to be performed
    /// * `reader` - A reader implementing [`embedded_io::Read`], to receive the messages
    /// * `writer` - A writer implementing [`embedded_io::Write`] to send the messages
    /// * `handshake_buffer` - A buffer big enough to hold the biggest message during the handshake.
    ///
    /// # Errors
    /// * [`ReadWriteAdapter::ReadAdapterError`] or [`ReadWriteAdapter::WriteAdapterError`] - The underlying reader or writer failed.
    /// * [`ReadWriteAdapterError::HandshakeError`] - There was a problem during the handshake (eg. the provided buffer is too small).
    pub fn try_new<HS: Handshaker<C, H>, R: Read>(
        hs: HS,
        mut reader: R,
        mut writer: W,
        handshake_buffer: &mut [u8],
    ) -> Result<Self, ReadWriteAdapterError<R::Error, W::Error>> {
        Ok(Self {
            transport_state: try_new_transport(hs, &mut reader, &mut writer, handshake_buffer)?,
            inner: WriteAdapterInner::new(writer),
        })
    }
}

impl<C: Cipher, H: Hash, W: Write, const BUF: usize> ErrorType for WriteAdapter<C, H, W, BUF> {
    type Error = WriteAdapterError<W::Error>;
}

impl<C: Cipher, H: Hash, W: Write, const BUF: usize> Write for WriteAdapter<C, H, W, BUF> {
    fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
        self.inner
            .write_with_transport_state(buf, &mut self.transport_state)
    }

    fn flush(&mut self) -> Result<(), Self::Error> {
        self.inner.flush()
    }
}
