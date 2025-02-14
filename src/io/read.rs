//! Implementation of the [`embedded_io::Read`] adapter.

use embedded_io::{ErrorType, Read, ReadExactError, Write};

use crate::{
    traits::{Cipher, Handshaker, Hash},
    transportstate::TransportState,
};

use super::{
    error::{ReadAdapterError, ReadWriteAdapterError},
    try_new_transport,
};

pub(crate) struct ReadAdapterInner<R: Read, const BUF: usize> {
    reader: R,
    read_buffer: [u8; BUF],
    available_to_read: usize,
}

impl<R: Read, const BUF: usize> ErrorType for ReadAdapterInner<R, BUF> {
    type Error = ReadAdapterError<R::Error>;
}

impl<R: Read, const BUF: usize> ReadAdapterInner<R, BUF> {
    pub(crate) fn new(reader: R) -> Self {
        Self {
            reader,
            read_buffer: [0u8; BUF],
            available_to_read: 0,
        }
    }

    pub(crate) fn read_with_transport_state<C: Cipher, H: Hash>(
        &mut self,
        buf: &mut [u8],
        transport_state: &mut TransportState<C, H>,
    ) -> Result<usize, <Self as ErrorType>::Error> {
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
                ReadExactError::Other(inner_e) => return Err(inner_e.into()),
            },
        };
        let msg_len = u16::from_be_bytes(msg_len_buf) as usize;

        if msg_len > BUF {
            return Err(ReadAdapterError::Mtu(msg_len as u16));
        }

        // At this point, self.available_to_read is guaranteed to be zero
        // and read_buffer only contains useless bytes.
        self.reader.read_exact(&mut self.read_buffer[..msg_len])?;
        let plain_len = transport_state
            .receive_in_place(&mut self.read_buffer[..msg_len], msg_len)
            .map_err(|e| ReadAdapterError::Noise(e.into()))?;

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

/// Adapter type to use a given reader with a Noise protocol.
///
/// Since [`embedded_io::Read`] interface do not provide a way to know message
/// boundaries, message length is assumed to be encoded as recommended in Section 13
/// of the Noise specification: with a 16-bits big-endian length field prior to each
/// transport message.
pub struct ReadAdapter<C: Cipher, H: Hash, R: Read, const BUF: usize> {
    transport_state: TransportState<C, H>,
    inner: ReadAdapterInner<R, BUF>,
}

impl<C: Cipher, H: Hash, R: Read, const BUF: usize> ReadAdapter<C, H, R, BUF> {
    /// Try to construct a new read adapter
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
    pub fn try_new<HS: Handshaker<C, H>, W: Write>(
        hs: HS,
        mut reader: R,
        mut writer: W,
        handshake_buffer: &mut [u8],
    ) -> Result<Self, ReadWriteAdapterError<R::Error, W::Error>> {
        Ok(Self {
            transport_state: try_new_transport(hs, &mut reader, &mut writer, handshake_buffer)?,
            inner: ReadAdapterInner::new(reader),
        })
    }
}

impl<C: Cipher, H: Hash, R: Read, const BUF: usize> ErrorType for ReadAdapter<C, H, R, BUF> {
    type Error = ReadAdapterError<R::Error>;
}

impl<C: Cipher, H: Hash, R: Read, const BUF: usize> Read for ReadAdapter<C, H, R, BUF> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        self.inner
            .read_with_transport_state(buf, &mut self.transport_state)
    }
}
