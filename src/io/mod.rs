//! Implementation of no-std [`embedded_io::Read`] and [`embedded_io::Write`] from the Embedded Working Group
//!
//! Provide a way to build an object that is [`embedded_io::Read`] and [`embedded_io::Write`] with a transport state
//! set up, from another [`embedded_io::Read`] and [`embedded_io::Write`] object (eg. a TCP socket).
//!
//! # Example
//!
//! Given an already established [`crate::transportstate::TransportState`] you can build
//! on top of an already insecure channel (eg. a pair ([`esp_hal::uart::UartRx`], [`esp_hal::uart::UartTx`]))
//! a secure channel with [`IoAdapter`]:
//!
//! ```no_run
//! // Estasblish a new transport state...
//! let transport_state = TransportState::new(...);
//!
//! // Retrieve a pair of reader and writer
//! let rx, tx = ...;
//!
//!//! // Instantiate a new [`IoAdapter`]
//! let channel = IoAdapter::new_with_transport_state(transport_state, rx, tx);
//!
//! ```

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
/// * [`ReadWriteAdapterError::ReadError`] or [`ReadWriteAdapterError::WriteError`] - The underlying reader or writer failed.
/// * [`ReadWriteAdapterError::Handshake`] - There was a problem during the handshake (eg. the provided buffer is too small).
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
    inner_read: ReadAdapterInner<R, BUF>,
    inner_write: WriteAdapterInner<W, BUF>,
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
    /// * [`ReadWriteAdapterError::ReadAdapter`] or [`ReadWriteAdapterError::WriteAdapter`] - The underlying reader or writer failed.
    /// * [`ReadWriteAdapterError::Handshake`] - There was a problem during the handshake (eg. the provided buffer is too small).
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

#[cfg(test)]
mod tests {
    extern crate alloc;

    use alloc::rc::Rc;
    use core::cell::RefCell;
    use core::convert::Infallible;

    use circular_buffer::CircularBuffer;
    use embedded_io::{ErrorType, Read, Write};
    use rand::rngs;

    use crate::handshakepattern::{noise_nn, HandshakePattern};
    use crate::traits::{Cipher, Dh, Handshaker, Hash};
    use crate::NqHandshake;
    use crate::{
        crypto::{cipher::ChaChaPoly, hash::Sha512},
        crypto_impl::x25519::X25519,
        transportstate::TransportState,
    };

    use super::IoAdapter;

    /// Interleave read and writes to complete the handshake
    /// and return both transport state (initiator and responder).
    ///
    /// Use classical (non post-quantic) handshake
    fn handshake<DH: Dh, C: Cipher, H: Hash>(
        pattern: HandshakePattern,
    ) -> (TransportState<C, H>, TransportState<C, H>) {
        let mut alice_rng = rngs::OsRng;
        let mut bob_rng = rngs::OsRng;
        // Instantiate initiator handshake
        let mut alice = NqHandshake::<DH, C, H, _>::new(
            pattern.clone(), // Handshake pattern
            &[],             // Prologue data
            true,            // Are we the initiator
            None,            // Pre-shared keys..
            None,            // ..
            None,            // ..
            None,            // ..
            &mut alice_rng,
        )
        .unwrap();

        let mut bob = NqHandshake::<X25519, C, H, _>::new(
            pattern, // Handshake pattern
            &[],     // Prologue data
            false,   // Are we the initiator
            None,    // Pre-shared keys..
            None,    // ..
            None,    // ..
            None,    // ..
            &mut bob_rng,
        )
        .unwrap();

        let mut buf = [0u8; 4096];
        while !alice.is_finished() || !bob.is_finished() {
            if alice.is_write_turn() {
                let n = alice.write_message(&[], &mut buf).unwrap();
                bob.read_message(&buf[..n], &mut []).unwrap();
            } else {
                let n = bob.write_message(&[], &mut buf).unwrap();
                alice.read_message(&buf[..n], &mut []).unwrap();
            }
        }

        let transport_alice = alice.finalize().unwrap();
        let transport_bob = bob.finalize().unwrap();
        (transport_alice, transport_bob)
    }

    /// Define this newtype to implement Read+Write on a circular buffer with mutable shared ownership.
    /// In real cases, we should be fine with the adapter taking ownership of the reader/writer;
    /// however in tests, since everything is in the same process, we need shared ownership.
    #[derive(Clone)]
    struct WrapCircularBuffer<const N: usize>(Rc<RefCell<CircularBuffer<N, u8>>>);

    impl<const N: usize> WrapCircularBuffer<N> {
        fn new() -> Self {
            Self(Rc::new(RefCell::new(CircularBuffer::<N, u8>::new())))
        }
    }

    impl<const N: usize> ErrorType for WrapCircularBuffer<N> {
        type Error = Infallible;
    }

    impl<const N: usize> Read for WrapCircularBuffer<N> {
        fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
            (*self.0).borrow_mut().read(buf)
        }
    }

    impl<const N: usize> Write for WrapCircularBuffer<N> {
        fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
            (*self.0).borrow_mut().write(buf)
        }

        fn flush(&mut self) -> Result<(), Self::Error> {
            (*self.0).borrow_mut().flush()
        }
    }

    fn test_adapter<const ADAPTER_BUFFER_SIZE: usize>() {
        let alice_comm_buf = WrapCircularBuffer::<1000>::new();
        let bob_comm_buf = WrapCircularBuffer::<1000>::new();

        let (alice_transport, bob_transport) = handshake::<X25519, ChaChaPoly, Sha512>(noise_nn());

        let mut alice_io_adapter =
            IoAdapter::<_, _, _, _, ADAPTER_BUFFER_SIZE>::new_with_transport_state(
                alice_transport,
                alice_comm_buf.clone(),
                bob_comm_buf.clone(),
            );

        let mut bob_io_adapter =
            IoAdapter::<_, _, _, _, ADAPTER_BUFFER_SIZE>::new_with_transport_state(
                bob_transport,
                bob_comm_buf.clone(),
                alice_comm_buf.clone(),
            );

        let mut test_buf = [0u8; 100];
        let data = b"But every knight has a horse";
        alice_io_adapter.write_all(data).unwrap();
        bob_io_adapter
            .read_exact(&mut test_buf[..data.len()])
            .unwrap();
        assert_eq!(&test_buf[..data.len()], data);
    }

    #[test]
    fn io_adapter_test() {
        // Basic test
        test_adapter::<100>();

        // Small (but sufficient) adapter buffer
        test_adapter::<20>();

        // Too small adapter buffer: does not compile
        // test_adapter::<16>();
    }
}
