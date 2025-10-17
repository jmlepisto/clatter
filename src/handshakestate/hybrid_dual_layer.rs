use crate::bytearray::ByteArray;
use crate::constants::HYBRID_DUAL_LAYER_HANDSHAKE_DOMAIN;
use crate::error::HandshakeResult;
use crate::traits::{Cipher, Handshaker, HandshakerInternal, Hash};
use crate::transportstate::TransportState;

/// Dual layer hybrid handshake
///
/// An "outer-encrypts-inner" hybrid handshake scheme which completes two handshakes:
/// an inner one and an outer one. The resulting handshake hash from the outer one is
/// mixed in to the inner handshake to bind the handshakes together. The resulting
/// transport keys will thus contain entropy from both handshakes.
///
/// The following Noise protocol steps are completed for the inner handshake after the outer
/// handshake finishes:
///
/// * `MixHash("clatter.hybrid_dual_layer.outer")`
/// * `MixKeyAndHash(h_outer)`
///
/// Hybrid handshakes require an additional intermediate buffer
/// for decrypting outer layer handshake messages. The buffer size
/// is controlled by the generic parameter `BUF`.
///
/// # Message Sequences
///
/// With hybrid handshakes it is possible to construct handshake pattern
/// combinations which result in one party having to send **two handshake
/// messages in a row**. Take care when implementing your handshaking logic and
/// always use [`Self::is_write_turn`] to check who should send next.
pub struct HybridDualLayerHandshake<Outer, Inner, C, H, const BUF: usize>
where
    Inner: Handshaker<C, H>,
    Outer: Handshaker<C, H>,
    C: Cipher,
    H: Hash,
{
    outer: Option<Outer>,
    inner: Inner,
    outer_transport: Option<TransportState<C, H>>,
    outer_is_finished: bool,
    outer_receive_buf: [u8; BUF],
}

impl<Outer, Inner, C, H, const BUF: usize> HybridDualLayerHandshake<Outer, Inner, C, H, BUF>
where
    Inner: Handshaker<C, H>,
    Outer: Handshaker<C, H>,
    C: Cipher,
    H: Hash,
{
    /// Initialize a new hybrid handshake
    ///
    /// # Arguments
    /// * `outer` - Outer handshake, which is completed first
    /// * `innter` - Inner handshake, which benefits from the security of the outer layer
    ///
    /// # Generic parameters
    /// * `const BUF` - Intermediate decrypt buffer size - Must be large enough to fit all inner handshake messages
    ///
    /// # Panics
    /// * If `outer` and `inner` aren't both either initiators or responders
    /// * If outer handshake is a one-way pattern
    pub fn new(outer: Outer, inner: Inner) -> Self {
        assert!(outer.is_initiator() == inner.is_initiator());
        assert!(!outer.get_pattern().is_one_way());

        Self {
            outer: Some(outer),
            inner,
            outer_transport: None,
            outer_is_finished: false,
            outer_receive_buf: [0u8; BUF],
        }
    }

    /// Check if outer handshake is completed
    pub fn outer_completed(&self) -> bool {
        self.outer_is_finished
    }

    /// Get reference to inner handshake
    pub fn inner(&self) -> &Inner {
        &self.inner
    }

    /// Get mutable reference to inner handshake
    pub fn inner_mut(&mut self) -> &mut Inner {
        &mut self.inner
    }

    /// Get reference to outer handshake
    pub fn outer(&self) -> Option<&Outer> {
        self.outer.as_ref()
    }

    /// Get mutable reference to outer handshake
    pub fn outer_mut(&mut self) -> Option<&mut Outer> {
        self.outer.as_mut()
    }

    fn update_outer_state(&mut self) -> HandshakeResult<()> {
        if self.outer.as_ref().unwrap().is_finished() {
            self.outer_transport = Some(self.outer.take().unwrap().finalize()?);
            self.outer_is_finished = true;

            // Mix in hash from the outer handshake to the inner one
            let h = self.outer_transport.as_ref().unwrap().get_handshake_hash();
            self.inner.mix_hash(HYBRID_DUAL_LAYER_HANDSHAKE_DOMAIN);
            self.inner.mix_key_and_hash(h.as_slice());
        }
        Ok(())
    }
}

impl<Outer, Inner, C, H, const BUF: usize> HandshakerInternal<C, H>
    for HybridDualLayerHandshake<Outer, Inner, C, H, BUF>
where
    Inner: Handshaker<C, H>,
    Outer: Handshaker<C, H>,
    C: Cipher,
    H: Hash,
{
    fn status(&self) -> super::HandshakeStatus {
        if self.outer_completed() {
            self.inner.status()
        } else {
            self.outer.as_ref().unwrap().status()
        }
    }

    fn set_error(&mut self) {
        self.inner.set_error();

        if self.outer.is_some() {
            self.outer.as_mut().unwrap().set_error();
        }
    }

    fn write_message_impl(
        &mut self,
        payload: &[u8],
        out: &mut [u8],
    ) -> crate::error::HandshakeResult<usize> {
        if self.outer_completed() {
            let n = self.inner.write_message_impl(payload, out)?;
            let n = self
                .outer_transport
                .as_mut()
                .unwrap()
                .send_in_place(out, n)?;
            Ok(n)
        } else {
            let r = self
                .outer
                .as_mut()
                .unwrap()
                .write_message_impl(payload, out)?;
            self.update_outer_state()?;
            Ok(r)
        }
    }

    fn read_message_impl(
        &mut self,
        message: &[u8],
        out: &mut [u8],
    ) -> crate::error::HandshakeResult<usize> {
        if self.outer_completed() {
            let n = self
                .outer_transport
                .as_mut()
                .unwrap()
                .receive(message, &mut self.outer_receive_buf)?;
            self.inner
                .read_message_impl(&self.outer_receive_buf[..n], out)
        } else {
            let r = self
                .outer
                .as_mut()
                .unwrap()
                .read_message_impl(message, out)?;
            self.update_outer_state()?;
            Ok(r)
        }
    }

    fn get_ciphers(&self) -> crate::cipherstate::CipherStates<C> {
        self.inner.get_ciphers()
    }

    fn get_hash(&self) -> <H as Hash>::Output {
        self.inner.get_hash()
    }

    fn mix_hash(&mut self, data: &[u8]) {
        if self.outer_is_finished {
            self.inner.mix_hash(data);
        } else {
            self.outer.as_mut().unwrap().mix_hash(data);
        }
    }

    fn mix_key_and_hash(&mut self, data: &[u8]) {
        if self.outer_is_finished {
            self.inner.mix_key_and_hash(data);
        } else {
            self.outer.as_mut().unwrap().mix_key_and_hash(data);
        }
    }

    fn get_pattern(&self) -> crate::handshakepattern::HandshakePattern {
        self.inner.get_pattern()
    }
}

impl<Outer, Inner, C, H, const BUF: usize> Handshaker<C, H>
    for HybridDualLayerHandshake<Outer, Inner, C, H, BUF>
where
    Inner: Handshaker<C, H>,
    Outer: Handshaker<C, H>,
    C: Cipher,
    H: Hash,
{
    type E = Inner::E;
    type S = Inner::S;

    fn push_psk(&mut self, _psk: &[u8]) {
        panic!("Not applicable for dual-layer handshakes");
    }

    fn is_write_turn(&self) -> bool {
        if self.outer_completed() {
            self.inner.is_write_turn()
        } else {
            self.outer.as_ref().unwrap().is_write_turn()
        }
    }

    fn is_initiator(&self) -> bool {
        self.inner.is_initiator()
    }

    fn get_next_message_overhead(&self) -> HandshakeResult<usize> {
        if self.outer_completed() {
            self.inner.get_next_message_overhead()
        } else {
            self.outer.as_ref().unwrap().get_next_message_overhead()
        }
    }

    fn build_name(_: &crate::handshakepattern::HandshakePattern) -> arrayvec::ArrayString<128> {
        panic!("Not applicable for dual-layer handshakes");
    }

    /// Get remote static key of the **inner** handshake (if available)
    fn get_remote_static(&self) -> Option<Self::S> {
        self.inner.get_remote_static()
    }

    /// Get remote ephemeral key of the **inner** handshake (if available)
    fn get_remote_ephemeral(&self) -> Option<Self::E> {
        self.inner.get_remote_ephemeral()
    }
}
