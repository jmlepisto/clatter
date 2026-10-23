//! Caller-provided Noise keys with no Clatter `alloc`, `std` or `getrandom` requirement.
//! Fixed private keys and deterministic RNG seeds below are test fixtures only.
//! Applications must generate a fresh ephemeral for each attempt whose role requires one.

use clatter::bytearray::{ByteArray, SensitiveByteArray};
use clatter::crypto::cipher::ChaChaPoly;
use clatter::crypto::dh::X25519;
use clatter::crypto::hash::Sha256;
use clatter::error::HandshakeError;
use clatter::handshakepattern::{
    HandshakePattern, noise_ik, noise_n, noise_nn, noise_pqnn, noise_xx, noise_xx_psk3,
};
use clatter::traits::Dh;
use clatter::{Handshaker, KeyPair, NqHandshakeCore, PreGeneratedKeys};
use core::convert::Infallible;
use rand::rngs::StdRng;
use rand::{SeedableRng, TryCryptoRng, TryRng};
use std::cell::Cell;

type Keys = KeyPair<[u8; 32], SensitiveByteArray<[u8; 32]>>;
type Prekeyed = NqHandshakeCore<X25519, ChaChaPoly, Sha256, PreGeneratedKeys>;
type RngBacked = NqHandshakeCore<X25519, ChaChaPoly, Sha256, FixtureRng>;

const PROLOGUE: &[u8] = b"caller-generated-key test";
const PSK: [u8; 32] = [0x55; 32];

// Per-thread counters keep parallel test cases independent.
thread_local! {
    static DEFAULT_CALLS: Cell<usize> = const { Cell::new(0) };
}

// The legacy constructor requires Default + Clone. Delegate every RNG operation
// to StdRng rather than fabricating randomness or implementing a production RNG.
// Its fixed seeds are reproducible test inputs; the example uses platform entropy.
struct FixtureRng {
    source: StdRng,
}

impl Clone for FixtureRng {
    fn clone(&self) -> Self {
        // This test-only guard detects any unexpected handshake/RNG clone.
        // StdRng itself intentionally does not implement Clone in rand 0.10.
        panic!("RNG instance was cloned")
    }
}

impl Default for FixtureRng {
    fn default() -> Self {
        DEFAULT_CALLS.with(|calls| calls.set(calls.get() + 1));
        Self {
            source: StdRng::seed_from_u64(0x7072_656b_6579_6564),
        }
    }
}

impl TryRng for FixtureRng {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        self.source.try_next_u32()
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        self.source.try_next_u64()
    }

    fn try_fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), Self::Error> {
        self.source.try_fill_bytes(destination)
    }
}

impl TryCryptoRng for FixtureRng {}

fn keypair(byte: u8) -> Keys {
    let secret = SensitiveByteArray::from_slice(&[byte; 32]);
    KeyPair::new(X25519::pubkey(&secret), secret)
}

fn material(initiator: bool) -> (Keys, Keys, [u8; 32]) {
    let (own, ephemeral, remote) = if initiator {
        (0x11, 0x33, 0x22)
    } else {
        (0x22, 0x44, 0x11)
    };
    (keypair(own), keypair(ephemeral), keypair(remote).public)
}

fn prekeyed(pattern: HandshakePattern, initiator: bool) -> Prekeyed {
    let (static_key, ephemeral, remote_static) = material(initiator);
    let has_psk = pattern.has_psk();
    let mut handshake = Prekeyed::new_prekeyed(
        pattern,
        PROLOGUE,
        initiator,
        Some(static_key),
        Some(ephemeral),
        Some(remote_static),
        None,
    )
    .unwrap();
    if has_psk {
        handshake.push_psk(&PSK);
    }
    handshake
}

fn with_default_rng(pattern: HandshakePattern, initiator: bool) -> RngBacked {
    let (static_key, ephemeral, remote_static) = material(initiator);
    let has_psk = pattern.has_psk();
    let mut handshake = RngBacked::new(
        pattern,
        PROLOGUE,
        initiator,
        Some(static_key),
        Some(ephemeral),
        Some(remote_static),
        None,
    )
    .unwrap();
    if has_psk {
        handshake.push_psk(&PSK);
    }
    handshake
}

#[derive(Debug, PartialEq, Eq)]
struct Transcript {
    messages: Vec<Vec<u8>>,
    handshake_hash: [u8; 32],
}

fn exchange<A, B>(mut alice: A, mut bob: B) -> Transcript
where
    A: Handshaker<ChaChaPoly, Sha256>,
    B: Handshaker<ChaChaPoly, Sha256>,
{
    let mut wire = [0; 1024];
    let mut clear = [0; 1024];
    let mut messages = Vec::new();
    let payload = b"handshake payload";

    // XX, IK and XXpsk3 need at most three messages; a stalled state fails here.
    for _ in 0..3 {
        if alice.is_finished() && bob.is_finished() {
            break;
        }
        assert_ne!(alice.is_write_turn(), bob.is_write_turn());
        let (written, received) = if alice.is_write_turn() {
            let written = alice.write_message(payload, &mut wire).unwrap();
            let received = bob.read_message(&wire[..written], &mut clear).unwrap();
            (written, received)
        } else {
            let written = bob.write_message(payload, &mut wire).unwrap();
            let received = alice.read_message(&wire[..written], &mut clear).unwrap();
            (written, received)
        };
        assert_eq!(&clear[..received], payload);
        messages.push(wire[..written].to_vec());
    }
    assert!(alice.is_finished() && bob.is_finished());
    assert_eq!(&messages[0][..32], &keypair(0x33).public);

    let mut alice = alice.finalize().unwrap();
    let mut bob = bob.finalize().unwrap();
    let alice_hash = alice.get_handshake_hash();
    assert_eq!(alice_hash, bob.get_handshake_hash());
    let mut handshake_hash = [0; 32];
    handshake_hash.copy_from_slice(alice_hash.as_slice());

    let payload = b"initiator application data";
    let written = alice.send(payload, &mut wire).unwrap();
    let received = bob.receive(&wire[..written], &mut clear).unwrap();
    assert_eq!(&clear[..received], payload);
    messages.push(wire[..written].to_vec());

    let payload = b"responder application data";
    let written = bob.send(payload, &mut wire).unwrap();
    let received = alice.receive(&wire[..written], &mut clear).unwrap();
    assert_eq!(&clear[..received], payload);
    messages.push(wire[..written].to_vec());

    Transcript {
        messages,
        handshake_hash,
    }
}

#[test]
fn prekeyed_transcripts_match_rng_backed_handshakes() {
    for pattern in [noise_xx(), noise_ik(), noise_xx_psk3()] {
        let supplied = exchange(
            prekeyed(pattern.clone(), true),
            prekeyed(pattern.clone(), false),
        );
        let original = exchange(
            with_default_rng(pattern.clone(), true),
            with_default_rng(pattern, false),
        );
        assert_eq!(supplied, original);
    }
}

#[test]
fn prekeyed_roles_only_require_the_ephemeral_material_they_use() {
    let responder_static = keypair(0x22);
    let mut alice = Prekeyed::new_prekeyed(
        noise_n(),
        PROLOGUE,
        true,
        None,
        Some(keypair(0x33)),
        Some(responder_static.public),
        None,
    )
    .unwrap();
    let mut bob = Prekeyed::new_prekeyed(
        noise_n(),
        PROLOGUE,
        false,
        Some(responder_static),
        None,
        None,
        None,
    )
    .unwrap();
    let mut wire = [0; 256];
    let mut clear = [0; 256];
    let written = alice
        .write_message(b"one-way handshake", &mut wire)
        .unwrap();
    let received = bob.read_message(&wire[..written], &mut clear).unwrap();
    assert_eq!(&clear[..received], b"one-way handshake");
    assert!(alice.is_finished() && bob.is_finished());
    let mut alice = alice.finalize().unwrap();
    let mut bob = bob.finalize().unwrap();
    assert_eq!(alice.get_handshake_hash(), bob.get_handshake_hash());
    let written = alice.send(b"one-way transport", &mut wire).unwrap();
    let received = bob.receive(&wire[..written], &mut clear).unwrap();
    assert_eq!(&clear[..received], b"one-way transport");

    // NN does send E. No RNG exists to fill absent material, and the original
    // public write path must poison the state after MissingMaterial.
    let mut missing =
        Prekeyed::new_prekeyed(noise_nn(), PROLOGUE, true, None, None, None, None).unwrap();
    assert!(matches!(
        missing.write_message(&[], &mut wire),
        Err(HandshakeError::MissingMaterial)
    ));
    assert!(matches!(
        missing.write_message(&[], &mut wire),
        Err(HandshakeError::ErrorState)
    ));
    assert!(matches!(
        missing.read_message(&[], &mut clear),
        Err(HandshakeError::ErrorState)
    ));
}

#[test]
fn default_rng_is_created_only_after_validation() {
    DEFAULT_CALLS.with(|calls| calls.set(0));
    assert!(matches!(
        RngBacked::new(noise_pqnn(), PROLOGUE, true, None, None, None, None),
        Err(HandshakeError::InvalidPattern(..)),
    ));
    assert!(matches!(
        RngBacked::new(noise_n(), PROLOGUE, true, None, None, None, None),
        Err(HandshakeError::MissingMaterial),
    ));
    assert_eq!(DEFAULT_CALLS.with(Cell::get), 0);

    RngBacked::new(noise_nn(), PROLOGUE, true, None, None, None, None).unwrap();
    assert_eq!(DEFAULT_CALLS.with(Cell::get), 1);
}
