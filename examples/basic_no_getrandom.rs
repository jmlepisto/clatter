// Clatter's `getrandom` and `rand` features are unnecessary when its caller
// supplies all local keys. On an embedded target, replace `getrandom::fill`
// with the platform's fallible cryptographic entropy API.
use clatter::bytearray::{ByteArray, SensitiveByteArray};
use clatter::crypto::cipher::ChaChaPoly;
use clatter::crypto::dh::X25519;
use clatter::crypto::hash::Sha512;
use clatter::error::{DhError, HandshakeError, HandshakeResult};
use clatter::handshakepattern::noise_xx;
use clatter::traits::{Dh, Handshaker};
use clatter::{KeyPair, NqHandshakeCore, PreGeneratedKeys};
use zeroize::Zeroizing;

fn keypair() -> Result<KeyPair<[u8; 32], SensitiveByteArray<[u8; 32]>>, DhError> {
    // The caller observes entropy failure before constructing a handshake.
    // Zeroizing also clears any partial output when the entropy call fails.
    let mut bytes = Zeroizing::new([0u8; 32]);
    getrandom::fill(bytes.as_mut()).map_err(|_| DhError::KeyGeneration)?;
    let secret = SensitiveByteArray::from_slice(bytes.as_slice());
    Ok(KeyPair::new(X25519::pubkey(&secret), secret))
}

fn main() -> HandshakeResult<()> {
    // Generate fresh ephemerals for every attempt; static keys may be reused.
    let alice_s = keypair()?;
    let alice_e = keypair()?;
    let bob_s = keypair()?;
    let bob_e = keypair()?;

    type Handshake = NqHandshakeCore<X25519, ChaChaPoly, Sha512, PreGeneratedKeys>;
    let mut alice = Handshake::new_prekeyed(
        noise_xx(),
        &[],
        true,
        Some(alice_s),
        Some(alice_e),
        None,
        None,
    )?;
    let mut bob =
        Handshake::new_prekeyed(noise_xx(), &[], false, Some(bob_s), Some(bob_e), None, None)?;

    let mut buf_alice = [0u8; 4096];
    let mut buf_bob = [0u8; 4096];

    // Three XX flights, using the same handshake state machine as `new`.
    let n = alice.write_message(&[], &mut buf_alice)?;
    bob.read_message(&buf_alice[..n], &mut buf_bob)?;
    let n = bob.write_message(&[], &mut buf_bob)?;
    alice.read_message(&buf_bob[..n], &mut buf_alice)?;
    let n = alice.write_message(&[], &mut buf_alice)?;
    bob.read_message(&buf_alice[..n], &mut buf_bob)?;
    assert!(alice.is_finished() && bob.is_finished());

    let mut alice = alice.finalize()?;
    let mut bob = bob.finalize()?;
    let n = alice.send(b"Hello from initiator", &mut buf_alice)?;
    let n = bob.receive(&buf_alice[..n], &mut buf_bob)?;
    println!(
        "Bob received from Alice: {}",
        std::str::from_utf8(&buf_bob[..n]).map_err(|_| HandshakeError::InvalidMessage)?
    );
    Ok(())
}
