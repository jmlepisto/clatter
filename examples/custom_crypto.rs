use core::str;

use arrayvec::ArrayVec;
use clatter::bytearray::{ByteArray, SensitiveByteArray};
use clatter::crypto::cipher::ChaChaPoly;
use clatter::crypto::kem::pqclean_kyber::Kyber768;
// We can mix and match KEMs from different vendors
use clatter::crypto::kem::rust_crypto_kyber::Kyber512;
use clatter::handshakepattern::noise_pqnn;
use clatter::traits::Handshaker;
use clatter::PqHandshake;

/// **Obvious warning**
///
/// This is not a real hash function. This is a silly example
/// which will NEVER WORK in real life.
///
/// With **careful** analysis you may implement support for existing well-established
/// cryptographic primitives but as a rule-of-thumb you should never implement
/// your own custom cryptography. Even if you use well known primitives you must have
/// the competence to evaluate the risks of integrating such cryptography to Noise protocol
/// which is not endorsed by the original author.
#[derive(Default)]
struct MySillyHash(u128);

// This has to be implemented for all cryptographic components.
// The component name will appear in the Noise pattern name.
impl clatter::traits::CryptoComponent for MySillyHash {
    fn name() -> &'static str {
        "SillyHash"
    }
}

impl clatter::traits::Hash for MySillyHash {
    // Most of the crypto traits by clatter have type parameters, which
    // indicate some static sizing qualities of the algorithms. These types
    // usually have to implement `clatter::bytearray::ByteArray` but implementations
    // for the most common static array sizes are built-in.
    type Block = [u8; 32];
    // ..But you can also use any size with the help of ArrayVec (stack allocated).
    // Here we are also using `SensitiveByteArray`, a wrapper provided
    // by Clatter, which is zeroized on drop.
    type Output = SensitiveByteArray<ArrayVec<u8, 32>>;

    // If you have the `alloc` crate feature enabled, you could
    // also use `clatter::bytearray::HeapArray` for a heap-allocated
    // alternative.

    fn input(&mut self, data: &[u8]) {
        for d in data {
            self.0 ^= *d as u128;
        }
    }

    fn result(self) -> Self::Output {
        let mut out = [0u8; 32];
        out[..16].copy_from_slice(&self.0.to_be_bytes());
        Self::Output::from_slice(&out)
    }
}

fn main() {
    let mut rng_alice = rand::thread_rng();
    let mut rng_bob = rand::thread_rng();
    let mut alice = PqHandshake::<Kyber512, Kyber768, ChaChaPoly, MySillyHash, _>::new(
        noise_pqnn(),
        &[],
        true,
        None,
        None,
        None,
        None,
        &mut rng_alice,
    )
    .unwrap();

    let mut bob = PqHandshake::<Kyber512, Kyber768, ChaChaPoly, MySillyHash, _>::new(
        noise_pqnn(),
        &[],
        false,
        None,
        None,
        None,
        None,
        &mut rng_bob,
    )
    .unwrap();

    // Handshake message buffers
    let mut buf_alice = [0u8; 4096];
    let mut buf_bob = [0u8; 4096];

    // First handshake message from initiator to responder
    // e -->
    let n = alice.write_message(&[], &mut buf_alice).unwrap();
    let _ = bob.read_message(&buf_alice[..n], &mut buf_bob).unwrap();

    // Second handshake message from responder to initiator
    // <-- ekem
    let n = bob.write_message(&[], &mut buf_bob).unwrap();
    let _ = alice.read_message(&buf_bob[..n], &mut buf_alice).unwrap();

    // Handshake should be done
    assert!(alice.is_finished() && bob.is_finished());

    // Finish handshakes and move to transport mode
    let mut alice = alice.finalize().unwrap();
    let mut bob = bob.finalize().unwrap();

    // Send a message from Alice to Bob
    let msg = b"Hello from initiator";
    let n = alice.send(msg, &mut buf_alice).unwrap();
    let n = bob.receive(&buf_alice[..n], &mut buf_bob).unwrap();

    println!(
        "Bob received from Alice: {}",
        str::from_utf8(&buf_bob[..n]).unwrap()
    );
}
