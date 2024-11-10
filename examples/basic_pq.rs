use core::str;

use clatter::crypto::cipher::ChaChaPoly;
use clatter::crypto::hash::Sha512;
use clatter::crypto::kem::pqclean_kyber::Kyber768;
// We can mix and match KEMs from different vendors
use clatter::crypto::kem::rust_crypto_kyber::Kyber512;
use clatter::handshakepattern::noise_pqnn;
use clatter::traits::Handshaker;
use clatter::PqHandshake;

fn main() {
    let mut rng_alice = rand::thread_rng();
    let mut rng_bob = rand::thread_rng();
    let mut alice = PqHandshake::<Kyber512, Kyber768, ChaChaPoly, Sha512, _>::new(
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

    let mut bob = PqHandshake::<Kyber512, Kyber768, ChaChaPoly, Sha512, _>::new(
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
