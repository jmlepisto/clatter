use core::str;

use clatter::crypto::cipher::ChaChaPoly;
use clatter::crypto::dh::X25519;
use clatter::crypto::hash::Sha512;
use clatter::handshakepattern::noise_xx;
use clatter::traits::{Dh, Handshaker};
use clatter::NqHandshake;

fn main() {
    let mut rng_alice = rand::thread_rng();
    let mut rng_bob = rand::thread_rng();

    // Generate static keys
    let alice_s = X25519::genkey(&mut rng_alice).unwrap();
    let bob_s = X25519::genkey(&mut rng_bob).unwrap();

    let mut alice = NqHandshake::<X25519, ChaChaPoly, Sha512, _>::new(
        noise_xx(),
        &[],
        true,
        Some(alice_s),
        None,
        None,
        None,
        &mut rng_alice,
    )
    .unwrap();

    let mut bob = NqHandshake::<X25519, ChaChaPoly, Sha512, _>::new(
        noise_xx(),
        &[],
        false,
        Some(bob_s),
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
    // <- e, ee, s, es
    let n = bob.write_message(&[], &mut buf_bob).unwrap();
    let _ = alice.read_message(&buf_bob[..n], &mut buf_alice).unwrap();

    // Third handshake message from initiator to responder
    // -> s, se
    let n = alice.write_message(&[], &mut buf_alice).unwrap();
    let _ = bob.read_message(&buf_alice[..n], &mut buf_bob).unwrap();

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
