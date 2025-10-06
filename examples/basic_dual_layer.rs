use clatter::crypto::cipher::ChaChaPoly;
use clatter::crypto::dh::X25519;
use clatter::crypto::hash::Sha512;
use clatter::crypto::kem::rust_crypto_ml_kem::MlKem512;
use clatter::handshakepattern::{noise_nn, noise_pqnn};
use clatter::traits::Handshaker;
use clatter::{DualLayerHandshake, NqHandshake, PqHandshake};

fn main() {
    let alice_nq = NqHandshake::<X25519, ChaChaPoly, Sha512>::new(
        noise_nn(),
        &[],
        true,
        None,
        None,
        None,
        None,
    )
    .unwrap();

    let bob_nq = NqHandshake::<X25519, ChaChaPoly, Sha512>::new(
        noise_nn(),
        &[],
        false,
        None,
        None,
        None,
        None,
    )
    .unwrap();

    let alice_pq = PqHandshake::<MlKem512, MlKem512, ChaChaPoly, Sha512>::new(
        noise_pqnn(),
        &[],
        true,
        None,
        None,
        None,
        None,
    )
    .unwrap();

    let bob_pq = PqHandshake::<MlKem512, MlKem512, ChaChaPoly, Sha512>::new(
        noise_pqnn(),
        &[],
        false,
        None,
        None,
        None,
        None,
    )
    .unwrap();

    let mut alice = DualLayerHandshake::<_, _, _, _, 1500>::new(alice_nq, alice_pq);
    let mut bob = DualLayerHandshake::<_, _, _, _, 1500>::new(bob_nq, bob_pq);

    // Handshake message buffers
    let mut buf_alice = [0u8; 4096];
    let mut buf_bob = [0u8; 4096];

    // OUTER LAYER - NQ HANDSHAKE
    // First handshake message from initiator to responder
    // e -->
    let n = alice.write_message(&[], &mut buf_alice).unwrap();
    let _ = bob.read_message(&buf_alice[..n], &mut buf_bob).unwrap();

    // Second handshake message from responder to initiator
    // <-- ekem
    let n = bob.write_message(&[], &mut buf_bob).unwrap();
    let _ = alice.read_message(&buf_bob[..n], &mut buf_alice).unwrap();
    // --------------------------

    assert!(alice.outer_completed() && bob.outer_completed());

    // INNER LAYER - PQ HANDSHAKE
    // First handshake message from initiator to responder
    // e -->
    let n = alice.write_message(&[], &mut buf_alice).unwrap();
    let _ = bob.read_message(&buf_alice[..n], &mut buf_bob).unwrap();

    // Second handshake message from responder to initiator
    // <-- e, ee
    let n = bob.write_message(&[], &mut buf_bob).unwrap();
    let _ = alice.read_message(&buf_bob[..n], &mut buf_alice).unwrap();
    // --------------------------

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
