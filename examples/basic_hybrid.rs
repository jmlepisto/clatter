use clatter::crypto::cipher::ChaChaPoly;
use clatter::crypto::dh::X25519;
use clatter::crypto::hash::Sha512;
use clatter::crypto::kem::pqclean_ml_kem::MlKem1024;
// We can mix and match KEMs from different vendors
use clatter::crypto::kem::rust_crypto_ml_kem::MlKem512;
use clatter::handshakepattern::noise_hybrid_nn;
use clatter::traits::Handshaker;
use clatter::{HybridHandshake, HybridHandshakeParams};

const PROLOGUE_BYTES: &[u8] = b"shared prologue bytes";

fn main() {
    let alice_params =
        HybridHandshakeParams::new(noise_hybrid_nn(), true).with_prologue(PROLOGUE_BYTES);
    let mut alice =
        HybridHandshake::<X25519, MlKem512, MlKem1024, ChaChaPoly, Sha512>::new(alice_params)
            .unwrap();

    let bob_params =
        HybridHandshakeParams::new(noise_hybrid_nn(), false).with_prologue(PROLOGUE_BYTES);
    let mut bob =
        HybridHandshake::<X25519, MlKem512, MlKem1024, ChaChaPoly, Sha512>::new(bob_params)
            .unwrap();

    // Handshake message buffers
    let mut buf_alice = [0u8; 4096];
    let mut buf_bob = [0u8; 4096];

    // First handshake message from initiator to responder
    // e -->
    let n = alice.write_message(&[], &mut buf_alice).unwrap();
    let _ = bob.read_message(&buf_alice[..n], &mut buf_bob).unwrap();

    // Second handshake message from responder to initiator
    // <-- e, ee, ekem
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
