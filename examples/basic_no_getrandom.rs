use clatter::crypto::cipher::ChaChaPoly;
use clatter::crypto::dh::X25519;
use clatter::crypto::hash::Sha512;
use clatter::handshakepattern::noise_xx;
use clatter::traits::{Dh, Handshaker};
// In no-std environments where getrandom is not supported we must use the lower level XXHandshakeCore structs
use clatter::NqHandshakeCore;

// You'll have to define your own bindings to your platform RNG services if you do not wish to add support for getrandom.
// Usually this is NOT the smartest way to go, but you should rather consider adding bindings for getrandom, which will handle
// everything automatically from there. The crate feature "getrandom" can be enabled without "std".
#[derive(Default)]
struct MyRng;

impl rand_core::RngCore for MyRng {
    fn next_u32(&mut self) -> u32 {
        return 42; // Replace with true randomness from reliable and secure system RNG
    }

    fn next_u64(&mut self) -> u64 {
        return 42; // Replace with true randomness from reliable and secure system RNG
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        dest.fill_with(|| 42); // Replace with true randomness from reliable and secure system RNG
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
        dest.fill_with(|| 42); // Replace with true randomness from reliable and secure system RNG
        Ok(())
    }
}

// Marker trait; we promise that MyRng is secure
impl rand_core::CryptoRng for MyRng {}

fn main() {
    let mut rng_alice = MyRng;
    let mut rng_bob = MyRng;

    // Generate keys
    let alice_s = X25519::genkey_rng(&mut rng_alice).unwrap();
    let bob_s = X25519::genkey_rng(&mut rng_bob).unwrap();

    let mut alice = NqHandshakeCore::<
        X25519,
        ChaChaPoly,
        Sha512,
        /* Here we instruct the handshaker to use our RNG */ MyRng,
    >::new(noise_xx(), &[], true, Some(alice_s), None, None, None)
    .unwrap();

    let mut bob = NqHandshakeCore::<X25519, ChaChaPoly, Sha512, MyRng>::new(
        noise_xx(),
        &[],
        false,
        Some(bob_s),
        None,
        None,
        None,
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
