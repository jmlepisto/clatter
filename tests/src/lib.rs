use clatter::traits::{Cipher, Hash};
use clatter::Handshaker;

#[allow(unused)]
mod smoke;

#[allow(unused)]
mod no_getrandom_smoke;

pub fn verify_handshake<A: Handshaker<C, H>, B: Handshaker<C, H>, C: Cipher, H: Hash>(
    mut alice: A,
    mut bob: B,
) {
    let mut alice_buf = [0u8; 8182];
    let mut bob_buf = [0u8; 8182];

    loop {
        if alice.is_write_turn() && !bob.is_write_turn() {
            let n = alice.write_message(&[], &mut alice_buf).unwrap();
            let _ = bob.read_message(&alice_buf[..n], &mut bob_buf).unwrap();
        } else if !alice.is_write_turn() && bob.is_write_turn() {
            let n = bob.write_message(&[], &mut bob_buf).unwrap();
            let _ = alice.read_message(&bob_buf[..n], &mut alice_buf).unwrap();
        } else {
            panic!("State issue");
        }

        if alice.is_finished() && bob.is_finished() {
            break;
        }
    }

    let mut alice = alice.finalize().unwrap();
    let mut bob = bob.finalize().unwrap();

    // "Normal" send-receive
    let n = alice
        .send(b"Scream without a sound", &mut alice_buf)
        .unwrap();
    let n = bob.receive(&alice_buf[..n], &mut bob_buf).unwrap();
    assert_eq!(bob_buf[..n], *b"Scream without a sound");

    // In-place send-receive
    let mut in_place_buf = [0; 4096];
    let msg = b"Flying off the handle";
    in_place_buf[..msg.len()].copy_from_slice(msg);
    let n = alice.send_in_place(&mut in_place_buf, msg.len()).unwrap();
    let n = bob.receive_in_place(&mut in_place_buf, n).unwrap();
    assert_eq!(in_place_buf[..n], *msg);

    // Vec send-receive
    assert_eq!(
        &bob.receive_vec(&alice.send_vec(b"Eugene gene the dance machine").unwrap())
            .unwrap(),
        b"Eugene gene the dance machine"
    );
}
