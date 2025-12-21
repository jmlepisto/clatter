use clatter::handshakepattern::*;
use clatter::traits::{Cipher, Hash};
use clatter::Handshaker;

#[allow(unused)]
mod smoke;

#[allow(unused)]
mod no_getrandom_smoke;

// Shared handshake pattern arrays for use in both smoke test files
pub fn nq_handshake_patterns() -> Vec<HandshakePattern> {
    vec![
        noise_n(),
        noise_k(),
        noise_x(),
        noise_ik(),
        noise_in(),
        noise_ix(),
        noise_kk(),
        noise_kn(),
        noise_kx(),
        noise_nk(),
        noise_nn(),
        noise_nx(),
        noise_xk(),
        noise_xn(),
        noise_xx(),
        noise_n_psk0(),
        noise_k_psk0(),
        noise_x_psk1(),
        noise_ik_psk1(),
        noise_ik_psk2(),
        noise_in_psk1(),
        noise_in_psk2(),
        noise_ix_psk2(),
        noise_kk_psk0(),
        noise_kk_psk2(),
        noise_kn_psk0(),
        noise_kn_psk2(),
        noise_kx_psk2(),
        noise_nk_psk0(),
        noise_nk_psk2(),
        noise_nn_psk0(),
        noise_nn_psk2(),
        noise_nx_psk2(),
        noise_xk_psk3(),
        noise_xn_psk3(),
        noise_xx_psk3(),
    ]
}

pub fn pq_handshake_patterns() -> Vec<HandshakePattern> {
    vec![
        noise_pqik(),
        noise_pqin(),
        noise_pqix(),
        noise_pqkk(),
        noise_pqkn(),
        noise_pqkx(),
        noise_pqnk(),
        noise_pqnn(),
        noise_pqnx(),
        noise_pqxk(),
        noise_pqxn(),
        noise_pqxx(),
        noise_pqik_psk1(),
        noise_pqik_psk2(),
        noise_pqin_psk1(),
        noise_pqin_psk2(),
        noise_pqix_psk2(),
        noise_pqkk_psk0(),
        noise_pqkk_psk2(),
        noise_pqkn_psk0(),
        noise_pqkn_psk2(),
        noise_pqkx_psk2(),
        noise_pqnk_psk0(),
        noise_pqnk_psk2(),
        noise_pqnn_psk0(),
        noise_pqnn_psk2(),
        noise_pqnx_psk2(),
        noise_pqxk_psk3(),
        noise_pqxn_psk3(),
        noise_pqxx_psk3(),
    ]
}

pub fn hybrid_handshake_patterns() -> Vec<HandshakePattern> {
    vec![
        noise_hybrid_ik(),
        noise_hybrid_in(),
        noise_hybrid_ix(),
        noise_hybrid_kk(),
        noise_hybrid_kn(),
        noise_hybrid_kx(),
        noise_hybrid_nk(),
        noise_hybrid_nn(),
        noise_hybrid_nx(),
        noise_hybrid_xk(),
        noise_hybrid_xn(),
        noise_hybrid_xx(),
        noise_hybrid_ik_psk1(),
        noise_hybrid_ik_psk2(),
        noise_hybrid_in_psk1(),
        noise_hybrid_in_psk2(),
        noise_hybrid_ix_psk2(),
        noise_hybrid_kk_psk0(),
        noise_hybrid_kk_psk2(),
        noise_hybrid_kn_psk0(),
        noise_hybrid_kn_psk2(),
        noise_hybrid_kx_psk2(),
        noise_hybrid_nk_psk0(),
        noise_hybrid_nk_psk2(),
        noise_hybrid_nn_psk0(),
        noise_hybrid_nn_psk2(),
        noise_hybrid_nx_psk2(),
        noise_hybrid_xk_psk3(),
        noise_hybrid_xn_psk3(),
        noise_hybrid_xx_psk3(),
    ]
}

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
