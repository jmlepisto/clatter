//! Shared utilities for fuzz testing

use clatter::constants::MAX_MESSAGE_LEN;
use clatter::handshakepattern::*;
use clatter::traits::{Cipher, Dh, Hash, Handshaker, Kem};
use clatter::transportstate::TransportState;
use clatter::{HybridHandshake, HybridHandshakeParams, NqHandshake, PqHandshake};

/// Common PSK used in fuzz tests
pub const PSK: &[u8] = b"Trapped inside this Octavarium!!";

/// Get all NQ handshake patterns
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

/// Get all PQ handshake patterns
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

/// Get all hybrid handshake patterns
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

/// Setup NQ handshake pair
pub fn setup_nq_handshake<DH: Dh, C: Cipher, H: Hash>(
    pattern: &HandshakePattern,
) -> (NqHandshake<DH, C, H>, NqHandshake<DH, C, H>) {
    let alice_key = DH::genkey().unwrap();
    let bob_key = DH::genkey().unwrap();
    let alice_pub = alice_key.public.clone();
    let bob_pub = bob_key.public.clone();

    let mut alice = NqHandshake::<DH, C, H>::new(
        pattern.clone(),
        &[],
        true,
        Some(alice_key),
        None,
        Some(bob_pub),
        None,
    )
    .unwrap();
    let mut bob = NqHandshake::<DH, C, H>::new(
        pattern.clone(),
        &[],
        false,
        Some(bob_key),
        None,
        Some(alice_pub),
        None,
    )
    .unwrap();

    alice.push_psk(PSK);
    bob.push_psk(PSK);

    (alice, bob)
}

/// Setup PQ handshake pair
pub fn setup_pq_handshake<EKEM: Kem, SKEM: Kem, C: Cipher, H: Hash>(
    pattern: &HandshakePattern,
) -> (PqHandshake<EKEM, SKEM, C, H>, PqHandshake<EKEM, SKEM, C, H>) {
    let alice_key = SKEM::genkey().unwrap();
    let bob_key = SKEM::genkey().unwrap();
    let alice_pub = alice_key.public.clone();
    let bob_pub = bob_key.public.clone();

    let mut alice = PqHandshake::<EKEM, SKEM, C, H>::new(
        pattern.clone(),
        &[],
        true,
        Some(alice_key),
        None,
        Some(bob_pub),
        None,
    )
    .unwrap();
    let mut bob = PqHandshake::<EKEM, SKEM, C, H>::new(
        pattern.clone(),
        &[],
        false,
        Some(bob_key),
        None,
        Some(alice_pub),
        None,
    )
    .unwrap();

    alice.push_psk(PSK);
    bob.push_psk(PSK);

    (alice, bob)
}

/// Setup hybrid handshake pair
pub fn setup_hybrid_handshake<DH: Dh, EKEM: Kem, SKEM: Kem, C: Cipher, H: Hash>(
    pattern: &HandshakePattern,
) -> (HybridHandshake<DH, EKEM, SKEM, C, H>, HybridHandshake<DH, EKEM, SKEM, C, H>) {
    let alice_dh_keys = DH::genkey().unwrap();
    let alice_dh_pub = alice_dh_keys.public.clone();
    let bob_dh_keys = DH::genkey().unwrap();
    let bob_dh_pub = bob_dh_keys.public.clone();

    let alice_kem_keys = SKEM::genkey().unwrap();
    let alice_kem_pub = alice_kem_keys.public.clone();
    let bob_kem_keys = SKEM::genkey().unwrap();
    let bob_kem_pub = bob_kem_keys.public.clone();

    let alice_params = HybridHandshakeParams::new(pattern.clone(), true)
        .with_prologue(&[])
        .with_s(alice_dh_keys)
        .with_rs(bob_dh_pub)
        .with_s_kem(alice_kem_keys)
        .with_rs_kem(bob_kem_pub);

    let mut alice = HybridHandshake::<DH, EKEM, SKEM, C, H>::new(alice_params).unwrap();

    let bob_params = HybridHandshakeParams::new(pattern.clone(), false)
        .with_prologue(&[])
        .with_s(bob_dh_keys)
        .with_rs(alice_dh_pub)
        .with_s_kem(bob_kem_keys)
        .with_rs_kem(alice_kem_pub);

    let mut bob = HybridHandshake::<DH, EKEM, SKEM, C, H>::new(bob_params).unwrap();

    alice.push_psk(PSK);
    bob.push_psk(PSK);

    (alice, bob)
}

/// Complete a handshake exchange between two parties
pub fn complete_handshake<A: Handshaker<C, H>, B: Handshaker<C, H>, C: Cipher, H: Hash>(
    mut alice: A,
    mut bob: B,
) -> (TransportState<C, H>, TransportState<C, H>) {
    let mut alice_buf = [0u8; MAX_MESSAGE_LEN];
    let mut bob_buf = [0u8; MAX_MESSAGE_LEN];

    loop {
        let n = alice.write_message(&[], &mut alice_buf).unwrap();
        let _ = bob.read_message(&alice_buf[..n], &mut bob_buf).unwrap();

        if alice.is_finished() && bob.is_finished() {
            break;
        }

        let n = bob.write_message(&[], &mut bob_buf).unwrap();
        let _ = alice.read_message(&bob_buf[..n], &mut alice_buf).unwrap();

        if alice.is_finished() && bob.is_finished() {
            break;
        }
    }

    let alice_transport = alice.finalize().unwrap();
    let bob_transport = bob.finalize().unwrap();

    (alice_transport, bob_transport)
}


