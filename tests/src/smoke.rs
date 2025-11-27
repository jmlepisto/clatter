use clatter::crypto::cipher::{AesGcm, ChaChaPoly};
use clatter::crypto::dh::X25519;
use clatter::crypto::hash::{Blake2b, Blake2s, Sha256, Sha512};
use clatter::crypto::kem::{pqclean_ml_kem, rust_crypto_ml_kem};
use clatter::handshakepattern::*;
use clatter::traits::{Cipher, Dh, Hash, Kem};
use clatter::{
    DualLayerHandshake, Handshaker, HybridDualLayerHandshake, HybridHandshake,
    HybridHandshakeParams, NqHandshake, PqHandshake,
};

use crate::verify_handshake;

const PSKS: &[[u8; 32]] = &[[0; 32], [1; 32], [2; 32], [3; 32]];

#[test]
fn smoke_nq_handshakes() {
    let handshakes = [
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
    ];

    for pattern in handshakes {
        nq_handshake::<X25519, ChaChaPoly, Sha512>(pattern.clone());
        nq_handshake::<X25519, ChaChaPoly, Sha256>(pattern.clone());
        nq_handshake::<X25519, ChaChaPoly, Blake2b>(pattern.clone());
        nq_handshake::<X25519, ChaChaPoly, Blake2s>(pattern.clone());

        nq_handshake::<X25519, AesGcm, Sha512>(pattern.clone());
        nq_handshake::<X25519, AesGcm, Sha256>(pattern.clone());
        nq_handshake::<X25519, AesGcm, Blake2b>(pattern.clone());
        nq_handshake::<X25519, AesGcm, Blake2s>(pattern.clone());
    }
}

#[test]
fn smoke_pq_handshakes() {
    let handshakes = [
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
    ];

    fn cipher_hash_combos<EKEM: Kem, SKEM: Kem>(pattern: HandshakePattern) {
        pq_handshake::<EKEM, SKEM, ChaChaPoly, Blake2b>(pattern.clone());
        pq_handshake::<EKEM, SKEM, ChaChaPoly, Blake2s>(pattern.clone());
        pq_handshake::<EKEM, SKEM, ChaChaPoly, Sha256>(pattern.clone());
        pq_handshake::<EKEM, SKEM, ChaChaPoly, Sha512>(pattern.clone());

        pq_handshake::<EKEM, SKEM, AesGcm, Blake2b>(pattern.clone());
        pq_handshake::<EKEM, SKEM, AesGcm, Blake2s>(pattern.clone());
        pq_handshake::<EKEM, SKEM, AesGcm, Sha256>(pattern.clone());
        pq_handshake::<EKEM, SKEM, AesGcm, Sha512>(pattern.clone());
    }

    for pattern in handshakes {
        // Rust crypto
        cipher_hash_combos::<rust_crypto_ml_kem::MlKem512, rust_crypto_ml_kem::MlKem512>(
            pattern.clone(),
        );
        cipher_hash_combos::<rust_crypto_ml_kem::MlKem768, rust_crypto_ml_kem::MlKem768>(
            pattern.clone(),
        );
        cipher_hash_combos::<rust_crypto_ml_kem::MlKem1024, rust_crypto_ml_kem::MlKem1024>(
            pattern.clone(),
        );

        // PQCLean
        cipher_hash_combos::<pqclean_ml_kem::MlKem512, pqclean_ml_kem::MlKem512>(pattern.clone());
        cipher_hash_combos::<pqclean_ml_kem::MlKem768, pqclean_ml_kem::MlKem768>(pattern.clone());
        cipher_hash_combos::<pqclean_ml_kem::MlKem1024, pqclean_ml_kem::MlKem1024>(pattern.clone());

        // One cross-use test just in case with two different KEM vendors
        cipher_hash_combos::<pqclean_ml_kem::MlKem768, rust_crypto_ml_kem::MlKem768>(
            pattern.clone(),
        );
    }
}

#[test]
fn smoke_hybrid_handshakes() {
    let handshakes = [
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
    ];

    fn cipher_hash_combos<DH: Dh, EKEM: Kem, SKEM: Kem>(pattern: HandshakePattern) {
        hybrid_handshake::<DH, EKEM, SKEM, ChaChaPoly, Blake2b>(pattern.clone());
        hybrid_handshake::<DH, EKEM, SKEM, ChaChaPoly, Blake2s>(pattern.clone());
        hybrid_handshake::<DH, EKEM, SKEM, ChaChaPoly, Sha256>(pattern.clone());
        hybrid_handshake::<DH, EKEM, SKEM, ChaChaPoly, Sha512>(pattern.clone());

        hybrid_handshake::<DH, EKEM, SKEM, AesGcm, Blake2b>(pattern.clone());
        hybrid_handshake::<DH, EKEM, SKEM, AesGcm, Blake2s>(pattern.clone());
        hybrid_handshake::<DH, EKEM, SKEM, AesGcm, Sha256>(pattern.clone());
        hybrid_handshake::<DH, EKEM, SKEM, AesGcm, Sha512>(pattern.clone());
    }

    for pattern in handshakes {
        // Rust crypto
        cipher_hash_combos::<X25519, rust_crypto_ml_kem::MlKem512, rust_crypto_ml_kem::MlKem512>(
            pattern.clone(),
        );
        cipher_hash_combos::<X25519, rust_crypto_ml_kem::MlKem768, rust_crypto_ml_kem::MlKem768>(
            pattern.clone(),
        );
        cipher_hash_combos::<X25519, rust_crypto_ml_kem::MlKem1024, rust_crypto_ml_kem::MlKem1024>(
            pattern.clone(),
        );

        // PQCLean
        cipher_hash_combos::<X25519, pqclean_ml_kem::MlKem512, pqclean_ml_kem::MlKem512>(
            pattern.clone(),
        );
        cipher_hash_combos::<X25519, pqclean_ml_kem::MlKem768, pqclean_ml_kem::MlKem768>(
            pattern.clone(),
        );
        cipher_hash_combos::<X25519, pqclean_ml_kem::MlKem1024, pqclean_ml_kem::MlKem1024>(
            pattern.clone(),
        );

        // One cross-use test just in case with two different KEM vendors
        cipher_hash_combos::<X25519, pqclean_ml_kem::MlKem768, rust_crypto_ml_kem::MlKem768>(
            pattern.clone(),
        );
    }
}

#[test]
fn smoke_dual_layer_handshakes() {
    let nq_handshakes = [
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
    ];

    let pq_handshakes = [
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
    ];

    fn cipher_hash_combos<EKEM: Kem, SKEM: Kem, DH: Dh>(
        nq_pattern: HandshakePattern,
        pq_pattern: HandshakePattern,
    ) {
        dual_layer_handshakes::<EKEM, SKEM, DH, ChaChaPoly, Blake2b>(
            nq_pattern.clone(),
            pq_pattern.clone(),
        );
        dual_layer_handshakes::<EKEM, SKEM, DH, ChaChaPoly, Blake2s>(
            nq_pattern.clone(),
            pq_pattern.clone(),
        );
        dual_layer_handshakes::<EKEM, SKEM, DH, ChaChaPoly, Sha256>(
            nq_pattern.clone(),
            pq_pattern.clone(),
        );
        dual_layer_handshakes::<EKEM, SKEM, DH, ChaChaPoly, Sha512>(
            nq_pattern.clone(),
            pq_pattern.clone(),
        );

        dual_layer_handshakes::<EKEM, SKEM, DH, AesGcm, Blake2b>(
            nq_pattern.clone(),
            pq_pattern.clone(),
        );
        dual_layer_handshakes::<EKEM, SKEM, DH, AesGcm, Blake2s>(
            nq_pattern.clone(),
            pq_pattern.clone(),
        );
        dual_layer_handshakes::<EKEM, SKEM, DH, AesGcm, Sha256>(
            nq_pattern.clone(),
            pq_pattern.clone(),
        );
        dual_layer_handshakes::<EKEM, SKEM, DH, AesGcm, Sha512>(
            nq_pattern.clone(),
            pq_pattern.clone(),
        );
    }

    for nq in &nq_handshakes {
        if nq.is_one_way() {
            continue;
        }
        for pq in &pq_handshakes {
            // Rust crypto
            cipher_hash_combos::<rust_crypto_ml_kem::MlKem512, rust_crypto_ml_kem::MlKem512, X25519>(
                nq.clone(),
                pq.clone(),
            );
            cipher_hash_combos::<rust_crypto_ml_kem::MlKem768, rust_crypto_ml_kem::MlKem768, X25519>(
                nq.clone(),
                pq.clone(),
            );
            cipher_hash_combos::<
                rust_crypto_ml_kem::MlKem1024,
                rust_crypto_ml_kem::MlKem1024,
                X25519,
            >(nq.clone(), pq.clone());

            // PQCLean
            cipher_hash_combos::<pqclean_ml_kem::MlKem512, pqclean_ml_kem::MlKem512, X25519>(
                nq.clone(),
                pq.clone(),
            );
            cipher_hash_combos::<pqclean_ml_kem::MlKem768, pqclean_ml_kem::MlKem768, X25519>(
                nq.clone(),
                pq.clone(),
            );
            cipher_hash_combos::<pqclean_ml_kem::MlKem1024, pqclean_ml_kem::MlKem1024, X25519>(
                nq.clone(),
                pq.clone(),
            );

            // One cross-use test just in case with two different KEM vendors
            cipher_hash_combos::<pqclean_ml_kem::MlKem768, rust_crypto_ml_kem::MlKem768, X25519>(
                nq.clone(),
                pq.clone(),
            );
        }
    }
}

fn dual_layer_handshakes<EKEM: Kem, SKEM: Kem, DH: Dh, C: Cipher, H: Hash>(
    nq_pattern: HandshakePattern,
    pq_pattern: HandshakePattern,
) {
    // -- Prepare NQ handshake --

    // Generate static keys
    let alice_s = DH::genkey().unwrap();
    let alice_s_pub = alice_s.public.clone();
    let bob_s = DH::genkey().unwrap();
    let bob_s_pub = bob_s.public.clone();

    let mut alice_nq = NqHandshake::<DH, C, H>::new(
        nq_pattern.clone(),
        b"Spinning round and round",
        true,
        Some(alice_s),
        None,
        Some(bob_s_pub),
        None,
    )
    .unwrap();

    let mut bob_nq = NqHandshake::<DH, C, H>::new(
        nq_pattern,
        b"Spinning round and round",
        false,
        Some(bob_s),
        None,
        Some(alice_s_pub),
        None,
    )
    .unwrap();

    // Push PSKs every time. No harm done if the pattern doesn't use those.
    for psk in PSKS {
        alice_nq.push_psk(psk);
        bob_nq.push_psk(psk);
    }

    // -- Prepare PQ handshake --

    // Generate static keys
    let alice_keys = SKEM::genkey().unwrap();
    let alice_pub = alice_keys.public.clone();
    let bob_keys = SKEM::genkey().unwrap();
    let bob_pub = bob_keys.public.clone();

    let mut alice_pq = PqHandshake::<EKEM, SKEM, C, H>::new(
        pq_pattern.clone(),
        b"Stumbling all around",
        true,
        Some(alice_keys),
        None,
        Some(bob_pub),
        None,
    )
    .unwrap();

    let mut bob_pq = PqHandshake::<EKEM, SKEM, C, H>::new(
        pq_pattern,
        b"Stumbling all around",
        false,
        Some(bob_keys),
        None,
        Some(alice_pub),
        None,
    )
    .unwrap();

    // Push PSKs every time. No harm done if the pattern doesn't use those.
    for psk in PSKS {
        alice_pq.push_psk(psk);
        bob_pq.push_psk(psk);
    }

    // -- Prepare and verify dual layer handshakes --
    let alice = DualLayerHandshake::<_, _, _, _, 8182>::new(alice_nq.clone(), alice_pq.clone());
    let bob = DualLayerHandshake::<_, _, _, _, 8182>::new(bob_nq.clone(), bob_pq.clone());
    verify_handshake(alice, bob);

    let alice =
        HybridDualLayerHandshake::<_, _, _, _, 8182>::new(alice_nq.clone(), alice_pq.clone());
    let bob = HybridDualLayerHandshake::<_, _, _, _, 8182>::new(bob_nq.clone(), bob_pq.clone());
    verify_handshake(alice, bob);
}

fn nq_handshake<DH: Dh, C: Cipher, H: Hash>(pattern: HandshakePattern) {
    // Generate static keys
    let alice_s = DH::genkey().unwrap();
    let alice_s_pub = alice_s.public.clone();
    let bob_s = DH::genkey().unwrap();
    let bob_s_pub = bob_s.public.clone();

    let mut alice = NqHandshake::<DH, C, H>::new(
        pattern.clone(),
        b"Spinning round and round",
        true,
        Some(alice_s),
        None,
        Some(bob_s_pub),
        None,
    )
    .unwrap();

    let mut bob = NqHandshake::<DH, C, H>::new(
        pattern,
        b"Spinning round and round",
        false,
        Some(bob_s),
        None,
        Some(alice_s_pub),
        None,
    )
    .unwrap();

    // Push PSKs every time. No harm done if the pattern doesn't use those.
    for psk in PSKS {
        alice.push_psk(psk);
        bob.push_psk(psk);
    }

    verify_handshake(alice, bob);
}

fn pq_handshake<EKEM: Kem, SKEM: Kem, C: Cipher, H: Hash>(pattern: HandshakePattern) {
    // Generate static keys
    let alice_keys = SKEM::genkey().unwrap();
    let alice_pub = alice_keys.public.clone();
    let bob_keys = SKEM::genkey().unwrap();
    let bob_pub = bob_keys.public.clone();

    let mut alice = PqHandshake::<EKEM, SKEM, C, H>::new(
        pattern.clone(),
        b"Stumbling all around",
        true,
        Some(alice_keys),
        None,
        Some(bob_pub),
        None,
    )
    .unwrap();

    let mut bob = PqHandshake::<EKEM, SKEM, C, H>::new(
        pattern,
        b"Stumbling all around",
        false,
        Some(bob_keys),
        None,
        Some(alice_pub),
        None,
    )
    .unwrap();

    // Push PSKs every time. No harm done if the pattern doesn't use those.
    for psk in PSKS {
        alice.push_psk(psk);
        bob.push_psk(psk);
    }

    verify_handshake(alice, bob);
}

fn hybrid_handshake<DH: Dh, EKEM: Kem, SKEM: Kem, C: Cipher, H: Hash>(pattern: HandshakePattern) {
    // Generate static keys
    let alice_dh_keys = DH::genkey().unwrap();
    let alice_dh_pub = alice_dh_keys.public.clone();
    let bob_dh_keys = DH::genkey().unwrap();
    let bob_dh_pub = bob_dh_keys.public.clone();

    let alice_kem_keys = SKEM::genkey().unwrap();
    let alice_kem_pub = alice_kem_keys.public.clone();
    let bob_kem_keys = SKEM::genkey().unwrap();
    let bob_kem_pub = bob_kem_keys.public.clone();

    let alice_params = HybridHandshakeParams::new(pattern.clone(), true)
        .with_prologue(b"Stumbling all around")
        .with_s(alice_dh_keys)
        .with_rs(bob_dh_pub)
        .with_s_kem(alice_kem_keys)
        .with_rs_kem(bob_kem_pub);

    let mut alice = HybridHandshake::<DH, EKEM, SKEM, C, H>::new(alice_params).unwrap();

    let bob_params = HybridHandshakeParams::new(pattern.clone(), false)
        .with_prologue(b"Stumbling all around")
        .with_s(bob_dh_keys)
        .with_rs(alice_dh_pub)
        .with_s_kem(bob_kem_keys)
        .with_rs_kem(alice_kem_pub);

    let mut bob = HybridHandshake::<DH, EKEM, SKEM, C, H>::new(bob_params).unwrap();

    // Push PSKs every time. No harm done if the pattern doesn't use those.
    for psk in PSKS {
        alice.push_psk(psk);
        bob.push_psk(psk);
    }

    verify_handshake(alice, bob);
}
