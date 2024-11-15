//! Basic smoke tests - not full coverage on all crypto primitive combinations but good enough

use clatter::bytearray::ByteArray;
use clatter::crypto::cipher::{AesGcm, ChaChaPoly};
use clatter::crypto::dh::X25519;
use clatter::crypto::hash::{Blake2b, Blake2s, Sha256, Sha512};
use clatter::crypto::kem::{pqclean_kyber, rust_crypto_kyber};
use clatter::handshakepattern::*;
use clatter::traits::{Cipher, Dh, Hash, Kem};
use clatter::{Handshaker, NqHandshake, PqHandshake};

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
        cipher_hash_combos::<rust_crypto_kyber::Kyber512, rust_crypto_kyber::Kyber512>(
            pattern.clone(),
        );
        cipher_hash_combos::<rust_crypto_kyber::Kyber768, rust_crypto_kyber::Kyber768>(
            pattern.clone(),
        );
        cipher_hash_combos::<rust_crypto_kyber::Kyber1024, rust_crypto_kyber::Kyber1024>(
            pattern.clone(),
        );

        // PQCLean
        cipher_hash_combos::<pqclean_kyber::Kyber512, pqclean_kyber::Kyber512>(pattern.clone());
        cipher_hash_combos::<pqclean_kyber::Kyber768, pqclean_kyber::Kyber768>(pattern.clone());
        cipher_hash_combos::<pqclean_kyber::Kyber1024, pqclean_kyber::Kyber1024>(pattern.clone());

        // One cross-use test just in case with two different KEM vendors
        cipher_hash_combos::<pqclean_kyber::Kyber768, rust_crypto_kyber::Kyber768>(pattern.clone());
    }
}

fn nq_handshake<DH: Dh, C: Cipher, H: Hash>(pattern: HandshakePattern) {
    let mut rng_alice = rand::thread_rng();
    let mut rng_bob = rand::thread_rng();

    // Generate static keys
    let alice_s = DH::genkey(&mut rng_alice).unwrap();
    let alice_s_pub = alice_s.public.clone();
    let bob_s = DH::genkey(&mut rng_bob).unwrap();
    let bob_s_pub = bob_s.public.clone();

    let mut alice = NqHandshake::<DH, C, H, _>::new(
        pattern.clone(),
        b"Spinning round and round",
        true,
        Some(alice_s),
        None,
        Some(bob_s_pub),
        None,
        &mut rng_alice,
    )
    .unwrap();

    let mut bob = NqHandshake::<DH, C, H, _>::new(
        pattern,
        b"Spinning round and round",
        false,
        Some(bob_s),
        None,
        Some(alice_s_pub),
        None,
        &mut rng_bob,
    )
    .unwrap();

    // Push PSKs every time. No harm done if the pattern doesn't use those.
    for psk in PSKS {
        alice.push_psk(psk);
        bob.push_psk(psk);
    }

    let mut alice_buf = [0u8; 4096];
    let mut bob_buf = [0u8; 4096];

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
    #[cfg(feature = "alloc")]
    assert_eq!(
        &bob.receive_vec(&alice.send_vec(b"Eugene gene the dance machine").unwrap())
            .unwrap(),
        b"Eugene gene the dance machine"
    );
}

fn pq_handshake<EKEM: Kem, SKEM: Kem, C: Cipher, H: Hash>(pattern: HandshakePattern) {
    let mut rng_alice = rand::thread_rng();
    let mut rng_bob = rand::thread_rng();

    // Generate static keys
    let alice_keys = SKEM::genkey(&mut rng_alice).unwrap();
    let alice_pub = alice_keys.public.clone();
    let bob_keys = SKEM::genkey(&mut rng_bob).unwrap();
    let bob_pub = bob_keys.public.clone();

    let mut alice = PqHandshake::<EKEM, SKEM, C, H, _>::new(
        pattern.clone(),
        b"Stumbling all around",
        true,
        Some(alice_keys),
        None,
        Some(bob_pub),
        None,
        &mut rng_alice,
    )
    .unwrap();

    let mut bob = PqHandshake::<EKEM, SKEM, C, H, _>::new(
        pattern,
        b"Stumbling all around",
        false,
        Some(bob_keys),
        None,
        Some(alice_pub),
        None,
        &mut rng_bob,
    )
    .unwrap();

    // Push PSKs every time. No harm done if the pattern doesn't use those.
    for psk in PSKS {
        alice.push_psk(psk);
        bob.push_psk(psk);
    }

    let mut alice_buf = [0u8; 8182];
    let mut bob_buf = [0u8; 8182];

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

    let mut alice = alice.finalize().unwrap();
    let mut bob = bob.finalize().unwrap();

    // "Normal" send-receive
    let n = alice
        .send(b"Find I've come full circle", &mut alice_buf)
        .unwrap();
    let n = bob.receive(&alice_buf[..n], &mut bob_buf).unwrap();

    assert_eq!(bob_buf[..n], *b"Find I've come full circle");

    // In-place send-receive
    let mut in_place_buf = [0; 4096];
    let msg = b"On a gleaming razor's edge";
    in_place_buf[..msg.len()].copy_from_slice(msg);
    let n = alice.send_in_place(&mut in_place_buf, msg.len()).unwrap();
    let n = bob.receive_in_place(&mut in_place_buf, n).unwrap();
    assert_eq!(in_place_buf[..n], *msg);

    // Vec send-receive
    #[cfg(feature = "alloc")]
    assert_eq!(
        &bob.receive_vec(&alice.send_vec(b"This story ends where it began").unwrap())
            .unwrap(),
        b"This story ends where it began"
    );
}
