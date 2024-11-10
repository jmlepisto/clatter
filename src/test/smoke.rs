//! Basic smoke tests - not full coverage on all crypto primitive combinations but good enough

use crate::bytearray::ByteArray;
use crate::crypto::cipher::{AesGcm, ChaChaPoly};
use crate::crypto::dh::X25519;
use crate::crypto::hash::{Blake2b, Sha512};
#[cfg(feature = "use-argyle-kyber768")]
use crate::crypto_impl::argyle_software_kyber::Kyber768 as ArgyleKyber;
use crate::crypto_impl::{pqclean_kyber, rust_crypto_kyber};
use crate::handshakepattern::{
    noise_ik, noise_in, noise_ix, noise_kk, noise_kn, noise_kx, noise_nk, noise_nn, noise_nx,
    noise_pqik, noise_pqin, noise_pqix, noise_pqkk, noise_pqkn, noise_pqkx, noise_pqnk, noise_pqnn,
    noise_pqnx, noise_pqxk, noise_pqxn, noise_pqxx, noise_xk, noise_xn, noise_xx, HandshakePattern,
};
use crate::traits::{Cipher, Dh, Hash, Kem};
use crate::{Handshaker, NqHandshake, PqHandshake};

#[test]
fn smoke_nq_handshakes() {
    let handshakes = [
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
    ];

    for pattern in handshakes {
        nq_handshake::<X25519, ChaChaPoly, Sha512>(pattern.clone());
        nq_handshake::<X25519, AesGcm, Blake2b>(pattern);
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
    ];

    for pattern in handshakes {
        pq_handshake::<rust_crypto_kyber::Kyber512, rust_crypto_kyber::Kyber768, ChaChaPoly, Blake2b>(
            pattern.clone(),
        );
        pq_handshake::<rust_crypto_kyber::Kyber1024, pqclean_kyber::Kyber512, AesGcm, Sha512>(
            pattern.clone(),
        );
        #[cfg(feature = "use-argyle-kyber768")]
        pq_handshake::<ArgyleKyber, rust_crypto_kyber::Kyber512, AesGcm, Sha512>(pattern);
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

    let n = alice
        .send(b"Scream without a sound", &mut alice_buf)
        .unwrap();
    let n = bob.receive(&alice_buf[..n], &mut bob_buf).unwrap();

    assert_eq!(bob_buf[..n], *b"Scream without a sound");
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

    let n = alice
        .send(b"Find I've come full circle", &mut alice_buf)
        .unwrap();
    let n = bob.receive(&alice_buf[..n], &mut bob_buf).unwrap();

    assert_eq!(bob_buf[..n], *b"Find I've come full circle");
}
