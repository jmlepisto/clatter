#![no_main]

use clatter::constants::MAX_MESSAGE_LEN;
use clatter::crypto::cipher::ChaChaPoly;
use clatter::crypto::hash::Sha256;
use clatter::crypto::kem::pqclean_kyber::Kyber768;
use clatter::crypto::kem::rust_crypto_kyber::Kyber512;
use clatter::handshakepattern::*;
use clatter::traits::Kem;
use clatter::{Handshaker, PqHandshake};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
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

    const PSK: &[u8] = b"Trapped inside this Octavarium!!";

    let mut alice_rng = rand::thread_rng();
    let mut bob_rng = rand::thread_rng();

    let mut alice_buf = [0u8; MAX_MESSAGE_LEN];
    let mut bob_buf = [0u8; MAX_MESSAGE_LEN];

    let alice_key = Kyber768::genkey(&mut alice_rng).unwrap();
    let bob_key = Kyber768::genkey(&mut bob_rng).unwrap();
    let alice_pub = alice_key.public.clone();
    let bob_pub = bob_key.public.clone();

    for pattern in handshakes {
        let mut alice = PqHandshake::<Kyber512, Kyber768, ChaChaPoly, Sha256, _>::new(
            pattern.clone(),
            &[],
            true,
            Some(alice_key.clone()),
            None,
            Some(bob_pub),
            None,
            &mut alice_rng,
        )
        .unwrap();
        let mut bob = PqHandshake::<Kyber512, Kyber768, ChaChaPoly, Sha256, _>::new(
            pattern,
            &[],
            false,
            Some(bob_key.clone()),
            None,
            Some(alice_pub),
            None,
            &mut bob_rng,
        )
        .unwrap();

        alice.push_psk(PSK);
        bob.push_psk(PSK);

        // Handshake
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

        // Both receive fuzzed data
        let _ = alice.receive(data, &mut alice_buf);
        let _ = bob.receive(data, &mut bob_buf);

        // Both send fuzzed data
        let _ = alice.send(data, &mut alice_buf);
        let _ = bob.send(data, &mut bob_buf);
    }
});
