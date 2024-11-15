#![no_main]

use clatter::bytearray::ByteArray;
use clatter::constants::MAX_MESSAGE_LEN;
use clatter::crypto::cipher::{AesGcm, ChaChaPoly};
use clatter::crypto::hash::{Blake2b, Blake2s, Sha256, Sha512};
use clatter::crypto::kem::pqclean_kyber::Kyber768;
use clatter::crypto::kem::rust_crypto_kyber::Kyber512;
use clatter::handshakepattern::*;
use clatter::traits::{Cipher, Hash, Kem};
use clatter::{Handshaker, PqHandshake};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // TODO: generate all combinations
    verify_with::<Kyber768, Kyber512, AesGcm, Sha256>(data);
    verify_with::<Kyber768, Kyber512, AesGcm, Sha512>(data);
    verify_with::<Kyber768, Kyber512, AesGcm, Blake2b>(data);
    verify_with::<Kyber768, Kyber512, AesGcm, Blake2s>(data);
    verify_with::<Kyber768, Kyber512, ChaChaPoly, Sha256>(data);
    verify_with::<Kyber768, Kyber512, ChaChaPoly, Sha512>(data);
    verify_with::<Kyber768, Kyber512, ChaChaPoly, Blake2b>(data);
    verify_with::<Kyber768, Kyber512, ChaChaPoly, Blake2b>(data);
});

fn verify_with<EKEM: Kem, SKEM: Kem, C: Cipher, H: Hash>(data: &[u8]) {
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

    for pattern in handshakes {
        let mut alice_rng = rand::thread_rng();
        let mut bob_rng = rand::thread_rng();

        let mut alice_buf = [0u8; MAX_MESSAGE_LEN];

        let alice_key = SKEM::genkey(&mut alice_rng).unwrap();
        let bob_key = SKEM::genkey(&mut bob_rng).unwrap();
        let bob_pub = bob_key.public.clone();

        let mut alice = PqHandshake::<EKEM, SKEM, C, H, _>::new(
            pattern.clone(),
            &[],
            true,
            Some(alice_key),
            None,
            Some(bob_pub),
            None,
            &mut alice_rng,
        )
        .unwrap();

        alice.push_psk(PSK);

        // Alice writes fuzzed payload
        let _ = alice.write_message(data, &mut alice_buf);
    }
}
