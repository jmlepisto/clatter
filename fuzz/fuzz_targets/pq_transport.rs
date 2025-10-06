#![no_main]

use clatter::bytearray::ByteArray;
use clatter::constants::MAX_MESSAGE_LEN;
use clatter::crypto::cipher::{AesGcm, ChaChaPoly};
use clatter::crypto::hash::{Blake2b, Blake2s, Sha256, Sha512};
use clatter::crypto::kem::pqclean_kyber::Kyber768;
use clatter::crypto::kem::rust_crypto_ml_kem::MlKem512;
use clatter::handshakepattern::*;
use clatter::traits::{Cipher, Hash, Kem};
use clatter::{Handshaker, PqHandshake};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // TODO: generate all combinations
    verify_with::<Kyber768, MlKem512, AesGcm, Sha256>(data);
    verify_with::<Kyber768, MlKem512, AesGcm, Sha512>(data);
    verify_with::<Kyber768, MlKem512, AesGcm, Blake2b>(data);
    verify_with::<Kyber768, MlKem512, AesGcm, Blake2s>(data);
    verify_with::<Kyber768, MlKem512, ChaChaPoly, Sha256>(data);
    verify_with::<Kyber768, MlKem512, ChaChaPoly, Sha512>(data);
    verify_with::<Kyber768, MlKem512, ChaChaPoly, Blake2b>(data);
    verify_with::<Kyber768, MlKem512, ChaChaPoly, Blake2b>(data);
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
        let mut alice_buf = [0u8; MAX_MESSAGE_LEN];
        let mut bob_buf = [0u8; MAX_MESSAGE_LEN];

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

        // Complete handshake
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

        // Handshake done
        let mut alice = alice.finalize().unwrap();
        let mut bob = bob.finalize().unwrap();

        if !pattern.is_one_way() {
            // Both receive fuzzed data
            let _ = alice.receive(data, &mut alice_buf);
            let _ = bob.receive(data, &mut bob_buf);

            // Both send fuzzed data
            let _ = alice.send(data, &mut alice_buf);
            let _ = bob.send(data, &mut bob_buf);
        } else {
            // Alice sends and Bob receives
            let _ = alice.send(data, &mut alice_buf);
            let _ = bob.receive(data, &mut bob_buf);
        }
    }
}
