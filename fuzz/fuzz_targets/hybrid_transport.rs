#![no_main]

use clatter::constants::MAX_MESSAGE_LEN;
use clatter::crypto::cipher::{AesGcm, ChaChaPoly};
use clatter::crypto::dh::X25519;
use clatter::crypto::hash::{Blake2b, Blake2s, Sha256, Sha512};
use clatter::crypto::kem::pqclean_ml_kem::MlKem1024;
use clatter::crypto::kem::rust_crypto_ml_kem::MlKem512;
use clatter::traits::{Cipher, Dh, Hash, Kem};
use clatter_fuzz::{complete_handshake, hybrid_handshake_patterns, setup_hybrid_handshake};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    verify_with::<X25519, MlKem1024, MlKem512, AesGcm, Sha256>(data);
    verify_with::<X25519, MlKem1024, MlKem512, AesGcm, Sha512>(data);
    verify_with::<X25519, MlKem1024, MlKem512, AesGcm, Blake2b>(data);
    verify_with::<X25519, MlKem1024, MlKem512, AesGcm, Blake2s>(data);
    verify_with::<X25519, MlKem1024, MlKem512, ChaChaPoly, Sha256>(data);
    verify_with::<X25519, MlKem1024, MlKem512, ChaChaPoly, Sha512>(data);
    verify_with::<X25519, MlKem1024, MlKem512, ChaChaPoly, Blake2b>(data);
    verify_with::<X25519, MlKem1024, MlKem512, ChaChaPoly, Blake2s>(data);
});

fn verify_with<DH: Dh, EKEM: Kem, SKEM: Kem, C: Cipher, H: Hash>(data: &[u8]) {
    let handshakes = hybrid_handshake_patterns();

    for pattern in handshakes {
        let mut alice_buf = [0u8; MAX_MESSAGE_LEN];
        let mut bob_buf = [0u8; MAX_MESSAGE_LEN];

        let (alice, bob) = setup_hybrid_handshake::<DH, EKEM, SKEM, C, H>(&pattern);

        // Complete handshake
        let (mut alice, mut bob) = complete_handshake(alice, bob);

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

