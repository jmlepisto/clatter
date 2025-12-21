#![no_main]

use clatter::constants::MAX_MESSAGE_LEN;
use clatter::crypto::cipher::{AesGcm, ChaChaPoly};
use clatter::crypto::hash::{Blake2b, Blake2s, Sha256, Sha512};
use clatter::crypto::kem::pqclean_ml_kem::MlKem1024;
use clatter::crypto::kem::rust_crypto_ml_kem::MlKem512;
use clatter::traits::{Cipher, Hash, Handshaker, Kem};
use clatter_fuzz::{pq_handshake_patterns, setup_pq_handshake};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // TODO: generate all combinations
    verify_with::<MlKem1024, MlKem512, AesGcm, Sha256>(data);
    verify_with::<MlKem1024, MlKem512, AesGcm, Sha512>(data);
    verify_with::<MlKem1024, MlKem512, AesGcm, Blake2b>(data);
    verify_with::<MlKem1024, MlKem512, AesGcm, Blake2s>(data);
    verify_with::<MlKem1024, MlKem512, ChaChaPoly, Sha256>(data);
    verify_with::<MlKem1024, MlKem512, ChaChaPoly, Sha512>(data);
    verify_with::<MlKem1024, MlKem512, ChaChaPoly, Blake2b>(data);
    verify_with::<MlKem1024, MlKem512, ChaChaPoly, Blake2b>(data);
});

fn verify_with<EKEM: Kem, SKEM: Kem, C: Cipher, H: Hash>(data: &[u8]) {
    let handshakes = pq_handshake_patterns();

    for pattern in handshakes {
        let mut alice_buf = [0u8; MAX_MESSAGE_LEN];

        let (mut alice, _) = setup_pq_handshake::<EKEM, SKEM, C, H>(&pattern);

        // Alice writes fuzzed payload
        let _ = alice.write_message(data, &mut alice_buf);
    }
}
