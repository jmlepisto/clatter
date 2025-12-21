#![no_main]

use clatter::constants::MAX_MESSAGE_LEN;
use clatter::crypto::cipher::{AesGcm, ChaChaPoly};
use clatter::crypto::dh::X25519;
use clatter::crypto::hash::{Blake2b, Blake2s, Sha256, Sha512};
use clatter::traits::{Cipher, Dh, Hash, Handshaker};
use clatter_fuzz::{nq_handshake_patterns, setup_nq_handshake};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    verify_with::<X25519, AesGcm, Sha256>(data);
    verify_with::<X25519, AesGcm, Sha512>(data);
    verify_with::<X25519, AesGcm, Blake2b>(data);
    verify_with::<X25519, AesGcm, Blake2s>(data);
    verify_with::<X25519, ChaChaPoly, Sha256>(data);
    verify_with::<X25519, ChaChaPoly, Sha512>(data);
    verify_with::<X25519, ChaChaPoly, Blake2b>(data);
    verify_with::<X25519, ChaChaPoly, Blake2s>(data);
});

fn verify_with<DH: Dh, C: Cipher, H: Hash>(data: &[u8]) {
    let handshakes = nq_handshake_patterns();

    for pattern in handshakes {
        let mut alice_buf = [0u8; MAX_MESSAGE_LEN];

        let (mut alice, _) = setup_nq_handshake::<DH, C, H>(&pattern);

        // Alice writes fuzzed payload
        let _ = alice.write_message(data, &mut alice_buf);
    }
}
