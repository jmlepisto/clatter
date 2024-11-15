#![no_main]

use clatter::bytearray::ByteArray;
use clatter::constants::MAX_MESSAGE_LEN;
use clatter::crypto::cipher::{AesGcm, ChaChaPoly};
use clatter::crypto::dh::X25519;
use clatter::crypto::hash::{Blake2b, Blake2s, Sha256, Sha512};
use clatter::handshakepattern::*;
use clatter::traits::{Cipher, Dh, Hash};
use clatter::{Handshaker, NqHandshake};
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

    const PSK: &[u8] = b"Trapped inside this Octavarium!!";

    for pattern in handshakes {
        let mut alice_rng = rand::thread_rng();
        let mut bob_rng = rand::thread_rng();

        let mut alice_buf = [0u8; MAX_MESSAGE_LEN];
        let mut bob_buf = [0u8; MAX_MESSAGE_LEN];

        let alice_key = DH::genkey(&mut alice_rng).unwrap();
        let bob_key = DH::genkey(&mut bob_rng).unwrap();
        let alice_pub = alice_key.public.clone();
        let bob_pub = bob_key.public.clone();

        let mut alice = NqHandshake::<DH, C, H, _>::new(
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
        let mut bob = NqHandshake::<DH, C, H, _>::new(
            pattern.clone(),
            &[],
            false,
            Some(bob_key),
            None,
            Some(alice_pub),
            None,
            &mut bob_rng,
        )
        .unwrap();

        alice.push_psk(PSK);
        bob.push_psk(PSK);

        // Verify Alice only if the pattern is not one-way
        if !pattern.is_one_way() {
            let _ = alice.write_message(&[], &mut alice_buf).unwrap();
            let _ = alice.read_message(data, &mut alice_buf);
        }
        let _ = bob.read_message(data, &mut bob_buf);
    }
}
