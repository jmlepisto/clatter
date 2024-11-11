#![no_main]

use clatter::constants::MAX_MESSAGE_LEN;
use clatter::crypto::cipher::ChaChaPoly;
use clatter::crypto::dh::X25519;
use clatter::crypto::hash::Sha256;
use clatter::handshakepattern::*;
use clatter::traits::Dh;
use clatter::{Handshaker, NqHandshake};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
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

    let mut alice_rng = rand::thread_rng();
    let mut bob_rng = rand::thread_rng();

    let mut alice_buf = [0u8; MAX_MESSAGE_LEN];
    let mut bob_buf = [0u8; MAX_MESSAGE_LEN];

    let alice_key = X25519::genkey(&mut alice_rng).unwrap();
    let bob_key = X25519::genkey(&mut bob_rng).unwrap();
    let alice_pub = alice_key.public.clone();
    let bob_pub = bob_key.public.clone();

    for pattern in handshakes {
        let mut alice = NqHandshake::<X25519, ChaChaPoly, Sha256, _>::new(
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
        let mut bob = NqHandshake::<X25519, ChaChaPoly, Sha256, _>::new(
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

        // Write once from alice to get it into receiving state
        let _ = alice.write_message(&[], &mut alice_buf).unwrap();

        // Both parties receive fuzzed data
        let _ = alice.read_message(data, &mut alice_buf);
        let _ = bob.read_message(data, &mut bob_buf);
    }
});
