use clatter::crypto::cipher::ChaChaPoly;
use clatter::crypto::dh::X25519;
use clatter::crypto::hash::Sha512;
use clatter::handshakepattern::noise_xx;
use clatter::traits::Dh;
use clatter::transportstate::TransportState;
use clatter::{Handshaker, NqHandshake};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc;
use std::thread;

fn setup_tcp_pair() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    let (tx, rx) = mpsc::channel();

    thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        tx.send(stream).unwrap();
    });

    let bob_stream = TcpStream::connect(addr).unwrap();
    let alice_stream = rx.recv().unwrap();

    (alice_stream, bob_stream)
}

pub fn alice_handshake(mut stream: TcpStream) -> Result<TransportState<ChaChaPoly, Sha512>, clatter::error::HandshakeError> {
    let mut alice_buffer = [0u8; 4096];
    let mut stream_buffer = [0u8; 4096];

    let mut rng = rand::thread_rng();
    let secret = X25519::genkey_rng(&mut rng)?;
    let mut handshaker = NqHandshake::<X25519, ChaChaPoly, Sha512>::new(
        noise_xx(),
        &[],
        true,
        Some(secret),
        None,
        None,
        None,
    )?;

    // First handshake message from initiator to responder
    // e -->
    let n = handshaker.write_message(&[], &mut alice_buffer)?;
    stream.write_all(&alice_buffer[..n]).unwrap();

    // Second handshake message from responder to initiator
    // <- e, ee, s, es
    let n = stream.read(&mut stream_buffer).unwrap();
    let _ = handshaker.read_message(&stream_buffer[..n], &mut alice_buffer)?;

    // Third handshake message from initiator to responder
    // -> s, se
    let n = handshaker.write_message(&[], &mut alice_buffer)?;
    stream.write_all(&alice_buffer[..n]).unwrap();

    if !handshaker.is_finished() {
        panic!("alice not handshake finished");
    }

    Ok(handshaker.finalize()?)
}

pub fn bob_handshake(mut stream: TcpStream) -> Result<TransportState<ChaChaPoly, Sha512>, clatter::error::HandshakeError> {
    let mut bob_buffer = [0u8; 4096];
    let mut stream_buffer = [0u8; 4096];

    let mut rng = rand::thread_rng();
    let secret = X25519::genkey_rng(&mut rng)?;
    let mut handshaker = NqHandshake::<X25519, ChaChaPoly, Sha512>::new(
        noise_xx(),
        &[],
        false,
        Some(secret),
        None,
        None,
        None,
    )?;

    // First handshake message from initiator to responder
    // e -->
    let n = stream.read(&mut stream_buffer).unwrap();
    let _ = handshaker.read_message(&stream_buffer[..n], &mut bob_buffer)?;

    // Second handshake message from responder to initiator
    // <- e, ee, s, es
    let n = handshaker.write_message(&[], &mut bob_buffer)?;
    stream.write_all(&bob_buffer[..n]).unwrap();

    // Third handshake message from initiator to responder
    // -> s, se
    let n = stream.read(&mut stream_buffer).unwrap();
    let _ = handshaker.read_message(&stream_buffer[..n], &mut bob_buffer)?;

    if !handshaker.is_finished() {
        panic!("bob not handshake finished");
    }

    Ok(handshaker.finalize()?)
}

fn main() {
    let (alice_stream, bob_stream) = setup_tcp_pair();

    let (alice_tx, alice_rx) = mpsc::channel();
    let (bob_tx, bob_rx) = mpsc::channel();

    thread::spawn(move || {
        let transport = alice_handshake(alice_stream).unwrap();
        alice_tx.send(transport).unwrap();
    });

    thread::spawn(move || {
        let transport = bob_handshake(bob_stream).unwrap();
        bob_tx.send(transport).unwrap();
    });

    let mut transport_bob = bob_rx.recv().unwrap();
    let mut transport_alice = alice_rx.recv().unwrap();

    // Send a message from Alice to Bob
    let msg = b"Hello from initiator";

    let mut bob_buffer = [0u8; 4096];
    let mut alice_buffer = [0u8; 4096];

    let n = transport_alice.send(msg, &mut alice_buffer).unwrap();
    let n = transport_bob.receive(&alice_buffer[..n], &mut bob_buffer).unwrap();

    println!(
        "Bob received from Alice: {}",
        str::from_utf8(&bob_buffer[..n]).unwrap()
    );
}
