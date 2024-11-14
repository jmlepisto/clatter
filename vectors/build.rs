use std::collections::HashMap;
use std::env;
use std::fs::File;
use std::io::Write;
use std::path::Path;

fn main() {
    let out_dir = env::var("OUT_DIR").unwrap();
    let dest_path = Path::new(&out_dir).join("crypto_mapping.rs");
    let mut out = File::create(&dest_path).unwrap();

    let mut dhs = HashMap::new();
    dhs.insert("25519", "clatter::crypto::dh::X25519");

    let mut ciphers = HashMap::new();
    ciphers.insert("ChaChaPoly", "clatter::crypto::cipher::ChaChaPoly");
    ciphers.insert("AESGCM", "clatter::crypto::cipher::AesGcm");

    let mut hashes = HashMap::new();
    hashes.insert("SHA256", "clatter::crypto::hash::Sha256");
    hashes.insert("SHA512", "clatter::crypto::hash::Sha512");
    hashes.insert("BLAKE2b", "clatter::crypto::hash::Blake2b");
    hashes.insert("BLAKE2s", "clatter::crypto::hash::Blake2s");

    writeln!(out, "fn verify_vector(v: &Vector) -> bool {{").unwrap();
    writeln!(
        out,
        "    let (_, dh, cipher, hash) = v.parse_protocol_name();"
    )
    .unwrap();
    writeln!(
        out,
        "    match (dh.as_str(), cipher.as_str(), hash.as_str()) {{"
    )
    .unwrap();
    for (dh, dh_impl) in &dhs {
        for (cipher, cipher_impl) in &ciphers {
            for (hash, hash_impl) in &hashes {
                writeln!(out, "        (\"{dh}\", \"{cipher}\", \"{hash}\") => verify_vector_with::<{dh_impl}, {cipher_impl}, {hash_impl}>(&v),").unwrap();
            }
        }
    }
    // 448 not supported
    writeln!(out, "        (\"448\", _, _) => false,").unwrap();
    writeln!(
        out,
        "        _ => panic!(\"Unsupported crypto combo: {{}} - {{}} - {{}}\", dh, cipher, hash)"
    )
    .unwrap();
    writeln!(out, "    }}").unwrap();
    writeln!(out, "}}").unwrap();
}
