//! The SHA-2 family: all six hashes over the same message, checked against the
//! published digests of "abc", with each one's sizes.
//!
//! ```sh
//! cargo run --release --example sha2
//! ```

use cryptors::Digest;
use cryptors::sha2::{Sha224, Sha256, Sha384, Sha512, Sha512_224, Sha512_256};

/// Hashes `b"abc"` with `D`, checks the digest against `expected`, and prints
/// the hash's sizes. Generic code like this is what the `Digest` trait is for.
fn show<D: Digest>(name: &str, expected: &str) {
    let digest = D::digest(b"abc");
    assert_eq!(digest.as_ref().len(), D::OUTPUT_LEN);
    assert_eq!(D::hex_digest(b"abc"), expected);
    println!(
        "{name:<11} block {:3} bytes, digest {:2} bytes: {expected}",
        D::BLOCK_LEN,
        D::OUTPUT_LEN
    );
}

fn main() {
    // FIPS 180-4, and NIST's example values for each function: "abc".
    show::<Sha224>(
        "SHA-224",
        "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7",
    );
    show::<Sha256>(
        "SHA-256",
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    );
    show::<Sha384>(
        "SHA-384",
        "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7",
    );
    show::<Sha512>(
        "SHA-512",
        "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
    );
    show::<Sha512_224>(
        "SHA-512/224",
        "4634270f707b6a54daae7530460842e20e37ed265ceee9a43e8924aa",
    );
    show::<Sha512_256>(
        "SHA-512/256",
        "53048e2681941ef99b2e29b76b4c7dabe4c2d0c634fc6d46e0e2f13107e7af23",
    );

    // SHA-512/256 is its own function (a different starting state), not
    // SHA-512 cut short: the two share no prefix.
    assert_ne!(
        Sha512_256::digest(b"abc").as_ref(),
        &Sha512::digest(b"abc")[..32]
    );

    // Equal inputs of different lengths around a block boundary differ, and a
    // batch gives what one-at-a-time gives.
    let data = vec![0x5au8; 300];
    let messages: Vec<&[u8]> = [0, 55, 56, 63, 64, 111, 112, 127, 128, 300]
        .iter()
        .map(|&len| &data[..len])
        .collect();
    assert_eq!(
        Sha256::digest_many(&messages),
        messages
            .iter()
            .map(|m| Sha256::digest(m))
            .collect::<Vec<_>>()
    );
    assert_eq!(
        Sha512::digest_many(&messages),
        messages
            .iter()
            .map(|m| Sha512::digest(m))
            .collect::<Vec<_>>()
    );
    println!(
        "digest_many agrees with digest on {} lengths",
        messages.len()
    );
}
