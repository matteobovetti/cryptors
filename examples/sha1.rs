//! SHA-1 over two of FIPS 180's examples, then over a batch of messages at
//! once. SHA-1 is broken for anything that needs collision resistance (the
//! first collision, SHAttered, was published in 2017); this is for legacy
//! checksums and for protocols that still name it.
//!
//! ```sh
//! cargo run --release --example sha1
//! ```

use cryptors::Digest;
use cryptors::sha1::Sha1;

fn main() {
    // FIPS 180 example: the three bytes "abc".
    let hex = Sha1::hex_digest(b"abc");
    assert_eq!(hex, "a9993e364706816aba3e25717850c26c9cd0d89d");
    println!("SHA-1(\"abc\")        = {hex}");

    // FIPS 180 example: one million 'a'. It is many blocks long, and the
    // padding goes after the last of them.
    let million = vec![b'a'; 1_000_000];
    let hex = Sha1::hex_digest(&million);
    assert_eq!(hex, "34aa973cd4c4daa4f61eeb2bdbad27316534016f");
    println!("SHA-1(1,000,000 'a') = {hex}");

    // Lengths around the padding boundary: the padding is a 0x80 byte, zeros
    // and an 8-byte length, so 55 bytes fit in one block and 56 need two.
    let long = [b'x'; 130];
    let messages: Vec<&[u8]> = (54..=57)
        .map(|len| &long[..len])
        .chain([&b""[..], &b"abc"[..], &long[..]])
        .collect();

    // `digest_many` must give what hashing them one at a time gives.
    let batch = Sha1::digest_many(&messages);
    assert_eq!(batch.len(), messages.len());
    for (message, digest) in messages.iter().zip(&batch) {
        assert_eq!(digest, &Sha1::digest(message));
    }
    println!(
        "digest_many agrees with digest on {} messages of {} to {} bytes",
        batch.len(),
        messages.iter().map(|m| m.len()).min().unwrap(),
        messages.iter().map(|m| m.len()).max().unwrap()
    );
}
