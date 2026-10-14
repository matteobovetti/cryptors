//! MD5 over RFC 1321's own test suite, then over a batch of messages at once.
//! MD5 is broken for anything that needs collision resistance (signatures,
//! certificates, integrity against an attacker); this is for legacy checksums.
//!
//! ```sh
//! cargo run --release --example md5
//! ```

use cryptors::Digest;
use cryptors::md5::Md5;

fn main() {
    // RFC 1321, appendix A.5: the full test suite.
    let suite: [(&[u8], &str); 7] = [
        (b"", "d41d8cd98f00b204e9800998ecf8427e"),
        (b"a", "0cc175b9c0f1b6a831c399e269772661"),
        (b"abc", "900150983cd24fb0d6963f7d28e17f72"),
        (b"message digest", "f96b697d7cb7938d525a2f31aaf161d0"),
        (
            b"abcdefghijklmnopqrstuvwxyz",
            "c3fcd3d76192e4007dfb496cca67e13b",
        ),
        (
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
            "d174ab98d277d9f5a5611c2c9f419d9f",
        ),
        (
            b"12345678901234567890123456789012345678901234567890123456789012345678901234567890",
            "57edf4a22be3c955ac49da2e2107b67a",
        ),
    ];
    for (message, expected) in suite {
        let hex = Md5::hex_digest(message);
        assert_eq!(hex, expected);
        println!("MD5({:?}) = {hex}", String::from_utf8_lossy(message));
    }

    // The same suite in one call. `digest_many` runs several messages side by
    // side where the CPU has SIMD lanes for it, and must give what hashing
    // them one at a time gives.
    let messages: Vec<&[u8]> = suite.iter().map(|(message, _)| *message).collect();
    let batch = Md5::digest_many(&messages);
    assert_eq!(batch.len(), messages.len());
    for ((message, expected), digest) in suite.iter().zip(&batch) {
        assert_eq!(digest, &Md5::digest(message));
        assert_eq!(
            digest
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>(),
            *expected
        );
    }
    println!(
        "digest_many agrees with digest on all {} messages",
        batch.len()
    );
}
