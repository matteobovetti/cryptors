//! SHA-3 and SHAKE (FIPS 202): the four fixed-output hashes over "abc", the two
//! extendable-output functions at several output lengths, and a batch.
//!
//! ```sh
//! cargo run --release --example sha3
//! ```

use cryptors::sha3;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn main() {
    // FIPS 202: the digests of "abc". The functions take bytes and give a
    // fixed-size array; the `_hex` forms render it.
    assert_eq!(
        sha3::sha3_256_hex(b"abc"),
        "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"
    );
    assert_eq!(
        sha3::sha3_224_hex(b"abc"),
        "e642824c3f8cf24ad09234ee7d3c766fc9a3a5168d0c94ad73b46fdf"
    );
    println!("SHA3-224(\"abc\") = {}", hex(&sha3::sha3_224(b"abc")));
    println!("SHA3-256(\"abc\") = {}", hex(&sha3::sha3_256(b"abc")));
    println!("SHA3-384(\"abc\") = {}", hex(&sha3::sha3_384(b"abc")));
    println!("SHA3-512(\"abc\") = {}", hex(&sha3::sha3_512(b"abc")));

    // The empty message, from FIPS 202's examples.
    assert_eq!(
        sha3::sha3_512_hex(b""),
        "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"
    );

    // SHAKE writes as many bytes as the output buffer holds.
    let mut short = [0u8; 32];
    sha3::shake128(b"", &mut short);
    assert_eq!(
        hex(&short),
        "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26"
    );
    let mut long = [0u8; 64];
    sha3::shake256(b"", &mut long);
    assert_eq!(
        hex(&long),
        "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762fd75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be"
    );

    // Asking for more output extends the stream; it does not change it. The
    // 32 bytes above are the first 32 of any longer SHAKE128 output.
    let mut longer = [0u8; 200];
    sha3::shake128(b"", &mut longer);
    assert_eq!(&longer[..32], &short);
    for len in [1, 16, 168, 169, 500] {
        let output = sha3::shake128_hex(b"abc", len);
        assert_eq!(output.len(), 2 * len);
        println!(
            "SHAKE128(\"abc\", {len:3} bytes) starts {}",
            &output[..output.len().min(16)]
        );
    }

    // A batch gives what one-at-a-time gives, for lengths around the block
    // size of each function (rate: 144, 136, 104 and 72 bytes for SHA-3).
    let data = vec![0xa3u8; 300];
    let messages: Vec<&[u8]> = [0, 71, 72, 103, 104, 135, 136, 143, 144, 300]
        .iter()
        .map(|&len| &data[..len])
        .collect();
    let batch = sha3::sha3_256_many(&messages);
    for (message, digest) in messages.iter().zip(&batch) {
        assert_eq!(digest, &sha3::sha3_256(message));
    }
    let batch = sha3::shake256_many(&messages, 100);
    for (message, output) in messages.iter().zip(&batch) {
        let mut one = [0u8; 100];
        sha3::shake256(message, &mut one);
        assert_eq!(output, &one);
    }
    println!(
        "the *_many functions agree with one-at-a-time on {} lengths",
        messages.len()
    );
}
