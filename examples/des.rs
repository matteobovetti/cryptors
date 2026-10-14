//! DES and Triple DES (TDEA) on FIPS 81's example and on a few published
//! vectors, with two of the properties that make DES weak. **Both are
//! obsolete**: this crate has them to read data that already exists. Use AES
//! (`examples/aes.rs`) for anything new.
//!
//! ```sh
//! cargo run --release --example des
//! ```

use cryptors::BlockCipher;
use cryptors::des::{Des, TripleDes};

fn unhex<const N: usize>(text: &str) -> [u8; N] {
    assert_eq!(text.len(), 2 * N);
    let mut bytes = [0u8; N];
    for (i, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[2 * i..2 * i + 2], 16).unwrap();
    }
    bytes
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Encrypts `plaintext` under `key`, checks the result against `ciphertext`,
/// decrypts it back, and prints the line.
fn known_answer<C: BlockCipher>(name: &str, key: &C::Key, plaintext: &[u8; 8], ciphertext: &[u8; 8])
where
    C::Block: From<[u8; 8]>,
{
    let cipher = C::new(key);
    let encrypted = cipher.encrypt_block(&(*plaintext).into());
    assert_eq!(encrypted.as_ref(), ciphertext);
    assert_eq!(cipher.decrypt_block(&encrypted).as_ref(), plaintext);
    println!(
        "{name:<4} key {}: {} -> {}",
        hex(key.as_ref()),
        hex(plaintext),
        hex(encrypted.as_ref())
    );
}

fn main() {
    // FIPS 81, the ECB example: the key 0123456789abcdef over "Now is t",
    // "he time " and "for all ".
    let key: [u8; 8] = unhex("0123456789abcdef");
    known_answer::<Des>("DES", &key, b"Now is t", &unhex("3fa40e8a984d4815"));
    known_answer::<Des>("DES", &key, b"he time ", &unhex("6a271787ab8883f9"));
    known_answer::<Des>("DES", &key, b"for all ", &unhex("893d51ec4b563b53"));

    // TDEA with three independent keys (K1 || K2 || K3), 24 bytes.
    known_answer::<TripleDes>(
        "TDEA",
        &unhex("0123456789abcdef23456789abcdef01456789abcdef0123"),
        b"The quic",
        &unhex("1ccf23869d09333e"),
    );

    // Keying option 3, K1 = K2 = K3, makes TDEA a single DES (encrypt, decrypt,
    // encrypt under one key cancels to one encryption), so TDEA can still
    // talk to a system that has only DES.
    let k: [u8; 8] = unhex("133457799bbcdff1");
    let bundle: [u8; 24] = [k, k, k].concat().try_into().unwrap();
    let plaintext: [u8; 8] = unhex("0123456789abcdef");
    assert_eq!(
        TripleDes::new(&bundle).encrypt_block(&plaintext),
        Des::new(&k).encrypt_block(&plaintext)
    );
    println!("TDEA with K1 = K2 = K3 gives what DES gives");

    // Weakness 1, the complementation property: DES(!k, !p) = !DES(k, p). Two
    // chosen plaintexts under one key halve a search over the key space.
    let key = [0u8; 8];
    let plain = [0u8; 8];
    let cipher = Des::new(&key).encrypt_block(&plain);
    let complemented = Des::new(&key.map(|b| !b)).encrypt_block(&plain.map(|b| !b));
    assert_eq!(complemented, cipher.map(|b| !b));
    assert_eq!(hex(&cipher), "8ca64de9c1b123a7");
    println!(
        "complementation: DES(0,0) = {}, DES(!0,!0) = {}",
        hex(&cipher),
        hex(&complemented)
    );

    // Weakness 2, the parity bits: the low bit of each key byte is a parity
    // bit the cipher ignores, so 8 of the 64 key bits do nothing and the key
    // is 56 bits.
    let a = Des::new(&unhex("0123456789abcdef")).encrypt_block(&plain);
    let b = Des::new(&unhex("0022446688aaccee")).encrypt_block(&plain);
    assert_eq!(a, b);
    println!(
        "two keys that differ only in their parity bits encrypt alike: {}",
        hex(&a)
    );
}
