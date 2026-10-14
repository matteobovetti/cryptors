//! AES-128, AES-192 and AES-256 on FIPS 197's example blocks, and what a block
//! cipher is not: encrypting each block of a message on its own (ECB) shows the
//! message's structure through, which is why a mode of operation goes on top.
//!
//! ```sh
//! cargo run --release --example aes
//! ```
//!
//! The key in the ECB part is a fixed demonstration key. A real one is random,
//! and comes from an `io::Read` of random bytes as in `examples/hmac.rs`.

use cryptors::BlockCipher;
use cryptors::aes::{Aes128, Aes192, Aes256};

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
/// decrypts it back, and prints the line. Works for any key size.
fn known_answer<C: BlockCipher>(
    name: &str,
    key: &C::Key,
    plaintext: &C::Block,
    ciphertext: &C::Block,
) {
    let cipher = C::new(key);
    let encrypted = cipher.encrypt_block(plaintext);
    assert_eq!(encrypted.as_ref(), ciphertext.as_ref());
    assert_eq!(
        cipher.decrypt_block(&encrypted).as_ref(),
        plaintext.as_ref()
    );
    println!(
        "{name} ({:2}-byte key): {} -> {}",
        C::KEY_LEN,
        hex(plaintext.as_ref()),
        hex(encrypted.as_ref())
    );
}

fn main() {
    // FIPS 197, appendix C: one plaintext, the key 00 01 02 ... of each size.
    let plaintext: [u8; 16] = unhex("00112233445566778899aabbccddeeff");
    known_answer::<Aes128>(
        "AES-128",
        &unhex("000102030405060708090a0b0c0d0e0f"),
        &plaintext,
        &unhex("69c4e0d86a7b0430d8cdb78070b4c55a"),
    );
    known_answer::<Aes192>(
        "AES-192",
        &unhex("000102030405060708090a0b0c0d0e0f1011121314151617"),
        &plaintext,
        &unhex("dda97ca4864cdfe06eaf70a0ec0d7191"),
    );
    known_answer::<Aes256>(
        "AES-256",
        &unhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"),
        &plaintext,
        &unhex("8ea2b7ca516745bfeafc49904b496089"),
    );

    // FIPS 197, appendix B: the example that walks through every round.
    known_answer::<Aes128>(
        "AES-128",
        &unhex("2b7e151628aed2a6abf7158809cf4f3c"),
        &unhex("3243f6a8885a308d313198a2e0370734"),
        &unhex("3925841d02dc09fbdc118597196a0b32"),
    );

    // ECB: every block is encrypted on its own, so equal blocks give equal
    // blocks. Three blocks of "ATTACK AT DAWN!!", then one of something else.
    let cipher = Aes128::new(b"demonstration-ky");
    let message = b"ATTACK AT DAWN!!ATTACK AT DAWN!!ATTACK AT DAWN!!retreat at dusk.";
    let blocks: Vec<[u8; 16]> = message
        .chunks_exact(16)
        .map(|chunk| cipher.encrypt_block(chunk.try_into().unwrap()))
        .collect();
    for (i, block) in blocks.iter().enumerate() {
        println!("ECB block {i}: {}", hex(block));
    }
    assert_eq!(blocks[0], blocks[1]);
    assert_eq!(blocks[1], blocks[2]);
    assert_ne!(blocks[2], blocks[3]);
    println!("blocks 0, 1 and 2 are equal: an observer learns that the plaintext repeats");

    // And nothing authenticates: an altered ciphertext decrypts to something
    // else, without an error. A mode with authentication (GCM) is what fixes
    // that.
    let mut altered = blocks[3];
    altered[0] ^= 1;
    assert_ne!(
        cipher.decrypt_block(&altered),
        cipher.decrypt_block(&blocks[3])
    );
    assert_eq!(&cipher.decrypt_block(&blocks[3]), &message[48..]);
}
