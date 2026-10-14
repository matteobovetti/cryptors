//! The operating system's random number generator: bytes for a key, a token for
//! a link, a uniform number for a draw, and a source of randomness for the keys
//! of the other modules.
//!
//! ```sh
//! cargo run --release --example rand
//! ```
//!
//! Everything here is random, so the output differs from run to run; what does
//! not change is what the program checks about it.

use cryptors::ecdh::{PrivateKey, X25519};
use cryptors::rand::{self, Reader};
use std::error::Error;
use std::io;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Shuffles `items` with Fisher-Yates, which is uniform only if each swap
/// partner is: `below(i + 1)` is, where `random % (i + 1)` is not.
fn shuffle<T>(items: &mut [T], rng: &mut impl io::Read) -> io::Result<()> {
    for i in (1..items.len()).rev() {
        let j = rand::below(rng, i as u64 + 1)? as usize;
        items.swap(i, j);
    }
    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    // A 256-bit key, for AES-256 or HMAC. `fill` has no error to handle: if the
    // system cannot give random bytes, it panics.
    let mut key = [0u8; 32];
    rand::fill(&mut key);
    assert_ne!(key, [0; 32]);
    println!("key                   {}", hex(&key));

    // A token for a reset link or an API key: 26 characters of the RFC 4648
    // base32 alphabet, 130 bits.
    for _ in 0..3 {
        let token = rand::text();
        assert_eq!(token.len(), 26);
        assert!(
            token
                .bytes()
                .all(|b| b.is_ascii_uppercase() || (b'2'..=b'7').contains(&b))
        );
        println!("token                 {token}");
    }

    // A die: a number below 6, with no bias. Sixty thousand rolls, each face
    // about ten thousand times (a standard deviation of 91).
    let mut faces = [0u32; 6];
    for _ in 0..60_000 {
        faces[rand::below(&mut Reader, 6)? as usize] += 1;
    }
    for (face, &count) in faces.iter().enumerate() {
        assert!(count.abs_diff(10_000) < 550, "face {}: {count}", face + 1);
    }
    println!("sixty thousand rolls  {faces:?}");

    // A shuffled deck: all 52 cards are still there, in an order that no one
    // can predict (there are about 2^226 of them).
    let mut deck: Vec<u8> = (0..52).collect();
    shuffle(&mut deck, &mut Reader)?;
    let mut sorted = deck.clone();
    sorted.sort_unstable();
    assert_eq!(sorted, (0..52).collect::<Vec<u8>>());
    println!("deck                  {deck:?}");

    // `Reader` is what the keys of the crate take as their source of
    // randomness. Two parties agree on a secret from keys made with it.
    let alice = PrivateKey::<X25519>::generate(&mut Reader)?;
    let bob = PrivateKey::<X25519>::generate(&mut Reader)?;
    let secret = alice.diffie_hellman(bob.public_key())?;
    assert_eq!(
        secret.as_bytes(),
        bob.diffie_hellman(alice.public_key())?.as_bytes()
    );
    println!(
        "shared secret         {}... (two X25519 keys from Reader)",
        hex(&secret.as_bytes()[..8])
    );

    // The functions that take a reader take any reader, so a test can give them
    // fixed bytes and get the same answer every time: here 0xff is refused as
    // above 5 (the first byte is masked down to the three bits that 5 needs, and
    // 7 is not below 6), and 0x04 is not.
    let mut script: &[u8] = &[0xff, 0x04];
    assert_eq!(rand::below(&mut script, 6)?, 4);
    println!("fixed bytes           ff 04 below 6 -> 4");

    // A source that runs out is an error, not a short answer or a hang.
    let error = rand::below(&mut io::empty(), 6).unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
    println!("empty source          {error}");
    Ok(())
}
