//! A complete ML-KEM key establishment on each of the three parameter sets: a
//! receiver makes a key and sends its encapsulation key, a sender that has only
//! those bytes makes a shared secret and a ciphertext for it, and the receiver
//! finds the same secret in the ciphertext.
//!
//! ```sh
//! cargo run --release --example mlkem
//! ```
//!
//! Key generation and encapsulation need a source of secure random bytes, and the
//! standard library has none that is stable, so this reads `/dev/urandom`, which
//! Unix systems have. On a platform without it, this example stops with an error at
//! the first line; supply any other `io::Read` of random bytes there.

use cryptors::hkdf::Hkdf;
use cryptors::mlkem::{
    Ciphertext, DecapsulationKey, EncapsulationKey, Error, MlKem512, MlKem768, MlKem1024,
    Parameters, SharedSecret,
};
use cryptors::sha2::Sha256;
use std::fs::File;
use std::io;

/// The receiver's first step: makes a decapsulation key, and has the encoding of
/// the encapsulation key to send. What it keeps is the 64-byte seed.
fn receiver_start<P: Parameters>(
    rng: &mut impl io::Read,
) -> io::Result<(DecapsulationKey<P>, Vec<u8>)> {
    let key = DecapsulationKey::<P>::generate(rng)?;

    // The key is its seed: that is what to store, and the same seed gives the
    // same key and the same encapsulation key again.
    let stored = *key.seed();
    assert_eq!(
        DecapsulationKey::<P>::from_seed(&stored).encapsulation_key(),
        key.encapsulation_key()
    );

    let to_send = key.encapsulation_key().as_bytes().to_vec();
    Ok((key, to_send))
}

/// The sender's step: parses the bytes it received, which is where an encapsulation
/// key of the wrong length, or with a coefficient that is not below q, is refused,
/// and makes a secret for it. What it sends back is the ciphertext.
fn sender<P: Parameters>(
    rng: &mut impl io::Read,
    received: &[u8],
) -> Result<(SharedSecret<P>, Vec<u8>), Box<dyn std::error::Error>> {
    let encapsulation_key = EncapsulationKey::<P>::from_bytes(received)?;
    let (secret, ciphertext) = encapsulation_key.encapsulate(rng)?;
    Ok((secret, ciphertext.as_bytes().to_vec()))
}

/// The receiver's last step: reads the ciphertext (a wrong length is refused here)
/// and finds the secret. It cannot fail after that: a ciphertext that is not one
/// of an encapsulation for this key gives a secret all the same, which is not the
/// sender's.
fn receiver_finish<P: Parameters>(
    key: &DecapsulationKey<P>,
    received: &[u8],
) -> Result<SharedSecret<P>, Error> {
    Ok(key.decapsulate(&Ciphertext::<P>::from_bytes(received)?))
}

fn round<P: Parameters>(rng: &mut impl io::Read) -> Result<(), Box<dyn std::error::Error>> {
    let (key, encapsulation_key) = receiver_start::<P>(rng)?;
    let (sender_secret, ciphertext) = sender::<P>(rng, &encapsulation_key)?;
    let receiver_secret = receiver_finish(&key, &ciphertext)?;
    assert_eq!(sender_secret, receiver_secret);

    // A ciphertext with a single bit changed is not refused: the receiver finds a
    // secret, and it is not the sender's.
    let mut changed = ciphertext.clone();
    changed[0] ^= 1;
    let rejected = receiver_finish(&key, &changed)?;
    assert_ne!(rejected, sender_secret);
    // It is the same every time, so the receiver gives nothing away by it.
    assert_eq!(rejected, receiver_finish(&key, &changed)?);

    // Bytes that are not an encapsulation key or a ciphertext are refused.
    assert_eq!(
        sender::<P>(rng, &encapsulation_key[1..])
            .err()
            .map(|e| e.to_string()),
        Some(Error::InvalidEncapsulationKey.to_string())
    );
    let mut unreduced = encapsulation_key.clone();
    unreduced[0] = 0xff;
    unreduced[1] |= 0x0f; // a coefficient of 4095, which is more than q = 3329
    assert!(sender::<P>(rng, &unreduced).is_err());
    assert_eq!(
        receiver_finish(&key, &ciphertext[1..]).err(),
        Some(Error::InvalidCiphertext)
    );

    // The secret is the input of a key derivation function, with what the two sides
    // have said to each other so far: here the encapsulation key and the ciphertext.
    // Both derive the same key.
    let context = [&encapsulation_key[..], &ciphertext[..]].concat();
    let mut session_key = [0u8; 32];
    Hkdf::<Sha256>::derive(&[], sender_secret.as_bytes(), &context, &mut session_key)?;
    let mut receiver_key = [0u8; 32];
    Hkdf::<Sha256>::derive(&[], receiver_secret.as_bytes(), &context, &mut receiver_key)?;
    assert_eq!(session_key, receiver_key);

    println!(
        "{}  encapsulation key {:4} bytes, ciphertext {:4} bytes: both sides find the same secret, and a changed ciphertext does not",
        P::NAME,
        encapsulation_key.len(),
        ciphertext.len(),
    );
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut rng = File::open("/dev/urandom")?;
    round::<MlKem512>(&mut rng)?;
    round::<MlKem768>(&mut rng)?;
    round::<MlKem1024>(&mut rng)?;
    Ok(())
}
