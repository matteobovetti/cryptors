//! A complete ECDH exchange on each of the four curves, between two parties
//! that each generate their own key.
//!
//! ```sh
//! cargo run --release --example ecdh
//! ```
//!
//! Key generation needs a source of secure random bytes, and the standard
//! library has none that is stable, so this reads `/dev/urandom`, which Unix
//! systems have. On a platform without it, this example stops with an error at
//! the first line; supply any other `io::Read` of random bytes there.

use cryptors::ecdh::{Curve, P256, P384, P521, PrivateKey, PublicKey, X25519};
use std::error::Error;
use std::fs::File;
use std::io;

/// Alice and Bob make a key each, send each other the public half as bytes,
/// and compute the secret.
fn exchange<C: Curve>(rng: &mut impl io::Read) -> Result<(), Box<dyn Error>> {
    let alice = PrivateKey::<C>::generate(rng)?;
    let bob = PrivateKey::<C>::generate(rng)?;

    // What goes over the wire is bytes. Receiving them is where an invalid
    // public key is refused.
    let sent_to_bob = alice.public_key().as_bytes().to_vec();
    let sent_to_alice = bob.public_key().as_bytes().to_vec();
    let alices_public = PublicKey::<C>::from_bytes(&sent_to_bob)?;
    let bobs_public = PublicKey::<C>::from_bytes(&sent_to_alice)?;

    let alices_secret = alice.diffie_hellman(&bobs_public)?;
    let bobs_secret = bob.diffie_hellman(&alices_public)?;
    assert_eq!(alices_secret, bobs_secret, "the two sides disagree");

    // A real program would feed the secret to a key derivation function, not
    // print it; this shows the start of it to show that the two sides got the
    // same bytes.
    let start: String = alices_secret.as_bytes()[..8]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    println!(
        "{:<7} public key {:3} bytes, shared secret {:2} bytes, starting {start}",
        C::NAME,
        alice.public_key().as_bytes().len(),
        alices_secret.as_bytes().len(),
    );
    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    let mut rng = File::open("/dev/urandom")?;
    exchange::<P256>(&mut rng)?;
    exchange::<P384>(&mut rng)?;
    exchange::<P521>(&mut rng)?;
    exchange::<X25519>(&mut rng)?;
    Ok(())
}
