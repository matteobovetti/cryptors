//! A complete ECDSA round on each of the four curves: a signer makes a key and
//! signs a message, and a verifier that has only the public key, the message and
//! the signature checks it.
//!
//! ```sh
//! cargo run --release --example ecdsa
//! ```
//!
//! Key generation and the randomized signature need a source of secure random
//! bytes, and the standard library has none that is stable, so this reads
//! `/dev/urandom`, which Unix systems have. On a platform without it, this
//! example stops with an error at the first line; supply any other `io::Read` of
//! random bytes there.

use cryptors::Digest;
use cryptors::ecdsa::{Curve, Error, P224, P256, P384, P521, PrivateKey, PublicKey, Signature};
use cryptors::sha2::{Sha256, Sha384, Sha512};
use std::fs::File;
use std::io;

const MESSAGE: &[u8] = b"pay the bearer of this message ten coins";

/// The signer's side: makes a key, and signs `MESSAGE` with it, once with fresh
/// randomness and once deterministically. What it sends over the wire is bytes: its
/// public key and the DER form of the signature.
fn sign<C: Curve, D: Digest>(rng: &mut impl io::Read) -> io::Result<(Vec<u8>, Vec<u8>)> {
    let key = PrivateKey::<C>::generate(rng)?;

    let signature = key.sign::<D, _>(rng, MESSAGE)?;
    // The deterministic form needs no randomness, and gives the same signature
    // every time for the same key and message.
    let first = key.sign_deterministic::<D>(MESSAGE);
    assert_eq!(first, key.sign_deterministic::<D>(MESSAGE));
    // The randomized form gives another one each time, and both are valid.
    assert_ne!(signature, key.sign::<D, _>(rng, MESSAGE)?);

    Ok((key.public_key().as_bytes().to_vec(), signature.to_der()))
}

/// The verifier's side: builds the public key from the bytes it received (where a
/// key that is not on the curve is refused), parses the signature (where one that
/// is not exactly a DER signature is refused), and checks it.
fn verify<C: Curve, D: Digest>(public: &[u8], der: &[u8], message: &[u8]) -> Result<(), Error> {
    let public = PublicKey::<C>::from_bytes(public)?;
    let signature = Signature::<C>::from_der(der)?;
    public.verify::<D>(message, &signature)
}

fn round<C: Curve, D: Digest>(rng: &mut impl io::Read) -> io::Result<()> {
    let (public, der) = sign::<C, D>(rng)?;

    assert_eq!(verify::<C, D>(&public, &der, MESSAGE), Ok(()));
    // A different message does not verify under the same signature, and neither
    // does a signature with a single bit changed.
    let mut changed = MESSAGE.to_vec();
    changed[0] ^= 1;
    assert_eq!(
        verify::<C, D>(&public, &der, &changed),
        Err(Error::VerificationFailed)
    );
    let mut forged = der.clone();
    *forged.last_mut().unwrap() ^= 1;
    assert!(verify::<C, D>(&public, &forged, MESSAGE).is_err());

    println!(
        "{:<6} public key {:3} bytes, DER signature {:3} bytes, {}-bit hash: verifies, and a changed message does not",
        C::NAME,
        public.len(),
        der.len(),
        D::OUTPUT_LEN * 8,
    );
    Ok(())
}

fn main() -> io::Result<()> {
    let mut rng = File::open("/dev/urandom")?;
    // The hash is the caller's choice. These are the pairs of a curve and the
    // SHA-2 function whose strength matches it.
    round::<P224, Sha256>(&mut rng)?;
    round::<P256, Sha256>(&mut rng)?;
    round::<P384, Sha384>(&mut rng)?;
    round::<P521, Sha512>(&mut rng)?;
    Ok(())
}
