//! A complete ML-DSA round on each of the three parameter sets: a signer makes a
//! key and signs a message, and a verifier that has only the public key, the
//! message, the context and the signature checks it.
//!
//! ```sh
//! cargo run --release --example mldsa
//! ```
//!
//! Key generation and the hedged signature need a source of secure random bytes,
//! and the standard library has none that is stable, so this reads
//! `/dev/urandom`, which Unix systems have. On a platform without it, this
//! example stops with an error at the first line; supply any other `io::Read` of
//! random bytes there.

use cryptors::mldsa::{
    Error, MlDsa44, MlDsa65, MlDsa87, Parameters, PreHash, PrivateKey, PublicKey, Signature,
};
use std::fs::File;
use std::io;

const MESSAGE: &[u8] = b"pay the bearer of this message ten coins";
const CONTEXT: &[u8] = b"cryptors example, v1";

/// The signer's side: makes a key, and signs `MESSAGE` under `CONTEXT` with it,
/// once with fresh randomness and once deterministically. What it sends over the
/// wire is bytes: its public key and the signature.
fn sign<P: Parameters>(rng: &mut impl io::Read) -> io::Result<(Vec<u8>, Vec<u8>)> {
    let key = PrivateKey::<P>::generate(rng)?;

    let signature = key.sign(rng, MESSAGE, CONTEXT)?;
    // The deterministic form needs no randomness, and gives the same signature
    // every time for the same key, message and context.
    let first = key.sign_deterministic(MESSAGE, CONTEXT).unwrap();
    assert_eq!(first, key.sign_deterministic(MESSAGE, CONTEXT).unwrap());
    // The hedged form gives another one each time, and both are valid.
    assert_ne!(signature, key.sign(rng, MESSAGE, CONTEXT)?);

    // The key is its 32-byte seed: that is what to store, and the same seed
    // gives the same key and the same public key again.
    let stored = *key.seed();
    assert_eq!(
        PrivateKey::<P>::from_seed(&stored).public_key(),
        key.public_key()
    );

    Ok((
        key.public_key().as_bytes().to_vec(),
        signature.as_bytes().to_vec(),
    ))
}

/// The verifier's side: builds the public key and the signature from the bytes it
/// received (where a key or a signature of the wrong length, or a signature
/// whose hint is not encoded as FIPS 204 requires, is refused), and checks it.
fn verify<P: Parameters>(
    public: &[u8],
    signature: &[u8],
    message: &[u8],
    context: &[u8],
) -> Result<(), Error> {
    let public = PublicKey::<P>::from_bytes(public)?;
    let signature = Signature::<P>::from_bytes(signature)?;
    public.verify(message, context, &signature)
}

fn round<P: Parameters>(rng: &mut impl io::Read) -> io::Result<()> {
    let (public, signature) = sign::<P>(rng)?;

    assert_eq!(verify::<P>(&public, &signature, MESSAGE, CONTEXT), Ok(()));
    // A different message, a different context and a signature with a single
    // bit changed do not verify.
    let mut changed = MESSAGE.to_vec();
    changed[0] ^= 1;
    assert_eq!(
        verify::<P>(&public, &signature, &changed, CONTEXT),
        Err(Error::VerificationFailed)
    );
    assert_eq!(
        verify::<P>(&public, &signature, MESSAGE, b"another protocol"),
        Err(Error::VerificationFailed)
    );
    let mut forged = signature.clone();
    forged[0] ^= 1;
    assert!(verify::<P>(&public, &forged, MESSAGE, CONTEXT).is_err());

    println!(
        "{}  public key {:4} bytes, signature {:4} bytes: verifies, and a changed message, context or signature does not",
        P::NAME,
        public.len(),
        signature.len(),
    );
    Ok(())
}

/// HashML-DSA signs the digest of a message, for a signer that is handed a
/// digest and not the message. The function that made the digest is signed
/// with it.
fn prehash<P: Parameters>(rng: &mut impl io::Read) -> io::Result<()> {
    let key = PrivateKey::<P>::generate(rng)?;
    let digest = PreHash::Sha3_512.digest(MESSAGE);
    let signature = key.sign_prehash(rng, PreHash::Sha3_512, &digest, CONTEXT)?;

    let public = key.public_key();
    assert_eq!(
        public.verify_prehash(PreHash::Sha3_512, &digest, CONTEXT, &signature),
        Ok(())
    );
    // It is not a signature of the message itself, nor of a digest made by
    // another function.
    assert!(public.verify(MESSAGE, CONTEXT, &signature).is_err());
    let other = PreHash::Sha512.digest(MESSAGE);
    assert!(
        public
            .verify_prehash(PreHash::Sha512, &other, CONTEXT, &signature)
            .is_err()
    );
    println!("{}  pre-hash signature with SHA3-512: verifies", P::NAME);
    Ok(())
}

fn main() -> io::Result<()> {
    let mut rng = File::open("/dev/urandom")?;
    round::<MlDsa44>(&mut rng)?;
    round::<MlDsa65>(&mut rng)?;
    round::<MlDsa87>(&mut rng)?;
    prehash::<MlDsa65>(&mut rng)?;
    Ok(())
}
