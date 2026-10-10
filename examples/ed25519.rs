//! Ed25519 from end to end: the first example of RFC 8032, then a key made from
//! random bytes that signs under each of the three schemes, and a verifier that
//! accepts the signatures and refuses a changed message, a changed signature and
//! a wrong context.
//!
//! ```sh
//! cargo run --release --example ed25519
//! ```
//!
//! Key generation needs a source of secure random bytes, and the standard
//! library has none that is stable, so this reads `/dev/urandom`, which Unix
//! systems have. On a platform without it, this example stops with an error at
//! the line that opens it; supply any other `io::Read` of random bytes there.

use cryptors::Digest;
use cryptors::ed25519::{Error, Signature, SigningKey, VerifyingKey};
use cryptors::sha2::Sha512;
use std::fs::File;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Signs a message with `sign`, sends the signature as bytes, and checks that
/// `verify` accepts it and refuses it for a changed message or once one bit of
/// it has changed.
fn round(
    name: &str,
    sign: impl Fn(&[u8]) -> Result<Signature, Error>,
    verify: impl Fn(&[u8], &Signature) -> Result<(), Error>,
) -> Result<(), Box<dyn std::error::Error>> {
    let message = b"a message to sign";
    let sent = sign(message)?.to_bytes();

    // What arrives is bytes.
    let received = Signature::try_from(&sent[..])?;
    verify(message, &received)?;
    assert_eq!(
        verify(b"another message", &received),
        Err(Error::InvalidSignature)
    );
    let mut changed = sent;
    changed[10] ^= 1;
    assert_eq!(
        verify(message, &Signature::from_bytes(&changed)),
        Err(Error::InvalidSignature)
    );

    println!(
        "{name:<10} signature {} bytes, starting {}",
        sent.len(),
        hex(&sent[..8])
    );
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // RFC 8032, section 7.1, test 1: a seed, its public key, and the signature
    // of the empty message, which signing always reproduces.
    let seed = [
        0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c,
        0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae,
        0x7f, 0x60,
    ];
    let rfc = SigningKey::from_seed(&seed);
    assert_eq!(
        hex(rfc.verifying_key().as_bytes()),
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
    );
    assert_eq!(
        hex(&rfc.sign(b"").to_bytes()),
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155\
         5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
    );
    println!("RFC 8032   test 1 reproduced");

    // A key of our own, and its public half as the verifier receives it.
    let mut rng = File::open("/dev/urandom")?;
    let key = SigningKey::generate(&mut rng)?;
    let public = VerifyingKey::from_bytes(&key.verifying_key().to_bytes())?;
    println!("public key {}", hex(public.as_bytes()));

    round("Ed25519", |m| Ok(key.sign(m)), |m, s| public.verify(m, s))?;

    let context = b"cryptors example, v1";
    round(
        "Ed25519ctx",
        |m| key.sign_ctx(m, context),
        |m, s| public.verify_ctx(m, context, s),
    )?;
    // The context is part of what is signed.
    let signature = key.sign_ctx(b"m", context)?;
    assert_eq!(
        public.verify_ctx(b"m", b"cryptors example, v2", &signature),
        Err(Error::InvalidSignature)
    );

    // Ed25519ph signs the SHA-512 digest of the message.
    round(
        "Ed25519ph",
        |m| key.sign_prehashed(&Sha512::digest(m), b""),
        |m, s| public.verify_prehashed(&Sha512::digest(m), b"", s),
    )?;
    Ok(())
}
