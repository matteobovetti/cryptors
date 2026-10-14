//! RSA end to end: a known answer from RSA Laboratories' test vectors, a key
//! generated here, a secret sent to its holder with OAEP, documents signed with PSS
//! and PKCS #1 v1.5, keys carried as numbers, and what each failure looks like.
//!
//! ```sh
//! cargo run --release --example rsa
//! ```
//!
//! The keys are random and the ciphertexts and PSS signatures are too, so the output
//! differs from run to run; what does not change is what the program checks about
//! it. Generating a key is a search, and takes a moment in a release build and much
//! longer without optimizations (hence `--release`). The random bytes come from the
//! operating system, through [`cryptors::rand::Reader`]; on a platform it does not
//! support, this example stops with an error at the first key.

use cryptors::hmac::Hmac;
use cryptors::rand::Reader;
use cryptors::rsa::{Error, PrivateKey, PublicKey, SaltLength};
use cryptors::sha1::Sha1;
use cryptors::sha2::Sha256;
use std::error::Error as StdError;
use std::io::{self, Read};
use std::time::Instant;

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
        .collect()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// The first key of RSA Laboratories' PKCS #1 test vectors (1,024 bits), and its
/// first OAEP example: the message, the random seed that the example gives, and
/// the ciphertext.
fn known_answer() -> Result<(), Box<dyn StdError>> {
    let key = PrivateKey::from_components(
        &unhex(concat!(
            "a8b3b284af8eb50b387034a860f146c4919f318763cd6c5598c8ae4811a1e0ab",
            "c4c7e0b082d693a5e7fced675cf4668512772c0cbc64a742c6c630f533c8cc72",
            "f62ae833c40bf25842e984bb78bdbf97c0107d55bdb662f5c4e0fab9845cb514",
            "8ef7392dd3aaff93ae1e6b667bb3d4247616d4f5ba10d4cfd226de88d39f16fb"
        )),
        65537,
        &unhex(concat!(
            "53339cfdb79fc8466a655c7316aca85c55fd8f6dd898fdaf119517ef4f52e8fd",
            "8e258df93fee180fa0e4ab29693cd83b152a553d4ac4d1812b8b9fa5af0e7f55",
            "fe7304df41570926f3311f15c4d65a732c483116ee3d3d2d0af3549ad9bf7cbf",
            "b78ad884f84d5beb04724dc7369b31def37d0cf539e9cfcdd3de653729ead5d1"
        )),
        &unhex(concat!(
            "d32737e7267ffe1341b2d5c0d150a81b586fb3132bed2f8d5262864a9cb9f30a",
            "f38be448598d413a172efb802c21acf1c11c520c2f26a471dcad212eac7ca39d"
        )),
        &unhex(concat!(
            "cc8853d1d54da630fac004f471f281c7b8982d8224a490edbeb33d3e3d5cc93c",
            "4765703d1dd791642f1f116a0dd852be2419b2af72bfe9a030e860b0288b5d77"
        )),
    )?;
    let message = unhex("6628194e12073db03ba94cda9ef9532397d50dba79b987004afefe34");
    let ciphertext = unhex(concat!(
        "354fe67b4a126d5d35fe36c777791a3f7ba13def484e2d3908aff722fad468fb",
        "21696de95d0be911c2d3174f8afcc201035f7b6d8e69402de5451618c21a535f",
        "a9d7bfc5b8dd9fc243f8cf927db31322d6e881eaa91a996170e657a05a266426",
        "d98c88003f8477c1227094a0d9fa1e8c4024309ce1ecccb5210035d47ac72e8a"
    ));

    // Decrypting the example's ciphertext gives its message...
    assert_eq!(key.decrypt_oaep::<Sha1>(&ciphertext, b"")?, message);

    // ...and encrypting the message with the example's seed in place of random
    // bytes gives its ciphertext, bit for bit. (Never do this with a seed you chose.)
    let mut seed: &[u8] = &unhex("18b776ea21069d69776a33e96bad48e1dda0a5ef");
    let encrypted = key
        .public_key()
        .encrypt_oaep::<Sha1, _>(&mut seed, &message, b"")?;
    assert_eq!(encrypted, ciphertext);
    println!(
        "RSA Laboratories      OAEP example 1.1 of {} bits: decrypts, and encrypts to the same {} bytes",
        key.public_key().bits(),
        encrypted.len()
    );
    Ok(())
}

/// What the sender has made: the secret, the secret wrapped for the receiver, and a
/// message followed by its tag.
type Sent = ([u8; 32], Vec<u8>, Vec<u8>);

/// Sends a secret to the holder of `receiver`'s public key, which is all the sender
/// has: its numbers. The secret is the key of an HMAC that authenticates what
/// follows.
fn send(modulus: &[u8], exponent: u32, rng: &mut impl io::Read) -> Result<Sent, Box<dyn StdError>> {
    // The numbers are checked here: a modulus that is even, too small or too large,
    // or an exponent that is not odd, is refused.
    let public = PublicKey::new(modulus, exponent)?;

    let mut secret = [0u8; 32];
    rng.read_exact(&mut secret)?;
    // The label binds the ciphertext to its purpose: a ciphertext made for another
    // use of the same key does not decrypt under this one.
    let wrapped = public.encrypt_oaep::<Sha256, _>(rng, &secret, b"example: session key")?;

    let message = b"the money is in the usual place".to_vec();
    let tag = Hmac::<Sha256>::new(&secret).mac(&message).to_vec();
    Ok((secret, wrapped, [message, tag].concat()))
}

fn receive(
    key: &PrivateKey,
    wrapped: &[u8],
    message_and_tag: &[u8],
) -> Result<Vec<u8>, Box<dyn StdError>> {
    let secret = key.decrypt_oaep::<Sha256>(wrapped, b"example: session key")?;
    let (message, tag) = message_and_tag.split_at(message_and_tag.len() - 32);
    Hmac::<Sha256>::new(&secret).verify(message, tag)?;
    Ok(message.to_vec())
}

fn main() -> Result<(), Box<dyn StdError>> {
    known_answer()?;

    let mut rng = Reader;
    let start = Instant::now();
    let key = PrivateKey::generate(&mut rng, 2048)?;
    let public = key.public_key();
    println!(
        "generated             {} bits, e = {}, in {:.0?}; modulus {}...",
        public.bits(),
        public.exponent(),
        start.elapsed(),
        hex(&public.modulus()[..8])
    );

    // The receiver publishes its modulus and exponent, and keeps the rest.
    let (secret, wrapped, message_and_tag) = send(&public.modulus(), public.exponent(), &mut rng)?;
    assert_eq!(wrapped.len(), public.size());
    let received = receive(&key, &wrapped, &message_and_tag)?;
    println!(
        "OAEP + HMAC           {}-byte ciphertext carried the secret {}...; \"{}\"",
        wrapped.len(),
        hex(&secret[..4]),
        String::from_utf8_lossy(&received)
    );

    // Nobody else can open it, and every way for it to fail is one error: a changed
    // ciphertext, another label, another hash, a ciphertext that is not the length of
    // the modulus.
    let mut changed = wrapped.clone();
    changed[100] ^= 1;
    assert_eq!(
        key.decrypt_oaep::<Sha256>(&changed, b"example: session key"),
        Err(Error::Decryption)
    );
    assert_eq!(
        key.decrypt_oaep::<Sha256>(&wrapped, b"another purpose"),
        Err(Error::Decryption)
    );
    assert_eq!(
        key.decrypt_oaep::<Sha1>(&wrapped, b"example: session key"),
        Err(Error::Decryption)
    );
    assert_eq!(
        key.decrypt_oaep::<Sha256>(&wrapped[1..], b"example: session key"),
        Err(Error::Decryption)
    );
    println!(
        "decryption            a changed bit, another label, another hash and a short ciphertext all give the same error"
    );

    // What fits in OAEP: 256 - 2 * 32 - 2 = 190 bytes with SHA-256 and a 2,048-bit key.
    assert!(
        public
            .encrypt_oaep::<Sha256, _>(&mut rng, &[0; 190], b"")
            .is_ok()
    );
    let too_long = public
        .encrypt_oaep::<Sha256, _>(&mut rng, &[0; 191], b"")
        .unwrap_err();
    println!("too long              191 bytes: {too_long}");

    // Signatures. PSS is randomized, with a salt as long as the hash...
    let document = b"I owe you ten euros";
    let signature = key.sign_pss::<Sha256, _>(&mut rng, document, SaltLength::EqualsHash)?;
    let other = key.sign_pss::<Sha256, _>(&mut rng, document, SaltLength::EqualsHash)?;
    assert_ne!(signature, other, "the salt makes each signature different");
    for signature in [&signature, &other] {
        public.verify_pss::<Sha256>(document, signature, SaltLength::EqualsHash)?;
    }
    assert_eq!(
        public.verify_pss::<Sha256>(
            b"I owe you ten thousand euros",
            &signature,
            SaltLength::EqualsHash
        ),
        Err(Error::VerificationFailed)
    );
    println!(
        "PSS                   two signatures of {} bytes of one document, both valid; a changed document is refused",
        signature.len()
    );

    // ...PKCS #1 v1.5 is deterministic, and is what most certificates carry.
    let v15 = key.sign_pkcs1v15::<Sha256>(document)?;
    assert_eq!(v15, key.sign_pkcs1v15::<Sha256>(document)?);
    public.verify_pkcs1v15::<Sha256>(document, &v15)?;
    // A signature of the digest, when the document is hashed elsewhere.
    let digest = <Sha256 as cryptors::Digest>::digest(document);
    assert_eq!(key.sign_pkcs1v15_prehash::<Sha256>(&digest)?, v15);
    // A signature is for one hash: SHA-384 does not verify what SHA-256 signed.
    assert_eq!(
        public.verify_pkcs1v15::<cryptors::sha2::Sha384>(document, &v15),
        Err(Error::VerificationFailed)
    );
    println!(
        "PKCS #1 v1.5          {} bytes, the same every time: {}...",
        v15.len(),
        hex(&v15[..8])
    );

    // The private key as numbers, to store and to load again: loading checks them.
    let restored = PrivateKey::from_components(
        &public.modulus(),
        public.exponent(),
        &key.d(),
        &key.p(),
        &key.q(),
    )?;
    assert!(restored == key);
    assert_eq!(restored.sign_pkcs1v15::<Sha256>(document)?, v15);
    // A key whose numbers do not go together is refused.
    let mut wrong_d = key.d();
    wrong_d[200] ^= 1;
    assert_eq!(
        PrivateKey::from_components(&public.modulus(), 65537, &wrong_d, &key.p(), &key.q()).err(),
        Some(Error::InvalidPrivateKey)
    );
    println!(
        "components            the key restored from n, e, d, p and q signs the same; a wrong d is refused"
    );

    // The old way of sending a session key, PKCS #1 v1.5, with the protection of
    // RFC 3218: start from a random key, let the decryption replace it if the
    // padding is right and the message is the key's length, and carry on either way.
    let mut session = [0u8; 16];
    rng.read_exact(&mut session)?;
    let sent = public.encrypt_pkcs1v15(&mut rng, &session)?;
    let mut recovered = [0u8; 16];
    rng.read_exact(&mut recovered)?;
    key.decrypt_pkcs1v15_session_key(&sent, &mut recovered)?;
    assert_eq!(recovered, session);
    let mut garbage = sent.clone();
    garbage[7] ^= 1;
    let mut fallback = [0x55u8; 16];
    key.decrypt_pkcs1v15_session_key(&garbage, &mut fallback)?;
    assert_eq!(fallback, [0x55; 16]);
    println!(
        "PKCS #1 v1.5 key      a good ciphertext replaces the random key, a bad one leaves it, and no error tells which"
    );
    Ok(())
}
