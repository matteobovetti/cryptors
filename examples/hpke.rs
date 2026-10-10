//! HPKE on each of the four KEMs and in each of the four modes: a recipient
//! makes a key pair, a sender seals two messages to its public key and exports
//! a secret, and the recipient opens the messages and exports the same secret.
//! First, one vector of RFC 9180 is checked, so that the run also says the
//! code computes what the standard does.
//!
//! ```sh
//! cargo run --release --example hpke
//! ```
//!
//! Every key, every setup and the pre-shared key need random bytes, and the
//! standard library has no secure source of them that is stable, so this
//! reads `/dev/urandom`, which Unix systems have. On a platform without it,
//! this example stops with an error at the first line of `main`; read random
//! bytes from any other source there.

use cryptors::hpke::{Aead, Kdf, Kem, Mode, PrivateKey, RecipientMode, SenderMode, Suite};
use std::error::Error;
use std::fs::File;
use std::io::{self, Read};

/// `n` random bytes from `rng`.
fn random(rng: &mut impl Read, n: usize) -> io::Result<Vec<u8>> {
    let mut bytes = vec![0u8; n];
    rng.read_exact(&mut bytes)?;
    Ok(bytes)
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).expect("hex"))
        .collect()
}

/// RFC 9180 Appendix A.1.1: the Base mode of DHKEM(X25519, HKDF-SHA256),
/// HKDF-SHA256, AES-128-GCM, with the RFC's inputs. Only a test may do this:
/// the published `ikmE` makes the encryption deterministic, which a real
/// sender's must never be.
fn published_vector() -> Result<(), Box<dyn Error>> {
    let suite = Suite::new(Kem::X25519HkdfSha256, Kdf::HkdfSha256, Aead::Aes128Gcm);
    let sk_r = Kem::X25519HkdfSha256.derive_key_pair(&unhex(
        "6db9df30aa07dd42ee5e8181afdb977e538f5e1fec8a06223f33f7013e525037",
    ))?;
    let ikm_e = unhex("7268600d403fce431561aef583ee1613527cff655c1343f29812e66706df3234");
    let info = b"Ode on a Grecian Urn";

    let (enc, mut sender) =
        suite.setup_sender(sk_r.public_key(), info, SenderMode::Base, &ikm_e)?;
    let ct = sender.seal(b"Count-0", b"Beauty is truth, truth beauty")?;
    assert_eq!(
        enc,
        unhex("37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431")
    );
    assert_eq!(
        ct,
        unhex(concat!(
            "f938558b5d72f1a23810b4be2ab4f84331acc02fc97babc53a52ae8218a355a9",
            "6d8770ac83d07bea87e13c512a",
        ))
    );
    let mut recipient = suite.setup_recipient(&enc, &sk_r, info, RecipientMode::Base)?;
    assert_eq!(
        recipient.open(b"Count-0", &ct)?,
        b"Beauty is truth, truth beauty"
    );
    println!("RFC 9180 A.1.1: sealed and opened as published");
    Ok(())
}

/// One sender and one recipient, in `mode`, with keys and entropy from `rng`.
fn exchange(rng: &mut impl Read, suite: Suite, mode: Mode) -> Result<(), Box<dyn Error>> {
    let kem = suite.kem();
    let len = kem.private_key_len();

    // The recipient's key pair, and in the authenticated modes the sender's:
    // DeriveKeyPair works for every KEM, from at least a private key's worth
    // of random bytes.
    let sk_r = kem.derive_key_pair(&random(rng, len)?)?;
    let sk_s: PrivateKey = kem.derive_key_pair(&random(rng, len)?)?;
    let psk = random(rng, 32)?;
    let psk_id = b"the key we agreed on";

    let sender_mode = match mode {
        Mode::Base => SenderMode::Base,
        Mode::Psk => SenderMode::Psk { psk: &psk, psk_id },
        Mode::Auth => SenderMode::Auth { sk_s: &sk_s },
        Mode::AuthPsk => SenderMode::AuthPsk {
            psk: &psk,
            psk_id,
            sk_s: &sk_s,
        },
    };
    let recipient_mode = match mode {
        Mode::Base => RecipientMode::Base,
        Mode::Psk => RecipientMode::Psk { psk: &psk, psk_id },
        Mode::Auth => RecipientMode::Auth {
            pk_s: sk_s.public_key(),
        },
        Mode::AuthPsk => RecipientMode::AuthPsk {
            psk: &psk,
            psk_id,
            pk_s: sk_s.public_key(),
        },
    };

    // The sender: fresh randomness for the setup, then a sequence of messages.
    let info = b"cryptors example v1";
    let (enc, mut sender) =
        suite.setup_sender(sk_r.public_key(), info, sender_mode, &random(rng, len)?)?;
    let first = sender.seal(b"message 1", b"attack at dawn")?;
    let second = sender.seal(b"message 2", b"bring coffee")?;

    // What goes over the wire is `enc` and the ciphertexts. The recipient
    // opens them in the order they were sealed.
    let mut recipient = suite.setup_recipient(&enc, &sk_r, info, recipient_mode)?;
    assert_eq!(recipient.open(b"message 1", &first)?, b"attack at dawn");
    assert_eq!(recipient.open(b"message 2", &second)?, b"bring coffee");
    assert_eq!(
        sender.export(b"reply key", 16)?,
        recipient.export(b"reply key", 16)?,
        "the two sides disagree"
    );

    println!(
        "{:<17} {:<8} enc {:3} bytes, ciphertext {} bytes for a {}-byte message",
        format!("{kem:?}"),
        format!("{mode:?}"),
        enc.len(),
        first.len(),
        b"attack at dawn".len(),
    );
    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    let mut rng = File::open("/dev/urandom")?;
    published_vector()?;
    for (kem, kdf) in [
        (Kem::X25519HkdfSha256, Kdf::HkdfSha256),
        (Kem::P256HkdfSha256, Kdf::HkdfSha256),
        (Kem::P384HkdfSha384, Kdf::HkdfSha384),
        (Kem::P521HkdfSha512, Kdf::HkdfSha512),
    ] {
        for mode in [Mode::Base, Mode::Psk, Mode::Auth, Mode::AuthPsk] {
            exchange(&mut rng, Suite::new(kem, kdf, Aead::Aes256Gcm), mode)?;
        }
    }
    Ok(())
}
