//! A sender and a receiver that share a key, with HMAC over each of the
//! crate's eight hashes: the sender tags a message, the receiver checks the
//! tag, and a forged tag or a changed message is refused.
//!
//! ```sh
//! cargo run --release --example hmac
//! ```
//!
//! The key is 32 random bytes, and the standard library has no source of them
//! that is stable, so this reads `/dev/urandom`, which Unix systems have. On a
//! platform without it, this example stops with an error at the first line;
//! supply any other `io::Read` of random bytes there. Before that, it checks one
//! published vector, so a broken build cannot pass for a working one.

use cryptors::Digest;
use cryptors::hmac::{self, Hmac, VerifyError};
use cryptors::md5::Md5;
use cryptors::sha1::Sha1;
use cryptors::sha2::{Sha224, Sha256, Sha384, Sha512, Sha512_224, Sha512_256};
use std::error::Error;
use std::fs::File;
use std::io::Read;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// The sender tags a message; the receiver, with the same key, checks it.
fn exchange<D: Digest>(name: &str, key: &[u8]) -> Result<(), Box<dyn Error>> {
    let message = b"transfer 100 to account 42";

    // The sender keys HMAC once, and can tag as many messages as it likes.
    let sender = Hmac::<D>::new(key);
    let tag = sender.mac(message);

    // What goes over the wire is the message and the tag. The receiver keys its
    // own HMAC with the shared key and checks the pair, in constant time.
    let receiver = Hmac::<D>::new(key);
    receiver.verify(message, tag.as_ref())?;

    // A tag with one bit changed, or a message with one byte changed, is
    // refused.
    let mut forged = tag.as_ref().to_vec();
    forged[0] ^= 1;
    assert_eq!(
        receiver.verify(message, &forged),
        Err(VerifyError::Mismatch)
    );
    assert_eq!(
        receiver.verify(b"transfer 900 to account 42", tag.as_ref()),
        Err(VerifyError::Mismatch)
    );

    // A protocol that sends half the tag checks it with `verify_truncated`.
    let half = &tag.as_ref()[..Hmac::<D>::MIN_TAG_LEN];
    receiver.verify_truncated(message, half)?;

    println!(
        "HMAC-{name:<11} tag {:2} bytes, shortest truncated tag {:2} bytes, starting {}",
        tag.as_ref().len(),
        Hmac::<D>::MIN_TAG_LEN,
        hex(&tag.as_ref()[..8])
    );
    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    // RFC 4231, test case 2, in one call.
    let tag = hmac::hmac::<Sha256>(b"Jefe", b"what do ya want for nothing?");
    assert_eq!(
        hex(&tag),
        "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
    );

    let mut key = [0u8; 32];
    File::open("/dev/urandom")?.read_exact(&mut key)?;
    exchange::<Md5>("MD5", &key)?;
    exchange::<Sha1>("SHA-1", &key)?;
    exchange::<Sha224>("SHA-224", &key)?;
    exchange::<Sha256>("SHA-256", &key)?;
    exchange::<Sha384>("SHA-384", &key)?;
    exchange::<Sha512>("SHA-512", &key)?;
    exchange::<Sha512_224>("SHA-512/224", &key)?;
    exchange::<Sha512_256>("SHA-512/256", &key)?;
    Ok(())
}
