//! Storing a password with PBKDF2 and checking it at the next login: a random
//! salt, a high iteration count, and a record that holds everything the check
//! needs, so that the count can be raised later without locking anyone out.
//!
//! ```sh
//! cargo run --release --example pbkdf2
//! ```
//!
//! The salt is 16 random bytes, and the standard library has no source of them
//! that is stable, so this reads `/dev/urandom`, which Unix systems have. On a
//! platform without it, this example stops with an error after the first check;
//! supply any other `io::Read` of random bytes there.

use cryptors::pbkdf2;
use cryptors::sha2::Sha256;
use std::error::Error;
use std::fs::File;
use std::io::Read;
use std::time::Instant;

/// OWASP's guidance for HMAC-SHA-256 at the time of writing. Raise it as
/// hardware gets faster; it is stored with each record, so old records still
/// check.
const ITERATIONS: u32 = 600_000;

/// What is kept for a user: never the password, but all that is needed to
/// derive the same key from it again.
struct Record {
    iterations: u32,
    salt: [u8; 16],
    key: [u8; 32],
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Derives the key for storage, with a new salt.
fn enroll(password: &str, rng: &mut impl Read) -> Result<Record, Box<dyn Error>> {
    let mut salt = [0; 16];
    rng.read_exact(&mut salt)?;
    let mut key = [0; 32];
    pbkdf2::derive::<Sha256>(password.as_bytes(), &salt, ITERATIONS, &mut key)?;
    Ok(Record {
        iterations: ITERATIONS,
        salt,
        key,
    })
}

/// Derives the key again from the record's salt and count, and compares it with
/// the stored one. The comparison looks at every byte, so that how long it takes
/// does not tell how many were right.
fn check(password: &str, record: &Record) -> Result<bool, pbkdf2::Error> {
    let mut key = [0; 32];
    pbkdf2::derive::<Sha256>(
        password.as_bytes(),
        &record.salt,
        record.iterations,
        &mut key,
    )?;
    let differences = key
        .iter()
        .zip(&record.key)
        .fold(0, |acc, (a, b)| acc | (a ^ b));
    Ok(std::hint::black_box(differences) == 0)
}

fn main() -> Result<(), Box<dyn Error>> {
    // RFC 7914, section 11: 1 iteration of HMAC-SHA-256, so that what follows
    // is known to be PBKDF2.
    let mut key = [0; 64];
    pbkdf2::derive::<Sha256>(b"passwd", b"salt", 1, &mut key)?;
    assert_eq!(
        hex(&key),
        "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc\
         49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783"
    );
    println!("RFC 7914 section 11   {}...", hex(&key[..16]));

    let mut rng = File::open("/dev/urandom")?;
    let start = Instant::now();
    let record = enroll("correct horse battery staple", &mut rng)?;
    println!(
        "enrolled              {} iterations in {:.0?}, salt {}, key {}...",
        record.iterations,
        start.elapsed(),
        hex(&record.salt),
        hex(&record.key[..8])
    );

    // The right password checks; a wrong one, or a near miss, does not.
    assert!(check("correct horse battery staple", &record)?);
    assert!(!check("correct horse battery stapl", &record)?);
    assert!(!check("Correct horse battery staple", &record)?);
    println!("login                 right password accepted, two wrong ones refused");

    // The same password under another salt gives another key, so two users who
    // chose alike cannot be told from their records.
    let other = enroll("correct horse battery staple", &mut rng)?;
    assert_ne!(record.salt, other.salt);
    assert_ne!(record.key, other.key);
    println!(
        "second user           same password, key {}...",
        hex(&other.key[..8])
    );
    Ok(())
}
