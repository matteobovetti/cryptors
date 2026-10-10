//! HKDF turning the shared secret of an ECDH exchange into session keys, as a
//! protocol does after a key agreement, once both sides have checked that the
//! derivation is the standard one.
//!
//! ```sh
//! cargo run --release --example hkdf
//! ```
//!
//! The exchange needs a source of secure random bytes, and the standard
//! library has none that is stable, so this reads `/dev/urandom`, which Unix
//! systems have. On a platform without it, this example stops with an error
//! after the first check; supply any other `io::Read` of random bytes there.

use cryptors::ecdh::{PrivateKey, PublicKey, X25519};
use cryptors::hkdf::Hkdf;
use cryptors::sha2::Sha256;
use std::error::Error;
use std::fs::File;

/// The two keys of a session: one for each direction.
#[derive(PartialEq, Eq)]
struct SessionKeys {
    client_to_server: [u8; 32],
    server_to_client: [u8; 32],
}

/// Derives the session keys from an X25519 shared secret.
///
/// There is no salt that both sides agreed on before the exchange, so there is
/// none. Both public keys go into each `info`, as RFC 7748 (section 6.1)
/// recommends, and so does what the key is for: the two directions get
/// independent keys.
fn session_keys(
    secret: &[u8],
    client: &PublicKey<X25519>,
    server: &PublicKey<X25519>,
) -> Result<SessionKeys, cryptors::hkdf::Error> {
    let hkdf = Hkdf::<Sha256>::extract(&[], secret);
    let info = |label: &[u8]| [label, client.as_bytes(), server.as_bytes()].concat();

    let mut keys = SessionKeys {
        client_to_server: [0; 32],
        server_to_client: [0; 32],
    };
    hkdf.expand(
        &info(b"example client to server"),
        &mut keys.client_to_server,
    )?;
    hkdf.expand(
        &info(b"example server to client"),
        &mut keys.server_to_client,
    )?;
    Ok(keys)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn main() -> Result<(), Box<dyn Error>> {
    // RFC 5869, Appendix A.1, so that what follows is known to be HKDF.
    let salt: Vec<u8> = (0x00..=0x0c).collect();
    let info: Vec<u8> = (0xf0..=0xf9).collect();
    let mut okm = [0; 42];
    Hkdf::<Sha256>::derive(&salt, &[0x0b; 22], &info, &mut okm)?;
    assert_eq!(
        hex(&okm),
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
    );
    println!("RFC 5869 A.1     {}", hex(&okm));

    // The client and the server make a key each and swap the public halves.
    let mut rng = File::open("/dev/urandom")?;
    let client = PrivateKey::<X25519>::generate(&mut rng)?;
    let server = PrivateKey::<X25519>::generate(&mut rng)?;
    let (client_public, server_public) = (client.public_key(), server.public_key());

    // Each side derives the session keys from its own copy of the secret.
    let at_client = session_keys(
        client.diffie_hellman(server_public)?.as_bytes(),
        client_public,
        server_public,
    )?;
    let at_server = session_keys(
        server.diffie_hellman(client_public)?.as_bytes(),
        client_public,
        server_public,
    )?;
    assert!(at_client == at_server, "the two sides disagree");
    assert_ne!(at_client.client_to_server, at_client.server_to_client);

    // A real program would use the keys, not print them; this shows the start
    // of each to show that the two directions differ.
    println!(
        "client to server {}...",
        hex(&at_client.client_to_server[..8])
    );
    println!(
        "server to client {}...",
        hex(&at_client.server_to_client[..8])
    );
    Ok(())
}
