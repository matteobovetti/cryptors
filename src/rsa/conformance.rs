//! The known-answer tests that the data in `testdata/` drives: Project
//! Wycheproof's RSA vectors, RSA Laboratories' PKCS #1 vectors as Go ships them,
//! the ciphertexts and signatures that OpenSSL makes, and c2sp.org/det-keygen's
//! vectors for key generation.
//!
//! The files are in the text form that [`records`] reads, made by scripts kept
//! outside the repository; do not edit them by hand. The selection of
//! Wycheproof's vectors is small enough to run on every `cargo test`.
//! [`every_vector`] runs the same checks over all of them, from a directory named
//! by `RSA_VECTORS` that holds `wycheproof_full.txt`.

use super::error::Error;
use super::keypair::{PrivateKey, PublicKey, SaltLength};
use super::testutil::{Drbg, Record, Script, hex, private_key, records, unhex};
use crate::md5::Md5;
use crate::sha1::Sha1;
use crate::sha2::{Sha224, Sha256, Sha384, Sha512, Sha512_224, Sha512_256};

const WYCHEPROOF: &str = include_str!("testdata/wycheproof.txt");
const RSALABS: &str = include_str!("testdata/rsalabs.txt");
const INTEROP: &str = include_str!("testdata/interop.txt");
const KEYGEN: &str = include_str!("testdata/keygen.txt");

/// Runs `$body` with the type `$h` set to the hash that `$name` names.
macro_rules! with_hash {
    ($name:expr, $h:ident => $body:expr) => {
        match $name {
            "MD5" => {
                type $h = Md5;
                $body
            }
            "SHA-1" => {
                type $h = Sha1;
                $body
            }
            "SHA-224" => {
                type $h = Sha224;
                $body
            }
            "SHA-256" => {
                type $h = Sha256;
                $body
            }
            "SHA-384" => {
                type $h = Sha384;
                $body
            }
            "SHA-512" => {
                type $h = Sha512;
                $body
            }
            "SHA-512/224" => {
                type $h = Sha512_224;
                $body
            }
            "SHA-512/256" => {
                type $h = Sha512_256;
                $body
            }
            other => panic!("unknown hash {other}"),
        }
    };
}

/// How many vectors of each kind a run checked, so that a file that stops
/// matching what the code reads is noticed instead of passing for nothing.
#[derive(Default, Debug)]
struct Counts {
    oaep: usize,
    pkcs1_decrypt: usize,
    pkcs1_sign: usize,
    pkcs1_verify: usize,
    pss: usize,
    /// Groups whose key the module refuses.
    refused_keys: usize,
}

/// The vectors of one scheme: the tests are split by it so that the harness runs
/// them side by side.
#[derive(Clone, Copy, PartialEq)]
enum Scheme {
    Oaep,
    Pkcs1Decrypt,
    Pkcs1Sign,
    Pkcs1Verify,
    Pss,
}

impl Scheme {
    const ALL: [Scheme; 5] = [
        Scheme::Oaep,
        Scheme::Pkcs1Decrypt,
        Scheme::Pkcs1Sign,
        Scheme::Pkcs1Verify,
        Scheme::Pss,
    ];

    fn prefix(self) -> &'static str {
        match self {
            Scheme::Oaep => "oaep-",
            Scheme::Pkcs1Decrypt => "pkcs1-decrypt-",
            Scheme::Pkcs1Sign => "pkcs1-sign-",
            Scheme::Pkcs1Verify => "pkcs1-verify-",
            Scheme::Pss => "pss-",
        }
    }
}

fn public_key(r: &Record<'_>) -> Option<PublicKey> {
    let exponent = u32::try_from(r.exponent()).ok()?;
    PublicKey::build(&r.bytes("n"), exponent, 0).ok()
}

fn describe(r: &Record<'_>, file: &str) -> String {
    format!("{file} tc {} ({})", r.text("tc"), r.text("flags"))
}

/// Runs the vectors of Project Wycheproof in `text`.
///
/// What each result means for this implementation: "valid" has to work, and
/// "invalid" has to be refused. The "acceptable" ones are the cases where a
/// correct implementation may go either way, and this one goes one way: an OAEP
/// ciphertext that is the encryption of a small number decrypts (it has the
/// length of the modulus, which is all RFC 8017 asks), a v1.5 signature without
/// the NULL of the algorithm identifier is refused (the block is rebuilt and
/// compared), and a signature by a small or weak key is made, since the module
/// is asked to.
fn check_wycheproof(text: &str, scheme: Scheme) -> Counts {
    let mut counts = Counts::default();
    let records = records(text);
    let mut private: Option<PrivateKey> = None;
    let mut public: Option<PublicKey> = None;
    let mut group: Option<&Record<'_>> = None;
    for r in records
        .iter()
        .filter(|r| r.kind.starts_with(scheme.prefix()))
    {
        match r.kind {
            "oaep-group" | "pkcs1-decrypt-group" | "pkcs1-sign-group" => {
                private = private_key(r);
                group = Some(r);
                if private.is_none() {
                    counts.refused_keys += 1;
                }
            }
            "pkcs1-verify-group" | "pss-group" => {
                public = public_key(r);
                group = Some(r);
                if public.is_none() {
                    counts.refused_keys += 1;
                }
            }
            "oaep-test" => {
                let g = group.unwrap();
                let Some(key) = &private else { continue };
                let what = describe(r, g.text("file"));
                let (ct, label) = (r.bytes("ct"), r.bytes("label"));
                let got = with_hash!(g.text("sha"), D => with_hash!(g.text("mgf_sha"), M =>
                    key.decrypt_oaep_mgf1::<D, M>(&ct, &label)));
                match r.text("result") {
                    // The acceptable ones are ciphertexts of a small integer, which
                    // are `k` bytes long all the same and decrypt.
                    "valid" | "acceptable" => assert_eq!(got, Ok(r.bytes("msg")), "{what}"),
                    _ => assert_eq!(got, Err(Error::Decryption), "{what}"),
                }
                counts.oaep += 1;
            }
            "pkcs1-decrypt-test" => {
                let g = group.unwrap();
                let Some(key) = &private else { continue };
                let what = describe(r, g.text("file"));
                let ct = r.bytes("ct");
                let got = key.decrypt_pkcs1v15(&ct);
                let mut session = [0xa5u8; 7];
                let session_got = key.decrypt_pkcs1v15_session_key(&ct, &mut session);
                match r.text("result") {
                    "valid" => {
                        let msg = r.bytes("msg");
                        assert_eq!(got, Ok(msg.clone()), "{what}");
                        // The session key function copies a message of its length
                        // and otherwise leaves the key alone.
                        assert_eq!(session_got, Ok(()), "{what}");
                        if msg.len() == session.len() {
                            assert_eq!(session[..], msg[..], "{what}");
                        } else {
                            assert_eq!(session, [0xa5; 7], "{what}");
                        }
                    }
                    _ => {
                        assert_eq!(got, Err(Error::Decryption), "{what}");
                        // A bad padding is not reported by the session key function,
                        // but a bad ciphertext is, and the key is left alone.
                        assert_eq!(session, [0xa5; 7], "{what}");
                    }
                }
                counts.pkcs1_decrypt += 1;
            }
            "pkcs1-sign-test" => {
                let g = group.unwrap();
                let Some(key) = &private else { continue };
                let what = describe(r, g.text("file"));
                let signature =
                    with_hash!(g.text("sha"), D => key.sign_pkcs1v15::<D>(&r.bytes("msg")));
                assert_eq!(
                    signature.map(|s| hex(&s)),
                    Ok(r.text("sig").to_string()),
                    "{what}"
                );
                counts.pkcs1_sign += 1;
            }
            "pkcs1-verify-test" => {
                let g = group.unwrap();
                if g.text("sha").starts_with("SHA3") {
                    continue;
                }
                let Some(key) = &public else { continue };
                let what = describe(r, g.text("file"));
                let (msg, sig) = (r.bytes("msg"), r.bytes("sig"));
                let got = with_hash!(g.text("sha"), D => key.verify_pkcs1v15::<D>(&msg, &sig));
                match r.text("result") {
                    "valid" => assert_eq!(got, Ok(()), "{what}"),
                    _ => assert_eq!(got, Err(Error::VerificationFailed), "{what}"),
                }
                counts.pkcs1_verify += 1;
            }
            "pss-test" => {
                let g = group.unwrap();
                // SHAKE has no `Digest` here, and an MGF1 with another hash than
                // the message's is not offered (nor is it by Go's crypto/rsa).
                if g.text("sha").starts_with("SHA3") || g.text("sha") != g.text("mgf_sha") {
                    continue;
                }
                let Some(key) = &public else { continue };
                let what = describe(r, g.text("file"));
                let (msg, sig) = (r.bytes("msg"), r.bytes("sig"));
                let slen = SaltLength::Len(g.int("slen"));
                let got = with_hash!(g.text("sha"), D => key.verify_pss::<D>(&msg, &sig, slen));
                let auto = with_hash!(g.text("sha"), D => key.verify_pss::<D>(&msg, &sig, SaltLength::Auto));
                match r.text("result") {
                    "valid" => {
                        assert_eq!(got, Ok(()), "{what}");
                        assert_eq!(auto, Ok(()), "{what}");
                    }
                    _ => assert_eq!(got, Err(Error::VerificationFailed), "{what}"),
                }
                counts.pss += 1;
            }
            other => panic!("unknown record {other}"),
        }
    }
    counts
}

/// The sizes of the selection (in the PSS vectors, the ones that use another
/// hash for MGF1 than for the message are left out), so that it cannot shrink
/// unnoticed, and that every key was accepted.
#[test]
fn wycheproof_oaep() {
    let counts = check_wycheproof(WYCHEPROOF, Scheme::Oaep);
    assert_eq!((counts.oaep, counts.refused_keys), (175, 0));
}

#[test]
fn wycheproof_pkcs1_decrypt() {
    let counts = check_wycheproof(WYCHEPROOF, Scheme::Pkcs1Decrypt);
    assert_eq!((counts.pkcs1_decrypt, counts.refused_keys), (58, 0));
}

#[test]
fn wycheproof_pkcs1_sign() {
    let counts = check_wycheproof(WYCHEPROOF, Scheme::Pkcs1Sign);
    assert_eq!((counts.pkcs1_sign, counts.refused_keys), (84, 0));
}

#[test]
fn wycheproof_pkcs1_verify() {
    let counts = check_wycheproof(WYCHEPROOF, Scheme::Pkcs1Verify);
    assert_eq!((counts.pkcs1_verify, counts.refused_keys), (224, 0));
}

#[test]
fn wycheproof_pss() {
    let counts = check_wycheproof(WYCHEPROOF, Scheme::Pss);
    assert_eq!((counts.pss, counts.refused_keys), (218, 0));
}

/// Every vector of Wycheproof, from the directory that `RSA_VECTORS` names.
#[test]
#[ignore = "manual: RSA_VECTORS=<dir with wycheproof_full.txt> cargo test --release rsa::conformance::every_vector -- --ignored"]
fn every_vector() {
    let dir = std::env::var("RSA_VECTORS").expect("RSA_VECTORS names a directory");
    let text = std::fs::read_to_string(format!("{dir}/wycheproof_full.txt")).unwrap();
    for scheme in Scheme::ALL {
        let counts = check_wycheproof(&text, scheme);
        eprintln!("{counts:?}");
        assert_eq!(counts.refused_keys, 0);
    }
}

/// RSA Laboratories' OAEP vectors: the ciphertext of each message under the
/// seed that the vector gives (the random bytes are the only thing left to
/// chance in OAEP), and its decryption.
#[test]
fn oaep_rsa_laboratories() {
    let records = records(RSALABS);
    let mut count = 0;
    for r in records.iter().filter(|r| r.kind == "oaep-key") {
        let key = private_key(r).unwrap();
        for v in records
            .iter()
            .filter(|v| v.kind == "oaep-vector" && v.text("key") == r.text("name"))
        {
            let what = format!("{} {}", r.text("name"), hex(&v.bytes("msg")));
            let encrypted = key
                .public_key()
                .encrypt_oaep::<Sha1, _>(&mut Script(v.bytes("seed")), &v.bytes("msg"), b"")
                .unwrap();
            assert_eq!(hex(&encrypted), v.text("ct"), "{what}");
            let decrypted = key.decrypt_oaep::<Sha1>(&v.bytes("ct"), b"");
            assert_eq!(decrypted, Ok(v.bytes("msg")), "{what}");
            count += 1;
        }
    }
    assert_eq!(count, 4);
}

/// RSA Laboratories' PSS vectors: 60 signatures by ten keys of 1,024 to 1,031
/// bits, 1,536 and 2,048, with SHA-1 and a salt of 20 bytes. The keys of
/// 1,025 to 1,031 bits are the ones for which the encoded message is a byte
/// shorter than the modulus, or has bits to clear. Both directions: the
/// signature verifies, and signing with the vector's salt gives it exactly.
#[test]
fn pss_rsa_laboratories() {
    let records = records(RSALABS);
    let mut count = 0;
    for r in records.iter().filter(|r| r.kind == "pss-key") {
        let key = private_key(r).unwrap();
        for v in records
            .iter()
            .filter(|v| v.kind == "pss-vector" && v.text("key") == r.text("name"))
        {
            let (msg, sig) = (v.bytes("msg"), v.bytes("sig"));
            let what = format!("{} {}", r.text("name"), hex(&msg[..4.min(msg.len())]));
            for salt in [
                SaltLength::Len(20),
                SaltLength::EqualsHash,
                SaltLength::Auto,
            ] {
                assert_eq!(
                    key.public_key().verify_pss::<Sha1>(&msg, &sig, salt),
                    Ok(()),
                    "{what}"
                );
            }
            assert_eq!(
                key.public_key()
                    .verify_pss::<Sha1>(&msg, &sig, SaltLength::Len(19)),
                Err(Error::VerificationFailed),
                "{what}"
            );
            let signed = key
                .sign_pss::<Sha1, _>(&mut Script(v.bytes("salt")), &msg, SaltLength::Len(20))
                .unwrap();
            assert_eq!(signed, sig, "{what}");
            count += 1;
        }
    }
    assert_eq!(count, 60);
}

/// The keys that OpenSSL generated, and what it made with them: OAEP with every
/// hash and label, PKCS #1 v1.5 encryption, v1.5 signatures (which are
/// deterministic, so signing must give the same bytes) and PSS signatures with
/// the salt lengths that protocols use.
#[test]
fn openssl_made() {
    let records = records(INTEROP);
    let key_of = |name: &str| {
        let r = records
            .iter()
            .find(|r| r.kind == "key" && r.text("name") == name)
            .unwrap();
        let key = private_key(r).unwrap_or_else(|| panic!("{name}"));
        assert_eq!(key.public_key().bits(), r.int("bits"), "{name}");
        key
    };
    let mut counts = [0; 4];
    for r in &records {
        match r.kind {
            "key" => {}
            "oaep" => {
                let key = key_of(r.text("key"));
                let (msg, label) = (r.bytes("msg"), r.bytes("label"));
                let got = with_hash!(r.text("hash"), D => with_hash!(r.text("mgf_hash"), M =>
                    key.decrypt_oaep_mgf1::<D, M>(&r.bytes("ct"), &label)));
                assert_eq!(got, Ok(msg), "{} {}", r.text("key"), r.text("hash"));
                counts[0] += 1;
            }
            "pkcs1-encrypt" => {
                let key = key_of(r.text("key"));
                assert_eq!(key.decrypt_pkcs1v15(&r.bytes("ct")), Ok(r.bytes("msg")));
                counts[1] += 1;
            }
            "pkcs1-sign" => {
                let key = key_of(r.text("key"));
                let msg = r.bytes("msg");
                let signature = with_hash!(r.text("hash"), D => key.sign_pkcs1v15::<D>(&msg));
                let what = format!("{} {}", r.text("key"), r.text("hash"));
                assert_eq!(
                    signature.map(|s| hex(&s)),
                    Ok(r.text("sig").to_string()),
                    "{what}"
                );
                let verified = with_hash!(r.text("hash"), D =>
                    key.public_key().verify_pkcs1v15::<D>(&msg, &r.bytes("sig")));
                assert_eq!(verified, Ok(()), "{what}");
                counts[2] += 1;
            }
            "pss" => {
                let key = key_of(r.text("key"));
                let msg = r.bytes("msg");
                let what = format!("{} {} {}", r.text("key"), r.text("hash"), r.text("slen"));
                for salt in [SaltLength::Len(r.int("slen")), SaltLength::Auto] {
                    let verified = with_hash!(r.text("hash"), D =>
                        key.public_key().verify_pss::<D>(&msg, &r.bytes("sig"), salt));
                    assert_eq!(verified, Ok(()), "{what}");
                }
                counts[3] += 1;
            }
            other => panic!("unknown record {other}"),
        }
    }
    assert_eq!(counts, [96, 21, 60, 138]);
}

/// Key generation against the vectors of c2sp.org/det-keygen: the key that comes
/// out of the process when the random bytes are those of an HMAC_DRBG seeded as
/// the vector says. They were made with another implementation (Go's, and
/// OpenSSL has read them), so they pin the order in which the candidates are
/// drawn, which of them are refused, the private exponent modulo
/// `lcm(p - 1, q - 1)`, and that it is the primes of the first and second
/// candidate, not the other way round.
///
/// The keys of 2,048 and 2,064 bits run in three tests, so that the harness runs
/// them side by side (`cargo test rsa::conformance::det_keygen` runs all of them),
/// and the larger ones are in [`det_keygen_large`].
fn det_keygen_part(part: usize) {
    let all = records(KEYGEN);
    let small: Vec<_> = all.iter().filter(|r| r.int("bits") <= 2064).collect();
    assert_eq!(small.len(), 18);
    for r in small.iter().skip(part).step_by(3) {
        check_keygen(r);
    }
}

// The same vectors in three tests, so that the harness runs them side by side.
#[test]
fn det_keygen_1() {
    det_keygen_part(0);
}

#[test]
fn det_keygen_2() {
    det_keygen_part(1);
}

#[test]
fn det_keygen_3() {
    det_keygen_part(2);
}

/// The keys of 3,072, 4,096 and 8,192 bits: the seeds are such that the search is short.
#[test]
fn det_keygen_large() {
    for r in records(KEYGEN).iter().filter(|r| r.int("bits") > 2064) {
        check_keygen(r);
    }
}

fn check_keygen(r: &Record<'_>) {
    let bits = r.int("bits");
    let mut personalization = b"det RSA key gen".to_vec();
    personalization.extend_from_slice(&(bits as u16).to_be_bytes());
    let mut rng = Drbg::new(&r.bytes("seed"), &personalization);
    let key = PrivateKey::generate(&mut rng, bits).unwrap();
    let what = format!("{bits} bits, seed {}", r.text("seed"));
    assert_eq!(
        key.public_key().modulus(),
        unhex_padded(r.text("n"), key.public_key().size()),
        "{what}"
    );
    assert_eq!(key.public_key().exponent() as u64, r.exponent(), "{what}");
    assert_eq!(
        key.d(),
        unhex_padded(r.text("d"), key.public_key().size()),
        "{what}"
    );
    assert_eq!(key.p(), unhex(r.text("p")), "{what}");
    assert_eq!(key.q(), unhex(r.text("q")), "{what}");
}

fn unhex_padded(s: &str, len: usize) -> Vec<u8> {
    let bytes = unhex(s);
    let mut out = vec![0; len - bytes.len()];
    out.extend_from_slice(&bytes);
    out
}
