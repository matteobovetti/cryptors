//! The known-answer tests that the data in `testdata/` drives: NIST's ACVP
//! vectors for ML-DSA (key generation, signature generation and signature
//! verification, over the external, pre-hash and internal interfaces) and the
//! ML-DSA vectors of Project Wycheproof.
//!
//! The files are a selection, in the text form that [`records`] reads, made by a
//! script kept outside the repository from the JSON files of the two projects;
//! do not edit them by hand. The selection is small enough to run on every
//! `cargo test`. [`every_vector`] runs the same checks over all of them, from a
//! directory named by `MLDSA_VECTORS`, which holds the same two files made with
//! no selection.

use super::algorithm::{
    Expanded, REJECTIONS, message_representative, sign as sign_mu, verify as verify_mu,
};
use super::error::Error;
use super::keypair::{PrivateKey, PublicKey, Signature};
use super::params::{MlDsa44, MlDsa65, MlDsa87, Parameters};
use super::prehash::PreHash;
use super::testutil::{hex, unhex};
use crate::Digest;
use crate::sha2::Sha256;

const ACVP: &str = include_str!("testdata/acvp.txt");
const WYCHEPROOF: &str = include_str!("testdata/wycheproof.txt");
const REJECTION: &str = include_str!("testdata/rejection.txt");

/// One `[kind]` block of a data file: lines of `key = value`.
struct Record<'a> {
    kind: &'a str,
    fields: Vec<(&'a str, &'a str)>,
}

impl<'a> Record<'a> {
    fn get(&self, key: &str) -> Option<&'a str> {
        self.fields.iter().find(|(k, _)| *k == key).map(|(_, v)| *v)
    }

    fn text(&self, key: &str) -> &'a str {
        self.get(key)
            .unwrap_or_else(|| panic!("{} has no {key}", self.kind))
    }

    fn bytes(&self, key: &str) -> Vec<u8> {
        unhex(self.text(key))
    }

    /// The bytes of `key`, or `None` if the record has no such field.
    fn optional_bytes(&self, key: &str) -> Option<Vec<u8>> {
        self.get(key).map(unhex)
    }

    fn flag(&self, key: &str) -> bool {
        self.get(key) == Some("true")
    }

    fn describe(&self) -> String {
        format!(
            "{} {} tc {}",
            self.kind,
            self.get("set").unwrap_or("?"),
            self.get("tc").unwrap_or("?")
        )
    }
}

fn records(text: &str) -> Vec<Record<'_>> {
    let mut out: Vec<Record<'_>> = Vec::new();
    for line in text.lines() {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(kind) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            out.push(Record {
                kind,
                fields: Vec::new(),
            });
        } else {
            let (key, value) = line.split_once(" = ").expect("key = value");
            out.last_mut()
                .expect("a field before any record")
                .fields
                .push((key, value));
        }
    }
    out
}

/// Calls the generic function `$f` with the parameter set that `$set` names.
macro_rules! by_set {
    ($set:expr, $f:ident($($arg:expr),*)) => {
        match $set {
            "ML-DSA-44" => $f::<MlDsa44>($($arg),*),
            "ML-DSA-65" => $f::<MlDsa65>($($arg),*),
            "ML-DSA-87" => $f::<MlDsa87>($($arg),*),
            other => panic!("unknown parameter set {other}"),
        }
    };
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}

/// ACVP's names for the hash functions of HashML-DSA.
fn pre_hash(name: &str) -> PreHash {
    match name {
        "SHA2-224" => PreHash::Sha224,
        "SHA2-256" => PreHash::Sha256,
        "SHA2-384" => PreHash::Sha384,
        "SHA2-512" => PreHash::Sha512,
        "SHA2-512/224" => PreHash::Sha512_224,
        "SHA2-512/256" => PreHash::Sha512_256,
        "SHA3-224" => PreHash::Sha3_224,
        "SHA3-256" => PreHash::Sha3_256,
        "SHA3-384" => PreHash::Sha3_384,
        "SHA3-512" => PreHash::Sha3_512,
        "SHAKE-128" => PreHash::Shake128,
        "SHAKE-256" => PreHash::Shake256,
        other => panic!("unknown hash {other}"),
    }
}

fn acvp_key_gen<P: Parameters>(r: &Record<'_>) {
    let seed: [u8; 32] = r.bytes("seed").try_into().unwrap();
    let key = PrivateKey::<P>::from_seed(&seed);
    let what = r.describe();
    assert_eq!(
        sha256_hex(key.public_key().as_bytes()),
        r.text("pk_sha256"),
        "{what}"
    );
    assert_eq!(
        sha256_hex(&key.expanded().to_expanded_bytes()),
        r.text("sk_sha256"),
        "{what}"
    );
}

/// The message representative that ACVP's parameters stand for, from the
/// hash `tr` of the public key.
fn acvp_mu(r: &Record<'_>, tr: &[u8; 64]) -> [u8; 64] {
    match (r.text("interface"), r.flag("external_mu")) {
        ("internal", true) => r.bytes("mu").try_into().unwrap(),
        // The message is `M'` itself.
        ("internal", false) => message_representative(tr, &[&r.bytes("message")]),
        ("external", false) => {
            let message = r.bytes("message");
            let context = r.bytes("context");
            let mut m_prime = Vec::new();
            match r.text("prehash") {
                "pure" => {
                    m_prime.extend([0, context.len() as u8]);
                    m_prime.extend(&context);
                    m_prime.extend(&message);
                }
                "preHash" => {
                    let hash = pre_hash(r.text("hash"));
                    m_prime.extend([1, context.len() as u8]);
                    m_prime.extend(&context);
                    m_prime.extend(hash.oid());
                    m_prime.extend(hash.digest(&message));
                }
                other => panic!("unknown pre-hash mode {other}"),
            }
            message_representative(tr, &[&m_prime])
        }
        other => panic!("unknown interface {other:?}"),
    }
}

fn acvp_sig_gen<P: Parameters>(r: &Record<'_>) {
    let what = r.describe();
    let expanded = Expanded::<P>::from_expanded_bytes(&r.bytes("sk")).expect(&what);
    let public_key = expanded.public_key_bytes();
    assert_eq!(sha256_hex(&public_key), r.text("pk_sha256"), "{what}");

    let mu = acvp_mu(r, &expanded.tr);
    let rnd: [u8; 32] = if r.flag("deterministic") {
        [0; 32]
    } else {
        r.bytes("rnd").try_into().unwrap()
    };
    let signature = sign_mu(&expanded, &mu, &rnd);
    assert_eq!(sha256_hex(&signature), r.text("signature_sha256"), "{what}");
    assert!(verify_mu::<P>(&public_key, &mu, &signature), "{what}");
}

/// A signature check through the public API, for the interfaces it has.
fn acvp_sig_ver<P: Parameters>(r: &Record<'_>) {
    let what = r.describe();
    let public = PublicKey::<P>::from_bytes(&r.bytes("pk")).expect(&what);
    let expected = r.text("expected") == "pass";
    let result = Signature::<P>::from_bytes(&r.bytes("signature")).and_then(|signature| {
        match (r.text("interface"), r.flag("external_mu")) {
            ("internal", true) => public.verify_mu(&r.bytes("mu").try_into().unwrap(), &signature),
            ("internal", false) => {
                // `M'` as given, which no public function takes.
                let mu = message_representative(&public_tr(&public), &[&r.bytes("message")]);
                public.verify_mu(&mu, &signature)
            }
            ("external", false) => match r.text("prehash") {
                "pure" => public.verify(&r.bytes("message"), &r.bytes("context"), &signature),
                "preHash" => {
                    let hash = pre_hash(r.text("hash"));
                    let digest = hash.digest(&r.bytes("message"));
                    public.verify_prehash(hash, &digest, &r.bytes("context"), &signature)
                }
                other => panic!("unknown pre-hash mode {other}"),
            },
            other => panic!("unknown interface {other:?}"),
        }
    });
    assert_eq!(
        result.is_ok(),
        expected,
        "{what}: {result:?} ({})",
        r.text("reason")
    );
}

fn public_tr<P: Parameters>(public: &PublicKey<P>) -> [u8; 64] {
    super::algorithm::public_key_hash(public.as_bytes())
}

fn wycheproof_sign_seed<P: Parameters>(r: &Record<'_>) {
    let what = r.describe();
    let seed: [u8; 32] = r.bytes("seed").try_into().unwrap();
    let key = PrivateKey::<P>::from_seed(&seed);
    if let Some(hash) = r.get("pk_sha256") {
        assert_eq!(sha256_hex(key.public_key().as_bytes()), hash, "{what}");
    }
    let valid = r.text("result") == "valid";
    let context = r.optional_bytes("ctx").unwrap_or_default();
    let message = r.optional_bytes("msg");
    let rnd: [u8; 32] = r
        .optional_bytes("rnd")
        .map_or([0; 32], |rnd| rnd.try_into().unwrap());

    // The signature of the message and context, and of the representative.
    let mut signatures = Vec::new();
    if let Some(message) = &message {
        match key.public_key().message_representative(message, &context) {
            Ok(mu) => {
                signatures.push(sign_mu(key.expanded(), &mu, &rnd));
                if rnd == [0; 32] {
                    let direct = key.sign_deterministic(message, &context).unwrap();
                    assert_eq!(direct.as_bytes(), signatures[0], "{what}");
                    assert!(
                        key.public_key().verify(message, &context, &direct).is_ok(),
                        "{what}"
                    );
                }
            }
            Err(error) => {
                assert!(!valid, "{what}: {error}");
                assert_eq!(error, Error::ContextTooLong, "{what}");
                assert_eq!(
                    key.sign_deterministic(message, &context),
                    Err(Error::ContextTooLong)
                );
                return;
            }
        }
    }
    if let Some(mu) = r.optional_bytes("mu") {
        let mu: [u8; 64] = mu.try_into().unwrap();
        signatures.push(sign_mu(key.expanded(), &mu, &rnd));
        if rnd == [0; 32] {
            assert_eq!(
                key.sign_mu_deterministic(&mu).as_bytes(),
                signatures.last().unwrap(),
                "{what}"
            );
        }
        assert!(
            verify_mu::<P>(key.public_key().as_bytes(), &mu, signatures.last().unwrap()),
            "{what}"
        );
    }
    assert!(valid, "{what}: signed what should be refused");
    assert!(!signatures.is_empty(), "{what}: neither a message nor mu");
    for signature in &signatures {
        assert_eq!(sha256_hex(signature), r.text("sig_sha256"), "{what}");
    }
}

fn wycheproof_sign_no_seed<P: Parameters>(r: &Record<'_>) {
    let what = r.describe();
    let valid = r.text("result") == "valid";
    let Some(expanded) = Expanded::<P>::from_expanded_bytes(&r.bytes("sk")) else {
        assert!(!valid, "{what}: refused a valid key");
        return;
    };
    if !valid {
        // Only the length and the range of the coefficients of `s1` and `s2` are
        // checked of a key in this form; the rest of what makes one invalid is
        // for the caller to have checked, which is why the API takes seeds.
        return;
    }
    if let Some(hash) = r.get("pk_sha256") {
        assert_eq!(sha256_hex(&expanded.public_key_bytes()), hash, "{what}");
    }
    let context = r.optional_bytes("ctx").unwrap_or_default();
    let rnd: [u8; 32] = r
        .optional_bytes("rnd")
        .map_or([0; 32], |rnd| rnd.try_into().unwrap());
    let mu: [u8; 64] = match (r.optional_bytes("msg"), r.optional_bytes("mu")) {
        (_, Some(mu)) => mu.try_into().unwrap(),
        (Some(message), None) => {
            let mut m_prime = vec![0, context.len() as u8];
            m_prime.extend(&context);
            m_prime.extend(message);
            message_representative(&expanded.tr, &[&m_prime])
        }
        (None, None) => panic!("{what}: neither a message nor mu"),
    };
    let signature = sign_mu(&expanded, &mu, &rnd);
    assert_eq!(sha256_hex(&signature), r.text("sig_sha256"), "{what}");
}

fn wycheproof_verify<P: Parameters>(r: &Record<'_>) {
    let what = r.describe();
    let valid = r.text("result") == "valid";
    let context = r.optional_bytes("ctx").unwrap_or_default();
    let result = PublicKey::<P>::from_bytes(&r.bytes("pk")).and_then(|public| {
        Signature::<P>::from_bytes(&r.bytes("sig"))
            .and_then(|signature| public.verify(&r.bytes("msg"), &context, &signature))
    });
    assert_eq!(
        result.is_ok(),
        valid,
        "{what} ({}): {result:?}",
        r.text("flags")
    );
}

fn run(kind_and_text: &[(&str, &str)]) -> usize {
    let mut count = 0;
    for (name, text) in kind_and_text {
        for r in records(text) {
            let set = r.text("set");
            match r.kind {
                "keygen" => by_set!(set, acvp_key_gen(&r)),
                "siggen" => by_set!(set, acvp_sig_gen(&r)),
                "sigver" => by_set!(set, acvp_sig_ver(&r)),
                "wy-sign-seed" => by_set!(set, wycheproof_sign_seed(&r)),
                "wy-sign-noseed" => by_set!(set, wycheproof_sign_no_seed(&r)),
                "wy-verify" => by_set!(set, wycheproof_verify(&r)),
                other => panic!("{name}: unknown record kind {other}"),
            }
            count += 1;
        }
    }
    count
}

#[test]
fn acvp_selection() {
    let count = run(&[("acvp", ACVP)]);
    // 75 key generations, 12 signature generations and 10 verifications.
    assert_eq!(count, 97);
}

#[test]
fn wycheproof_selection() {
    let count = run(&[("wycheproof", WYCHEPROOF)]);
    assert!(count > 80, "{count}");
}

/// NIST's known answers for the rejection loop of signing: signatures that need
/// attempts to be thrown away, each in one of the four ways, and a number of
/// them. They fix the checks of the loop exactly, because a signature made after
/// the wrong attempts is another signature.
fn rejection_case<P: Parameters>(r: &Record<'_>) -> [usize; 4] {
    let what = format!("{} {} {}", r.text("set"), r.text("kind"), r.text("number"));
    let seed: [u8; 32] = r.bytes("seed").try_into().unwrap();
    let key = PrivateKey::<P>::from_seed(&seed);

    let mut pk_sk = key.public_key().as_bytes().to_vec();
    pk_sk.extend(key.expanded().to_expanded_bytes());
    assert_eq!(sha256_hex(&pk_sk), r.text("key_sha256"), "{what}");

    // The message of the table is `M'`, which is hashed after the key's hash.
    let mu = message_representative(&key.expanded().tr, &[&r.bytes("message")]);
    REJECTIONS.with(|counts| counts.set([0; 4]));
    let signature = sign_mu(key.expanded(), &mu, &[0; 32]);
    let rejected = REJECTIONS.with(|counts| counts.get());
    assert_eq!(sha256_hex(&signature), r.text("sig_sha256"), "{what}");
    assert!(
        verify_mu::<P>(key.public_key().as_bytes(), &mu, &signature),
        "{what}"
    );
    rejected
}

#[test]
fn rejection_loop() {
    for r in records(REJECTION) {
        let rejected = by_set!(r.text("set"), rejection_case(&r));
        let [z, low_bits, ct0, hint] = rejected;
        let what = format!("{} {} {}", r.text("set"), r.text("kind"), r.text("number"));
        match r.text("kind") {
            // Each of these reaches every way to reject that the set has: all
            // four for ML-DSA-44, and the three but `ct0` for the others, which
            // cannot reach it.
            "path" => {
                assert!(z > 0 && low_bits > 0 && hint > 0, "{what}: {rejected:?}");
                if r.text("set") == "ML-DSA-44" {
                    assert!(ct0 > 0, "{what}: {rejected:?}");
                }
            }
            // The number is how many attempts were thrown away, whatever the reason.
            "count" => assert_eq!(
                rejected.iter().sum::<usize>(),
                r.text("number").parse::<usize>().unwrap(),
                "{what}: {rejected:?}"
            ),
            other => panic!("unknown kind {other}"),
        }
    }
}

/// The selection is not all there is: every vector of the two projects, from
/// the directory that `MLDSA_VECTORS` names (the same files, made with no
/// selection): 615 records from ACVP (75 key generations, 360 signature
/// generations and 180 verifications) and 1,129 from Wycheproof (278 signatures
/// from a seed, 220 from an expanded key and 631 verifications).
#[test]
#[ignore = "needs the full vector files: MLDSA_VECTORS=/dir cargo test --release mldsa::conformance -- --ignored --nocapture"]
fn every_vector() {
    // `cargo test -- --ignored` runs every ignored test, whether or not the files
    // are there.
    let Ok(dir) = std::env::var("MLDSA_VECTORS") else {
        println!("skipped: MLDSA_VECTORS does not name a directory");
        return;
    };
    let acvp = std::fs::read_to_string(format!("{dir}/acvp.txt")).unwrap();
    let wycheproof = std::fs::read_to_string(format!("{dir}/wycheproof.txt")).unwrap();
    let count = run(&[("acvp", &acvp), ("wycheproof", &wycheproof)]);
    println!("{count} records");
}

#[test]
fn parser() {
    let text = "# a comment\n\n[kind]\na = 1\nb = two words\n\n[other]\nc = \n";
    let all = records(text);
    assert_eq!(all.len(), 2);
    assert_eq!(all[0].kind, "kind");
    assert_eq!(all[0].get("a"), Some("1"));
    assert_eq!(all[0].get("b"), Some("two words"));
    assert_eq!(all[0].get("missing"), None);
    assert_eq!(all[1].get("c"), Some(""));
}
