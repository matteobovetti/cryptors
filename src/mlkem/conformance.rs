//! The known-answer tests that the data in `testdata/` drives: NIST's ACVP
//! vectors for ML-KEM (key generation, encapsulation, decapsulation and the
//! checks of keys), the ML-KEM vectors of Project Wycheproof, and the "unlucky"
//! vectors of C2SP's CCTV.
//!
//! The files are a selection, in the text form that [`records`] reads, made by a
//! script kept outside the repository from the JSON and text files of the three
//! projects; do not edit them by hand. The selection is small enough to run on
//! every `cargo test`. [`every_vector`] runs the same checks over all of them,
//! from a directory named by `MLKEM_VECTORS`, which holds the same three files
//! made with no selection.

use super::error::Error;
use super::keypair::{Ciphertext, DecapsulationKey, EncapsulationKey};
use super::params::{MlKem512, MlKem768, MlKem1024, Parameters};
use super::testutil::{draft_key, hex, unhex};
use crate::Digest;
use crate::sha2::Sha256;

const ACVP: &str = include_str!("testdata/acvp.txt");
const WYCHEPROOF: &str = include_str!("testdata/wycheproof.txt");
const CCTV: &str = include_str!("testdata/cctv.txt");

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

    fn flag(&self, key: &str) -> bool {
        match self.text(key) {
            "true" => true,
            "false" => false,
            other => panic!("{other} is not a boolean"),
        }
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
            "ML-KEM-512" => $f::<MlKem512>($($arg),*),
            "ML-KEM-768" => $f::<MlKem768>($($arg),*),
            "ML-KEM-1024" => $f::<MlKem1024>($($arg),*),
            other => panic!("unknown parameter set {other}"),
        }
    };
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}

/// The key that the seed `d || z` makes, checked against the hashes of the
/// encapsulation key and of the expanded decapsulation key, when the record has
/// them.
fn check_key<P: Parameters>(key: &DecapsulationKey<P>, r: &Record<'_>) {
    let what = r.describe();
    if let Some(ek) = r.get("ek_sha256") {
        assert_eq!(sha256_hex(key.encapsulation_key().as_bytes()), ek, "{what}");
    }
    if let Some(dk) = r.get("dk_sha256") {
        assert_eq!(sha256_hex(&key.to_expanded()), dk, "{what}");
    }
}

fn acvp_key_gen<P: Parameters>(r: &Record<'_>) {
    let seed: [u8; 64] = [r.bytes("d"), r.bytes("z")].concat().try_into().unwrap();
    check_key(&DecapsulationKey::<P>::from_seed(&seed), r);
}

fn acvp_encaps<P: Parameters>(r: &Record<'_>) {
    let what = r.describe();
    let ek = EncapsulationKey::<P>::from_bytes(&r.bytes("ek")).expect(&what);
    let m: [u8; 32] = r.bytes("m").try_into().unwrap();
    let (secret, ciphertext) = ek.encapsulate_with(&m);
    assert_eq!(hex(secret.as_bytes()), r.text("k"), "{what}");
    assert_eq!(
        sha256_hex(ciphertext.as_bytes()),
        r.text("c_sha256"),
        "{what}"
    );
}

/// Decapsulation with the expanded key: a good ciphertext gives the secret that
/// was encapsulated, and a modified one gives the one that implicit rejection
/// makes, which the vector has too.
fn acvp_decaps<P: Parameters>(r: &Record<'_>) {
    let what = r.describe();
    let key = DecapsulationKey::<P>::from_expanded(&r.bytes("dk")).expect(&what);
    let ciphertext = Ciphertext::<P>::from_bytes(&r.bytes("c")).expect(&what);
    assert_eq!(
        hex(key.decapsulate(&ciphertext).as_bytes()),
        r.text("k"),
        "{what}"
    );
}

fn acvp_ek_check<P: Parameters>(r: &Record<'_>) {
    let result = EncapsulationKey::<P>::from_bytes(&r.bytes("ek"));
    assert_eq!(result.is_ok(), r.flag("passed"), "{}", r.describe());
}

fn acvp_dk_check<P: Parameters>(r: &Record<'_>) {
    let result = DecapsulationKey::<P>::from_expanded(&r.bytes("dk"));
    assert_eq!(result.is_ok(), r.flag("passed"), "{}", r.describe());
}

fn check_acvp(text: &str) -> usize {
    let all = records(text);
    for r in &all {
        let set = r.text("set");
        match r.kind {
            "keygen" => by_set!(set, acvp_key_gen(r)),
            "encaps" => by_set!(set, acvp_encaps(r)),
            "decaps" => by_set!(set, acvp_decaps(r)),
            "ek-check" => by_set!(set, acvp_ek_check(r)),
            "dk-check" => by_set!(set, acvp_dk_check(r)),
            other => panic!("unknown record {other}"),
        }
    }
    all.len()
}

/// `mlkem_*_test.json`: a key from its seed, and a ciphertext to open with it.
/// A "valid" case has the secret that decapsulation gives, and an "invalid" one
/// a ciphertext of the wrong length.
fn wy_decaps_seed<P: Parameters>(r: &Record<'_>) {
    let what = r.describe();
    let seed: [u8; 64] = r.bytes("seed").try_into().expect(&what);
    let key = DecapsulationKey::<P>::from_seed(&seed);
    check_key(&key, r);

    let ciphertext = Ciphertext::<P>::from_bytes(&r.bytes("c"));
    match r.text("result") {
        "valid" => {
            let ciphertext = ciphertext.expect(&what);
            assert_eq!(
                hex(key.decapsulate(&ciphertext).as_bytes()),
                r.text("k"),
                "{what}"
            );
        }
        "invalid" => assert_eq!(ciphertext.unwrap_err(), Error::InvalidCiphertext, "{what}"),
        other => panic!("{what}: result {other}"),
    }
}

fn wy_key_gen<P: Parameters>(r: &Record<'_>) {
    let seed: [u8; 64] = r.bytes("seed").try_into().unwrap();
    check_key(&DecapsulationKey::<P>::from_seed(&seed), r);
}

/// `mlkem_*_encaps_test.json`: encapsulation with the message given, and keys
/// that must be refused (too long or too short, or with a coefficient that is
/// not below `q`).
fn wy_encaps<P: Parameters>(r: &Record<'_>) {
    let what = r.describe();
    let ek = EncapsulationKey::<P>::from_bytes(&r.bytes("ek"));
    match r.text("result") {
        "valid" => {
            let m: [u8; 32] = r.bytes("m").try_into().expect(&what);
            let (secret, ciphertext) = ek.expect(&what).encapsulate_with(&m);
            assert_eq!(hex(secret.as_bytes()), r.text("k"), "{what}");
            assert_eq!(
                sha256_hex(ciphertext.as_bytes()),
                r.text("c_sha256"),
                "{what}"
            );
        }
        "invalid" => assert_eq!(ek.unwrap_err(), Error::InvalidEncapsulationKey, "{what}"),
        other => panic!("{what}: result {other}"),
    }
}

/// `mlkem_*_semi_expanded_decaps_test.json`: the decapsulation key in the
/// expanded form of FIPS 203, which is checked on the way in (its length, and
/// the hash of the encapsulation key in it), and a ciphertext.
fn wy_decaps_expanded<P: Parameters>(r: &Record<'_>) {
    let what = r.describe();
    let key = DecapsulationKey::<P>::from_expanded(&r.bytes("dk"));
    let ciphertext = Ciphertext::<P>::from_bytes(&r.bytes("c"));
    let flags = r.get("flags").unwrap_or("");
    match r.text("result") {
        "valid" => {
            let (key, ciphertext) = (key.expect(&what), ciphertext.expect(&what));
            assert_eq!(
                hex(key.decapsulate(&ciphertext).as_bytes()),
                r.text("k"),
                "{what}"
            );
        }
        "invalid" if flags.contains("IncorrectCiphertextLength") => {
            key.expect(&what);
            assert_eq!(ciphertext.unwrap_err(), Error::InvalidCiphertext, "{what}");
        }
        "invalid" => {
            assert!(key.is_err(), "{what}: {flags}");
        }
        other => panic!("{what}: result {other}"),
    }
}

fn check_wycheproof(text: &str) -> usize {
    let all = records(text);
    for r in &all {
        let set = r.text("set");
        match r.kind {
            "wy-decaps-seed" => by_set!(set, wy_decaps_seed(r)),
            "wy-keygen" => by_set!(set, wy_key_gen(r)),
            "wy-encaps" => by_set!(set, wy_encaps(r)),
            "wy-decaps-expanded" => by_set!(set, wy_decaps_expanded(r)),
            other => panic!("unknown record {other}"),
        }
    }
    all.len()
}

/// C2SP's "unlucky" vectors: seeds, for the draft of FIPS 203, for which
/// `SampleNTT` has to read more than 575 bytes of SHAKE128 for some entry of
/// the matrix, which a random seed needs once in `2^38`.
fn cctv_unlucky<P: Parameters>(r: &Record<'_>) {
    let what = r.describe();
    let seed: [u8; 64] = [r.bytes("d"), r.bytes("z")].concat().try_into().unwrap();
    let key = draft_key::<P>(&seed);
    check_key(&key, r);

    let m: [u8; 32] = r.bytes("m").try_into().unwrap();
    let (secret, ciphertext) = key.encapsulation_key().encapsulate_with(&m);
    assert_eq!(hex(secret.as_bytes()), r.text("k"), "{what}");
    assert_eq!(
        sha256_hex(ciphertext.as_bytes()),
        r.text("c_sha256"),
        "{what}"
    );
    assert_eq!(key.decapsulate(&ciphertext), secret, "{what}");
}

fn check_cctv(text: &str) -> usize {
    let all = records(text);
    for r in &all {
        match r.kind {
            "unlucky" => by_set!(r.text("set"), cctv_unlucky(r)),
            other => panic!("unknown record {other}"),
        }
    }
    all.len()
}

#[test]
fn acvp_selection() {
    // Every kind of record, for all three sets.
    assert_eq!(check_acvp(ACVP), 54);
}

#[test]
fn wycheproof_selection() {
    assert_eq!(check_wycheproof(WYCHEPROOF), 123);
}

#[test]
fn cctv_unlucky_vectors() {
    assert_eq!(check_cctv(CCTV), 3);
}

/// Every vector, not only the selection that the other tests run. The directory
/// in `MLKEM_VECTORS` holds `acvp.txt`, `wycheproof.txt` and `cctv.txt` as the
/// script that made `testdata/` writes them with no selection.
#[test]
#[ignore = "needs the full vector files: MLKEM_VECTORS=/dir cargo test --release mlkem::conformance -- --ignored --nocapture"]
fn every_vector() {
    // `cargo test -- --ignored` runs every ignored test, whether or not the files
    // are there.
    let Ok(dir) = std::env::var("MLKEM_VECTORS") else {
        println!("skipped: MLKEM_VECTORS does not name a directory");
        return;
    };
    let read = |name: &str| std::fs::read_to_string(format!("{dir}/{name}")).unwrap();
    let acvp = check_acvp(&read("acvp.txt"));
    let wycheproof = check_wycheproof(&read("wycheproof.txt"));
    let cctv = check_cctv(&read("cctv.txt"));
    println!("ACVP {acvp}, Wycheproof {wycheproof}, CCTV {cctv}: all passed");
}
