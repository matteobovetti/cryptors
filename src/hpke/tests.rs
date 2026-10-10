//! The tests of HPKE as a whole: the vectors of RFC 9180 and of Go's
//! crypto/hpke, interoperation with Go in both directions, the ways it must
//! fail, and the throughput test. The building blocks have their own, in their
//! files.

use super::context::key_schedule;
use super::vectors::{Accumulated, CFRG, GO_ACCUMULATED, Vector};
use super::*;
use crate::Digest;
use crate::digest::hex;
use crate::sha2::Sha256;
use crate::sha3;

/// The bytes of a hex string, which may be broken over lines. Shared with the
/// tests of the KDF.
pub(super) fn unhex(s: &str) -> Vec<u8> {
    let s: String = s.split_whitespace().collect();
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

/// `len` bytes derived from `label` and `i`: SHA-256(`label` || `i` || `j`)
/// for `j` = 0, 1, ..., each counter as four big-endian bytes, cut to length.
/// Simple enough to reproduce in any language, which is how the values from
/// Go in these tests and in those of the KDF were made.
pub(super) fn stream(label: &[u8], i: u32, len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len + 32);
    for j in 0u32.. {
        if out.len() >= len {
            break;
        }
        let mut input = label.to_vec();
        input.extend_from_slice(&i.to_be_bytes());
        input.extend_from_slice(&j.to_be_bytes());
        out.extend_from_slice(&Sha256::digest(&input));
    }
    out.truncate(len);
    out
}

const ALL_KEMS: [Kem; 4] = [
    Kem::P256HkdfSha256,
    Kem::P384HkdfSha384,
    Kem::P521HkdfSha512,
    Kem::X25519HkdfSha256,
];

const ALL_MODES: [Mode; 4] = [Mode::Base, Mode::Psk, Mode::Auth, Mode::AuthPsk];

/// The mode of a vector's `mode` field.
fn mode_of(id: u8) -> Mode {
    ALL_MODES[usize::from(id)]
}

/// The sender's side of `mode`, from its inputs.
fn sender_mode<'a>(
    mode: Mode,
    psk: &'a [u8],
    psk_id: &'a [u8],
    sk_s: &'a PrivateKey,
) -> SenderMode<'a> {
    match mode {
        Mode::Base => SenderMode::Base,
        Mode::Psk => SenderMode::Psk { psk, psk_id },
        Mode::Auth => SenderMode::Auth { sk_s },
        Mode::AuthPsk => SenderMode::AuthPsk { psk, psk_id, sk_s },
    }
}

/// The recipient's side of `mode`, from its inputs.
fn recipient_mode<'a>(
    mode: Mode,
    psk: &'a [u8],
    psk_id: &'a [u8],
    pk_s: &'a PublicKey,
) -> RecipientMode<'a> {
    match mode {
        Mode::Base => RecipientMode::Base,
        Mode::Psk => RecipientMode::Psk { psk, psk_id },
        Mode::Auth => RecipientMode::Auth { pk_s },
        Mode::AuthPsk => RecipientMode::AuthPsk { psk, psk_id, pk_s },
    }
}

/// `SerializePrivateKey` of the private key `sk_m` of a vector, which the
/// vectors print as `DeriveKeyPair` produced it: for X25519, before the
/// clamping that serializing does.
fn serialized(kem: Kem, sk_m: &str) -> Vec<u8> {
    let mut sk = unhex(sk_m);
    if kem == Kem::X25519HkdfSha256 {
        sk[0] &= 248;
        sk[31] &= 127;
        sk[31] |= 64;
    }
    sk
}

/// Checks a key pair of a vector: `DeriveKeyPair(ikm)` gives the public key
/// and the private key, and the vector's private key deserializes to the same
/// key.
fn check_key_pair(kem: Kem, ikm: &str, sk_m: &str, pk_m: &str, what: &str) -> PrivateKey {
    let derived = kem.derive_key_pair(&unhex(ikm)).unwrap();
    assert_eq!(hex(derived.public_key().as_bytes()), pk_m, "{what}");
    assert_eq!(derived.as_bytes(), serialized(kem, sk_m), "{what}");
    let deserialized = PrivateKey::from_bytes(kem, &unhex(sk_m)).unwrap();
    assert_eq!(deserialized.public_key(), derived.public_key(), "{what}");
    derived
}

/// Runs one vector of RFC 9180's file through the KEM, the key schedule, the
/// contexts of both sides and the single-shot functions.
fn check_vector(v: &Vector) {
    let what = format!(
        "mode {}, KEM {:#06x}, KDF {:#06x}, AEAD {:#06x}",
        v.mode, v.kem_id, v.kdf_id, v.aead_id
    );
    let suite = Suite::from_ids(v.kem_id, v.kdf_id, v.aead_id).unwrap();
    let kem = suite.kem();
    let mode = mode_of(v.mode);
    let (info, psk, psk_id) = (unhex(v.info), unhex(v.psk), unhex(v.psk_id));
    let ikm_e = unhex(v.ikm_e);

    let sk_r = check_key_pair(kem, v.ikm_r, v.sk_rm, v.pk_rm, &what);
    // Outside the authenticated modes the sender key is unused; any will do.
    let sk_s = if v.ikm_s.is_empty() {
        sk_r.clone()
    } else {
        check_key_pair(kem, v.ikm_s, v.sk_sm, v.pk_sm, &what)
    };
    let authenticated = matches!(mode, Mode::Auth | Mode::AuthPsk);

    // The KEM, from both sides.
    let (shared_secret, enc) = kem::encap(
        kem,
        sk_r.public_key(),
        authenticated.then_some(&sk_s),
        &ikm_e,
    )
    .unwrap();
    assert_eq!(hex(&enc), v.enc, "{what}");
    assert_eq!(hex(shared_secret.as_bytes()), v.shared_secret, "{what}");
    let pk_s = authenticated.then_some(sk_s.public_key());
    let decapsulated = kem::decap(kem, &enc, &sk_r, pk_s).unwrap();
    assert_eq!(decapsulated.as_bytes(), shared_secret.as_bytes(), "{what}");

    // The key schedule.
    let schedule =
        key_schedule(suite, mode, shared_secret.as_bytes(), &info, &psk, &psk_id).unwrap();
    assert_eq!(hex(schedule.key.as_bytes()), v.key, "{what}");
    assert_eq!(hex(schedule.base_nonce.as_bytes()), v.base_nonce, "{what}");
    assert_eq!(
        hex(schedule.exporter_secret.as_bytes()),
        v.exporter_secret,
        "{what}"
    );

    // The public API.
    let sender_side = sender_mode(mode, &psk, &psk_id, &sk_s);
    let recipient_side = recipient_mode(mode, &psk, &psk_id, sk_s.public_key());
    let (enc, mut sender) = suite
        .setup_sender(sk_r.public_key(), &info, sender_side, &ikm_e)
        .unwrap();
    assert_eq!(hex(&enc), v.enc, "{what}");
    let mut recipient = suite
        .setup_recipient(&enc, &sk_r, &info, recipient_side)
        .unwrap();

    if suite.aead() == Aead::ExportOnly {
        assert!(v.encryptions.is_empty(), "{what}");
        assert_eq!(sender.seal(b"", b""), Err(Error::ExportOnly), "{what}");
        assert_eq!(
            recipient.open(b"", &[0; 16]),
            Err(Error::ExportOnly),
            "{what}"
        );
        assert_eq!(
            suite.seal(sk_r.public_key(), &info, b"", b"", sender_side, &ikm_e),
            Err(Error::ExportOnly),
            "{what}"
        );
    } else {
        // Every sequence number up to the last one kept, with the plaintext
        // and associated data the file uses, and the kept ones compared.
        let pt = unhex(v.encryptions[0].pt);
        let mut kept = v.encryptions.iter().peekable();
        for seq in 0..=v.encryptions.last().unwrap().seq {
            let aad = format!("Count-{seq}").into_bytes();
            let ct = sender.seal(&aad, &pt).unwrap();
            if let Some(e) = kept.next_if(|e| e.seq == seq) {
                assert_eq!((unhex(e.aad), unhex(e.pt)), (aad.clone(), pt.clone()));
                assert_eq!(hex(&ct), e.ct, "{what}, sequence number {seq}");
            }
            assert_eq!(recipient.open(&aad, &ct).unwrap(), pt, "{what}, {seq}");
        }
        assert!(kept.next().is_none(), "{what}: encryptions out of order");

        // The single-shot functions are sequence number 0.
        let first = &v.encryptions[0];
        let (enc, ct) = suite
            .seal(
                sk_r.public_key(),
                &info,
                b"Count-0",
                &pt,
                sender_side,
                &ikm_e,
            )
            .unwrap();
        assert_eq!(
            (hex(&enc), hex(&ct)),
            (v.enc.to_string(), first.ct.to_string())
        );
        assert_eq!(
            suite.open(&enc, &sk_r, &info, b"Count-0", &ct, recipient_side),
            Ok(pt),
            "{what}"
        );
    }

    for export in v.exports {
        let context = unhex(export.context);
        let value = sender.export(&context, export.len).unwrap();
        assert_eq!(hex(&value), export.value, "{what}, export");
        assert_eq!(recipient.export(&context, export.len).unwrap(), value);
    }
}

#[test]
fn rfc9180_appendix_a() {
    // The suites RFC 9180 prints in Appendix A that are in scope, each in the
    // four modes, with the encryptions at sequence numbers 0, 1, 2, 4, 255 and
    // 256 and the three exports: A.1 DHKEM(X25519), HKDF-SHA256, AES-128-GCM;
    // A.3 DHKEM(P-256), HKDF-SHA256, AES-128-GCM; A.4 the same with
    // HKDF-SHA512; A.6 DHKEM(P-521), HKDF-SHA512, AES-256-GCM; A.7 DHKEM(X25519),
    // HKDF-SHA256, export-only.
    let mut seen = Vec::new();
    for v in CFRG.iter().filter(|v| !v.appendix.is_empty()) {
        let seqs: Vec<u32> = v.encryptions.iter().map(|e| e.seq).collect();
        if v.aead_id == 0xffff {
            assert!(seqs.is_empty());
        } else {
            assert_eq!(seqs, [0, 1, 2, 4, 255, 256], "{}", v.appendix);
        }
        assert_eq!(v.exports.len(), 3);
        check_vector(v);
        seen.push((v.appendix, v.mode));
    }
    seen.sort();
    let want: Vec<(&str, u8)> = ["A.1", "A.3", "A.4", "A.6", "A.7"]
        .into_iter()
        .flat_map(|a| (0..4).map(move |mode| (a, mode)))
        .collect();
    assert_eq!(seen, want);
}

#[test]
fn cfrg_vectors() {
    // The rest of the file in scope: DHKEM(P-256), DHKEM(P-521) and
    // DHKEM(X25519), each with HKDF-SHA256 and HKDF-SHA512 and the three AEADs,
    // in the four modes. The file has no DHKEM(P-384) and no HKDF-SHA384.
    let rest: Vec<&Vector> = CFRG.iter().filter(|v| v.appendix.is_empty()).collect();
    assert_eq!(rest.len(), 52);
    for v in rest {
        check_vector(v);
    }
}

/// The inputs Go's tests draw from a SHAKE128 stream of the empty string: a
/// byte that gives a length, then that many bytes.
struct Draws<'s> {
    stream: &'s [u8],
}

impl<'s> Draws<'s> {
    fn next(&mut self) -> &'s [u8] {
        let (len, rest) = self.stream.split_first().unwrap();
        let (drawn, rest) = rest.split_at(usize::from(*len));
        self.stream = rest;
        drawn
    }
}

fn check_accumulated(v: &Accumulated, stream: &[u8]) {
    let what = format!(
        "KEM {:#06x}, KDF {:#06x}, AEAD {:#06x}",
        v.kem_id, v.kdf_id, v.aead_id
    );
    let suite = Suite::from_ids(v.kem_id, v.kdf_id, v.aead_id).unwrap();
    let info = unhex(v.info);
    let sk_r = check_key_pair(suite.kem(), v.ikm_r, v.sk_rm, v.pk_rm, &what);

    let (enc, mut sender) = suite
        .setup_sender(sk_r.public_key(), &info, SenderMode::Base, &unhex(v.ikm_e))
        .unwrap();
    assert_eq!(hex(&enc), v.enc, "{what}");
    let mut recipient = suite
        .setup_recipient(&enc, &sk_r, &info, RecipientMode::Base)
        .unwrap();

    let shake = |sink: &[u8]| {
        let mut out = [0u8; 16];
        sha3::shake128(sink, &mut out);
        hex(&out)
    };

    if suite.aead() != Aead::ExportOnly {
        let (mut draws, mut sink) = (Draws { stream }, Vec::new());
        for _ in 0..1000 {
            let (aad, pt) = (draws.next(), draws.next());
            let ct = sender.seal(aad, pt).unwrap();
            assert_eq!(recipient.open(aad, &ct).unwrap(), pt, "{what}");
            sink.extend_from_slice(&ct);
        }
        assert_eq!(shake(&sink), v.encryptions, "{what}, encryptions");
    }

    // Exports of every length from 0 to 999 bytes.
    let (mut draws, mut sink) = (Draws { stream }, Vec::new());
    for len in 0..1000 {
        let context = draws.next();
        let value = sender.export(context, len).unwrap();
        assert_eq!(recipient.export(context, len).unwrap(), value, "{what}");
        sink.extend_from_slice(&value);
    }
    assert_eq!(shake(&sink), v.exports, "{what}, exports");
}

#[test]
fn go_accumulated() {
    // Go's own vectors: a thousand encryptions of random lengths up to 255
    // bytes, of plaintext and of associated data, and a thousand exports.
    let mut stream = vec![0u8; 1000 * 2 * 256];
    sha3::shake128(b"", &mut stream);
    assert_eq!(GO_ACCUMULATED.len(), 18);
    for v in GO_ACCUMULATED {
        check_accumulated(v, &stream);
    }
}

/// A suite of `kem`, and the key pairs of a recipient and of a sender, for the
/// tests that are not about vectors.
fn fixture(kem: Kem, aead: Aead) -> (Suite, PrivateKey, PrivateKey) {
    let suite = Suite::new(kem, Kdf::HkdfSha256, aead);
    let len = kem.private_key_len();
    let sk_r = kem.derive_key_pair(&vec![0x52; len]).unwrap();
    let sk_s = kem.derive_key_pair(&vec![0x53; len]).unwrap();
    (suite, sk_r, sk_s)
}

/// Fresh enough entropy for a setup of any KEM in these tests.
const IKM_E: [u8; 66] = [0x45; 66];
const PSK: &[u8; 32] = &[0x50; 32];
const PSK_ID: &[u8] = b"psk id";
const INFO: &[u8] = b"info";
const AAD: &[u8] = b"aad";

#[test]
fn every_change_fails_to_open() {
    // One KEM of each kind: what binds a message to its inputs is the key
    // schedule, which does not depend on the curve.
    for kem in [Kem::X25519HkdfSha256, Kem::P256HkdfSha256] {
        let (suite, sk_r, sk_s) = fixture(kem, Aead::Aes128Gcm);
        let other = kem.derive_key_pair(&[0x99; 66]).unwrap();
        let other_psk = [0x51; 32];

        for mode in ALL_MODES {
            let sender_side = sender_mode(mode, PSK, PSK_ID, &sk_s);
            let (enc, ct) = suite
                .seal(
                    sk_r.public_key(),
                    INFO,
                    AAD,
                    b"message",
                    sender_side,
                    &IKM_E,
                )
                .unwrap();
            let open = |enc: &[u8], sk_r: &PrivateKey, info: &[u8], aad: &[u8], ct: &[u8], side| {
                suite.open(enc, sk_r, info, aad, ct, side)
            };
            let right = recipient_mode(mode, PSK, PSK_ID, sk_s.public_key());
            assert_eq!(
                open(&enc, &sk_r, INFO, AAD, &ct, right),
                Ok(b"message".to_vec())
            );

            let fails = |result: Result<Vec<u8>, Error>, what: &str| {
                assert_eq!(result, Err(Error::Open), "{kem:?}, {mode:?}: {what}");
            };
            for i in 0..ct.len() {
                let mut forged = ct.clone();
                forged[i] ^= 0x01;
                fails(open(&enc, &sk_r, INFO, AAD, &forged, right), "ciphertext");
            }
            // Another valid encapsulated key: on a NIST curve a changed byte
            // would not be a point at all.
            let (other_enc, _) = suite
                .seal(
                    sk_r.public_key(),
                    INFO,
                    AAD,
                    b"",
                    SenderMode::Base,
                    &[0x46; 66],
                )
                .unwrap();
            fails(open(&other_enc, &sk_r, INFO, AAD, &ct, right), "enc");
            fails(open(&enc, &sk_r, INFO, b"aaD", &ct, right), "aad");
            fails(open(&enc, &sk_r, b"infO", AAD, &ct, right), "info");
            fails(open(&enc, &other, INFO, AAD, &ct, right), "recipient key");
            if matches!(mode, Mode::Psk | Mode::AuthPsk) {
                let wrong = recipient_mode(mode, &other_psk, PSK_ID, sk_s.public_key());
                fails(open(&enc, &sk_r, INFO, AAD, &ct, wrong), "psk");
                let wrong = recipient_mode(mode, PSK, b"psk iD", sk_s.public_key());
                fails(open(&enc, &sk_r, INFO, AAD, &ct, wrong), "psk_id");
            }
            if matches!(mode, Mode::Auth | Mode::AuthPsk) {
                let wrong = recipient_mode(mode, PSK, PSK_ID, other.public_key());
                fails(open(&enc, &sk_r, INFO, AAD, &ct, wrong), "sender key");
            }
            // Opened in another mode: the mode is in the key schedule.
            for other_mode in ALL_MODES.into_iter().filter(|&m| m != mode) {
                let wrong = recipient_mode(other_mode, PSK, PSK_ID, sk_s.public_key());
                fails(open(&enc, &sk_r, INFO, AAD, &ct, wrong), "mode");
            }
        }
    }
}

#[test]
fn messages_open_only_in_order() {
    let (suite, sk_r, _) = fixture(Kem::X25519HkdfSha256, Aead::Aes256Gcm);
    let (enc, mut sender) = suite
        .setup_sender(sk_r.public_key(), INFO, SenderMode::Base, &IKM_E)
        .unwrap();
    let first = sender.seal(AAD, b"first").unwrap();
    let second = sender.seal(AAD, b"second").unwrap();
    let mut recipient = suite
        .setup_recipient(&enc, &sk_r, INFO, RecipientMode::Base)
        .unwrap();

    // Out of order it fails, and a failure does not move the sequence on.
    assert_eq!(recipient.open(AAD, &second), Err(Error::Open));
    assert_eq!(
        recipient.open(AAD, &first[..first.len() - 1]),
        Err(Error::Open)
    );
    assert_eq!(recipient.open(AAD, &first).unwrap(), b"first");
    // Nor can a message be opened twice.
    assert_eq!(recipient.open(AAD, &first), Err(Error::Open));
    assert_eq!(recipient.open(AAD, &second).unwrap(), b"second");
}

#[test]
fn sequence_number_limit() {
    // RFC 9180 section 5.2: a context fails once the sequence number reaches
    // 2^(8 * Nn) - 1 = 2^96 - 1, so the last message it seals or opens is at
    // 2^96 - 2.
    let last = (1u128 << 96) - 2;
    let (suite, sk_r, _) = fixture(Kem::X25519HkdfSha256, Aead::Aes128Gcm);
    let (enc, mut sender) = suite
        .setup_sender(sk_r.public_key(), INFO, SenderMode::Base, &IKM_E)
        .unwrap();
    let mut recipient = suite
        .setup_recipient(&enc, &sk_r, INFO, RecipientMode::Base)
        .unwrap();
    sender.set_sequence(last);
    recipient.set_sequence(last);

    let ct = sender.seal(AAD, b"last").unwrap();
    assert_eq!(
        sender.seal(AAD, b"one too many"),
        Err(Error::MessageLimitReached)
    );
    assert_eq!(recipient.open(AAD, &ct).unwrap(), b"last");
    assert_eq!(recipient.open(AAD, &ct), Err(Error::MessageLimitReached));

    // The nonce at 2^96 - 2 is not the one at 0: the whole sequence number
    // goes into it, and the message does not open at the start of the
    // sequence.
    let mut fresh = suite
        .setup_recipient(&enc, &sk_r, INFO, RecipientMode::Base)
        .unwrap();
    assert_eq!(fresh.open(AAD, &ct), Err(Error::Open));
}

#[test]
fn invalid_psk_inputs() {
    let (suite, sk_r, sk_s) = fixture(Kem::X25519HkdfSha256, Aead::Aes128Gcm);
    let short = [0x50; 31];
    let bad: [(&[u8], &[u8]); 4] = [
        (b"", b""),       // "Missing required PSK input"
        (PSK, b""),       // "Inconsistent PSK inputs"
        (b"", PSK_ID),    // "Inconsistent PSK inputs"
        (&short, PSK_ID), // fewer than 32 bytes, so less entropy than required
    ];
    for (psk, psk_id) in bad {
        for mode in [Mode::Psk, Mode::AuthPsk] {
            let sender_side = sender_mode(mode, psk, psk_id, &sk_s);
            let result = suite.setup_sender(sk_r.public_key(), INFO, sender_side, &IKM_E);
            assert_eq!(result.map(|_| ()), Err(Error::InvalidPsk), "{mode:?}");
            let enc = sk_s.public_key().as_bytes();
            let recipient_side = recipient_mode(mode, psk, psk_id, sk_s.public_key());
            let result = suite.setup_recipient(enc, &sk_r, INFO, recipient_side);
            assert_eq!(result.map(|_| ()), Err(Error::InvalidPsk), "{mode:?}");
        }
    }

    // "PSK input provided when not needed": the public API cannot express it,
    // the key schedule still checks it.
    let secret = [7u8; 32];
    for mode in [Mode::Base, Mode::Auth] {
        let result = key_schedule(suite, mode, &secret, INFO, PSK, PSK_ID);
        assert!(matches!(result, Err(Error::InvalidPsk)), "{mode:?}");
        assert!(key_schedule(suite, mode, &secret, INFO, b"", b"").is_ok());
    }
    assert!(key_schedule(suite, Mode::Psk, &secret, INFO, PSK, PSK_ID).is_ok());
}

#[test]
fn x25519_small_order_keys_are_rejected() {
    // RFC 9180 section 7.1.4: a Diffie-Hellman output of all zeros aborts,
    // whichever of the public keys it comes from. The points are 0, 1 and one
    // of order 8; ECDH's own tests have the rest.
    let small_order = [
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0100000000000000000000000000000000000000000000000000000000000000",
        "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
    ];
    let kem = Kem::X25519HkdfSha256;
    let (suite, sk_r, sk_s) = fixture(kem, Aead::Aes128Gcm);
    for point in small_order {
        let bad = PublicKey::from_bytes(kem, &unhex(point)).unwrap();
        for mode in ALL_MODES {
            let sender_side = sender_mode(mode, PSK, PSK_ID, &sk_s);
            let result = suite.setup_sender(&bad, INFO, sender_side, &IKM_E);
            assert_eq!(
                result.map(|_| ()),
                Err(Error::LowOrderPublicKey),
                "pkR, {mode:?}"
            );

            let recipient_side = recipient_mode(mode, PSK, PSK_ID, sk_s.public_key());
            let result = suite.setup_recipient(bad.as_bytes(), &sk_r, INFO, recipient_side);
            assert_eq!(
                result.map(|_| ()),
                Err(Error::LowOrderPublicKey),
                "enc, {mode:?}"
            );
        }
        // The sender's public key, in the authenticated modes, with an
        // encapsulated key that is fine.
        let (enc, _) = suite
            .setup_sender(sk_r.public_key(), INFO, SenderMode::Base, &IKM_E)
            .unwrap();
        for mode in [Mode::Auth, Mode::AuthPsk] {
            let recipient_side = recipient_mode(mode, PSK, PSK_ID, &bad);
            let result = suite.setup_recipient(&enc, &sk_r, INFO, recipient_side);
            assert_eq!(
                result.map(|_| ()),
                Err(Error::LowOrderPublicKey),
                "pkS, {mode:?}"
            );
        }
    }
}

#[test]
fn nist_invalid_public_keys_are_rejected() {
    // RFC 9180 section 7.1.4 requires the NIST curves' public keys to be
    // validated: on the curve, coordinates in range, not the point at
    // infinity. ECDH's `PublicKey::from_bytes` does it, as a public key or as
    // the encapsulated key the recipient receives.
    for kem in [
        Kem::P256HkdfSha256,
        Kem::P384HkdfSha384,
        Kem::P521HkdfSha512,
    ] {
        let (suite, sk_r, _) = fixture(kem, Aead::Aes128Gcm);
        let good = sk_r.public_key().as_bytes().to_vec();
        let coordinate = (good.len() - 1) / 2;

        let mut off_curve = good.clone();
        *off_curve.last_mut().unwrap() ^= 1;
        // The compressed form: 0x02 or 0x03 and the x-coordinate.
        let mut compressed = vec![0x02 | (good.last().unwrap() & 1)];
        compressed.extend_from_slice(&good[1..=coordinate]);
        // A coordinate not below the prime: all ones is above every prime
        // here.
        let mut unreduced = good.clone();
        unreduced[1..=coordinate].fill(0xff);
        let bad = [
            ("off the curve", off_curve),
            ("compressed", compressed),
            ("the point at infinity", vec![0x00]),
            ("an unreduced coordinate", unreduced),
            ("one byte short", good[..good.len() - 1].to_vec()),
            ("one byte long", [&good[..], &[0]].concat()),
            ("empty", Vec::new()),
        ];
        for (what, bytes) in bad {
            assert_eq!(
                PublicKey::from_bytes(kem, &bytes),
                Err(Error::InvalidPublicKey),
                "{kem:?}, {what}"
            );
            let result = suite.setup_recipient(&bytes, &sk_r, INFO, RecipientMode::Base);
            assert_eq!(
                result.map(|_| ()),
                Err(Error::InvalidPublicKey),
                "{kem:?}, enc {what}"
            );
        }
        assert!(PublicKey::from_bytes(kem, &good).is_ok());
    }
}

#[test]
fn invalid_private_keys_are_rejected() {
    // A NIST scalar must be at least 1 and below the order; any length but
    // the KEM's is refused.
    for kem in ALL_KEMS {
        let len = kem.private_key_len();
        for bytes in [vec![1; len - 1], vec![1; len + 1], Vec::new()] {
            assert_eq!(
                PrivateKey::from_bytes(kem, &bytes).map(|_| ()),
                Err(Error::InvalidPrivateKey),
                "{kem:?}, {} bytes",
                bytes.len()
            );
        }
        if kem != Kem::X25519HkdfSha256 {
            for bytes in [vec![0; len], vec![0xff; len]] {
                assert_eq!(
                    PrivateKey::from_bytes(kem, &bytes).map(|_| ()),
                    Err(Error::InvalidPrivateKey),
                    "{kem:?}, {:02x}",
                    bytes[0]
                );
            }
        }
    }
    // Any 32 bytes are an X25519 key.
    assert!(PrivateKey::from_bytes(Kem::X25519HkdfSha256, &[0; 32]).is_ok());
    assert!(PrivateKey::from_bytes(Kem::X25519HkdfSha256, &[0xff; 32]).is_ok());
}

#[test]
fn keys_of_another_kem_are_refused() {
    let (suite, sk_r, sk_s) = fixture(Kem::P256HkdfSha256, Aead::Aes128Gcm);
    let (_, x25519_r, x25519_s) = fixture(Kem::X25519HkdfSha256, Aead::Aes128Gcm);
    let mismatch = |result: Result<(), Error>, what: &str| {
        assert_eq!(result, Err(Error::KemMismatch), "{what}");
    };
    let setup_sender =
        |pk_r: &PublicKey, mode| suite.setup_sender(pk_r, INFO, mode, &IKM_E).map(|_| ());
    let (enc, _) = suite
        .setup_sender(sk_r.public_key(), INFO, SenderMode::Base, &IKM_E)
        .unwrap();
    let setup_recipient =
        |sk_r: &PrivateKey, mode| suite.setup_recipient(&enc, sk_r, INFO, mode).map(|_| ());
    mismatch(setup_sender(x25519_r.public_key(), SenderMode::Base), "pkR");
    mismatch(
        setup_sender(sk_r.public_key(), SenderMode::Auth { sk_s: &x25519_s }),
        "skS",
    );
    mismatch(setup_recipient(&x25519_r, RecipientMode::Base), "skR");
    mismatch(
        setup_recipient(
            &sk_r,
            RecipientMode::Auth {
                pk_s: x25519_s.public_key(),
            },
        ),
        "pkS",
    );
    assert!(
        setup_recipient(
            &sk_r,
            RecipientMode::Auth {
                pk_s: sk_s.public_key()
            }
        )
        .is_ok()
    );
    assert_eq!(x25519_r.kem(), Kem::X25519HkdfSha256);
    assert_eq!(sk_r.public_key().kem(), Kem::P256HkdfSha256);
}

#[test]
fn input_keying_material_lengths() {
    // At least a private key's worth, for DeriveKeyPair and for a sender's
    // setup alike (RFC 9180 section 7.1.3 says "should"; the crate refuses
    // less).
    for kem in ALL_KEMS {
        let len = kem.private_key_len();
        let (suite, sk_r, _) = fixture(kem, Aead::Aes128Gcm);
        assert_eq!(
            kem.derive_key_pair(&vec![1; len - 1]).map(|_| ()),
            Err(Error::IkmTooShort),
            "{kem:?}"
        );
        assert!(kem.derive_key_pair(&vec![1; len]).is_ok());
        assert!(kem.derive_key_pair(&vec![1; 2 * len]).is_ok());
        let setup = |ikm: &[u8]| {
            suite
                .setup_sender(sk_r.public_key(), INFO, SenderMode::Base, ikm)
                .map(|_| ())
        };
        assert_eq!(setup(&vec![1; len - 1]), Err(Error::IkmTooShort), "{kem:?}");
        assert_eq!(setup(&vec![1; len]), Ok(()));
    }

    // A ciphertext shorter than a tag does not open.
    let (suite, sk_r, _) = fixture(Kem::X25519HkdfSha256, Aead::Aes128Gcm);
    let (enc, _) = suite
        .seal(sk_r.public_key(), INFO, AAD, b"", SenderMode::Base, &IKM_E)
        .unwrap();
    for len in [0, 15] {
        let result = suite.open(&enc, &sk_r, INFO, AAD, &vec![0; len], RecipientMode::Base);
        assert_eq!(result, Err(Error::Open), "{len}-byte ciphertext");
    }
}

#[test]
fn export_lengths() {
    // RFC 9180 section 5.3: at most 255 * Nh bytes.
    for (kdf, hash_len) in [
        (Kdf::HkdfSha256, 32),
        (Kdf::HkdfSha384, 48),
        (Kdf::HkdfSha512, 64),
    ] {
        let suite = Suite::new(Kem::X25519HkdfSha256, kdf, Aead::ExportOnly);
        let (_, sk_r, _) = fixture(Kem::X25519HkdfSha256, Aead::ExportOnly);
        let (_, sender) = suite
            .setup_sender(sk_r.public_key(), INFO, SenderMode::Base, &IKM_E)
            .unwrap();
        assert_eq!(sender.export(b"", 0), Ok(Vec::new()));
        assert_eq!(
            sender.export(b"", 255 * hash_len).unwrap().len(),
            255 * hash_len
        );
        assert_eq!(
            sender.export(b"", 255 * hash_len + 1),
            Err(Error::ExportTooLong)
        );
        assert_eq!(sender.export(b"", usize::MAX), Err(Error::ExportTooLong));
    }
}

#[test]
fn unsupported_algorithms() {
    let unsupported = [
        (0x0021, 0x0001, 0x0001), // DHKEM(X448, HKDF-SHA512)
        (0x0041, 0x0001, 0x0001), // ML-KEM-768
        (0x647a, 0x0001, 0x0001), // MLKEM768-X25519
        (0x0020, 0x0000, 0x0001), // the reserved KDF
        (0x0020, 0x0010, 0x0001), // SHAKE128
        (0x0020, 0x0001, 0x0003), // ChaCha20-Poly1305
        (0x0020, 0x0001, 0x0000), // the reserved AEAD
    ];
    for (kem, kdf, aead) in unsupported {
        assert_eq!(
            Suite::from_ids(kem, kdf, aead),
            Err(Error::UnsupportedAlgorithm),
            "{kem:#06x}, {kdf:#06x}, {aead:#06x}"
        );
    }
}

#[test]
fn debug_hides_the_secrets() {
    let (suite, sk_r, _) = fixture(Kem::X25519HkdfSha256, Aead::Aes128Gcm);
    let (enc, sender) = suite
        .setup_sender(sk_r.public_key(), INFO, SenderMode::Base, &IKM_E)
        .unwrap();
    let recipient = suite
        .setup_recipient(&enc, &sk_r, INFO, RecipientMode::Base)
        .unwrap();
    assert_eq!(format!("{sender:?}"), "Sender { .. }");
    assert_eq!(format!("{recipient:?}"), "Recipient { .. }");
    let psk = SenderMode::Psk {
        psk: PSK,
        psk_id: PSK_ID,
    };
    assert_eq!(format!("{psk:?}"), "SenderMode::Psk");
    let psk = RecipientMode::Psk {
        psk: PSK,
        psk_id: PSK_ID,
    };
    assert_eq!(format!("{psk:?}"), "RecipientMode::Psk");
}

/// Messages sealed by one side of an interop test, for the other to open, all
/// in Base mode to the recipient `DeriveKeyPair(stream("interop ikmR", kem_id,
/// Nsk))` of the KEM, with the info `cryptors interop`: three messages through
/// one context (see [`interop_messages`]), an export of 48 bytes for `interop
/// export`, and a single-shot `enc || ct` of `single shot` with no associated
/// data. The export-only suites have the export only.
struct Interop {
    kem_id: u16,
    kdf_id: u16,
    aead_id: u16,
    enc: &'static str,
    ciphertexts: [&'static str; 3],
    export: &'static str,
    single_shot: &'static str,
}

/// The (associated data, plaintext) of the three messages of an interop
/// context: an empty one, 100 bytes with associated data, and 17 bytes.
fn interop_messages() -> [(&'static [u8], Vec<u8>); 3] {
    [
        (b"", Vec::new()),
        (b"aad 1", stream(b"interop pt", 1, 100)),
        (b"", stream(b"interop pt", 2, 17)),
    ]
}

/// The interop recipient of `kem`, checked against the public key that Go
/// derived from the same input.
fn interop_recipient(kem: Kem) -> PrivateKey {
    let ikm = stream(b"interop ikmR", u32::from(kem.id()), kem.private_key_len());
    let sk_r = kem.derive_key_pair(&ikm).unwrap();
    let from_go = match kem {
        Kem::P256HkdfSha256 => concat!(
            "0490d1c96dca5cecdbbd9a50c474992b1f59a71415d0a7a5cb83f47987492c22dd",
            "287e0ef588bd9dc8d124f106f03ca8bd1026e5a124793cbdde2d9c2bdb9e646e",
        ),
        Kem::P384HkdfSha384 => concat!(
            "04b5728bc207ec7224b113f37fdf28142f27d4f7b192b338039513385714b6ea2a",
            "09e5f47e64bb741f95e98c296dbd6de9423dc71a0f50186b1957cfd2d3f1da7183",
            "efc372815c95ab3be790ff5e49f26299eb32704c9be50f4fbfa64f5a20a96f",
        ),
        Kem::P521HkdfSha512 => concat!(
            "0400bdbc75996156565c45aae99ede80c31d924447b9c8efd37cbd0bdc3f509e2e",
            "74c0c8515414a1db23eca8ca17897a6ab97360db927145b182d4a337f4f40cba7a",
            "ae01c8309774b2f4b4541cc41a326ff44052f72cac62d3b7913bbc523a1f1e5fdf",
            "318ed1aa7da204f3cf5ffa0ec308aa02bcc55165d7d4a80fcfdf952428fc5aee8d5a",
        ),
        _ => "79e4b9951757313aa0375ad3f39bf6272e223e056eae40244702463d2165f629",
    };
    assert_eq!(hex(sk_r.public_key().as_bytes()), from_go, "{kem:?}");
    sk_r
}

/// Sealed by Go's crypto/hpke (Go 1.27.1, `hpke.NewSender`, `Sender.Seal`,
/// `Sender.Export` and `hpke.Seal`), with its own random ephemeral keys.
const GO_SEALED: [Interop; 36] = [
    Interop {
        kem_id: 0x0010,
        kdf_id: 0x0001,
        aead_id: 0x0001,
        enc: "04bb417233efc206dfb2159e63a33de03ac416defb4431d8eeed4810b119081bbb82a71d57766dda10f39cefbdfe0b950e7e536a8fb10bbee0075241e5a4e9685e",
        ciphertexts: [
            "1c836ec00318297c6cccd699b3098649",
            "f95ccb44c7acdb61b5e4996705b7d2ff092ad4fd79bd8f952978912fd6337426088d63c1e8231ea46fcf36c7c8d55ab4759ff3a2f5eeb637c3b3f5ec7fead0b81a138139d756ffd106de191dc66f9cc10c4f142ed0f946059c9145f3f46116e679341ee827a848529d225ac17a031286bfb805b4",
            "d10aaf9f4ae4ab96e87c9dc6e7e5fe9ab01ac9c3fe430160efc9de35881fb083bc",
        ],
        export: "b06ecb8dc93c21d7ce795c38b8ddf1363135e124f31b0be78e2ce8c41d5648be9acc3b9c1b73e8cd551290a8fa0f259b",
        single_shot: "04fe086726ae1ff24b29812260a58d5979a5046659a6e353a0fe9c52d3b27d9e25bf07d661033bc7e3c86513bf2f7e9a210c2e266407bcb97231e5d23bb1372a562c6004823ce2675fe35884da9484e1da6fc3e21d760b620e017db3",
    },
    Interop {
        kem_id: 0x0010,
        kdf_id: 0x0001,
        aead_id: 0x0002,
        enc: "047c2c45672acf020c0e4ef3f0bd89ea0fbb7b26faafbd560a8818a741c80d4d08bf4da8d986bb6283cccdb8a60e4153eaa352053cf7bb55de38cf28baa19d15a2",
        ciphertexts: [
            "ac10b5e19440471e38bec7407df50444",
            "6df95109c443355f1bbd0b2c20068120b45ede26e776eafbf5fcf408af179aa14e45710d0bee8a01b3a5faadab852847a8ab9bb010142bea970ea29fa239471f0cc59bffaeb3bd9c6357e3e7c0881e0330d8d1df3423026ed4f1e861e8977fd85815403377f2ae95db700c107780d2562aad29a0",
            "6d5d377c9335398c01d2341066d76836183749597a99f49b2166f4bf81027f1a54",
        ],
        export: "bb73916e7e9dfed09fc38cf28b59f78dab3909f75ca6e09e3da549e8b83ac4f7cf4fc42a6b16d99b6377dde95bbebdd0",
        single_shot: "0494d033d922d5b6db6e8b2134b0fb7bac553f28b8f08d2176283aa0969fe0f456ec099bdfca35af93d4bd0b0efe741e62258f207721127099e0d45867449c666d7eb8efe7afd92546c856d387fec12b633c8ccafd10bcbf859e662d",
    },
    Interop {
        kem_id: 0x0010,
        kdf_id: 0x0001,
        aead_id: 0xffff,
        enc: "04a229797d87465df7cd91bc5fb6b19d94be6407fd4b4a69da27cbe496bc61a2d8ecfb9513b7832d432fee6e3525f053258e7568031b4441e3bcc27fb31b03e54a",
        ciphertexts: ["", "", ""],
        export: "31aa93a4e4f4c95dd3a6d3358635ee0562d3219b300b883e302896b62808dd0c0be7ff319f3f732189cbbc2bf96e1a13",
        single_shot: "",
    },
    Interop {
        kem_id: 0x0010,
        kdf_id: 0x0002,
        aead_id: 0x0001,
        enc: "043790051e2ab9d34373f1ba6cde9dec958662d31095baca628cfbb4fda0c954efc7624d96c6356f5324702653e1e9742ca6094421d45d050ca2eaf2635b305149",
        ciphertexts: [
            "d590c1c2117f59cd6ba83d3c2937e41c",
            "f7d52a872035120c9c320efde827681ebcf8caeb6cf66f7705107811c31e741ce9f4672ac2a0695727f5f8b9ee72a1e7bedaded7314b4e6d31ef04726bc1ceebc6382e0cd2449ae8b99d0b07b3fa716167a73c65614cf4d6565a520b4a5c2a285f4ff1e6785bfb43da4c108ae7be5ec0e88918fa",
            "ce90ce65c63ee2ae022c6673f6c9538b410b3f9de1e594dc88868f937513c5a586",
        ],
        export: "b551afb50e675d7602b8d811c9df82427d3b7f0a1a11d54bb71d676492e940533e896802c40df151f08b199c45f3de8c",
        single_shot: "0405f99dd9cc2b8bbf3225673e34a2c8dc981e125475b8731a4b2673c9092ca3e1130a26dc141449e5ba1ec4005b1ca4391410884ba2ec014a30fd36329e80fcfd7679f5af140fbe3c6796d537749cce95d8f39fa6042c260d2d3abf",
    },
    Interop {
        kem_id: 0x0010,
        kdf_id: 0x0002,
        aead_id: 0x0002,
        enc: "048cb2068931f8564fec1c0a84014035058bd48d7c4afb0fc99bf55981f52a306b9e6d06636fb2946c86399de04e71dd23fb225b151c6e88e1ce74c8e60f130641",
        ciphertexts: [
            "58d772adda287c90d6729edfa70697ac",
            "05516828987d38b8d49f546f5eff540edc31db8faacbbc14f1af94b27b93bbae2537ef9577a349a25139ebfad59e3fb14c039fd5a2ced973311cac9369be2ce2f3a545977f566dc3ad33561abb36b05e147bcd05c5129068005ee6ab2e31aa8a2e66ddbcfed6d89eaa727af6895863b0ef6da04d",
            "3d38171e11724a8d52f084aa2a6b644bc5efa695b3ca73576ee5d304a86ec23fe0",
        ],
        export: "a21678daebfed6784d30b67b1ee15fa8091446af2b1df0e8ddf21fc21b14ae0aff644b1bbe8a42602f2d85c985152e55",
        single_shot: "043a3d0f0a56cf9d251d79d4fc7761c3100e7046ce1a3a2a2a7bc94030d108f5c48def38a8087ef085d64b331ad7bc95ef7537f398f277ded3d5d70dfcc09553ac7af5b183f47da752bce3734db94abbc46072596fcb7d310b721acd",
    },
    Interop {
        kem_id: 0x0010,
        kdf_id: 0x0002,
        aead_id: 0xffff,
        enc: "0487e6291fc38708dc81fc06caeca9c97f86c3b3e334729622fdef406f8ec2db1a48f3c1789cd6e8eac2173559ea776755d71332abc2f9d1508b8902feadc8a742",
        ciphertexts: ["", "", ""],
        export: "8d415b0d48366d9cbcc214d8a0a2f94f1bfcfeb2823307b11a4a11f992926db646f97c2a26b402e27110299a2d39b588",
        single_shot: "",
    },
    Interop {
        kem_id: 0x0010,
        kdf_id: 0x0003,
        aead_id: 0x0001,
        enc: "0415175fb1bc31937fa8e6f497833e78d9eb038124e3a57ba2a0e46780f1dc702d8e9be1f7066297ddab1cc127f288b5ae37d4a48ec0ede03ced36753fda6da37e",
        ciphertexts: [
            "bcf341047d4be83258e9e5278add040f",
            "d058a615fd2aaedf89a4a8877f26a54660d49e0a0e03efe0f4c07ad3ae770f621ff02339e2a94979f81089ea36d470afd50fca04155bbbafa3fa439a61dfe6d26aaaf98039400522d0fda8eb2c968dcf18f918d8a6be51a41f112fa55ea4221cb05f28e29c64114151b83141dc216c9e0e849171",
            "64a936ad110985c395c33bd66f25646db9b4bd73343e588cabeb0adaf3829ebece",
        ],
        export: "00dd04115a811d6449340b9b7c909de9156c9ab43efe22f7dda1ec792882a77730a7a5e0ee3f983c01988fba5d26e6e9",
        single_shot: "04d11d01181f3f704d7cfaa803a755e3c026396426a3b0756f06d50c403fb9dbf2d86443c7fe1a121e406fada8f16f5590ddb0f9195bb540e41da96917dd9fdf89dcaf17f5f9d14ca807df5845fa02872fc7d9484acf13b1f3a4e316",
    },
    Interop {
        kem_id: 0x0010,
        kdf_id: 0x0003,
        aead_id: 0x0002,
        enc: "045fc4640a029b07e37b80c5f82da551628edc72d73b25cbd19488e60cbe4b0a4c6343ccfb8f4dd05f8a29025f6856b92eb872cca5f4251d30d20dbc5589bdc1ca",
        ciphertexts: [
            "28c17f764ab34084877f3d6bc7f3b70e",
            "874b7fe9f920f3ab3f6a90a78d9acf8008345c5cfc377e2f3dde5b6af271a4cc54abd6179797599d479e914ccb3b6b3e700823d284a9726f1f31e203f94c81ed8bb7b860ba8c55261a43f7653d66f5f9e45ada6df8425325168794bbcd59742ee0a044adf7110b2c9bcb88ee23e64f68e8245d33",
            "67861a250cd37bff0c6a2cbd0b1fcb3286ceb2c74d64b809140ddcaba3839c9284",
        ],
        export: "49c45e6af83fa3e905634f851d8ef1659aa327f85543b9586b032c723e433ec1190b732277558bd6ce695333de77178b",
        single_shot: "044d0dc88f5df84872c0099ccf498664526645a40485974fd68ecee36f0957aaf5d76a21f40edc03d8c9aa6579c002d7ecd74e4c8bce895bcc3727ecefccbfad466d65915ba1136dfb230934160cede67057db913864404f3f9c17ae",
    },
    Interop {
        kem_id: 0x0010,
        kdf_id: 0x0003,
        aead_id: 0xffff,
        enc: "049e7cd6dd6a0e722841fe7426d93817f3e084fa73efa45839009d51f01b94026a2c35e73c7f47032d99caed3a3d9c529b455f1697f37a5ef116f667d18937ce60",
        ciphertexts: ["", "", ""],
        export: "4340ffeb2a2d856390c78b5009932c9ca78fab8c40d912484f7d36e10b1a3c9b986982409f9ccce8395f35d320d5a235",
        single_shot: "",
    },
    Interop {
        kem_id: 0x0011,
        kdf_id: 0x0001,
        aead_id: 0x0001,
        enc: "04961cb6a2fd92b70badfbbbd5b72b7daf8246a492b715fba2e4ff468a7b29d6d1e291edc351dda942cfd41076fb6914b6316433ea497d933ca41ea60f93f50f1643afb060e2d12dec71526021819d8baae46bd1961bce35a84878477c8e97902f",
        ciphertexts: [
            "6990593d4ac27250961260ce3cd3fd89",
            "fad2b4b7d8eb60a917866f5d09f35802d4c97830e1b40aa65e9635724feaea0d96c974664cde54c6ccd28571d83eec50c02c0e69777c44ddfcb1dd8394bdfa0988ea5477ad9cdd78f8a8bbb8ed9790089953c47122c03e7e842447da1ef5726b6f78a2b8ae91f376bdbf091774a6776aadad8845",
            "d9c0cef9e1f82c8998ef355e1bb8720b5755a6dff59b1bcf39a5938c407d850d01",
        ],
        export: "cc1d86b040fe81cb1821fee2aa6dfc96202a32d3d11e443467d3973d0e685a66b9b150c7d5feb48dc4bd0f657092233e",
        single_shot: "04a258212110d4e02be5b48f9f079468a1acc3a550a401ec8b385e6612ff83fc24035a04ba082730c030be1401ea8a4708f88aab242cb31d77b77c39bb53fd2d6ec8b7fd7684149f069a2ddccc598c544a5d4f8373ab28c5c3aa99ea4043e9aefe08d5beede37a8e6cf93ec2135eebfb4733fd6c0de7db76239ba344",
    },
    Interop {
        kem_id: 0x0011,
        kdf_id: 0x0001,
        aead_id: 0x0002,
        enc: "04b8a869f811e48930e457075c6efa12ac96cab5d1cb31c67e718f01e3c705c638ea98897d967bc9d2a310eff065963b645ff52a52fccfbf25412cdf8826b77d87a943efc60cf09526ad210f62551ae0e70956116e21caa3b8552f4e12fd28977e",
        ciphertexts: [
            "2c9c71fe4284623552355c116c83c092",
            "33a16380685e97f36c0801ff78b18cbacd8b0ba23aafa87902b526c8dc1f876473aa4fc773f533e310ffdeff9b7fdedc537ba08c23048dc7f34584f6430832ad5489724b10133bbb6a934f781ff2f7a2bf5ab163ddf8a9ecb774ff05c9c579880d52ca13f26f176852b168e94683217dea98032d",
            "59512cac918a46353be4e85e239b0a7bff8f7d0e8ea745957fd950d15eef39a25e",
        ],
        export: "c6dd062c0a6d72a8e8e6be55e8aba615e8314d928e97e5bc7f6c32a1f7c00a6acc57201c27fef64b0f976ef533c742dd",
        single_shot: "04047d1afaafaef83f82bd80a33b86cb271791fe8ef9ca979f3c2d5c7bc100fe012bb1ce9331cff3be5a64c407d3bba602c6b65af6730c78d68533a9727793c1d3c53c9b5107139941eb15933bc1ad1f7446e493dee8c1996347f8ff5c8287dde61bd1ec4afd0f62d2136f5992de61bb0d02f4b2c429e6d237292682",
    },
    Interop {
        kem_id: 0x0011,
        kdf_id: 0x0001,
        aead_id: 0xffff,
        enc: "04aad4848f91e665ea476ffed3b3b9d254824ac2b12afd7060db216216147fb240fda37fff49b2c0993e8c76d5c522a5a4e080e3d5932a68ecc90cfa697e28084217f2ecf144a3c6abb9913e11cd4383d56b41533be97ddad5e2850f01a87edf78",
        ciphertexts: ["", "", ""],
        export: "02d6d91fbe5ce7c3de326c58f738bd790a042a33668faf8a0616c5b5091ce34929e1326576c6296da17fb2a3e9734a87",
        single_shot: "",
    },
    Interop {
        kem_id: 0x0011,
        kdf_id: 0x0002,
        aead_id: 0x0001,
        enc: "04cf8b5cee0334c9038a3e5eb47ef6b31d9a9c7032886ba3ffc3cf0f02d72ec47b5d25ef948bc02d370039170339b18864ec773e67fbd17cccd37738b262d0f28b71afa3da15321bcc1a64c68fac82ac1e76db5b56a09d5e4e67d6f38b6c9b7ae3",
        ciphertexts: [
            "f64f986e88fcffd95f0ebc2afe67a617",
            "67c5866bdb0b89a65a9e17c2180d791dad995b14709d8365fafac852f5510c0c65d52d05cc14889c0e02d4e44021db4c24a939723642c985b506139c32a0fe67a7f6b8f5d9c31a0d6e75672be7032b53edf746eb137ebaead890483276cb901617749f8729c0353108628ff40239075b707fe15b",
            "b5c30a5ebc432f85eed3aefc3ff83b19cdddc2fe4f30014fcdf51adbd652634c1b",
        ],
        export: "121531ca0262b0cb5a900a16aac5b64e6d7c77dfabc7debd4bd5b9b532661698937a409f85c08c5d283c031d7ab6132a",
        single_shot: "04606f3250eb9e8abe837d12029ae734c5d95ecbf79b2ff8552acc4fb2ef28e04b4a0e99c75eb271060c2a53fbbc487c6a287451204707adb34ca19df0abe4a93fc9bde36519e69a9711e02f03ea28e5cd8646356fc52eccd7efd62bb97e6ee39b5be44e490e61c25b23b9823b297e7a5c681c0634b954139d76a529",
    },
    Interop {
        kem_id: 0x0011,
        kdf_id: 0x0002,
        aead_id: 0x0002,
        enc: "0459538f886209728acc073347c085fbe2b1b45bf85033c78aafcfde795cbaa8cee30e095edc670432970d00088cfd003ba008e0fe74ab054ea184bf52c804a0f2c7c24dac9970cb6d07baaf9cae8e274c183b811fab83bed349c9f75bcd02537b",
        ciphertexts: [
            "ae2376bf0a460af47b15e5103e403d9f",
            "2450eb060d7961804bb8b0eddbf31f64f32236f5a0153ffac12c6f53b7fac3f7c97f8051be09fc93572aee51fb65d90c8e98242f013b3dce40eaa316af8f945a406dded0b8e7f7005620402a61fe9a7f4a09633d3cf5458fa40a965c646bfd8e811e9a53f9b03e8527036f5f38cb09b84108fa60",
            "a34826d1e454e1f74bb486de13efe2808724a501f1de33d781f8382e4943d273fe",
        ],
        export: "19126c72686a72da53d9a2dbad151fa8c7213bd0bdb5c1edafc3fe503f4db311e38a1e6a692e1891f8097f7b1894d367",
        single_shot: "04c50878e59f964d29db11e052e377256728740225eb09e8cca9560cce36b59a77282fb8a9440041585a812b4eed85fe8cfb7c0120ebc50109823082f2362256d678a2d7e83c746a087e7d207dd434591ab40b443cc379c8420ee02e70eae587bb7722dc553a6a220aa3d4c1eac4327b877bd9f394c3fb1e8be3d8ac",
    },
    Interop {
        kem_id: 0x0011,
        kdf_id: 0x0002,
        aead_id: 0xffff,
        enc: "04fd68ffa433bd118e743fc3d138e6c4c39f4cb8f3b67670d60633613cdb5092cce040ea05acf85183829d5c9b54affcbe4d79c930dc71b79315bb674acdcee5fd528cfa8042605b62a1f230641dbf55178cd77928b88632fe9f2cce0f7c6e4386",
        ciphertexts: ["", "", ""],
        export: "01bb56232fca8c5ae4830ff3eac96708fccb71380686c7096b8140722e91ac310b70f3099bfb72e37562324d8980d505",
        single_shot: "",
    },
    Interop {
        kem_id: 0x0011,
        kdf_id: 0x0003,
        aead_id: 0x0001,
        enc: "042e0cfabbd40a74fa622b1d9aa25541352c6a86877b7e3bb6b21d2a7720028d3a8c51e109b53199b17edd0c54080e9fd64e30cb691213aaf470e8c83cd6a7b8af2ee50b6f6bd79d6bab5b82e4f34d94eb2e46b1b5bbd38be34e7bcbf1abc9f576",
        ciphertexts: [
            "105312d7f8103b12bfe0eb1d560269ce",
            "7e416ed43ba53fb994b02a4f988b383bb01f7fb26070b5c43917212bc13ff08e67de087fcba2a90a5c9de78ae6f35d3c1db522551e30b2981679daae4fc3ee05632e65cd5fe1ec1b3521220d3dfb8becd7e2f5fe385b2f196abfa1df7834dfa81c6bcc7d7ba5fa834c7d8d0aebcfcab780e88065",
            "d7b11ef3512ae74722cb36d0467e1913efc6fa7eff0322099b255cd1d99c889542",
        ],
        export: "f16fd7ced03d25ec23dfbaf655288bacfa372d7e8fbec91b589f1b52df8b848ec3080e505b80105a9a348c7c35f0bbff",
        single_shot: "04dd6d6afcbcad78f708a6905b32c7c2dbc159711ce2e2c234adb91e9425ea160ba4a92d7e29f4669615a1fee70448858129ad7f282b9a2d237f439118dc602b320ae21e956d08a855e92428226ae6edfc7ac122949ce8656da5315f2a41a05d0fdeb104385dbd02ab610de40dc2fe8d8fbfd72fa858a9dba80f2dba",
    },
    Interop {
        kem_id: 0x0011,
        kdf_id: 0x0003,
        aead_id: 0x0002,
        enc: "045cbfde3eb876f89572adc8b06f40bdd57efc995ea7e9cf9778a135804300338673f3b6758d92fbd11e9045c7eb25b9bb7b6fd5f2c7fa3373426bdbfe2f6a4db7982e622648842a7896ebcc0b9b60edc17163bb9599d61a258113435d51d394b5",
        ciphertexts: [
            "e3614c0ee065250f77110a11cea6c4e4",
            "4313ce6fc62db4ba12d3f39593e7f72cf57bf15bc9e49887ec15439235b969c8daa8c9e4692ae9aafcd58c236956355ab9551fd86a649ce476d0db40b3c614aac0714426c9d4c280d64266da0889a7c9e193d9cdc8e06cdaa91000e9b5cdd7a6b567ebc4b9dc06eac25a7e58d3c0d0afe0684acf",
            "4e02bfe5527ac50d60aca21f11c72a4e60489f7efd37ae138d30b8c1add45a2ed2",
        ],
        export: "553639d1a95cd61916e1c13a859cbdd7f8436d0c860118b673a3e28a4b8f0b03b4d608b3abfd3408c6ece803f8873412",
        single_shot: "0402a07aee07d5b26df9217bd61cebd686b3aa200732ebab0ffd4e97002f501581bdb83ff0040abaded1dc68fc26343bff252906926bb893aa7b9f2b796778577358094f4e6c515f27f84d7a56b9386eb9374810d435d1c2737683e5f930ca6ada3a105405e3dfd1797c6f65d52e9a080150f0e5c9d0996c2b9faf5c",
    },
    Interop {
        kem_id: 0x0011,
        kdf_id: 0x0003,
        aead_id: 0xffff,
        enc: "04f70bc36893826da4786ce1e929923a6e5a1730aabf969e0597f93864c41d3385dc7fa6eaba5054b8fba403a5a9d6f6e248cb3062ecf4da06a766619ce03395af8fe70b4ca5931648d84845afb845ecd308fddd5259807a5dd00e34eb79aff124",
        ciphertexts: ["", "", ""],
        export: "195bb091a156e4aaa98349370cb4e825d89ec6d90315ac186c901423940e67bc917b9146ecb423ed964aaa68648a9b4f",
        single_shot: "",
    },
    Interop {
        kem_id: 0x0012,
        kdf_id: 0x0001,
        aead_id: 0x0001,
        enc: "040100475730a10fb5d2e298566222002b1ed79c1ee831a4827f27903180967e73124a697b8d5a00c23f1ecf6b44cdb2c1571222a7cb039a7af1695d05ca73013526ee01a8a2e6d41c5420626fad6c526f6777d1121ac985d41a8b5d1c82f878899dec8621410435a34a81fa61af63cee9a7ef8224079a432344cae464ba7e197dd930113d",
        ciphertexts: [
            "f4d710772b1386b64ce123910581370d",
            "4721dca84ba4e43453cabaac2587c337a230bba81317c169505cd73b2d939f949c08860f59b7a30a0d34de4d3721f816baddce0f95ec7ec8ceea160474ce9e8d7edd8e91e11375c2280a6fc14431bb8f13c480b3a6913bbcef2092041f05ed9f6d7d54fcf7e2216370075491a894b9bb23774d15",
            "f2ad7353226a46603b36c4f0a64c29301301dbd7b7cf4a93349a62ef387a3ee99c",
        ],
        export: "9f4124e268c69b9efeeda3ee5ec2ecedba3a26d1a6dfb08ffbf95c26bb70814003948c245a99a6454123cc6a81fbffa7",
        single_shot: "0400e9ff5e925926f8675f3e997dae8c6cb726b9dca686844ae2d42b08d2c313ee32d30648c66f645d27db412cb774f79bda313105ffb0430574082cefb49b6a6118ed0019126027b46f223a2ef1689e65a73c7dc03426cde24b9c785c3ec592a6fb3bddd5759e22be942ce286610cbaa3f8579b4f1c91e8e72bd153b778ffc165774b5ed9ab4106d920044fe60e6d3a790b7a50161b42ce23d9428e42595e8d",
    },
    Interop {
        kem_id: 0x0012,
        kdf_id: 0x0001,
        aead_id: 0x0002,
        enc: "04019ace46f757f5da7026cbcc0e940516fa2d4f02bc8636f76799d2fcef20873fbf4b13aabc39f1726b359eac93fcd21a5cd35c68ef834564ab985f0b0be6fd25b5580190d93118cdab38f6f2df1390e504383d756d3b568da3ce8c39c6072e766cd9b4b77a465efa4a7a509d97c954e8f02762a04af309efdcebdb1c1511d6f7db4e2cd1",
        ciphertexts: [
            "a090e52dd378d0efe4d13c33ce5f7e0b",
            "0d6b9a252bc7641f65870e62f96451b3888f6af97c91eb09053c47bbf906767efa3392ff7a3b7fba680bb34d64d42e55ac11a746c64f40644a7a0a2a97af19cee34a8b518925f5592028badadac8228a7a4eea774b1df33762ab90d36550dba143c11e073ab7cc7cf37d2bdc9bea0152e91202c7",
            "9234928859b35f9a8c3a2ab8296f32b644aaf1bb2004a6d0ea898c1307cea492a7",
        ],
        export: "b322fdf2dbd4b75ff5e8c1702b33cbe6256f620e9450f8275008e4fd6c14c8bbd39a07b3baea8f20f50a98632c539223",
        single_shot: "0401471085c312862e27f077aeee4504d538b3d8c98c551fb48b42d4841e4a254d2f700b9e8727f931d9e37e287020e88456bf3b922475dbcd1f41b796be1fcdbac30e01f2bfe9fcd7c123dd7a4a25346479881e097359fe405e1eecb1e1e4e233a3cff8bdb0f1ac57b57db04e304eb07b1d82a130b1433c1c5bd63aa3656dc664c4db2813d6f0a94d63ca54c868f40b6fd10444c28ea538c8c114cd9178b170",
    },
    Interop {
        kem_id: 0x0012,
        kdf_id: 0x0001,
        aead_id: 0xffff,
        enc: "04001dabb4f3266c1cf906b428870729acbccf432045da97a00d0f0e2262bb4ce1744b0ad340777385d2f3134dfbc4c2c6e61288245615b264e2edc687adc445a64def012d7b92eb2f69ad860924900c9331d5ba6bc3228f1d21c369dfbacafff3c2c4d9b34d6bbd928069c707ec42eb8ee48702aa51035bf4568e202aa57809305400b395",
        ciphertexts: ["", "", ""],
        export: "74ff45c2608cb7ab64821faf05566ad1fa6f662f14a4f4c5d59139f72b1bb9c266e7d0baacba5ced83614b4f6c004d8c",
        single_shot: "",
    },
    Interop {
        kem_id: 0x0012,
        kdf_id: 0x0002,
        aead_id: 0x0001,
        enc: "0400d454fbb4b0aa222f30ce5c2f5753bba18a6b04f175760735a88b539fda9cc580d4c6644132964730c440b6579106f914addb8eae386080f1cf84f50c36cf83e216002d292daa3b546c39fe957acf0e9efcff560728ccd4b4e962059c9daf427f8b8062ad404b5ef96451c4928545258c096f6507685595daee8b358370aaa5e06c0bcc",
        ciphertexts: [
            "ea6e7d74c20bded1c3a64478f901f8c5",
            "16a2a5d9a631b015bcd88169d4e6fb8e93223431fb0dc86ebb1b51ee7225fdd81462fce0b83c44a093d5f8fba68a2b79154ac127b2f932ed47108e6ffeaa20d21fb7200048ac80e7969e61adfc54b9ebc5a85893c243355f70ed5e2b9b26212a7d92974ee38219096b672d63c67a06348255316e",
            "61d0f9e0492ee8b9d94a8aaba247022852633e23871a5c5c0da59d3015ec7727f0",
        ],
        export: "ebf87a3a7027d5cbf587160acce2788e105d2ff03d84a36a4438a5d3fb378df858a0dfb1cfd759a398f35d4015d9141b",
        single_shot: "0401b33ff33076fef5908c2a076baf2c44b25be4c8267bce8d8c75f1f842d099e3d90e3f0586e7e3430c85e83f72f137ee3653bdf6cf20f917b75651bcf45fd636c25e0122f51bdb2391e50ada6ac7e1f85c68d2273a1d1e9a02179f296884db506c4f96eb95805714dc68a8f138c354f2bd04accccdf036d247e16287f6032dc9a175f19bcec2236ceb3a4cfb05994d9372e152b879adcd46791963ac41dbc9",
    },
    Interop {
        kem_id: 0x0012,
        kdf_id: 0x0002,
        aead_id: 0x0002,
        enc: "0401dce445abc6559da2f1cb4d77dad0b83da47cfe69ea6e4ab06cd79a1c4a25c3b367011c5f9f695737850ba8099a1e9edc37f640d799e87bc7bb6c83bbee6d2c1796019243e489da35dc2b909e8b9ae8b57b25169a2a56a16ba99e19d4d26f0f181ed2c7f1e2b86fbd2cc2e76f60b9514fbdac6d84a0aca5474329afd9aa91dca177bfc5",
        ciphertexts: [
            "c9665e9b8bb61d192431565bd08b960c",
            "db603200c1ae22df08b2a3f7f43f0e874636f1a39aed2728bcdf4da0f7865f242a6ca6828f5773cd7fd13e806cef10aa504bdbf1e138005464225cdf468abfb0f6060d540f17ce19b5034f497e1aef7d83943ff9297d97e777fe1c20109b4497f0c0581024db7fbb4d1e1aeae8b0c0f6651a2744",
            "37d1e062096cbdee7bd382cd85daae3e4c9c950dcdc45bba19b20ce29719cd6b1b",
        ],
        export: "6bd5ce7ffa0bd971ce9e9e0bd1e8326598474467d38d48f94de0cf9dd366e4b910058680ff9deb040f5c63c2e679a032",
        single_shot: "0400169d4b25741c663a0656a9f7acd59b46b6b0ff00d67bcf5f9eb0450656b4bd64afc747a89a734e10f44e4fedd8e68309920c810da342ecf6f6674118a2455a0476004e5b943f01f227f2ce959042c3ec2e6602252231b90d20a43b6699779b44df58bbd2c4a46c2bad10c66342012546ef3108950dae8a2cb3b18141fee3935aacfb6ba1aaafe738c3d8ee37b3e993a1d2b764506324857964e934a69025",
    },
    Interop {
        kem_id: 0x0012,
        kdf_id: 0x0002,
        aead_id: 0xffff,
        enc: "0400dcbf3d64abdd5034b86ecf490ce3cace7910db8946d6637d70788adf031c32e9c847c46413b8885946d88eeab8a8d090a154089fb9b4b6f2419ffc24090b1173ad01b4b2cf4f26aaf78a4a66a2562b0ae745ed32abe98e1555a4ca2098a275ad554f63eba5fd9fbceaaf8e20d30b56af02822d1fbc6aed360f86131230fed93893860c",
        ciphertexts: ["", "", ""],
        export: "ec3171778fdd548eebdb71fc6d5ee57f5d5966abb32e0e5e709f45e5c73defbe5f0a4fcdf959df3db40818aa9b7ee49b",
        single_shot: "",
    },
    Interop {
        kem_id: 0x0012,
        kdf_id: 0x0003,
        aead_id: 0x0001,
        enc: "0400dead1e8c46ea2385ad15bfb8a08c0f13dc5881ef16b0cb27964998dd9e23aaaaf3a56a50e70b29c7aa70eb3086be79275a2e813cbad59facaffffb146da4358de401a52273f6bcce48a15f422f507b0fcac92a13773e1aac71bb2df691474674812c160823e66a0258c36bf74dafcd313d2f1a0b3935f85feb56951f072d5ee24a9d11",
        ciphertexts: [
            "006b1cb50225a87295a7e336e3a2a865",
            "3896502f5600f6adecc8fb25703e881c34ab9451c051ab568ef9fe7a22b01992c2a5e5b94043fe2b304711b54a68253f4de1f8fb276b29b316d21009db9b8a6d37abac35d198825c443c1115f12e0c3197511c19a8753cba00fc40e7847048a91748bdd9762e0ae0679c83c14e0be6bd77402f83",
            "77d2781ff5644399a2345bd0d0d31f07e8dbd7f4a47e740687736104287a2a622c",
        ],
        export: "7db9d048314797837ab0cb144f5c9928d141fe13bb082da3e51fc64a337edd7cb8bdb29eee56212154cf01a3bc480c7a",
        single_shot: "0401c36c1d1a886f3f9d9eb057b8d6041a0c8e2ef32d432ff761ac32395da5ecc319755cec9b115d5fda01057c1535cc05e77f98efe0ea6ea4f8b5bfa2b331bd17ec110123df826643fb49f2155e8696a6c3ea28abcd02a6ebaebeeb11db377693a3776abb6d70c51599d2b9bbdae484c351726730d574edce3939fcc80757ce08fd4466608a3092c7932c7d359496b5ae96d3707f899cfd6cc285331119e13c",
    },
    Interop {
        kem_id: 0x0012,
        kdf_id: 0x0003,
        aead_id: 0x0002,
        enc: "0401ae3dd939bda88f863192dbc8fd722d9e50c2eb90046e1e92c692ff3c24eee4290bf3224f837dc590d056488a9a4eff012817be3f0de9c4b3181ca3c603450fc1090009f45d0856eb2191d00a6306be51a2629a4ee97bb3cb1bc07c976a6cd98e02ee78cce0e200c5d97d652381a237679d9fd0ae0f8e8825b81766739bc0b15f6fed01",
        ciphertexts: [
            "a2c28ac268d6b7bf2b77cc91aac5fb83",
            "9c1a23129375792a7826ae44917e287863fa68ca2b2385815ce51a3799b98b8d5630fe26a282ce017d99cf2d9a7dd7fe45a96e7c853a3a2c0b64a5838babec6402d7abf1c20970fb0cc36fc346e24bd0ad475b52bba9c9bf84689f0c27eeb80bce6bbdd4f39e683d161fa9c436bde64baaa97582",
            "e259c9d79039af70c427acdd293b0b9b7c7e0d6febc289765314958c1cdc19bdd3",
        ],
        export: "8b767cdfec3563a1de4fe31d7402f7e022318be1785459300b055c71171930c49967d318ba23ac1fba8cb2850ace7c94",
        single_shot: "0400d09cebab05a1c6ce557f7bbb75bc23276f8bfd7623dd655f373c0594cc863b650125c4d8430462a052a6c75efbfbf6cfb5644874705ecc3d14017e4da2de7c21a10157654bece2d229536e9274483daf238f6e76c83ef8845db428809337e88a5c6524879a7aa4f239bae9e0c0fa54e25276b616f13875b4b0946b64022e7170665b0c10259643557aed43f6ace0291f1b5330ff8673d3785251e28df8f5",
    },
    Interop {
        kem_id: 0x0012,
        kdf_id: 0x0003,
        aead_id: 0xffff,
        enc: "0400a52078f48dc6889aa288c7457ce2764ff6ab6e6729b8c90c6dbaed5aec45c8a1422c8ad87938eb32b51591236a94d291633db65dd8b96178516babf6b6bb1eb1c201a7a844dd9492419ca653def6b4b718583f415ba405309b26f9681b04d1907ab9f1ad76140c2afebce2b7b03e5895f718be5d3ec67b2b7ab85c2821724570d86725",
        ciphertexts: ["", "", ""],
        export: "508e3f085285eb972473bc64df0741389ee0965d00c5ea744faa4b7532287a23f4331041ffadb390858e58a17d30528e",
        single_shot: "",
    },
    Interop {
        kem_id: 0x0020,
        kdf_id: 0x0001,
        aead_id: 0x0001,
        enc: "586e4d0bb6709982c20266ece9e3be6d380d009d643539b7d81d3b176a23ed21",
        ciphertexts: [
            "3dfd50f741c0b82bd448990ff61b3cb9",
            "070bc4b42a95fc578542710bf3bbc2b29c00b30772d0d21dac980414bb98ea6e417fa5e7fe30a4ce37701515ce4c173363e83dbfd1d8727afdc06d875328c4166460a6911cc29c0632d0b9e038daba2e91b58fdf7cac8cb17efd8d0bd61e5adeefef9136822bcc5368bea21fbc93bd04768dc459",
            "f0f347c41d6a2cfe14b7f63d1deb234dadb6832dfc8fa3862b9135ab32b5d2cf73",
        ],
        export: "786711a4c3759b4cc698391e106343f5018b4ac0c02897306c592bb1abb6d959c23aeb5f01beaa0a4d7d2596f11621f8",
        single_shot: "15c73502f029942cbd72511f9a401aaa720a169b9adedc6f9bf654a67181806f9fe8fbbed9f5628a3ad6be83861cde06841ef95f673e5134817b09",
    },
    Interop {
        kem_id: 0x0020,
        kdf_id: 0x0001,
        aead_id: 0x0002,
        enc: "16873670d7893ec8890851c1058dcd2399f18f16f40231d747b70f95b63fc06d",
        ciphertexts: [
            "4a78d2b1bed50952ecef85e6becf9b8b",
            "2e2d1ef2a0ffb9ca08059e7863d51491c8f441fd48602deb91d362d1d3eb1bf75e039c9176ef605cd0d1ae47e1c7c47a8d71ef87bc938470dbcf049e9540f762e5d80dd0372620beb3758d1a64fbb43a93fa98492d3aa44c8288f388392ee4cd1aa93eb33164eca6b8d31f37321cb9b11605f389",
            "cff21414e0cd40ab3012767a04c05696c451e9cbac025211d264cd43f04cc9b0c6",
        ],
        export: "5abf66284f0701f02cf2440d927f072940665c2ac2366c24ef1ffdd3057d1ddb7d6b27c5fad9c4fb002f7da05c35e1fd",
        single_shot: "a3c3131f665706a3bb6a013dfd6b5f38aa81409793619082fd0d73f143dc457f54a38179194ba30b1a69297b149e73160edfecc07b6333ff7c5541",
    },
    Interop {
        kem_id: 0x0020,
        kdf_id: 0x0001,
        aead_id: 0xffff,
        enc: "66d2458e4f6b13b11e8c4e52deb0ed3db680ae774c1100f2980d329fbb868011",
        ciphertexts: ["", "", ""],
        export: "17a64b90d118c8fc3381fae6c1c76e03aa0610b1d73172930398514314764fca6c785fa98550b21fb20cebdc2dd5c537",
        single_shot: "",
    },
    Interop {
        kem_id: 0x0020,
        kdf_id: 0x0002,
        aead_id: 0x0001,
        enc: "a1df1ea3cec43d0b126ec03b68030518d37f9148be79cbde594616e8b541d33d",
        ciphertexts: [
            "dcae71668f413d2f353218f7c3b9736b",
            "0c7f27ba00c0866b0f365ab8619f95d775d904c0a5cf9233f885169e12227b83a061feecef986a2d314805306b16c450b85f9dc17431ac39c2c64d62640e00ade9ef067a4b9ca89050887ff224330b28cd4a0da24361bce68f691f5185c3daf75c6cf933c0420b72e481fbebc741ba7aa9651f57",
            "0cd438fcc55ef194e842034d8b7d31d1f855060fd63248384625d59069a251c29c",
        ],
        export: "06cf51906073c39ef29fa8d61d5170ee4adf9050a6e737795613ffd263e3ffde039ae75caf114ad9dd0766d2e99aa773",
        single_shot: "b73251319a8d619e649814bd6fe083319c023d1bf7e844876f03c3e98a667038be6b0cbb88f51eaa4782e11f48eb7feebc470de611f338ef4626fb",
    },
    Interop {
        kem_id: 0x0020,
        kdf_id: 0x0002,
        aead_id: 0x0002,
        enc: "0f00a26a33bd07620259a82113162832f2443f978768894f22b98f192ae2645f",
        ciphertexts: [
            "9b2090ff0b93cac4b2e09fd868e2d674",
            "7287b9a2d765a250df855301a3a9aa73e6fee0ea1f70a2bf8b6fbb102b3a0a4448a41072f4ec5e5c16d306f6a3b5743c3a933cefb5a6732c58adaf6c0cc2469480ccb396a5c5b29f3107c3d77affb245f0cc69b4e22e1cca466134286f6548bab866f3eea81e0ef9b61f1db4861098f3adf042ca",
            "0857aeada7fe9b463252fbf777775874b721fb11d14df019e4f1ffd863185f0268",
        ],
        export: "b0aa65521857ae9db7e2097b80be3341ab681cd8a36d9d7eebea801ad11aa333c118dc92e38a6a6726478ba75e40c0e1",
        single_shot: "314bd5a45c034e29737dcfa3684510a54ed43b83ff636e64857b1cc7a3b25b4bd445d08e493549b51b90e2e8fb9aff4959f0fc9f2b1b8f4b9fe93e",
    },
    Interop {
        kem_id: 0x0020,
        kdf_id: 0x0002,
        aead_id: 0xffff,
        enc: "ebbe08331ba4b2fe41b614ef13c212a775607b79a4c4cb46c87a2fd591315736",
        ciphertexts: ["", "", ""],
        export: "ce13c403eb1492ca2dacf4c6c73450bfb277324d71e713a6eaaaab45de9c76f7698c2a8a8d75ef3b1d31d218c8b1b1a8",
        single_shot: "",
    },
    Interop {
        kem_id: 0x0020,
        kdf_id: 0x0003,
        aead_id: 0x0001,
        enc: "5d9d557278e9c0237d96da80c749973c8cbf1c61b46b08cee48efdfc4e577474",
        ciphertexts: [
            "3d3227d16f78e525290e4785b06863b8",
            "27c7d5829473588573b04d97dd8da28ea16819779fed32fbda09eabb569a2bd45f7d127c605b7012679655660184ca88f162b07352a916552038d3a14a7e7a3773468e8829026325bad83039d5b7123f4e9b628700a41025e98d47bbea73a92f18a7da844faa4e40b50891a039c1e3e961e2dfea",
            "81266bd0f01a57004a80495cbbea9e8cc52e41382cc3bc661ee6e9c6ef600312a0",
        ],
        export: "0607a87fbfb2de9e25989ea184818682607b71adfbd3435b16bd5b86231b6547659125808b7513b0925a9854e6225b9f",
        single_shot: "08399a7efe9005ebec233608868d339f992a3474234f8f38df96facbfd73ec229512dd808d425aea92c808a60714ce9be9d803f14c0d518ad09cd8",
    },
    Interop {
        kem_id: 0x0020,
        kdf_id: 0x0003,
        aead_id: 0x0002,
        enc: "b490289233b186fbd2aa840336c0b5c7314e1ee5851cd3999a6f33dce0e4c437",
        ciphertexts: [
            "d01c98384ea19b2d60a80b98e98fb451",
            "351fdef0e171632d94ae7851942f140187c05e95a8fa595695217d5e6fa099c3d0b6aceaa9b57c53501afe7722b97e179cecc1d5dba718f114e8a6da6923f62b049b418c456584282d6e84b4509bb6e425f98f0dccb0baa2076e2687ce5f2ac1d8c83b595f0fc60645b22fd20468f1dc30c9bbc1",
            "f3ef0235d761f38567acd6ac4573ca27d875e72aee462a2330d361062a6881345b",
        ],
        export: "cb19fb27b4db1ffaf0fd304b47d7e9ab4a614054b6e0626b58fe7b17f0288dfb2af1ab9fdc79a720874a3d475462b30f",
        single_shot: "fbb73072e59485068920de5a6c1f0c5754721cc9e6b3ae474d1e525d57724e43387bbafe662672dba32d98948531d9a85fbbd05951083bc82c4ba9",
    },
    Interop {
        kem_id: 0x0020,
        kdf_id: 0x0003,
        aead_id: 0xffff,
        enc: "30a7d8a8d39beda96d2717bb7a887de53b7bb85688d78125aaa90a17f6b4cb74",
        ciphertexts: ["", "", ""],
        export: "0cc68e20328520efab1dba187d891a0f08ab5344f58229e4bef7cfab0401e4aa18cbc3938d8f1be61f8cf1426a608d24",
        single_shot: "",
    },
];

#[test]
fn opens_what_go_sealed() {
    for v in &GO_SEALED {
        let what = format!(
            "KEM {:#06x}, KDF {:#06x}, AEAD {:#06x}",
            v.kem_id, v.kdf_id, v.aead_id
        );
        let suite = Suite::from_ids(v.kem_id, v.kdf_id, v.aead_id).unwrap();
        let sk_r = interop_recipient(suite.kem());
        let mut recipient = suite
            .setup_recipient(
                &unhex(v.enc),
                &sk_r,
                b"cryptors interop",
                RecipientMode::Base,
            )
            .unwrap();
        if suite.aead() != Aead::ExportOnly {
            for ((aad, pt), ct) in interop_messages().iter().zip(v.ciphertexts) {
                assert_eq!(recipient.open(aad, &unhex(ct)).as_ref(), Ok(pt), "{what}");
            }
            // Go's single-shot output is `enc || ct`.
            let single = unhex(v.single_shot);
            let (enc, ct) = single.split_at(suite.kem().public_key_len());
            let pt = suite.open(
                enc,
                &sk_r,
                b"cryptors interop",
                b"",
                ct,
                RecipientMode::Base,
            );
            assert_eq!(pt.as_deref(), Ok(&b"single shot"[..]), "{what}");
        }
        let export = recipient.export(b"interop export", 48).unwrap();
        assert_eq!(hex(&export), v.export, "{what}");
    }
}

/// Sealed by this crate, with the ephemeral keys `DeriveKeyPair(stream("interop
/// ikmE", i, Nsk))` for the `i`th suite, and `stream("interop single ikmE", i,
/// Nsk)` for the single shot. `bench/hpkecmp/interop_test.go` opens the same
/// bytes with Go's crypto/hpke; this test keeps them in step with the code.
const SEALED_FOR_GO: [Interop; 36] = [
    Interop {
        kem_id: 0x0010,
        kdf_id: 0x0001,
        aead_id: 0x0001,
        enc: "04417f076d57fbf8f584dd0c2df6c9f137c496ee83edc3d08c5bc41493e67db3005adabe91edf5b269152331499e25add34b8c6437d8156ea9e2ecc6e283267546",
        ciphertexts: [
            "6f3957c16aa54fc23f4e9f1cdf585741",
            "bf779b29eeab11ec8d5fd389dad6f60ae2922d129076448aa1e161f50c0187a4aa559584278bf660e9ee9a8355e25b6041de1c9edd587af03ae51a6c08c54b851a9dfbaeb457b23a1b8cc87ad9379c109853d1d3b2dd8fad5512f1c4135a52c8d0d0228876dc2c12e05687e8a3bad76b891e7e9a",
            "26fc2da539527d27e1b4dd49d948a9b311a517a4944cae72006acc8d04aad44458",
        ],
        export: "7fb7865b1b11bb1f0c089bf54a215509ec8ed7d316a5b3381bfd468631fba22f3250de58434c4fa593f5f468f9edd776",
        single_shot: "04ef24e02055c4b400f9892db935134006f8cb15fab5249da1d158f1b07b01b6daa178604f791615d907ed16f78550b844121602ccac4c6a2f1dd956aa5ca2914940e233d08813eca53ebe5f24ff2a8c8859f096745d7d9338282a8c",
    },
    Interop {
        kem_id: 0x0010,
        kdf_id: 0x0001,
        aead_id: 0x0002,
        enc: "04beac26e846111c5d287342b82bdfe7e31004e1778bab12a8007011c4afbc0ca52f99ba70ca7b0497a7ff051aca93544b78eb33bd5602ee6d13e5ed8d35b042a0",
        ciphertexts: [
            "5f0c902ba6385681a7946db6a951966d",
            "88785d4c54652932479612de87cb1fd90f67f7a5a66def0acafcc103f3a1aa7ca130c7f95ef4a0eb39a63dfb7e7ff55ad97d9679eea079ec79600dc455e4c7559d18080d628d92499e5a5354468cf80523007673653e2bde59690c0e0a873f0fb61e65e78f8ccec9fa34cbf9ae08808f4e41a6e9",
            "f960008655a2ddffe7bc05e7368dff6a8438534ed2b1c25266e16d0fd8af62394e",
        ],
        export: "ab815e8a7843dbe857906263b7e479c00d9a38a2b3ff7b5208f9186e7341ca02c64a315d65d2ce16f9dc61cc505d2a3b",
        single_shot: "044cea23ccdfc4455a8aea61574c853db4011fa688c2326cdb981462909970ebc3c1064a62fff169a48bfd5e31828bbbc14d9c569df837cff77058a3d5f57e050ef022246db53970228cbc312bb4eb8062b69f36c5f5a56a25ba5dc1",
    },
    Interop {
        kem_id: 0x0010,
        kdf_id: 0x0001,
        aead_id: 0xffff,
        enc: "045ef5d52bcb7261f97190efb759567c82b6b761273f451e1034ec21e63000311f5013f4c5c924ac937692f8c153d4f8e87d36fcef3d1732d13ff0bfd96532b1b2",
        ciphertexts: ["", "", ""],
        export: "002ffe006a9706fdf995032a4d951453ddcfa3877523534d64042a66db5701fbca67dae5186a020e7a20e1294f6f2b35",
        single_shot: "",
    },
    Interop {
        kem_id: 0x0010,
        kdf_id: 0x0002,
        aead_id: 0x0001,
        enc: "04f27d180430df2fbb1b2d0e625e4fb5e9f076d06806a4a5be01b9cace1c82b4f5ae11e0c0a6e78a1f3ae94366d059518583c1720d137ae1a518bffebe8a21599e",
        ciphertexts: [
            "23f826096289216c21571f427f819bc7",
            "12503396f8e80fbfe8216ed9fff0c8c892105dfa099f890d75b06c7c95b6786e7f3e552244ad8b8eb67d9a2f4602c9b190b0869c103f41891262f9601edd1bf0cea46923240c4221b4971dafa956a0e793c17cb7d1aa68848b2d452550b3d6d3f72e5d19c5a754224dffd9dac4c0c56ce21dd055",
            "bb33a35614d9610c72578de27161e264eac835bc7caed21d2797f292937b41af6c",
        ],
        export: "0de73784b101bafc9ecf8b756662f7c4959599e787151bf986870e70e6c8e5412e177a45a0065fe3675356fc2d8cb0c5",
        single_shot: "0408bdaa3923140e495b6c66883f2264b663605d593239a8cfbf36699c69a075722c7668390f90c8b4bb776c2687ad530d847c68630181af95575e8d9f74e541fe9ba84ca0a564a437f949c5473a5ed03d22552b87ec2b0f7500129f",
    },
    Interop {
        kem_id: 0x0010,
        kdf_id: 0x0002,
        aead_id: 0x0002,
        enc: "04c8039254d459983ac65b792b86cd0fcfe3014483a49b3baf210088e7d0e4ad20e1927a3b95ff4d1777fe10e85d5b5a67c11059a0122df3779f7b5fd595cce388",
        ciphertexts: [
            "43b7ff42fe1e074b2f6710497f81d5b7",
            "b3b741f1e9d15453699d15be37b821cb96610070cdd2f4fccddc1dc9f0504c275575afead2dd15f8619eadb5546ea7f171fd73834682e85c1afaf1c153bd2acdd5071788b3221df0db46201477ae85523925945414e8fac351ac2fb44d101858aa2f4c17fee1f0bebab08a7c20f699eee215cf08",
            "f920f68c5e2a037589132f7c2ae84e2403439970498e71028556d29fd7b6151be2",
        ],
        export: "87a2f7fffe7a8548521e219569af4c5b1e31840a1f14061f50151a1ee20709bd7c33c3a1a0e82e4d489a789024245d13",
        single_shot: "04ddaae1cf1f663efbb23dde0fda2f79a6b5d91831b4d4f4247c48c69e3e219e839dc437e0f645bef95563ec0836a35e82fd60caef96208033e18ceb9285e1f3f2b3a7d9a589e10e7ecc038836752a6a641b03067b80a678fa77682b",
    },
    Interop {
        kem_id: 0x0010,
        kdf_id: 0x0002,
        aead_id: 0xffff,
        enc: "04f6a1d7fa527ee4f1135a5155d70d16836e514b848815162e5ae21b4dcd57bc68a8bd10a724dca30f1f705bedf13b8529d9185949a360d4214f13c9c3983ac12c",
        ciphertexts: ["", "", ""],
        export: "a7b8c297c035cc88d15458fa4acc741472216cf0bf9002c61199f8a1bc02f799b2d5b8ec28434a40361bcc999da3df9a",
        single_shot: "",
    },
    Interop {
        kem_id: 0x0010,
        kdf_id: 0x0003,
        aead_id: 0x0001,
        enc: "0410ed5c83524213755cb6a95392c3c67e46139a6382dcc3f6a3c199fc57885e2cf14d0f6e7e698b5d638052c3e0f4c0888bc273cd281a8d94e93c8cd5968c0a61",
        ciphertexts: [
            "50992b1e4dc2c1fc047ba46a33077276",
            "2667e34b9162337cc6548d70aeaa20190180a8b03d176bf43fbde624a583041f376a6d93582c53a2c6b521b9e5f929d1ff522aa25f0a708333fc6db4b1d9f97694075e93fd727e56d7c5ec797a6e60aec97725142e252a3f2c8b9a06eae0c32bd45b53cd403d39994a6d2261680c02102ae29bf9",
            "66576bf8209a715034a752685426d3380fad78951a05454e93e732380d827c90e5",
        ],
        export: "4ec29ef6705f90e67ed56067f7ae1a4c0f42148fdc31ca08886cc03cecd71b13994564cd488a2bdc624a5accff306c9e",
        single_shot: "0485a60279d24ebba7bd69038c70adb0596b9b0f0ff183ba00dc63e92368b4a269d975db1f212e0cf539fd41e6b55a963cce9cc813c4c1d41196790654f16afbdcdb2865ff5425f603315b90823053b18329070d290783c355b8e4fb",
    },
    Interop {
        kem_id: 0x0010,
        kdf_id: 0x0003,
        aead_id: 0x0002,
        enc: "045f12be7f725ceef2681e4892bc2b7c6a163f6faa9941bf08267cb49e5f8c084c9b0b8e0f7d4ab920862c2b81ac02459085751bc4bf463b72303c122e9c97f46b",
        ciphertexts: [
            "f5622e06ada35a59fafd23a934902567",
            "a2b7d331e93ef09352c6ef38c82e82370479ca616db95e62c216ac1eefef5b23ea9ff9780ccaf721d589383b51d29ef65d26b4f2ce21696e7f1320d89821b7c6bc21a89d2dea8868dec5b780191013f6870bfd3bf2441ce46f4864774364eaea7a1965b9ebd40e614a95f6dee4a6ad62c44288dd",
            "49b45c11ab14f9fa20352daa1c57eeedf9d2c4516600279a481d1d554fbea372f9",
        ],
        export: "2ae8843db55c72942193e409c6d25af1ecb73e40c587ac90611646e815fdf6c3f74da2bbc000a10256723297d485dfdd",
        single_shot: "0467b20a8ae339c4ad3157bf59aa0031fac94ecc4416f8d1eef5b64f63fed4eadad621e678af7e08dc15a2f08fc11017d9aa6d055aee23d22f237a3350f5eb1426f36bc80dcd17b3060f3c8156f799891d8d942e748f3602132af3bb",
    },
    Interop {
        kem_id: 0x0010,
        kdf_id: 0x0003,
        aead_id: 0xffff,
        enc: "04d3037a245ba300ec4031fbf18f66bca8ec3b2f4ad66b07c4604adea65cf68dbf8c558ee0b1d61798377ce88c2c5b4ee09212625392dd04e95a2876dfa5669762",
        ciphertexts: ["", "", ""],
        export: "b3196fc1e9308deb1517bc8ede4b258c404ed976bbb3797f7bf43a9da6fe6104800916eedf01a2db3e865ce27828e88d",
        single_shot: "",
    },
    Interop {
        kem_id: 0x0011,
        kdf_id: 0x0001,
        aead_id: 0x0001,
        enc: "0406ad0037dee6765c177dac5dccd01463891d84c50e9538b4a844b50520776291703dc74328539ca492dbcc21920ab728b1d11efa7017d55788b804d8f19a1b4c2941dc2174d8a051d77da3833826415d3fc288f0ea27d0d0eee54e3001ebe4c9",
        ciphertexts: [
            "53bd0a9f6a7160782f2dbfbd5eef9419",
            "a7caf02e361660d61b32a97b7342e039291990b50e0961d66c78872ec26c7ec27efa48f4c1ebb000bb56c574e9dc8caa719176e6eb20307e175a6be3c6af011003253e162844a67507e40165205348dec3e2afa13a1b0f9fd848ca73b85c30da7156a306899a7ab36d6b4bd2625d10a3999d6d79",
            "8e84b9532d0278b21d408f815f059a6cc8dfe1dd15c51378df9a9a0356933ee4b3",
        ],
        export: "48b267ec243bb3b5b9be917122899ea59c001aa25bb4158dc285234c2fae7131076b5d204f493ea260d1b09077083394",
        single_shot: "04223daa235d3e8be284bccf9354aede56be08da70f154ae99fa97c931f70f97657a5b1d34205e768da176625cd09ec3dfd25a6433a2715e141a7844855175a21314dd65868ed2193c527f62c4d7f5425292b98b908cdab436233c6a1b3ca050165ca2d483d29580ac946ac1ca8fb232615e85cf32bbc5410efa7f19",
    },
    Interop {
        kem_id: 0x0011,
        kdf_id: 0x0001,
        aead_id: 0x0002,
        enc: "046984d9f768378d490d88b4f08e58f0445ed7e621517fc3ae01f1911c8fedb6927adb74822c468361648951ed6d7d4d2ee5777ac06c0f9270c79e7c9b236dde9f41dd7eb4bfc69ec7cb6a06de747d5f92dcae8f24e00703d64a55ec161bbea24f",
        ciphertexts: [
            "dee67c7c4be09e50f7c111c63c48be77",
            "25c6e92511c0a40c2e62cd864bd902429933e30f79d0613093c13a45776b71fbb17a3c074dfc369cb1e9db13215c8e51ff611b7605e878138f04544770a6b930fc7bf76443e956be1700630fdfe9d495206763544385401e359e882e9b8c04f63009ce21fb8f84ca4d089e54ca0f99da3547a783",
            "b31e2fc3f15282e76d8aa52a1272b797d5f25535d89e9df44fda478ad0ab599987",
        ],
        export: "d748704ac9664c92d95093476d5aa656cad507a8ee8d943a8f230c8b51f0ade47190067c241ceec079b6750f9876fcb4",
        single_shot: "04e4c81ff18e4a18424fcf13834a82eb6ecbbf57c3c44c62ed3bfdc55598cf6970c1568591404b9cb9a75520c296b9547bf8641710e581744720c2573e293141baa29d5a401cda98dbc12cf82c43571376c506e21e1904c0542c1d74544d63c91931586726bfcb0ec54994d4e1810d9464251b681cc84aa0b5732449",
    },
    Interop {
        kem_id: 0x0011,
        kdf_id: 0x0001,
        aead_id: 0xffff,
        enc: "0467bf5b3808bc65f774cf5e5efc7d1ce3a5ae3175caf322c4887bc57eed00a04ae7e5a2688485759f2fef5049b4e28da8a1c13ffe6d9976a8b7f4b44ae02447c16c8ab10964d98ec6d934db6fc897022557aa39da2120bf63d4a00c6b35856042",
        ciphertexts: ["", "", ""],
        export: "5b11e4b09d613de14b76c636e5b0561a5b738bd17c30fc25160dbd3a60d9b1387af942eaf74ca94c52e8655c60adba3e",
        single_shot: "",
    },
    Interop {
        kem_id: 0x0011,
        kdf_id: 0x0002,
        aead_id: 0x0001,
        enc: "045e93783bb3dfcd8f1de20e0d643b81a7b4dc80a4eeb911c3eae80ace73bd3e2ea4d76fc8e57815a1dc582e01df0004a0b1f82bb9ff655e3a0dffccfa5cf27fb43b9f11d111c0baadc67624267b3c2f845fa084f86460591d8aa03cffd2e10e08",
        ciphertexts: [
            "13d717ce76eff762ef17c333f025f9d1",
            "ed9856d9d4d5307dfa5971ecb1a98265d2159c8c19593ed978a4dd20202b2afeffd812885a0cab62a3b74ab171c8fb15d3cb445d16f34183ef01349b33440d095f11fba48ca9d5913b594ea3a21808a5c404ca327bb2439202bc3ff3cccf3f049aeaf0ed8b53a9c5a42487fa647ce5ff1aee106d",
            "ee3f48ec1d947ca30732432e430e239657f0112036d2fa7bf33e2ee7de573bfb28",
        ],
        export: "9de4fb6c67d809b38efdce549f479b99cafdbc85e737617db7b9e081a3c90f9210d9feff34e479e6d92f056c77193d04",
        single_shot: "043580f51ca5495f83bc37f8f8a9d493c9a7ae4f3a52836d53645f9486c46fe14b10e251e72c8cf8d72b36adddec951d7669051ce15422cd2d05206ae6b418fa2c44526d7bafe7ca3801ec4dcb387a193b8015832a8ed6f138cfacd33ea6bcec1f0f77c45cb255ef410fba191157a0d714bbaad1e23deec1b98225e9",
    },
    Interop {
        kem_id: 0x0011,
        kdf_id: 0x0002,
        aead_id: 0x0002,
        enc: "04e8f8a9d3e6666fa542fabcb8c36bb5b185164574bb8acd41247ee6a2c2d58552ca47c415049407e72a4a4eec6f09d9f3c481dc69f74049e11e4b851e20354d86898a2b3ec3064319a79101a85844b0e88977eca7f3510cbc75cc4a520b49f3d7",
        ciphertexts: [
            "78b77297fd40dc305d40911b2a45d8c1",
            "a0529dc0c66fed17469485eb67544b138535fb2f27786fca0ea2116b87098ed3ce90845f0ca63ec6791c2a060d6fe146fba3f00e89eae1072f2e33c17dcfc6693d3f8ae2e6454186b09aebda9cdfdfb6d4119ee8979ef3af959bf2f34c37f417a9187632d8fb2e0abb6078d315ed09b131b02b60",
            "c0d79950c7ceaaa082f8ae2d793d6849f9cf3010cc67760faa7c187a5b62ba5a00",
        ],
        export: "9d8045a4f73f4cea52340a127e3aab81cf147b283796309b0a1fbd7efa637e623897fe41ed97f776aa82264271d9e02f",
        single_shot: "0440cbc008d6502d20c38dc166e536422a22d93aa3dc42c88a6a7a4c9aecd2ea0f43bd282fcd638708e9135a72e6396e576c63199a04d5b6d55fecdc6f21f45da67526856c82ec082dc6765bb4ace23d05f2f329cbbe7d7e79d717d85cfd5f83b50a8fae75e4593fad32cc165486ec57e2aa84371bf5b48f8ee26dfb",
    },
    Interop {
        kem_id: 0x0011,
        kdf_id: 0x0002,
        aead_id: 0xffff,
        enc: "0462ff4a60694672a7943f5e9a8051010316c3165823f3f954bc31317886a433f81b3c4db81719744e40104fb58a29ca90f153c940d13ada0923c8953cced6273294ad7d1ee541ed5df7c1a601ae66d8660c50544e8f1c065f114ef978315adf6a",
        ciphertexts: ["", "", ""],
        export: "3519f9bb2a1d7a99e2f090d01cf75af688cd6fb9146d900591e821b1909815389b2fdbf063c32101d0d3ac52c94fbe4b",
        single_shot: "",
    },
    Interop {
        kem_id: 0x0011,
        kdf_id: 0x0003,
        aead_id: 0x0001,
        enc: "044b3ffe8cd371cbe98ffdb05ab8f8b503edcba16e3aa5b050e82c533f38e6c13c9049aec144dba247382ce9519a6a19116b90e5c340ff6e670f3df1b06008c6935402d4117a116addae65762cadcf75ea66166845bc9a04b520bc207560e355ba",
        ciphertexts: [
            "35da6b52fd8068171610c72fd928e5d6",
            "296fd842ec078e563e889805ba39d22d31c2fe3206a270786eaf1fd5f3a6b64f279147dbe3d9e2f85ff9cc11abb0633324cc50c4f049df324333225f2b7115e5653c1fa369da0129993e0fe4006ea5b83bc58caec3e56f5c74435f11948a0815877a7e8802e1c7a1883b65c5d6499bdd57954760",
            "c61d4af72e77c62b297cc7a26451e5d1e0859d0d60aa1417933b938b7aa0b9ee00",
        ],
        export: "6a5c578f0f73d4817616cef70709c45f513c3bcc25c82864f0375dfc6b6411ed0f72876326d294f27db25898d1f9ef59",
        single_shot: "04355368609ed6f04b81625916390cb12878fb9b1217af15e624a7e39fcb7e20989fde722a74c32be4bf8284e6fa83a161349b278c30eb117fa9c3105f8ffe5eb82df55f21fe406eeaa4c6273614c6ac5bf97383672797092fe5a0ccdf054ee674561c28fb3a47368a3893caf396729a2497d63a273cb62106f4bab3",
    },
    Interop {
        kem_id: 0x0011,
        kdf_id: 0x0003,
        aead_id: 0x0002,
        enc: "04575e49cae93c5d5e97fcc6cf173f4107fb16101fc30537891075ddf82107024f274be3b44a5c6be0a1456a6a289d7091d569875ccacea9809fa596083143abeaba1c97a69757c291d38356955a2305ae155268fc42b8a4b507dad7145d8579fb",
        ciphertexts: [
            "c008302097f6d06e09c8e553cdcd5aec",
            "9a171c8c8230468815f959f21654ecc3527e2392f4872d53ea99901649ead40ed333b705f9deb8052dc64b0a719eb53de718432c0502a50593397e3aae31b33b3cf1b1f8b8d8dbee5ed79119ef60d40546858524430ef306eef38877e79e93a90506dd5ddfbf9c19e084e6253258f2f9efb75536",
            "95bc02544f0c09b0f37aa73b421db822ef146f7ac1bcc0a228908668373db5c624",
        ],
        export: "d2bae6bad204cb79cef529a77231fb1a6181bdedf09e11a05a4edf59c4233f97d3d98b5a69116e4f59e133d7187e6763",
        single_shot: "0410ad30cbb934168557ac1916c82174585a0b3c0f10db7181b842a6b871383578136990a3ae5608009f286b1486dbdebe9346af2e783ce045896fd8aa91a74f78876f5b460bbbe6afb9bd328c2812898d38dfb3c49aa990f9a3f0f5079cb1856ab1fd39b045b8ad0f6b18ef184a2975e5ad52d09bfd80439c82e2bd",
    },
    Interop {
        kem_id: 0x0011,
        kdf_id: 0x0003,
        aead_id: 0xffff,
        enc: "043fa9df29a28cdb143b468fbf516d16f78fd782b48894ea2b9c7082ad62ed687ec1ef1fc11572b2d0a8b0510b10ac5f377152c2495990a4ab79a60203b7ea3ec39be11c0c5a1626a6a6349a310e192aabd4f5fa9c050f3e8c6525ad90493edb44",
        ciphertexts: ["", "", ""],
        export: "1c985f6cb5accaba7557eef9f0cca1d226a3653cfc8b807fd5485b43d33572125476541236d593f12612363ce4225059",
        single_shot: "",
    },
    Interop {
        kem_id: 0x0012,
        kdf_id: 0x0001,
        aead_id: 0x0001,
        enc: "04000107360b3aeb38a472e1da672556509883d66b4cc9b9c0cf1a6fdfb610cd54cd23006ae94c720ca487389cd72de0b5e716c0a19e1aba78803cb88dc20eb98d842501a9d3bbca4fe2d151b07cfc25b48d683e97bf2a9a14e58eefd7f0da432129417e5ee6203d662f4cb8d417566c59a04f69de80fb907c9f844b24600950a8dfea60d8",
        ciphertexts: [
            "c0977a62ce3eddd6944164fe00765f45",
            "344e3e505dcf7a2a9802be3ada47e00c9de28a1daf5ca0fab703006dbf52fbea918b31870c058202cb9ff7582d1489e099a36ed25e964ddb666babfb28cf73b838eef82ada774ac14f88e8b4e42570a57cc287b10984d0fb52567b92bf23ce0b8c5fc68889c9b8d18968779a2ea04af49ab337d4",
            "a573ba5a219dca9ea1084087d4056515227840908b533f6ab114e4924150822c69",
        ],
        export: "67ca100db921091e9c5a3952dfa2c4a6e50f2fdc7f035b17ac774028927364a16690f4e6f1d0db1ee2eb7331161d86fa",
        single_shot: "04002226d10fa7009087b765a026d31c2813583a878014f08dbaa015853982d2e95a4123b4d1bfdb94d50722793c88df46d2bd264e6ed0ca8e892d5d2f632a6303cb8f00fd56c395a713ba0f1a132bb6ddd80fd9a3c46e011a27b46c26ffc25ed982194225d717014146c7824499f7c5f3036299015d87686b9e02488c6fbc4a491abdc3ea948ac6680812ea3237d5a9735404996325fdadb436c3659e6b8cf0",
    },
    Interop {
        kem_id: 0x0012,
        kdf_id: 0x0001,
        aead_id: 0x0002,
        enc: "0400871c9864b8253144ed746b34d0143d90e39b99c1cb5363d813d47b6afa33c239fe62b8f51bf1081909a07024f33be4a577a437d983842e0ddb6e1715344f9ee1390015e6e167300a0b81cc21a4cb636a5d7fbc2f47c9f5e9b62c08ec0ae72ec962d1a8dd0fbef50c35a494732f1b905295d0f2399a0720d973ae02c94a9b0f59666c91",
        ciphertexts: [
            "74f4f443c2f1ff119b2de84b6397172b",
            "2a1b4a975657e5fc56cf64c24bdb0351c933116f8bbd7e564b8342b264b31790f3c2134bc967496739fa18471736293a950b2d61005542426727cdb16a85b68540586d5f5ddb113489835155533bd64a218fe551d5ac779451939f43606872d78d8d4e7abd7abf1ee0eab725c0954cfb3ba6ee8e",
            "69bae90473d84cfbf4d0cc46a64f8ab8176a2fca3ff918ad89985eaac18294c924",
        ],
        export: "a4ca934ffa7be5d745fc2481f3e7aa5fb5af17a6f5639cebde11dab22d7b5b0f85dabbc178088e20c184e0e01bbdccf1",
        single_shot: "040087a88886328310e8f4ff22dc94786941928c181dfa15b62462b810bde38c71a9b4ca9b96dc82c5b135843fa46703723b691a076afa1803717ddae16efc753fec03016867f6b173182a4b5022a7abf998980c52962020f46e6364d730721865eb27c21b8e409274bbe2e36e6bf22ad8e164ec2b1c2c14fa7d8e358be912a1763cdab5f1196f6e5f855f7b15b6dd8d237bd4609c042ea4cc95defe5739451a",
    },
    Interop {
        kem_id: 0x0012,
        kdf_id: 0x0001,
        aead_id: 0xffff,
        enc: "040066ef12fbca5858fb461e943a1e704bcff7e667990985ff5501190092126ecec64f3a093d90f47cff06a8e3362399a1801f81cabfb63d1efe723d2cf77d7ddeb825013ed26656ca01b979eb2f805228728d83adb114b24c519dc8a312dca912b6fee2373d16422174e62a5cb5d73b424bdca821f5c2aff30e52e99389e501bfd7dab8c3",
        ciphertexts: ["", "", ""],
        export: "ab4e9b15f6cc2f0db598175941eec28b8ebaeb99497c7cb07bd824ad10ee29383a55173e8354dab9d9feceb51167c64a",
        single_shot: "",
    },
    Interop {
        kem_id: 0x0012,
        kdf_id: 0x0002,
        aead_id: 0x0001,
        enc: "04017d5a680b2c20f21f5cec6f2a3096d0f40b61496d6451bd2c06fbb390d37337ba0f3ea188d8a5e0242233cb217b93ebfb874dc251879a0934368c5a0a9cb55ce605011b1427a6f8511c01832fa93c85e630c99c77a05da38e143fcc5de038ccdc297f31d3d56c10ab6315491c8cd34e1617274b68143c6ce076c5fe06c8f5ce7fe39402",
        ciphertexts: [
            "57a7b3dc2b3fb5e6b2d5756b07f3e2ed",
            "95884581a9705a31be7d4f7bad9f338573bf2caa15f83422461c2aca4bf6f6736db13fd8537bd76859a808437435dea1db1e44f01c3abf6470b37d0bd929e8f977452a421e5da752729338a102f1d750df8062b55f992d46309af6289a8e66ed7db1ee654137575c746675bb63e507fe67ae5ff7",
            "5fa4365ce1fb042fc4127f8b542277b34e1cfbe8ecc9eb7e2ca6a37cde28ff442e",
        ],
        export: "f3597450696702546699ef49e9383232c5f0e968d7f8137bf0b1a3d43c7803be4c9728c42f8bab6edcd693ec68e419a2",
        single_shot: "0400c45806c15108630bf12a423b1df03bbcb92ee764d41ab70bfce076fc76d1204b5b668312d8a2c346311c9801e57b4838255975c721be5c262123de32092dbe20f700b956fbbe9cd986c476d2364d8da7e3bf3c6d19fee5660443c4156b28b8a631843c03d18fd3057d07c94ca3204e1eb08fcf228e47027e5345a0261d570de34ff87320ca360784cb842584a27fa747da4cd2f672f13f23df593c322ece",
    },
    Interop {
        kem_id: 0x0012,
        kdf_id: 0x0002,
        aead_id: 0x0002,
        enc: "04005e24cb0a5fca6f57c7cd5206ab1226544057710ca2ae36e25a085c076a517cabc6b979816b3c550f57b3ebc88ea05e55ca20a08abcdffdc2e7e8a8a5bd0d2313af0150108b838ec2bde5ce64a2374a33424709492452eb2652560cf481dc6dab5958056a5c4d95c37b0c6a95765b86c1f0f86c1764454d7b80f05402f982255ba14bd9",
        ciphertexts: [
            "d80371f5aee99409a46cfef46b5923da",
            "f4fe4ac0477c42816f78bc7bb4e012b72001815b66c778a60cc98f224db0e5a5e8dd2d14be825ea6c6715a803c8a59987399e0ce7ec50459b2bd3dcb7e78deaa09f7e5ef3a18f5992bd6268916646248541ae777bcd970818c3ad87f8eb4ab838b4966f552331995b4e6256d141eac3200baa4d1",
            "41ddae21dc3e611aa6d94592a2d112d302578a3371c14f493096e3506c8e283acd",
        ],
        export: "a5e9ee9d85db4d5db59ecb106d8dde052b92b433c18fd7c399538282ff60d60654b20969ff5dbdf4e3385ba3a45a454a",
        single_shot: "0401c4f1ddf59596c2eea169cece1846b44c79c9f047776d1a6ca8a5098cb19914807d5cb489b5e95186f6aef01502970ee8f6d9745bebb03096c8934f3cecc44936080100736e56f0d21667491b21689f439c7eb39f9444852fec92758e7f90ec648bbadaa3b25f3a9a65c25bc8240e30d912a2b975bfd5305e9fcbaceab8d6a145d80f9a9faf0cacf80129016778f2dffa19b5c2381c8f88dc12c3340b23eb",
    },
    Interop {
        kem_id: 0x0012,
        kdf_id: 0x0002,
        aead_id: 0xffff,
        enc: "04002a007828ad3f4137f4c9ef21d574f2a0ce17a20b77fd57887b36c2f39106f048dab6b6c17fa13637ab564ac2dbd93445cc931452a5a2db20615633f3455cad1f5601c794b9e0a2caae1faf8e0be51ddedd51f10fc12e8725be260eec656ef8c52b56a8f0f439ea35871de6c3779b06a0dfc0cf79262f31517e140b0fd97e51727305e1",
        ciphertexts: ["", "", ""],
        export: "f96766af3e99b4b5d114529cd33d3d5ab6eadee0e7afabe7c99d7a28e69ac00f09f9efbfbb11ac2ff6d32d102b4905de",
        single_shot: "",
    },
    Interop {
        kem_id: 0x0012,
        kdf_id: 0x0003,
        aead_id: 0x0001,
        enc: "040163940a11828b3b551ca8b6adfff40b56d877b0a22c49cdd8d685d36076bd26239b73be1eee33d61cebb4c540962f080e8618724f92a2f6c1f6aff9a1b8dae397d801fd967b101d7f00f0bb3d0e3429d33ca29835373065e5dd03c3f1c6cc76bc7cfc74599c5f8e49010df41fb658f56838570013b96a08dc29293483a1ead910f8e245",
        ciphertexts: [
            "51346c64c5325733c22834df83d5188a",
            "3573df7a878fd5946b4b62b4969b2f1ccb195195509ab8bb398935d6b3c188c07d42ee3029e8a304c99a0971c9cfa34fa0d694bd9b7c386ac6367cc090501155e323205c6d62750552ebc92e09223e3ed3a920f6e9a59a0441c61abb83332e897a0b12084eb28220adbf0d5d732bc78b16123791",
            "7b4d464e28113601f5c79f82b6231e8f2e2eaa799587416880d9894f88c9fc0a0d",
        ],
        export: "ab4ce8d49a77684df4a7ea744d584ccd1094d216e9c8a345ed709c0e5c9c318f1a3609e3c43b65965fd115ec97e87944",
        single_shot: "04002f32d64dfd57c1ecceba280c64ef8a9d8d37d032452fb293919ab7d1dda04997bbd10cd0bf7eeea9feb74014a0d30de481773cda1b2cd2e0e2c168f9098e6ab8b500e18e2a79696bb5c3ef2e989b91cdec640b32f7afb89d4ad0b7417538373307044ca8cc0242c14023d84fe7450751a0afa14e4b6e51ac334fea0cef6640f9f23c229238ce3bb2a06683942e75b57734bc560a4007f46b394a93064d71",
    },
    Interop {
        kem_id: 0x0012,
        kdf_id: 0x0003,
        aead_id: 0x0002,
        enc: "04016cecd7b4708ebe177e8a43ffcdb8a1910dbbed38c9e76faff5a370db1cb8a7fea935efeb3f0e425ab0bb6a8081ae9764ae8f501c04f288e2cc3adbd59e639ec5a001c80d29421971574025f25e806b43c1f1158b024270c9dbf9a6c9fce11accf4171cd06e7e83a8c77968cf59503532acba7b43ef6d085b4b33852844edd1fce615db",
        ciphertexts: [
            "56229273cfe0af41e2f41eb00d4d45b3",
            "2f499f0c1e311257c49ec0ef0e19dbbbdd03f7eb396d3090fcf45f8030912cb00a81ee6bfda911ec09e41a409c088937c67e49092e28ce67b94d0154f6aee5b5ab247e4eab43cc0b47986c7e5e64fe9b5fa12cc05785c45da0c338a36692e2f4b58ad613a93ffb5b5e816668de3ad06b0ba9e852",
            "0628f67a7813f908834bcd767edd8b5378dab3729ddbbe23d834f03cfab34b74b9",
        ],
        export: "2ae4226bb939cb578d13fbe551ece7fc10b224449b066686fa607a1914a5c1bb0165c8fa199c37d27a6f1ad9b72ee874",
        single_shot: "0400ef214fe6c3a3150102965b9471bf7ef1f5bf697f35ea47ba7501c2bb65b07cbc0835b40f330cf7cbe12164e4621ec4038cadd6b6216075b56136f46012f36338e201fd7ae75a2a156320130e4a26e3ab45c7e0d45d32015471f30f0125e13276200191e6515a6c69143f77e87897c2adf9d560cfbcaf4e4b37505ed46a822b96fc46043c5cccf0740f3429f8b221753d9d25bdd1126deff8f1b6e6555d47",
    },
    Interop {
        kem_id: 0x0012,
        kdf_id: 0x0003,
        aead_id: 0xffff,
        enc: "0401b353f185bae985536257d59456d50a70322fa43a3d91c716229ec401c57be728a32c83f49589f425e168af4824bad88aac2b04749678ed0839154f432bf756486d01813f00bd1a37c74103a8eec7ee2aaaa2b305e0c66c7d81780646918d7c3f49b7d83b073d338f18ee1ecd2f8b3a4d41e7699bfccd828633b8672b2232b1f5caffeb",
        ciphertexts: ["", "", ""],
        export: "7641292316fadb3a2090795f1ebf625224acb2a0d280d0e051c70ecbda4cbe4645be8a7046959fdbbe37cc068ed7136e",
        single_shot: "",
    },
    Interop {
        kem_id: 0x0020,
        kdf_id: 0x0001,
        aead_id: 0x0001,
        enc: "535b74f38235eb5b9f2efd3831a3c36e429afdf5bd77ae2b462d58ac0894475f",
        ciphertexts: [
            "0ae297dda2f09319739cae257ec74ed0",
            "bb54206a52abe46a63393ab65b6b5a220528d0592d8ed82dd47d0ae0f2f5b9fee92729a1a73a8978afe8044dd507c35fa45df2d490504ef8d4a656257256a6e243d9a38fc07560a2493915ed8faa7343fa4c271d1e17956c59165b433a04b638c7336a4a00f0e48599ffb27291d28b68fa9271d7",
            "a1c35a7481e8c23ab890fc6c697486ee732d45ef6d3654da24bed4f56fe3f95cee",
        ],
        export: "db886d716f997354b111a6d53f0940c8d15470d4f274c0c1affabfe9ee60514aa8859d356683eda91bc281241b6c434f",
        single_shot: "5264ec25cfe38ba27f1a227b3052268ea883966ba4e321892bef585a642e724d77a5cffe27bfaa249920a30c7a09368d2ddaa8685bf225719d45ce",
    },
    Interop {
        kem_id: 0x0020,
        kdf_id: 0x0001,
        aead_id: 0x0002,
        enc: "9d885500dc5989a2d785cb5469b57527e9039c948f1c149efc5b81f237555359",
        ciphertexts: [
            "449ef0a94b35103d636c0e6963ea40cd",
            "e9d7f3c325368e5b0f59b6666ddbdfbb145c9327f2f09a70abdbd15a89df44a5ecc081228fe44ee4d46dee7107ba8b9c5e9381ec408e45ac526c3ec94e3d037850285928cf70855ddc3fa3df680a4280c861a0cba8e3c23e7385d7b7277ed006e1d546f0b55630a7f158f70fa06735c517a0063b",
            "e1d68de34eacd7391d0f61d21656b1d37b7fdb02c16c26a172452171f3cc584682",
        ],
        export: "a5909d3c9189025235c26fb5f8cb350e42dc0754e219a6d6a7b6f6aad622b6cff901a5368040ffd6d1c4e948717c1d64",
        single_shot: "6a863a75858b9e4fb716fccbdc6a4aa99d3605f5c13bd83eb6c9fa1742f5ec04be037e53fc990ffbb9f6dab630b61ae79e0fa661d6bb3702945943",
    },
    Interop {
        kem_id: 0x0020,
        kdf_id: 0x0001,
        aead_id: 0xffff,
        enc: "ba67b3403b652354e144ae37555070d6c104a1f35c22ef230c3955faf7318e25",
        ciphertexts: ["", "", ""],
        export: "8f928aa7f9adf58bd1fc9cbf0081e25bf31302c455f2c3225fe7e49a2d50f0e4649ff8d3193ba53597d7fa2cee5a26de",
        single_shot: "",
    },
    Interop {
        kem_id: 0x0020,
        kdf_id: 0x0002,
        aead_id: 0x0001,
        enc: "35d7bb3418b63d9253774cddf01ff1809eb81ecffcc590a979550e841cbb0166",
        ciphertexts: [
            "7d2db48effe2e66e098b9341f2f4efe4",
            "dc29677d103523d4f8d029bb346cadb0af07408e7a8409a6f89b3b7841c1b6180a8758ca3d00ce544ef045b90c2654043f3304383bb7dd89b9fc07557e824e83fe070ba84ec6d720f57936998ec996b2774a703027aeaa0d354ae871c0e1c788096aa31941c08057804f87c93bef59a6d6401718",
            "9bf3cd91edc76d795eba1e705240c6c60c4862c882a2b74acba42e81874b9b5bb0",
        ],
        export: "700e2d3fbaacb4ad0f65c9718adbee42b8ea1f2b3c3fcb59a7888c50a7db6450cbd5ac2fdba5c8c93d84bb3704e143ce",
        single_shot: "fd246bc8d0b8349c41f8019ec4146f9b62524ed14382c5c2a7dcc09bcfba2d5aa5ca94e59532d88942f1637514cf6cdb31aedc870512807a29d910",
    },
    Interop {
        kem_id: 0x0020,
        kdf_id: 0x0002,
        aead_id: 0x0002,
        enc: "bd292bdf34159c63b2a95ec5b558f58818c8e77d7112cc226540d2e1aeaf7645",
        ciphertexts: [
            "ee50aedc79fcc708ba7d49a8142b9c68",
            "dc25f818ff84f9048be74f103321986c028aa66ef048309f9802e5c66342269df0337b4fdcf160f397f0afa5a2dd42baeb1507401b76b96581e517d31a07dfa2a81d038a1560f13be62bf28f4266667bac49d85891e1784152fa608dd42fc8c32e064b09bba3f59defe4992e006a5913de2ff1c3",
            "95d7d5ab0998bbf6fa1d38d6f2ec4a6075fb69a5d10c50073bbc552d91d1934d00",
        ],
        export: "7f45ac17d7abb8644b2d80874bea0b73ad8e2433e6f7070414ac5c85b44cb0013b3af958681bc63cae9a394b88c606ad",
        single_shot: "3750f6083ffbbf602473ab6cf6f179d51a8d6d7979ece0414ad3e5578e09fc5eeeedfd089ad51230144ff2cdb1e8818b6b05eaa09c2ec1fc8a409c",
    },
    Interop {
        kem_id: 0x0020,
        kdf_id: 0x0002,
        aead_id: 0xffff,
        enc: "795e1a25e2f67e47d8d863dd0f290df8933b9da92c848e3355d3a80b3b533166",
        ciphertexts: ["", "", ""],
        export: "3904d211d722f34970bd123a724d70c9b4185f6ddd578354fa4007ef9fa839769dc8e0b9706bf144e6e9e4137995ef59",
        single_shot: "",
    },
    Interop {
        kem_id: 0x0020,
        kdf_id: 0x0003,
        aead_id: 0x0001,
        enc: "65e8bd4daf00cd2d2a09d03a17eec09e59b5ce9df359457271d0754fd8a2fd1d",
        ciphertexts: [
            "b0f18776a65897cd1a33a14699c6b57b",
            "f16ae4565df29dc07640febfced8f0c0dd24094202393d0ef1777c54a12af1bbbf1ae566b3b8ee4ebd5bb98ff218d2e6d3e1215b02e7f105e667d8eb25eca79c556177631f119f78820c0423fe121f235a64610b175e86816d47330c2ad26818dd8085acc845915ffb685742e6aa8cb454f0205e",
            "7dc4bfc67ebcf6d4ec35002bf2b4bddd63cbeba9e80119c180922305c9ddb06bdd",
        ],
        export: "dd6b9d94aa49149f146fd7960190f8b50a43622386b3e7571330ca56cf6ccfbccd50e1885e2daa161eb4655fc02839f3",
        single_shot: "f54f57238fd86280822148a9e8a47eaf10a39381d4a8f77533369ac710f6492bf473f110b075aff09e091831838b28fd71535736feb73250e7f6c7",
    },
    Interop {
        kem_id: 0x0020,
        kdf_id: 0x0003,
        aead_id: 0x0002,
        enc: "a7e03f8733ff947986bace1f7f2604d0dbb1dc4f1f64ede24e66ee5d580cda5d",
        ciphertexts: [
            "a07a9ab5bcb493c4880dbafd4e9dd300",
            "b833c9aab1486fb12a198b84352a58ff7a075a67ea6d1d588d9ce685dcffa09463265821fbdbcea04377ea293ddcbf35f2154ab5e63396da6d287ccf856de5392b14d8069e5a62de020dbeb0603214605957c4b0699602dd0b72901d93c15e8a65d396df56442fda38e683ee383e294034c58c72",
            "34b5063c0e3bad1c154a2bb90a2bff47ec4f5297462258bea30cb36309bebc0658",
        ],
        export: "69c1bcdc9be59e69c4e9d5bd9b3d3b2ea5c159f1d31bb9fc48e70b9dbb0da0efb03c1b35d314ca4592c9285202780cc4",
        single_shot: "31ced9ec37e151dc37a2ca8879696056024e3b027e5c5868a855e2339810d027f0efcf8db9358202d28a32cc8f9ddbf5a7b43a1279a77c859f5e7b",
    },
    Interop {
        kem_id: 0x0020,
        kdf_id: 0x0003,
        aead_id: 0xffff,
        enc: "3fc4bd8e3c37562ec7fc88c410079cc36e807cc2b045729f98b966567f123220",
        ciphertexts: ["", "", ""],
        export: "11babcb24b77a86720b884942d580e6d012637b7c2fd0e8e945561d6babcbcc487b5eb8c49c0379d6b778d0b82cb0420",
        single_shot: "",
    },
];

#[test]
fn seals_what_go_opens() {
    for (i, v) in (0u32..).zip(&SEALED_FOR_GO) {
        let what = format!(
            "KEM {:#06x}, KDF {:#06x}, AEAD {:#06x}",
            v.kem_id, v.kdf_id, v.aead_id
        );
        let suite = Suite::from_ids(v.kem_id, v.kdf_id, v.aead_id).unwrap();
        let len = suite.kem().private_key_len();
        let sk_r = interop_recipient(suite.kem());
        let (enc, mut sender) = suite
            .setup_sender(
                sk_r.public_key(),
                b"cryptors interop",
                SenderMode::Base,
                &stream(b"interop ikmE", i, len),
            )
            .unwrap();
        assert_eq!(hex(&enc), v.enc, "{what}");
        if suite.aead() != Aead::ExportOnly {
            for ((aad, pt), ct) in interop_messages().iter().zip(v.ciphertexts) {
                assert_eq!(hex(&sender.seal(aad, pt).unwrap()), ct, "{what}");
            }
            let (enc, ct) = suite
                .seal(
                    sk_r.public_key(),
                    b"cryptors interop",
                    b"",
                    b"single shot",
                    SenderMode::Base,
                    &stream(b"interop single ikmE", i, len),
                )
                .unwrap();
            assert_eq!(hex(&[&enc[..], &ct].concat()), v.single_shot, "{what}");
        }
        let export = sender.export(b"interop export", 48).unwrap();
        assert_eq!(hex(&export), v.export, "{what}");
    }
}

#[test]
#[ignore = "manual throughput check: cargo test --release hpke:: -- --ignored --nocapture --test-threads=1"]
fn throughput() {
    use std::hint::black_box;
    use std::time::Instant;

    const LEN: usize = 64 * 1024 * 1024;
    const MESSAGE_LEN: usize = 64 * 1024;
    let mib = LEN as f64 / (1024.0 * 1024.0);

    // The inputs of bench/hpkecmp, which makes the same passes through Go's
    // crypto/hpke. For each KEM, the recipient key DeriveKeyPair(00 01 ..),
    // as many bytes as a private key, and the ephemeral input DeriveKeyPair(20
    // 21 ..); the info "cryptors hpke benchmark"; and for the AEADs, 64 MiB of
    // the byte pattern i % 251 cut into 1024 messages of 64 KiB, sealed with
    // no associated data. Go draws its ephemeral keys from crypto/rand and
    // cannot be given one; here they come from `ikm_e`.
    let info = b"cryptors hpke benchmark";
    let pattern: Vec<u8> = (0..LEN).map(|i| (i % 251) as u8).collect();
    let ikm = |start: u8, kem: Kem| -> Vec<u8> {
        (0..kem.private_key_len())
            .map(|i| start.wrapping_add(i as u8))
            .collect()
    };

    /// Runs `pass` once to warm up, then five times, and keeps the shortest
    /// of the times it reports. The first pass is slowed by page faults and
    /// clock ramp-up, not just HPKE. A pass times itself, so that setting up
    /// its context stays out of the bulk figures.
    fn best_of_five(mut pass: impl FnMut() -> f64) -> f64 {
        pass();
        (0..5).map(|_| pass()).fold(f64::INFINITY, f64::min)
    }

    // Setup: SetupBaseS and SetupBaseR with the KEM's own KDF and AES-128-GCM:
    // an ephemeral key pair and a Diffie-Hellman on each side, and the key
    // schedules. Fewer of them for the slower curves.
    let mut checks = Vec::new();
    for (kem, kdf, setups) in [
        (Kem::X25519HkdfSha256, Kdf::HkdfSha256, 1000),
        (Kem::P256HkdfSha256, Kdf::HkdfSha256, 400),
        (Kem::P384HkdfSha384, Kdf::HkdfSha384, 100),
        (Kem::P521HkdfSha512, Kdf::HkdfSha512, 50),
    ] {
        let suite = Suite::new(kem, kdf, Aead::Aes128Gcm);
        let sk_r = kem.derive_key_pair(&ikm(0x00, kem)).unwrap();
        let pk_r = sk_r.public_key();
        let seconds = best_of_five(|| {
            let start = Instant::now();
            for i in 0..setups {
                let mut ikm_e = ikm(0x20, kem);
                ikm_e[..4].copy_from_slice(&(i as u32).to_be_bytes());
                let (enc, sender) = suite
                    .setup_sender(pk_r, info, SenderMode::Base, &ikm_e)
                    .unwrap();
                let recipient = suite
                    .setup_recipient(&enc, &sk_r, info, RecipientMode::Base)
                    .unwrap();
                black_box((sender, recipient));
            }
            start.elapsed().as_secs_f64()
        });
        println!(
            "hpke setup [{kem:?}]: {setups} x SetupBaseS + SetupBaseR, best {:.1} ops/s ({:.1} us each)",
            setups as f64 / seconds,
            seconds * 1e6 / setups as f64
        );

        // The cross-check, which Go prints too: an export of the recipient's
        // context for the encapsulated key of DeriveKeyPair(20 21 ..).
        let (enc, _) = suite
            .setup_sender(pk_r, info, SenderMode::Base, &ikm(0x20, kem))
            .unwrap();
        let recipient = suite
            .setup_recipient(&enc, &sk_r, info, RecipientMode::Base)
            .unwrap();
        checks.push(hex(&recipient
            .export(b"cryptors hpke benchmark", 8)
            .unwrap()));
    }

    for aead in [Aead::Aes128Gcm, Aead::Aes256Gcm] {
        let kem = Kem::X25519HkdfSha256;
        let suite = Suite::new(kem, Kdf::HkdfSha256, aead);
        let sk_r = kem.derive_key_pair(&ikm(0x00, kem)).unwrap();
        let pk_r = sk_r.public_key();

        // Seal: every message through one fresh context per pass.
        let mut ciphertexts: Vec<Vec<u8>> = Vec::with_capacity(LEN / MESSAGE_LEN);
        let mut enc = Vec::new();
        let seal = best_of_five(|| {
            let (e, mut sender) = suite
                .setup_sender(pk_r, info, SenderMode::Base, &ikm(0x20, kem))
                .unwrap();
            enc = e;
            ciphertexts.clear();
            let start = Instant::now();
            for message in pattern.chunks(MESSAGE_LEN) {
                ciphertexts.push(sender.seal(b"", message).unwrap());
            }
            start.elapsed().as_secs_f64()
        });

        // Open: the ciphertexts of the last sealing pass, through one fresh
        // recipient context per pass.
        let mut last = Vec::new();
        let open = best_of_five(|| {
            let mut recipient = suite
                .setup_recipient(&enc, &sk_r, info, RecipientMode::Base)
                .unwrap();
            let start = Instant::now();
            for ciphertext in &ciphertexts {
                last = recipient.open(b"", ciphertext).unwrap();
            }
            start.elapsed().as_secs_f64()
        });
        assert_eq!(last, pattern[LEN - MESSAGE_LEN..]);
        println!(
            "hpke seal [{aead:?}]: {mib:.0} MiB in 64 KiB messages, best {:.1} MiB/s",
            mib / seal
        );
        println!(
            "hpke open [{aead:?}]: {mib:.0} MiB in 64 KiB messages, best {:.1} MiB/s",
            mib / open
        );
    }
    println!("hpke cross-check: exports {}", checks.join(" "));
}
