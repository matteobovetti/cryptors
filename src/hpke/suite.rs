//! The algorithms of a suite (RFC 9180 section 7), and the labelled forms of
//! HKDF that HPKE derives every key with (section 4).

use super::Error;
use crate::Digest;
use crate::hkdf::{self, Hkdf};
use crate::hmac::Hmac;

/// The version label that starts every derivation in HPKE (RFC 9180 section
/// 4), so that its secrets are bound to the scheme and its version.
const VERSION: &[u8] = b"HPKE-v1";

/// `LabeledExtract(salt, label, ikm)` (RFC 9180 section 4): HKDF-Extract of
/// `"HPKE-v1" || suite_id || label || ikm`, as the bytes of the pseudorandom
/// key.
///
/// Extract is the HMAC of the input keying material under the salt (RFC 5869
/// section 2.2), and HMAC takes the four parts one after the other, so they are
/// never copied together, and the secret among them never lands in a buffer
/// of this module. `suite_id` says where in HPKE the call is made: `"KEM"` and
/// the KEM's identifier inside the KEM, `"HPKE"` and the whole suite's
/// elsewhere.
pub(super) fn labeled_extract_bytes<D: Digest>(
    suite_id: &[u8],
    salt: &[u8],
    label: &[u8],
    ikm: &[u8],
) -> D::Output {
    Hmac::<D>::new(salt).mac_parts(&[VERSION, suite_id, label, ikm])
}

/// `LabeledExtract(salt, label, ikm)` as a [`Hkdf`], ready to expand: HMAC keyed
/// with the pseudorandom key once, for every [`labeled_expand`] from it.
pub(super) fn labeled_extract<D: Digest>(
    suite_id: &[u8],
    salt: &[u8],
    label: &[u8],
    ikm: &[u8],
) -> Hkdf<D> {
    let prk = labeled_extract_bytes::<D>(suite_id, salt, label, ikm);
    Hkdf::from_prk(prk.as_ref()).expect("an extracted key is one hash output long")
}

/// `LabeledExpand(prk, label, info, L)` (RFC 9180 section 4): HKDF-Expand with
/// the info `I2OSP(L, 2) || "HPKE-v1" || suite_id || label || info`, where `L`
/// is the length of `out`.
///
/// Fails, as HKDF-Expand does, if `out` is longer than 255 hash outputs.
pub(super) fn labeled_expand<D: Digest>(
    prk: &Hkdf<D>,
    suite_id: &[u8],
    label: &[u8],
    info: &[u8],
    out: &mut [u8],
) -> Result<(), hkdf::Error> {
    // Every length Expand accepts, at most 255 * 64 bytes, fits in the two
    // bytes of I2OSP(L, 2). The labelled info is public, and short but for an
    // exporter context, so one allocation holds it.
    let len = u16::try_from(out.len()).map_err(|_| hkdf::Error::InvalidLength)?;
    let labeled_info = [&len.to_be_bytes()[..], VERSION, suite_id, label, info].concat();
    prk.expand(&labeled_info, out)
}

/// A key encapsulation mechanism (RFC 9180 section 7.1): Diffie-Hellman over
/// one of the crate's [`ecdh`](crate::ecdh) curves, with a KDF of its own
/// inside the KEM, whatever the KDF of the suite.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Kem {
    /// DHKEM(P-256, HKDF-SHA256), `0x0010`: 32-byte private keys, 65-byte
    /// public and encapsulated keys, a 32-byte shared secret.
    P256HkdfSha256,
    /// DHKEM(P-384, HKDF-SHA384), `0x0011`: 48, 97 and 48 bytes.
    P384HkdfSha384,
    /// DHKEM(P-521, HKDF-SHA512), `0x0012`: 66, 133 and 64 bytes.
    P521HkdfSha512,
    /// DHKEM(X25519, HKDF-SHA256), `0x0020`: 32 bytes each.
    X25519HkdfSha256,
}

impl Kem {
    /// The identifier, `kem_id`.
    pub const fn id(self) -> u16 {
        match self {
            Kem::P256HkdfSha256 => 0x0010,
            Kem::P384HkdfSha384 => 0x0011,
            Kem::P521HkdfSha512 => 0x0012,
            Kem::X25519HkdfSha256 => 0x0020,
        }
    }
}

/// A key derivation function (RFC 9180 section 7.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Kdf {
    /// HKDF-SHA256 (RFC 5869), `0x0001`.
    HkdfSha256,
    /// HKDF-SHA384, `0x0002`.
    HkdfSha384,
    /// HKDF-SHA512, `0x0003`.
    HkdfSha512,
}

impl Kdf {
    /// The identifier, `kdf_id`.
    pub const fn id(self) -> u16 {
        match self {
            Kdf::HkdfSha256 => 0x0001,
            Kdf::HkdfSha384 => 0x0002,
            Kdf::HkdfSha512 => 0x0003,
        }
    }

    /// `Nh`: the length of the hash, and so of the exporter secret.
    pub(super) const fn hash_len(self) -> usize {
        match self {
            Kdf::HkdfSha256 => 32,
            Kdf::HkdfSha384 => 48,
            Kdf::HkdfSha512 => 64,
        }
    }
}

/// An authenticated encryption algorithm (RFC 9180 section 7.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Aead {
    /// AES-128-GCM, `0x0001`: a 16-byte key, 12-byte nonces, 16-byte tags.
    Aes128Gcm,
    /// AES-256-GCM, `0x0002`: a 32-byte key, 12-byte nonces, 16-byte tags.
    Aes256Gcm,
    /// Export-only, `0xFFFF`: no encryption at all, for a context that is
    /// only used to [export](super::Sender::export) secrets. `seal` and `open`
    /// fail with [`Error::ExportOnly`].
    ExportOnly,
}

impl Aead {
    /// The identifier, `aead_id`.
    pub const fn id(self) -> u16 {
        match self {
            Aead::Aes128Gcm => 0x0001,
            Aead::Aes256Gcm => 0x0002,
            Aead::ExportOnly => 0xffff,
        }
    }
}

/// A cipher suite: the KEM, the KDF and the AEAD that sender and recipient
/// agree on (RFC 9180 section 4).
///
/// Every combination of the three is a valid suite. All the operations of HPKE
/// are methods of the suite they run in: [`setup_sender`](Suite::setup_sender)
/// and [`setup_recipient`](Suite::setup_recipient) for a context that carries
/// a sequence of messages, and [`seal`](Suite::seal) and [`open`](Suite::open)
/// for a single one.
///
/// ```
/// use cryptors::hpke::{Aead, Kdf, Kem, Suite};
///
/// let suite = Suite::new(Kem::X25519HkdfSha256, Kdf::HkdfSha256, Aead::Aes128Gcm);
/// assert_eq!(Suite::from_ids(0x0020, 0x0001, 0x0001), Ok(suite));
/// assert_eq!(suite.aead().id(), 0x0001);
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Suite {
    kem: Kem,
    kdf: Kdf,
    aead: Aead,
}

impl Suite {
    /// The suite of these three algorithms.
    pub const fn new(kem: Kem, kdf: Kdf, aead: Aead) -> Self {
        Self { kem, kdf, aead }
    }

    /// The suite with these identifiers (RFC 9180 section 7), as they appear
    /// on the wire or in test vectors.
    ///
    /// Fails with [`Error::UnsupportedAlgorithm`] for an identifier this
    /// crate does not implement, such as DHKEM(X448) (`0x0021`) or
    /// ChaCha20-Poly1305 (`0x0003`).
    pub fn from_ids(kem_id: u16, kdf_id: u16, aead_id: u16) -> Result<Self, Error> {
        let kem = match kem_id {
            0x0010 => Kem::P256HkdfSha256,
            0x0011 => Kem::P384HkdfSha384,
            0x0012 => Kem::P521HkdfSha512,
            0x0020 => Kem::X25519HkdfSha256,
            _ => return Err(Error::UnsupportedAlgorithm),
        };
        let kdf = match kdf_id {
            0x0001 => Kdf::HkdfSha256,
            0x0002 => Kdf::HkdfSha384,
            0x0003 => Kdf::HkdfSha512,
            _ => return Err(Error::UnsupportedAlgorithm),
        };
        let aead = match aead_id {
            0x0001 => Aead::Aes128Gcm,
            0x0002 => Aead::Aes256Gcm,
            0xffff => Aead::ExportOnly,
            _ => return Err(Error::UnsupportedAlgorithm),
        };
        Ok(Self::new(kem, kdf, aead))
    }

    /// The key encapsulation mechanism.
    pub const fn kem(&self) -> Kem {
        self.kem
    }

    /// The key derivation function.
    pub const fn kdf(&self) -> Kdf {
        self.kdf
    }

    /// The authenticated encryption algorithm.
    pub const fn aead(&self) -> Aead {
        self.aead
    }

    /// `suite_id = "HPKE" || I2OSP(kem_id, 2) || I2OSP(kdf_id, 2) ||
    /// I2OSP(aead_id, 2)` (RFC 9180 section 5.1), which every derivation
    /// outside the KEM is labelled with.
    pub(super) fn id(&self) -> [u8; 10] {
        let mut id = [0u8; 10];
        id[..4].copy_from_slice(b"HPKE");
        id[4..6].copy_from_slice(&self.kem.id().to_be_bytes());
        id[6..8].copy_from_slice(&self.kdf.id().to_be_bytes());
        id[8..].copy_from_slice(&self.aead.id().to_be_bytes());
        id
    }
}
