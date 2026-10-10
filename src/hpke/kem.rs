//! DHKEM (RFC 9180 section 4.1) over the crate's ECDH, and the keys of the
//! four KEMs.

use core::fmt;

use super::secret::Secret;
use super::{Error, Kdf, Kem};
use crate::digest::hex;
use crate::ecdh::{self, Curve, P256, P384, P521, X25519};

/// What DHKEM needs of a group beyond ECDH itself (RFC 9180 section 7.1), and
/// how its keys go in and out of the KEM-agnostic [`PrivateKey`] and
/// [`PublicKey`].
trait Group: Curve {
    /// The KEM built on this group.
    const KEM: Kem;
    /// The KDF of the KEM, which `DeriveKeyPair` and `ExtractAndExpand` use
    /// whatever the KDF of the suite is.
    const KDF: Kdf;
    /// The mask of `DeriveKeyPair`'s rejection sampling (RFC 9180 section
    /// 7.1.3): `0xff` for P-256 and P-384, `0x01` for P-521, whose order has
    /// only one bit in its first byte. `None` for X25519, which takes the
    /// derived bytes as they are.
    const BITMASK: Option<u8>;

    fn private(key: ecdh::PrivateKey<Self>) -> Private;
    fn public(key: ecdh::PublicKey<Self>) -> Public;
    fn as_private(key: &PrivateKey) -> Option<&ecdh::PrivateKey<Self>>;
    fn as_public(key: &PublicKey) -> Option<&ecdh::PublicKey<Self>>;
}

macro_rules! group {
    ($curve:ident, $kem:ident, $kdf:ident, $bitmask:expr) => {
        impl Group for $curve {
            const KEM: Kem = Kem::$kem;
            const KDF: Kdf = Kdf::$kdf;
            const BITMASK: Option<u8> = $bitmask;

            fn private(key: ecdh::PrivateKey<Self>) -> Private {
                Private::$curve(key)
            }

            fn public(key: ecdh::PublicKey<Self>) -> Public {
                Public::$curve(key)
            }

            fn as_private(key: &PrivateKey) -> Option<&ecdh::PrivateKey<Self>> {
                match &key.inner {
                    Private::$curve(key) => Some(key),
                    _ => None,
                }
            }

            fn as_public(key: &PublicKey) -> Option<&ecdh::PublicKey<Self>> {
                match &key.0 {
                    Public::$curve(key) => Some(key),
                    _ => None,
                }
            }
        }
    };
}

group!(P256, P256HkdfSha256, HkdfSha256, Some(0xff));
group!(P384, P384HkdfSha384, HkdfSha384, Some(0xff));
group!(P521, P521HkdfSha512, HkdfSha512, Some(0x01));
group!(X25519, X25519HkdfSha256, HkdfSha256, None);

/// A private key of one of the four KEMs, wrapping the crate's ECDH key.
#[derive(Clone)]
enum Private {
    P256(ecdh::PrivateKey<P256>),
    P384(ecdh::PrivateKey<P384>),
    P521(ecdh::PrivateKey<P521>),
    X25519(ecdh::PrivateKey<X25519>),
}

/// A public key of one of the four KEMs.
#[derive(Clone, PartialEq, Eq)]
enum Public {
    P256(ecdh::PublicKey<P256>),
    P384(ecdh::PublicKey<P384>),
    P521(ecdh::PublicKey<P521>),
    X25519(ecdh::PublicKey<X25519>),
}

/// Runs `$body` with `G` the group of `$kem`.
macro_rules! with_group {
    ($kem:expr, $group:ident => $body:expr) => {
        match $kem {
            Kem::P256HkdfSha256 => {
                type $group = P256;
                $body
            }
            Kem::P384HkdfSha384 => {
                type $group = P384;
                $body
            }
            Kem::P521HkdfSha512 => {
                type $group = P521;
                $body
            }
            Kem::X25519HkdfSha256 => {
                type $group = X25519;
                $body
            }
        }
    };
}

/// A private key of a KEM: the recipient's long-term key, or the sender's in
/// the authenticated modes.
///
/// It is a key of the crate's [`ecdh`](crate::ecdh) for the KEM's curve, and
/// holds its public key. The key is overwritten with zeros when it is dropped,
/// and `Debug` shows only the KEM; as for ECDH's keys, that is best effort.
///
/// Make one with [`Kem::derive_key_pair`] from fresh random bytes, which works
/// for every KEM, or deserialize a stored one with
/// [`from_bytes`](Self::from_bytes).
#[derive(Clone)]
pub struct PrivateKey {
    inner: Private,
    public: PublicKey,
}

impl PrivateKey {
    /// `DeserializePrivateKey` (RFC 9180 section 7.1.2): the key of `kem`
    /// with these bytes, [`Kem::private_key_len`] of them.
    ///
    /// For the NIST curves that is the scalar as a big-endian number, which
    /// must be at least 1 and below the order of the curve. For X25519 it is
    /// any 32 bytes, clamped as RFC 9180 requires (the three low bits and the
    /// top bit cleared, bit 254 set), so 32 random bytes are a key.
    ///
    /// Computes the public key: one multiplication of the curve's generator.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidPrivateKey`] for bytes of the wrong length or, on a NIST
    /// curve, a scalar out of range.
    ///
    /// ```
    /// use cryptors::hpke::{Kem, PrivateKey};
    ///
    /// // RFC 7748 section 6.1, Alice.
    /// let key: [u8; 32] = [
    ///     0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d, 0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2, 0x66, 0x45,
    ///     0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a, 0xb1, 0x77, 0xfb, 0xa5, 0x1d, 0xb9, 0x2c, 0x2a,
    /// ];
    /// let sk = PrivateKey::from_bytes(Kem::X25519HkdfSha256, &key)?;
    /// assert_eq!(sk.public_key().as_bytes()[..4], [0x85, 0x20, 0xf0, 0x09]);
    ///
    /// // Serializing gives the key back clamped.
    /// assert_eq!(sk.as_bytes()[0], 0x77 & 248);
    /// # Ok::<(), cryptors::hpke::Error>(())
    /// ```
    pub fn from_bytes(kem: Kem, bytes: &[u8]) -> Result<Self, Error> {
        with_group!(kem, G => from_bytes::<G>(bytes))
    }

    /// `SerializePrivateKey` (RFC 9180 section 7.1.2): the bytes of the key,
    /// in the form [`from_bytes`](Self::from_bytes) takes. For X25519 they are
    /// clamped, so they can differ from the bytes the key was made from, while
    /// standing for the same key.
    pub fn as_bytes(&self) -> &[u8] {
        match &self.inner {
            Private::P256(key) => key.as_bytes(),
            Private::P384(key) => key.as_bytes(),
            Private::P521(key) => key.as_bytes(),
            Private::X25519(key) => key.as_bytes(),
        }
    }

    /// The public key, `pk(sk)`.
    pub fn public_key(&self) -> &PublicKey {
        &self.public
    }

    /// The KEM the key belongs to.
    pub fn kem(&self) -> Kem {
        self.public.kem()
    }
}

/// Shows the KEM and nothing else: the key is secret.
impl fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateKey")
            .field("kem", &self.kem())
            .finish_non_exhaustive()
    }
}

/// A public key of a KEM: the recipient's, or the sender's in the
/// authenticated modes. An encapsulated key `enc` is the serialization of one
/// too.
///
/// Holding one means the bytes passed the checks of the curve's ECDH: for the
/// NIST curves, an uncompressed point on the curve with reduced coordinates,
/// which is the validation RFC 9180 section 7.1.4 requires.
#[derive(Clone, PartialEq, Eq)]
pub struct PublicKey(Public);

impl PublicKey {
    /// `DeserializePublicKey` (RFC 9180 section 7.1.1): the key of `kem` with
    /// these bytes, [`Kem::public_key_len`] of them.
    ///
    /// For the NIST curves that is an uncompressed point, `0x04` followed by
    /// the two coordinates (SEC 1, section 2.3.3), which must be on the curve
    /// with coordinates below the prime; compressed points and the point at
    /// infinity are refused. For X25519 it is any 32 bytes, as RFC 7748
    /// requires: a key of small order, which would make the shared secret
    /// independent of the other side's key, is caught where it is used, with
    /// [`Error::LowOrderPublicKey`].
    ///
    /// # Errors
    ///
    /// [`Error::InvalidPublicKey`] for bytes of the wrong length or, on a NIST
    /// curve, that are not a valid point.
    pub fn from_bytes(kem: Kem, bytes: &[u8]) -> Result<Self, Error> {
        with_group!(kem, G => public_from_bytes::<G>(bytes))
    }

    /// `SerializePublicKey` (RFC 9180 section 7.1.1): the bytes of the key.
    pub fn as_bytes(&self) -> &[u8] {
        match &self.0 {
            Public::P256(key) => key.as_bytes(),
            Public::P384(key) => key.as_bytes(),
            Public::P521(key) => key.as_bytes(),
            Public::X25519(key) => key.as_bytes(),
        }
    }

    /// The KEM the key belongs to.
    pub fn kem(&self) -> Kem {
        match &self.0 {
            Public::P256(_) => Kem::P256HkdfSha256,
            Public::P384(_) => Kem::P384HkdfSha384,
            Public::P521(_) => Kem::P521HkdfSha512,
            Public::X25519(_) => Kem::X25519HkdfSha256,
        }
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "PublicKey {{ kem: {:?}, bytes: {} }}",
            self.kem(),
            hex(self.as_bytes())
        )
    }
}

impl Kem {
    /// `Nsk`: the length of a private key, and the least input keying material
    /// that [`derive_key_pair`](Self::derive_key_pair) and a sender's setup
    /// take: 32 bytes for X25519 and P-256, 48 for P-384, 66 for P-521.
    pub const fn private_key_len(self) -> usize {
        with_group!(self, G => G::PRIVATE_KEY_LEN)
    }

    /// `Npk` and `Nenc`: the length of a public key, and of an encapsulated key:
    /// 32 bytes for X25519, 65, 97 and 133 for P-256, P-384 and P-521.
    pub const fn public_key_len(self) -> usize {
        with_group!(self, G => G::PUBLIC_KEY_LEN)
    }

    /// `DeriveKeyPair(ikm)` (RFC 9180 section 7.1.3): the private key, which
    /// holds its public key, derived from the input keying material `ikm`.
    ///
    /// The key has only as much entropy as `ikm`, which RFC 9180 says should
    /// be at least [`private_key_len`](Self::private_key_len) bytes long with
    /// as many bytes of entropy. The length is enforced here; the entropy
    /// cannot be checked, and is the caller's to provide. An `ikm` must not be
    /// used for anything else, such as deriving a key of another KEM.
    ///
    /// For X25519 the derived bytes are the key. For the NIST curves they are
    /// a candidate scalar, masked to the bits the order has, and drawn again,
    /// up to 256 times, while they are zero or not below the order.
    ///
    /// # Errors
    ///
    /// [`Error::IkmTooShort`] for an `ikm` shorter than the private key, and
    /// [`Error::DeriveKeyPair`] if 256 candidates in a row are out of range,
    /// which no input is known to cause.
    ///
    /// ```
    /// use cryptors::hpke::Kem;
    ///
    /// // RFC 9180 Appendix A.1.1, the recipient.
    /// let ikm_r = [
    ///     0x6d, 0xb9, 0xdf, 0x30, 0xaa, 0x07, 0xdd, 0x42, 0xee, 0x5e, 0x81, 0x81, 0xaf, 0xdb, 0x97, 0x7e,
    ///     0x53, 0x8f, 0x5e, 0x1f, 0xec, 0x8a, 0x06, 0x22, 0x3f, 0x33, 0xf7, 0x01, 0x3e, 0x52, 0x50, 0x37,
    /// ];
    /// let sk_r = Kem::X25519HkdfSha256.derive_key_pair(&ikm_r)?;
    /// assert_eq!(sk_r.public_key().as_bytes()[..4], [0x39, 0x48, 0xcf, 0xe0]);
    /// # Ok::<(), cryptors::hpke::Error>(())
    /// ```
    pub fn derive_key_pair(self, ikm: &[u8]) -> Result<PrivateKey, Error> {
        with_group!(self, G => derive_key_pair::<G>(ikm).map(wrap::<G>))
    }
}

/// The KEM's `suite_id`: `"KEM" || I2OSP(kem_id, 2)` (RFC 9180 section 4.1),
/// which labels the derivations inside the KEM.
fn suite_id(kem: Kem) -> [u8; 5] {
    let id = kem.id().to_be_bytes();
    [b'K', b'E', b'M', id[0], id[1]]
}

/// An ECDH key as a KEM-agnostic one.
fn wrap<G: Group>(key: ecdh::PrivateKey<G>) -> PrivateKey {
    let public = PublicKey(G::public(key.public_key().clone()));
    PrivateKey {
        inner: G::private(key),
        public,
    }
}

fn from_bytes<G: Group>(bytes: &[u8]) -> Result<PrivateKey, Error> {
    let key = if G::BITMASK.is_none() {
        // X25519: RFC 9180 section 7.1.2 has the key clamped when it is
        // deserialized, so it is stored, and serialized, clamped.
        let bytes: &[u8; 32] = bytes.try_into().map_err(|_| Error::InvalidPrivateKey)?;
        let mut clamped = Secret::from_slice(bytes);
        clamp(clamped.as_mut_bytes());
        ecdh::PrivateKey::<G>::from_bytes(clamped.as_bytes())
    } else {
        ecdh::PrivateKey::<G>::from_bytes(bytes)
    };
    key.map(wrap::<G>).map_err(|_| Error::InvalidPrivateKey)
}

fn public_from_bytes<G: Group>(bytes: &[u8]) -> Result<PublicKey, Error> {
    let key = ecdh::PublicKey::<G>::from_bytes(bytes).map_err(|_| Error::InvalidPublicKey)?;
    Ok(PublicKey(G::public(key)))
}

/// `decodeScalar25519` of RFC 7748 section 5, as bytes.
fn clamp(scalar: &mut [u8]) {
    scalar[0] &= 248;
    scalar[31] &= 127;
    scalar[31] |= 64;
}

/// `DeriveKeyPair(ikm)` for the group `G` (RFC 9180 section 7.1.3).
fn derive_key_pair<G: Group>(ikm: &[u8]) -> Result<ecdh::PrivateKey<G>, Error> {
    if ikm.len() < G::PRIVATE_KEY_LEN {
        return Err(Error::IkmTooShort);
    }
    let suite_id = suite_id(G::KEM);
    let dkp_prk = G::KDF.labeled_extract(&suite_id, b"", b"dkp_prk", ikm);
    let mut sk = Secret::zeroed(G::PRIVATE_KEY_LEN);
    let expand = |label: &[u8], info: &[u8], out: &mut Secret| {
        G::KDF
            .labeled_expand(
                &suite_id,
                dkp_prk.as_bytes(),
                label,
                info,
                out.as_mut_bytes(),
            )
            .expect("a private key is within every KDF's limit");
    };

    let Some(bitmask) = G::BITMASK else {
        // X25519: sk = LabeledExpand(dkp_prk, "sk", "", Nsk), clamped as every
        // deserialized key is.
        expand(b"sk", b"", &mut sk);
        clamp(sk.as_mut_bytes());
        return ecdh::PrivateKey::<G>::from_bytes(sk.as_bytes()).map_err(|_| Error::DeriveKeyPair);
    };
    // The NIST curves: candidates until one is a valid scalar. Which one is
    // accepted depends on the key, as in every implementation of the RFC, but
    // a rejection happens with probability below 2^-32.
    for counter in 0..=255u8 {
        expand(b"candidate", &[counter], &mut sk);
        sk.as_mut_bytes()[0] &= bitmask;
        if let Ok(key) = ecdh::PrivateKey::<G>::from_bytes(sk.as_bytes()) {
            return Ok(key);
        }
    }
    Err(Error::DeriveKeyPair)
}

/// `DH(sk, pk)` (RFC 9180 section 4.1): the crate's ECDH, whose shared secret
/// is the x-coordinate on the NIST curves and the X25519 output otherwise. It
/// refuses the point at infinity, which for X25519 is the all-zero secret of
/// section 7.1.4.
fn dh<G: Group>(sk: &ecdh::PrivateKey<G>, pk: &ecdh::PublicKey<G>) -> Result<Secret, Error> {
    let shared = sk
        .diffie_hellman(pk)
        .map_err(|_| Error::LowOrderPublicKey)?;
    Ok(Secret::from_slice(shared.as_bytes()))
}

/// `ExtractAndExpand(dh, kem_context)` (RFC 9180 section 4.1), with the KDF of
/// the KEM: the KEM shared secret, `Nsecret` (the KDF's hash length) bytes.
fn extract_and_expand<G: Group>(dh: &Secret, kem_context: &[&[u8]]) -> Secret {
    let suite_id = suite_id(G::KEM);
    let eae_prk = G::KDF.labeled_extract(&suite_id, b"", b"eae_prk", dh.as_bytes());
    let mut shared_secret = Secret::zeroed(G::KDF.hash_len());
    G::KDF
        .labeled_expand(
            &suite_id,
            eae_prk.as_bytes(),
            b"shared_secret",
            &kem_context.concat(),
            shared_secret.as_mut_bytes(),
        )
        .expect("a hash length is within every KDF's limit");
    shared_secret
}

/// The two Diffie-Hellman outputs of the authenticated modes, one after the
/// other.
fn concat(first: &Secret, second: &Secret) -> Secret {
    let (a, b) = (first.as_bytes(), second.as_bytes());
    let mut both = Secret::zeroed(a.len() + b.len());
    both.as_mut_bytes()[..a.len()].copy_from_slice(a);
    both.as_mut_bytes()[a.len()..].copy_from_slice(b);
    both
}

/// The key of `G` that `key` is, or [`Error::KemMismatch`].
fn private_of<G: Group>(key: &PrivateKey) -> Result<&ecdh::PrivateKey<G>, Error> {
    G::as_private(key).ok_or(Error::KemMismatch)
}

fn public_of<G: Group>(key: &PublicKey) -> Result<&ecdh::PublicKey<G>, Error> {
    G::as_public(key).ok_or(Error::KemMismatch)
}

/// `Encap(pkR)`, or `AuthEncap(pkR, skS)` with a sender key (RFC 9180 section
/// 4.1), for the KEM `kem`, with the ephemeral key pair `DeriveKeyPair(ikm_e)`
/// in place of `GenerateKeyPair()`: the shared secret and the encapsulated
/// key `enc`.
pub(super) fn encap(
    kem: Kem,
    pk_r: &PublicKey,
    sk_s: Option<&PrivateKey>,
    ikm_e: &[u8],
) -> Result<(Secret, Vec<u8>), Error> {
    with_group!(kem, G => encap_in::<G>(pk_r, sk_s, ikm_e))
}

fn encap_in<G: Group>(
    pk_r: &PublicKey,
    sk_s: Option<&PrivateKey>,
    ikm_e: &[u8],
) -> Result<(Secret, Vec<u8>), Error> {
    let pk_r = public_of::<G>(pk_r)?;
    let sk_s = sk_s.map(private_of::<G>).transpose()?;
    let sk_e = derive_key_pair::<G>(ikm_e)?;
    let enc = sk_e.public_key().as_bytes().to_vec();
    let shared_secret = match sk_s {
        None => extract_and_expand::<G>(&dh(&sk_e, pk_r)?, &[&enc, pk_r.as_bytes()]),
        Some(sk_s) => extract_and_expand::<G>(
            &concat(&dh(&sk_e, pk_r)?, &dh(sk_s, pk_r)?),
            &[&enc, pk_r.as_bytes(), sk_s.public_key().as_bytes()],
        ),
    };
    Ok((shared_secret, enc))
}

/// `Decap(enc, skR)`, or `AuthDecap(enc, skR, pkS)` with a sender key (RFC
/// 9180 section 4.1), for the KEM `kem`: the shared secret.
pub(super) fn decap(
    kem: Kem,
    enc: &[u8],
    sk_r: &PrivateKey,
    pk_s: Option<&PublicKey>,
) -> Result<Secret, Error> {
    with_group!(kem, G => decap_in::<G>(enc, sk_r, pk_s))
}

fn decap_in<G: Group>(
    enc: &[u8],
    sk_r: &PrivateKey,
    pk_s: Option<&PublicKey>,
) -> Result<Secret, Error> {
    let sk_r = private_of::<G>(sk_r)?;
    let pk_s = pk_s.map(public_of::<G>).transpose()?;
    // DeserializePublicKey(enc), which on the NIST curves is the validation of
    // the ephemeral key that section 7.1.4 requires of the recipient.
    let pk_e = ecdh::PublicKey::<G>::from_bytes(enc).map_err(|_| Error::InvalidPublicKey)?;
    let pk_rm = sk_r.public_key().as_bytes();
    Ok(match pk_s {
        None => extract_and_expand::<G>(&dh(sk_r, &pk_e)?, &[enc, pk_rm]),
        Some(pk_s) => extract_and_expand::<G>(
            &concat(&dh(sk_r, &pk_e)?, &dh(sk_r, pk_s)?),
            &[enc, pk_rm, pk_s.as_bytes()],
        ),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_hides_the_key() {
        let key = PrivateKey::from_bytes(Kem::X25519HkdfSha256, &[0xab; 32]).unwrap();
        assert_eq!(
            format!("{key:?}"),
            "PrivateKey { kem: X25519HkdfSha256, .. }"
        );
    }
}
