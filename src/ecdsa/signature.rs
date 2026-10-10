//! The signature type and its two encodings.

use super::curve::{Curve, Error, MAX_SIGNATURE_LEN};
use super::der;
use crate::digest::hex;
use core::fmt;
use core::marker::PhantomData;

/// An ECDSA signature on the curve `C`: the pair of numbers `(r, s)`.
///
/// It is written two ways. [`as_bytes`](Signature::as_bytes) is `r || s`, each
/// number a big-endian string of [`Curve::PRIVATE_KEY_LEN`] bytes (the form of
/// IEEE P1363, JSON Web Signature and COSE). [`to_der`](Signature::to_der)
/// is the ASN.1 DER `SEQUENCE { r INTEGER, s INTEGER }` of RFC 3279 and SEC 1,
/// which X.509 certificates and TLS carry.
///
/// Holding one means `r` and `s` are numbers from 1 to the order of the curve
/// minus 1. That a signature is well formed says nothing about whether it is a
/// signature of anything: [`PublicKey::verify`](super::PublicKey::verify) says
/// that.
pub struct Signature<C: Curve> {
    bytes: [u8; MAX_SIGNATURE_LEN],
    curve: PhantomData<C>,
}

impl<C: Curve> Signature<C> {
    /// `bytes` must have passed `C::check_signature`.
    pub(super) fn new(bytes: &[u8]) -> Self {
        let mut signature = Self {
            bytes: [0; MAX_SIGNATURE_LEN],
            curve: PhantomData,
        };
        signature.bytes[..C::SIGNATURE_LEN].copy_from_slice(bytes);
        signature
    }

    /// Builds a signature from `r || s`: [`Curve::SIGNATURE_LEN`] bytes, each
    /// half a big-endian number from 1 to the order of the curve minus 1.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if !C::check_signature(bytes) {
            return Err(Error::InvalidSignature);
        }
        Ok(Self::new(bytes))
    }

    /// Builds a signature from its DER encoding.
    ///
    /// Only the encoding that DER prescribes is accepted: a sequence of exactly
    /// the length that was declared, with nothing after it, holding two
    /// positive integers, each in its shortest form (a leading zero byte only
    /// where the top bit of the next one is set) and each from 1 to the order
    /// of the curve minus 1. A looser reader would make one signature valid in
    /// several forms.
    pub fn from_der(der: &[u8]) -> Result<Self, Error> {
        let mut bytes = [0u8; MAX_SIGNATURE_LEN];
        let bytes = &mut bytes[..C::SIGNATURE_LEN];
        der::decode(der, C::PRIVATE_KEY_LEN, bytes).ok_or(Error::InvalidSignature)?;
        Self::from_bytes(bytes)
    }

    /// The signature as `r || s`, in the form [`from_bytes`] takes.
    ///
    /// [`from_bytes`]: Signature::from_bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..C::SIGNATURE_LEN]
    }

    /// The DER encoding of the signature, in the form [`from_der`] takes. Its
    /// length depends on the numbers: from 8 bytes up to 64, 72, 104 and 139 for
    /// P-224, P-256, P-384 and P-521.
    ///
    /// [`from_der`]: Signature::from_der
    pub fn to_der(&self) -> Vec<u8> {
        der::encode(self.as_bytes())
    }
}

impl<C: Curve> AsRef<[u8]> for Signature<C> {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl<C: Curve> Clone for Signature<C> {
    fn clone(&self) -> Self {
        Self {
            bytes: self.bytes,
            curve: PhantomData,
        }
    }
}

/// Two signatures are equal if their numbers are.
impl<C: Curve> PartialEq for Signature<C> {
    fn eq(&self, other: &Self) -> bool {
        self.as_bytes() == other.as_bytes()
    }
}

impl<C: Curve> Eq for Signature<C> {}

impl<C: Curve> fmt::Debug for Signature<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Signature<{}>({})", C::NAME, hex(self.as_bytes()))
    }
}
