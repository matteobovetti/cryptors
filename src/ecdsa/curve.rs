//! The [`Curve`] trait and the error type shared by every curve.

use core::fmt;

/// The longest private key of any curve here, in bytes (P-521: the order has 521
/// bits). It is also the longest `r` or `s`.
pub(super) const MAX_PRIVATE_KEY_LEN: usize = 66;
/// The longest public key, in bytes (P-521: `1 + 2 * 66`).
pub(super) const MAX_PUBLIC_KEY_LEN: usize = 133;
/// The longest signature as `r || s`, in bytes.
pub(super) const MAX_SIGNATURE_LEN: usize = 2 * MAX_PRIVATE_KEY_LEN;

/// A curve that [`PrivateKey`](super::PrivateKey),
/// [`PublicKey`](super::PublicKey) and [`Signature`](super::Signature) can be
/// used with: [`P224`](super::P224), [`P256`](super::P256),
/// [`P384`](super::P384) or [`P521`](super::P521).
///
/// The keys and signatures are generic over the curve, so a key of one curve
/// cannot be used with a signature of another: the compiler refuses it, where a
/// library that picks the curve at run time can only return an error.
///
/// The trait cannot be implemented outside this crate. What it exposes are the
/// sizes of the encodings; the arithmetic behind them is private.
pub trait Curve: sealed::Sealed {
    /// The name of the curve, as in the standards: `"P-256"`.
    const NAME: &'static str;

    /// Size in bytes of an encoded private key, which is also the size of `r`
    /// and of `s`.
    const PRIVATE_KEY_LEN: usize;

    /// Size in bytes of an encoded public key.
    const PUBLIC_KEY_LEN: usize;

    /// Size in bytes of a signature written as `r || s`.
    const SIGNATURE_LEN: usize;
}

pub(super) mod sealed {
    /// What a curve does for the keys and signatures, in terms of byte
    /// strings. Every `bytes`, `private`, `public`, `signature` and `out` has
    /// the length the curve's `Curve` constants give, except where a function
    /// says it checks the length.
    pub trait Sealed: Sized + 'static {
        /// The number of bits that a private key of `PRIVATE_KEY_LEN` bytes has
        /// beyond the bit length of the order: 0 for every curve but P-521, which
        /// has 7. A random string of that many bytes is shifted right by it, so
        /// that what is tested is its leftmost bits (FIPS 186-5, appendix B.2.1:
        /// the first bit of a string is the most significant), and a curve whose
        /// order is not a whole number of bytes does not reject nearly all of
        /// its candidates.
        const EXCESS_BITS: u32;

        /// Whether `bytes` encodes a valid private key. It checks the length.
        fn check_private(bytes: &[u8]) -> bool;

        /// Writes the encoding of the public key of a valid `private` to `out`.
        fn public_key(private: &[u8], out: &mut [u8]);

        /// Whether `bytes` encodes a valid public key. It checks the length.
        fn check_public(bytes: &[u8]) -> bool;

        /// Whether `bytes` is `r || s` with both numbers from 1 to the order
        /// minus 1. It checks the length.
        fn check_signature(bytes: &[u8]) -> bool;

        /// Writes `bits2octets(digest)` (RFC 6979, section 2.3.4) to `out`: the
        /// digest as a number modulo the order, as many bytes as a private key.
        fn digest_to_octets(digest: &[u8], out: &mut [u8]);

        /// Writes the signature of `digest` by a valid `private` to `out` as
        /// `r || s`, with the per-message secrets that `nonces` offers.
        fn sign(private: &[u8], digest: &[u8], nonces: &mut dyn Nonces, out: &mut [u8]);

        /// Whether `signature` is a signature of `digest` by `public`. It checks
        /// the length of all three.
        fn verify(public: &[u8], digest: &[u8], signature: &[u8]) -> bool;
    }

    /// A source of candidates for the per-message secret number.
    pub trait Nonces {
        /// Fills `out` with the next candidate: a string of bytes of which the
        /// signing code takes the leftmost bits (FIPS 186-5, appendix A.3), and
        /// tests whether they are a number from 1 to the order minus 1.
        fn candidate(&mut self, out: &mut [u8]);
    }
}

/// Why a key, a signature or a verification was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// The bytes are not a private key of the curve: wrong length, zero, or not
    /// below the order of the curve.
    InvalidPrivateKey,

    /// The bytes are not a public key of the curve: wrong length, not an
    /// uncompressed point, a coordinate that is not reduced, or a point that is
    /// not on the curve.
    InvalidPublicKey,

    /// The bytes are not a signature of the curve: wrong length, `r` or `s`
    /// zero or not below the order of the curve, or, for the DER form, not
    /// exactly the encoding that DER prescribes.
    InvalidSignature,

    /// The digest to sign or verify is empty, or is not as long as the output of
    /// the hash function that was named for it.
    InvalidDigest,

    /// The signature is well formed, but it is not a signature of this message
    /// by this key.
    VerificationFailed,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Error::InvalidPrivateKey => "ecdsa: invalid private key",
            Error::InvalidPublicKey => "ecdsa: invalid public key",
            Error::InvalidSignature => "ecdsa: invalid signature encoding",
            Error::InvalidDigest => "ecdsa: invalid digest",
            Error::VerificationFailed => "ecdsa: signature did not verify",
        })
    }
}

impl std::error::Error for Error {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn errors_say_what_went_wrong() {
        assert_eq!(
            Error::InvalidPrivateKey.to_string(),
            "ecdsa: invalid private key"
        );
        assert_eq!(
            Error::InvalidPublicKey.to_string(),
            "ecdsa: invalid public key"
        );
        assert_eq!(
            Error::InvalidSignature.to_string(),
            "ecdsa: invalid signature encoding"
        );
        assert_eq!(Error::InvalidDigest.to_string(), "ecdsa: invalid digest");
        assert_eq!(
            Error::VerificationFailed.to_string(),
            "ecdsa: signature did not verify"
        );

        // It is a standard error, so it works with `?` into a `Box<dyn Error>`.
        fn fails() -> Result<(), Box<dyn std::error::Error>> {
            Err(Error::VerificationFailed)?
        }
        assert_eq!(
            fails().unwrap_err().to_string(),
            Error::VerificationFailed.to_string()
        );
    }
}
