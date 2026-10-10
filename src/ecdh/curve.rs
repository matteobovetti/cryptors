//! The [`Curve`] trait and the error type shared by every curve.

use core::fmt;

/// The longest private key, public key and shared secret of any curve here, in
/// bytes (P-521: a 66-byte scalar, and `1 + 2 * 66 = 133` for a point).
pub(super) const MAX_PRIVATE_KEY_LEN: usize = 66;
pub(super) const MAX_PUBLIC_KEY_LEN: usize = 133;
pub(super) const MAX_SHARED_SECRET_LEN: usize = 66;

/// A curve that [`PrivateKey`](super::PrivateKey) and
/// [`PublicKey`](super::PublicKey) can be used with: [`P256`](super::P256),
/// [`P384`](super::P384), [`P521`](super::P521) or [`X25519`](super::X25519).
///
/// The keys are generic over the curve, so a private key of one curve cannot be
/// combined with a public key of another: the compiler refuses it, where a
/// library that picks the curve at run time can only return an error.
///
/// The trait cannot be implemented outside this crate. What it exposes are the
/// sizes of the encodings; the arithmetic behind them is private.
pub trait Curve: sealed::Sealed {
    /// The name of the curve, as in the standards: `"P-256"`, `"X25519"`.
    const NAME: &'static str;

    /// Size in bytes of an encoded private key.
    const PRIVATE_KEY_LEN: usize;

    /// Size in bytes of an encoded public key.
    const PUBLIC_KEY_LEN: usize;

    /// Size in bytes of the shared secret of an exchange.
    const SHARED_SECRET_LEN: usize;
}

pub(super) mod sealed {
    use super::Error;

    /// What a curve does for the keys, in terms of byte strings. Every `bytes`,
    /// `private`, `public` and `out` has the length the curve's `Curve`
    /// constants give, except where a function says it checks the length.
    pub trait Sealed: Sized + 'static {
        /// The bits of the first byte of a random private key that can be set.
        /// Random bytes are masked with it before they are tested, so that a
        /// curve whose order is not a whole number of bytes (P-521) does not
        /// reject nearly all of its candidates.
        const FIRST_BYTE_MASK: u8;

        /// Whether `bytes` encodes a valid private key. It checks the length.
        fn check_private(bytes: &[u8]) -> bool;

        /// Writes the encoding of the public key of a valid `private` to `out`.
        fn public_key(private: &[u8], out: &mut [u8]);

        /// Whether `bytes` encodes a valid public key. It checks the length.
        fn check_public(bytes: &[u8]) -> bool;

        /// Writes the shared secret of a valid `private` and a valid `public`
        /// to `out`, or fails if the secret would be the point at infinity (or,
        /// for X25519, all zeros).
        fn diffie_hellman(private: &[u8], public: &[u8], out: &mut [u8]) -> Result<(), Error>;
    }
}

/// Why a key or an exchange was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// The bytes are not a private key of the curve: wrong length or, for a
    /// NIST curve, zero or not below the order of the curve.
    InvalidPrivateKey,

    /// The bytes are not a public key of the curve: wrong length or, for a
    /// NIST curve, not an uncompressed point on the curve with both coordinates
    /// reduced.
    InvalidPublicKey,

    /// The shared secret would be the point at infinity, which for X25519 is
    /// the all-zero value. That happens when the peer's public key is one of
    /// the few points of small order, and a peer that sends one is trying to
    /// force the secret to a known value. NIST curves have prime order, so a
    /// valid public key never does this to them.
    LowOrderPoint,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Error::InvalidPrivateKey => "ecdh: invalid private key",
            Error::InvalidPublicKey => "ecdh: invalid public key",
            Error::LowOrderPoint => "ecdh: the peer's public key is a point of small order",
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
            "ecdh: invalid private key"
        );
        assert_eq!(
            Error::InvalidPublicKey.to_string(),
            "ecdh: invalid public key"
        );
        assert_eq!(
            Error::LowOrderPoint.to_string(),
            "ecdh: the peer's public key is a point of small order"
        );

        // It is a standard error, so it works with `?` into a `Box<dyn Error>`.
        fn fails() -> Result<(), Box<dyn std::error::Error>> {
            Err(Error::LowOrderPoint)?
        }
        assert_eq!(
            fails().unwrap_err().to_string(),
            Error::LowOrderPoint.to_string()
        );
    }
}
