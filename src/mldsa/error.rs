//! The error type of the module.

use core::fmt;

/// Why a key, a signature, a context or a verification was refused.
///
/// None of the variants carries data: an error says what went wrong and never
/// anything about the key it happened with.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Error {
    /// The bytes are not a public key of the parameter set: they are not as
    /// long as [`Parameters::PUBLIC_KEY_LEN`](super::Parameters::PUBLIC_KEY_LEN).
    /// Every string of that length is a public key.
    InvalidPublicKey,

    /// The bytes are not a signature of the parameter set: they are not as long
    /// as [`Parameters::SIGNATURE_LEN`](super::Parameters::SIGNATURE_LEN), or the
    /// hint at the end is not encoded the one way that FIPS 204 allows
    /// (indices that do not increase, counts that fall or go past `omega`, or a
    /// nonzero byte among the unused ones).
    InvalidSignature,

    /// The context is longer than 255 bytes.
    ContextTooLong,

    /// The digest handed to a pre-hash function is not as long as the output of
    /// the [`PreHash`](super::PreHash) that was named for it.
    InvalidDigest,

    /// The signature is well formed, but it is not a signature of this message
    /// (with this context) by this key.
    VerificationFailed,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Error::InvalidPublicKey => "mldsa: invalid public key",
            Error::InvalidSignature => "mldsa: invalid signature encoding",
            Error::ContextTooLong => "mldsa: context is longer than 255 bytes",
            Error::InvalidDigest => "mldsa: digest is not as long as the pre-hash function's",
            Error::VerificationFailed => "mldsa: signature did not verify",
        })
    }
}

impl core::error::Error for Error {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn errors_say_what_went_wrong() {
        assert_eq!(
            Error::InvalidPublicKey.to_string(),
            "mldsa: invalid public key"
        );
        assert_eq!(
            Error::InvalidSignature.to_string(),
            "mldsa: invalid signature encoding"
        );
        assert_eq!(
            Error::ContextTooLong.to_string(),
            "mldsa: context is longer than 255 bytes"
        );
        assert_eq!(
            Error::InvalidDigest.to_string(),
            "mldsa: digest is not as long as the pre-hash function's"
        );
        assert_eq!(
            Error::VerificationFailed.to_string(),
            "mldsa: signature did not verify"
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
