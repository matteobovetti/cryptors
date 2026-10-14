//! The error type of the module.

use core::fmt;

/// Why a key, a message, a ciphertext or a signature was refused.
///
/// None of the variants carries data: an error says what went wrong and never
/// anything about the key it happened with. [`Decryption`](Error::Decryption)
/// and [`VerificationFailed`](Error::VerificationFailed) are deliberately vague:
/// they are the same whichever of the checks of the padding failed, because a
/// caller that can tell them apart can be used as an oracle (Bleichenbacher's
/// attack on PKCS #1 v1.5, Manger's on OAEP).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Error {
    /// The modulus has fewer than 1,024 or more than 16,384 bits. Smaller keys
    /// can be factored; larger ones are refused so that an input from outside
    /// cannot make a verification take minutes.
    UnsupportedKeySize,

    /// The modulus is even, or the public exponent is not an odd number from 3
    /// to 2^31 - 1.
    InvalidPublicKey,

    /// The components of a private key are not those of an RSA key: the primes
    /// do not multiply to the modulus, they are too close to each other, the
    /// private exponent is too small or is not the inverse of the public
    /// exponent, or a number is out of range.
    InvalidPrivateKey,

    /// The message is too long for the key (and, for OAEP, the hash), or the
    /// salt is too long for it: there is no room for the padding.
    MessageTooLong,

    /// The digest handed to a signature function is not as long as the output
    /// of the hash that was named for it.
    InvalidDigest,

    /// The ciphertext did not decrypt: it is not as long as the modulus, it is
    /// not below the modulus, or its padding is wrong. Which of them is not
    /// said.
    Decryption,

    /// The signature is not a signature of this message by this key. Which
    /// check failed is not said.
    VerificationFailed,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Error::UnsupportedKeySize => "rsa: unsupported key size",
            Error::InvalidPublicKey => "rsa: invalid public key",
            Error::InvalidPrivateKey => "rsa: invalid private key",
            Error::MessageTooLong => "rsa: message too long for RSA key size",
            Error::InvalidDigest => "rsa: digest is not as long as the hash's output",
            Error::Decryption => "rsa: decryption error",
            Error::VerificationFailed => "rsa: verification error",
        })
    }
}

impl core::error::Error for Error {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn errors_say_what_went_wrong() {
        let all = [
            (Error::UnsupportedKeySize, "rsa: unsupported key size"),
            (Error::InvalidPublicKey, "rsa: invalid public key"),
            (Error::InvalidPrivateKey, "rsa: invalid private key"),
            (
                Error::MessageTooLong,
                "rsa: message too long for RSA key size",
            ),
            (
                Error::InvalidDigest,
                "rsa: digest is not as long as the hash's output",
            ),
            (Error::Decryption, "rsa: decryption error"),
            (Error::VerificationFailed, "rsa: verification error"),
        ];
        for (error, text) in all {
            assert_eq!(error.to_string(), text);
        }

        // It is a standard error, so it works with `?` into a `Box<dyn Error>`.
        fn fails() -> Result<(), Box<dyn std::error::Error>> {
            Err(Error::Decryption)?
        }
        assert_eq!(
            fails().unwrap_err().to_string(),
            Error::Decryption.to_string()
        );
    }
}
