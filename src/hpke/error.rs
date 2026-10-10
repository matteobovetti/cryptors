use core::fmt;

/// Why an HPKE operation failed.
///
/// Where RFC 9180 names the error (section 8.2), the variant says which one
/// it is. None of them carries data: an error says what went wrong, never
/// anything about the secrets involved.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Error {
    /// [`Suite::from_ids`](super::Suite::from_ids) was given a KEM, KDF or
    /// AEAD identifier that this crate does not implement.
    UnsupportedAlgorithm,
    /// Bytes that are not a private key of the KEM: the wrong length or, on a
    /// NIST curve, a scalar that is zero or not below the order. RFC 9180's
    /// `DeserializeError`.
    InvalidPrivateKey,
    /// Bytes that are not a public key or an encapsulated key of the KEM: the
    /// wrong length or, on a NIST curve, not an uncompressed point on the
    /// curve. RFC 9180's `DeserializeError`, and for an encapsulated key the
    /// `ValidationError` of section 7.1.4.
    InvalidPublicKey,
    /// A key of one KEM was given to a suite of another.
    KemMismatch,
    /// Input keying material shorter than the KEM's private key
    /// ([`Kem::private_key_len`](super::Kem::private_key_len)) was given to
    /// [`Kem::derive_key_pair`](super::Kem::derive_key_pair) or to a sender's
    /// setup.
    IkmTooShort,
    /// `DeriveKeyPair` drew 256 candidate scalars in a row that were out of
    /// range: RFC 9180's `DeriveKeyPairError` (section 7.1.3), which no input
    /// is known to cause.
    DeriveKeyPair,
    /// A pre-shared key and its identifier that do not go together: one of
    /// them is empty and the other is not, both are empty in a mode that needs
    /// them, or the key is shorter than 32 bytes.
    InvalidPsk,
    /// A Diffie-Hellman shared secret came out as the point at infinity, which
    /// for X25519 is the all-zero value and happens exactly when the other
    /// side's public key is a point of small order: RFC 9180's
    /// `ValidationError` (section 7.1.4). A valid key of a NIST curve never
    /// causes it.
    LowOrderPublicKey,
    /// A ciphertext did not decrypt: it was altered, or the key, `info`,
    /// associated data, pre-shared key, sender key or position in the sequence
    /// is not the one it was sealed with. RFC 9180's `OpenError`. Which of
    /// those it was cannot be told apart, by design.
    Open,
    /// The context has used every nonce its sequence number can make, `2^96 -
    /// 1` of them: RFC 9180's `MessageLimitReachedError`.
    MessageLimitReached,
    /// A plaintext longer than AES-GCM can encrypt under one nonce, `2^36 -
    /// 32` bytes.
    MessageTooLong,
    /// An export longer than 255 hash lengths of the suite's KDF.
    ExportTooLong,
    /// `seal` or `open` on a suite whose AEAD is
    /// [`Aead::ExportOnly`](super::Aead::ExportOnly), which only exports.
    ExportOnly,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Error::UnsupportedAlgorithm => "unsupported HPKE KEM, KDF or AEAD identifier",
            Error::InvalidPrivateKey => "invalid HPKE private key",
            Error::InvalidPublicKey => "invalid HPKE public key or encapsulated key",
            Error::KemMismatch => "HPKE key of another KEM than the suite's",
            Error::IkmTooShort => "HPKE input keying material is shorter than a private key",
            Error::DeriveKeyPair => "HPKE key derivation found no valid scalar",
            Error::InvalidPsk => "inconsistent or too short HPKE pre-shared key",
            Error::LowOrderPublicKey => "HPKE public key of small order (all-zero shared secret)",
            Error::Open => "HPKE ciphertext failed to decrypt",
            Error::MessageLimitReached => "HPKE context has reached its message limit",
            Error::MessageTooLong => "HPKE plaintext is too long for AES-GCM",
            Error::ExportTooLong => "HPKE export is longer than 255 hash lengths",
            Error::ExportOnly => "HPKE suite is export-only and cannot seal or open",
        })
    }
}

impl core::error::Error for Error {}
