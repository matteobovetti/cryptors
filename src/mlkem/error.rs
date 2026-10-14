//! The error type of the module.

use core::fmt;

/// Why a key or a ciphertext was refused.
///
/// None of the variants carries data: an error says what went wrong and never
/// anything about the key it happened with.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Error {
    /// The bytes are not an encapsulation key of the parameter set: they are
    /// not as long as
    /// [`Parameters::ENCAPSULATION_KEY_LEN`](super::Parameters::ENCAPSULATION_KEY_LEN),
    /// or a coefficient of the key is not below `q = 3329` (the "modulus check"
    /// of FIPS 203, section 7.2).
    InvalidEncapsulationKey,

    /// The bytes are not a ciphertext of the parameter set: they are not as long
    /// as [`Parameters::CIPHERTEXT_LEN`](super::Parameters::CIPHERTEXT_LEN).
    /// Every string of that length is a ciphertext.
    InvalidCiphertext,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Error::InvalidEncapsulationKey => "mlkem: invalid encapsulation key",
            Error::InvalidCiphertext => "mlkem: invalid ciphertext length",
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
            Error::InvalidEncapsulationKey.to_string(),
            "mlkem: invalid encapsulation key"
        );
        assert_eq!(
            Error::InvalidCiphertext.to_string(),
            "mlkem: invalid ciphertext length"
        );

        // It is a standard error, so it works with `?` into a `Box<dyn Error>`.
        fn fails() -> Result<(), Box<dyn std::error::Error>> {
            Err(Error::InvalidCiphertext)?
        }
        assert_eq!(
            fails().unwrap_err().to_string(),
            Error::InvalidCiphertext.to_string()
        );
    }
}
