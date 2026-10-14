//! The hash functions that HashML-DSA can pre-hash a message with (FIPS 204,
//! section 5.4.1, algorithm 4).

use crate::Digest;
use crate::sha2::{Sha224, Sha256, Sha384, Sha512, Sha512_224, Sha512_256};
use crate::sha3;

/// The hash function or extendable-output function that HashML-DSA signs a digest
/// of: the twelve that NIST gave an object identifier in its hash algorithm
/// registry, which FIPS 204 names.
///
/// The identifier goes into the bytes that are signed, so a signature made over
/// a SHA-256 digest does not verify as one made over a SHA3-256 digest, whatever
/// the digest.
///
/// FIPS 204 asks for a hash with at least `lambda` bits of strength against
/// collisions and second preimages, where `lambda` is 128, 192 and 256 for
/// ML-DSA-44, ML-DSA-65 and ML-DSA-87 (section 5.4): a digest of at least `2 *
/// lambda` bits. That makes the 224-bit hashes too short for every set, and
/// the 256-bit ones for ML-DSA-65 and ML-DSA-87. This crate leaves the choice
/// to the caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum PreHash {
    /// SHA-224: a digest of 28 bytes.
    Sha224,
    /// SHA-256: 32 bytes.
    Sha256,
    /// SHA-384: 48 bytes.
    Sha384,
    /// SHA-512: 64 bytes.
    Sha512,
    /// SHA-512/224: 28 bytes.
    Sha512_224,
    /// SHA-512/256: 32 bytes.
    Sha512_256,
    /// SHA3-224: 28 bytes.
    Sha3_224,
    /// SHA3-256: 32 bytes.
    Sha3_256,
    /// SHA3-384: 48 bytes.
    Sha3_384,
    /// SHA3-512: 64 bytes.
    Sha3_512,
    /// SHAKE128 with an output of 256 bits: 32 bytes.
    Shake128,
    /// SHAKE256 with an output of 512 bits: 64 bytes.
    Shake256,
}

impl PreHash {
    /// Size in bytes of the digest that this function gives and that the signing
    /// functions expect. For the two SHAKE functions it is the length that
    /// FIPS 204 fixes: 256 and 512 bits.
    pub const fn digest_len(self) -> usize {
        match self {
            PreHash::Sha224 | PreHash::Sha512_224 | PreHash::Sha3_224 => 28,
            PreHash::Sha256 | PreHash::Sha512_256 | PreHash::Sha3_256 | PreHash::Shake128 => 32,
            PreHash::Sha384 | PreHash::Sha3_384 => 48,
            PreHash::Sha512 | PreHash::Sha3_512 | PreHash::Shake256 => 64,
        }
    }

    /// The digest of `message`, with this crate's implementation of the function.
    ///
    /// ```
    /// use cryptors::mldsa::PreHash;
    ///
    /// let digest = PreHash::Sha3_256.digest(b"abc");
    /// assert_eq!(digest.len(), PreHash::Sha3_256.digest_len());
    /// assert_eq!(digest[..4], [0x3a, 0x98, 0x5d, 0xa7]);
    /// ```
    pub fn digest(self, message: &[u8]) -> Vec<u8> {
        match self {
            PreHash::Sha224 => Sha224::digest(message).to_vec(),
            PreHash::Sha256 => Sha256::digest(message).to_vec(),
            PreHash::Sha384 => Sha384::digest(message).to_vec(),
            PreHash::Sha512 => Sha512::digest(message).to_vec(),
            PreHash::Sha512_224 => Sha512_224::digest(message).to_vec(),
            PreHash::Sha512_256 => Sha512_256::digest(message).to_vec(),
            PreHash::Sha3_224 => sha3::sha3_224(message).to_vec(),
            PreHash::Sha3_256 => sha3::sha3_256(message).to_vec(),
            PreHash::Sha3_384 => sha3::sha3_384(message).to_vec(),
            PreHash::Sha3_512 => sha3::sha3_512(message).to_vec(),
            PreHash::Shake128 => {
                let mut digest = vec![0; 32];
                sha3::shake128(message, &mut digest);
                digest
            }
            PreHash::Shake256 => {
                let mut digest = vec![0; 64];
                sha3::shake256(message, &mut digest);
                digest
            }
        }
    }

    /// The DER encoding of the object identifier, tag and length included
    /// (`06 09 60 86 48 01 65 03 04 02` and one more byte): the `OID` of
    /// algorithm 4. They are the identifiers 2.16.840.1.101.3.4.2.1 to
    /// 2.16.840.1.101.3.4.2.12 of NIST's hash algorithm registry.
    pub(super) const fn oid(self) -> [u8; 11] {
        let last = match self {
            PreHash::Sha256 => 0x01,
            PreHash::Sha384 => 0x02,
            PreHash::Sha512 => 0x03,
            PreHash::Sha224 => 0x04,
            PreHash::Sha512_224 => 0x05,
            PreHash::Sha512_256 => 0x06,
            PreHash::Sha3_224 => 0x07,
            PreHash::Sha3_256 => 0x08,
            PreHash::Sha3_384 => 0x09,
            PreHash::Sha3_512 => 0x0a,
            PreHash::Shake128 => 0x0b,
            PreHash::Shake256 => 0x0c,
        };
        [
            0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, last,
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL: [PreHash; 12] = [
        PreHash::Sha224,
        PreHash::Sha256,
        PreHash::Sha384,
        PreHash::Sha512,
        PreHash::Sha512_224,
        PreHash::Sha512_256,
        PreHash::Sha3_224,
        PreHash::Sha3_256,
        PreHash::Sha3_384,
        PreHash::Sha3_512,
        PreHash::Shake128,
        PreHash::Shake256,
    ];

    #[test]
    fn digests_have_the_lengths_they_declare() {
        for hash in ALL {
            assert_eq!(hash.digest(b"abc").len(), hash.digest_len(), "{hash:?}");
        }
    }

    /// FIPS 204 (algorithm 4) gives the encodings for SHA-256, SHA-512 and
    /// SHAKE128; the rest follow the registry, whose arcs are distinct.
    #[test]
    fn object_identifiers() {
        assert_eq!(
            PreHash::Sha256.oid(),
            [
                0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01
            ]
        );
        assert_eq!(PreHash::Sha512.oid()[10], 0x03);
        assert_eq!(PreHash::Shake128.oid()[10], 0x0b);
        let mut last: Vec<u8> = ALL.iter().map(|h| h.oid()[10]).collect();
        last.sort_unstable();
        assert_eq!(last, (1..=12).collect::<Vec<u8>>());
        for hash in ALL {
            assert_eq!(hash.oid()[..10], PreHash::Sha256.oid()[..10]);
        }
    }
}
