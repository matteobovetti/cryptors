//! The [`Digest`] trait: the interface shared by every fixed-output hash
//! function in this crate.

/// A hash function with a fixed-size output, such as MD5, SHA-1 or SHA-256.
///
/// Implementors are zero-sized marker types (`Md5`, `Sha1`, `Sha256`, ...);
/// the trait only carries functions and constants, no state. Everything is
/// resolved at compile time, so calling `Sha256::digest(x)` and calling
/// `D::digest(x)` in code generic over `D: Digest` compile to the same thing.
///
/// Bring the trait into scope to call the functions:
///
/// ```
/// use cryptors::{Digest, sha2::Sha256};
///
/// assert_eq!(
///     Sha256::hex_digest(b"abc"),
///     "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
/// );
/// ```
///
/// And, in generic code, treat the hash as a parameter:
///
/// ```
/// use cryptors::{Digest, md5::Md5, sha1::Sha1};
///
/// fn digest_len<D: Digest>() -> usize {
///     D::digest(b"abc").as_ref().len()
/// }
///
/// assert_eq!(digest_len::<Md5>(), 16);
/// assert_eq!(digest_len::<Sha1>(), 20);
/// ```
pub trait Digest {
    /// Size in bytes of the blocks the hash function consumes at a time. HMAC
    /// needs this to size its key padding.
    const BLOCK_LEN: usize;

    /// Size in bytes of a digest. Always equals `Self::Output`'s length.
    const OUTPUT_LEN: usize;

    /// A digest: a `[u8; OUTPUT_LEN]`.
    type Output: AsRef<[u8]>;

    /// Computes the digest of `input`.
    fn digest(input: &[u8]) -> Self::Output;

    /// Computes the digest of `input` and renders it as lowercase hex.
    fn hex_digest(input: &[u8]) -> String {
        hex(Self::digest(input).as_ref())
    }

    /// Computes the digest of every message in `inputs`, in order.
    ///
    /// The default hashes them one at a time. A hash function that can do
    /// better by hashing several messages side by side (MD5 does, in SIMD
    /// lanes) overrides it.
    fn digest_many(inputs: &[&[u8]]) -> Vec<Self::Output> {
        inputs.iter().map(|input| Self::digest(input)).collect()
    }
}

const HEX: &[u8; 16] = b"0123456789abcdef";

/// Renders `bytes` as lowercase hex.
pub(crate) fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(char::from(HEX[(b >> 4) as usize]));
        out.push(char::from(HEX[(b & 0xf) as usize]));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        md5::Md5,
        sha1::Sha1,
        sha2::{Sha224, Sha256, Sha384, Sha512, Sha512_224, Sha512_256},
    };

    /// Checks, for any hash, that the constants agree with the output type
    /// and that the provided functions agree with `digest`. The digests
    /// themselves are checked against known answers by each algorithm's own
    /// tests.
    fn check<D: Digest>() {
        let digest = D::digest(b"abc");
        assert_eq!(digest.as_ref().len(), D::OUTPUT_LEN);
        assert_eq!(D::hex_digest(b"abc"), hex(digest.as_ref()));

        let messages: [&[u8]; 3] = [b"abc", b"", b"a longer message"];
        let many = D::digest_many(&messages);
        assert_eq!(many.len(), messages.len());
        for (one, message) in many.iter().zip(messages) {
            assert_eq!(one.as_ref(), D::digest(message).as_ref());
        }
        assert!(D::digest_many(&[]).is_empty());
    }

    #[test]
    fn every_hash_satisfies_the_contract() {
        check::<Md5>();
        check::<Sha1>();
        check::<Sha224>();
        check::<Sha256>();
        check::<Sha384>();
        check::<Sha512>();
        check::<Sha512_224>();
        check::<Sha512_256>();
    }

    #[test]
    fn block_lengths() {
        assert_eq!(Md5::BLOCK_LEN, 64);
        assert_eq!(Sha1::BLOCK_LEN, 64);
        assert_eq!(Sha224::BLOCK_LEN, 64);
        assert_eq!(Sha256::BLOCK_LEN, 64);
        assert_eq!(Sha384::BLOCK_LEN, 128);
        assert_eq!(Sha512::BLOCK_LEN, 128);
        assert_eq!(Sha512_224::BLOCK_LEN, 128);
        assert_eq!(Sha512_256::BLOCK_LEN, 128);
    }

    #[test]
    fn hex_renders_lowercase() {
        assert_eq!(hex(&[]), "");
        assert_eq!(hex(&[0x00, 0x0f, 0xa5, 0xff]), "000fa5ff");
    }
}
