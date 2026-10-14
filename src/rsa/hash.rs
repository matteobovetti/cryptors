//! The hashes that a PKCS #1 v1.5 signature can name.

use crate::Digest;
use crate::md5::Md5;
use crate::sha1::Sha1;
use crate::sha2::{Sha224, Sha256, Sha384, Sha512, Sha512_224, Sha512_256};

mod sealed {
    pub trait Sealed {}
}

/// A hash whose name goes into a PKCS #1 v1.5 signature.
///
/// The signature of RSASSA-PKCS1-v1_5 does not carry the digest alone: it
/// carries a DER-encoded `DigestInfo`, which says which hash made it (RFC 8017,
/// section 9.2). The identifier of each hash is fixed by the standards, so this
/// trait is implemented for the eight hashes of this crate, and only for them:
/// it is sealed. OAEP and PSS name no hash in what they output, so they take any
/// [`Digest`].
///
/// SHA-3 is not a [`Digest`] yet, and so has no PKCS #1 v1.5 signature here.
pub trait Pkcs1Hash: Digest + sealed::Sealed {
    /// The bytes of the DER encoding of the `DigestInfo` that come before the
    /// digest: the sequence, the algorithm identifier (the OID of the hash, with
    /// its parameters set to NULL) and the header of the octet string.
    const DIGEST_INFO_PREFIX: &'static [u8];
}

macro_rules! pkcs1_hash {
    ($($hash:ty => [$($byte:expr),+ $(,)?]),+ $(,)?) => {$(
        impl sealed::Sealed for $hash {}

        impl Pkcs1Hash for $hash {
            const DIGEST_INFO_PREFIX: &'static [u8] = &[$($byte),+];
        }
    )+};
}

pkcs1_hash! {
    Md5 => [0x30, 0x20, 0x30, 0x0c, 0x06, 0x08, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x05, 0x05, 0x00, 0x04, 0x10],
    Sha1 => [0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14],
    Sha224 => [0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04, 0x05, 0x00, 0x04, 0x1c],
    Sha256 => [0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20],
    Sha384 => [0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30],
    Sha512 => [0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40],
    Sha512_224 => [0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x05, 0x05, 0x00, 0x04, 0x1c],
    Sha512_256 => [0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x06, 0x05, 0x00, 0x04, 0x20],
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The `DigestInfo` is a SEQUENCE of an `AlgorithmIdentifier` and an OCTET
    /// STRING, and the prefix is all of it but the digest: so its two lengths are
    /// determined by the digest's, and the OID is the one the hash is known by.
    fn check<D: Pkcs1Hash>(oid: &[u8]) {
        let prefix = D::DIGEST_INFO_PREFIX;
        let digest_len = D::OUTPUT_LEN;
        // SEQUENCE { SEQUENCE { OID, NULL }, OCTET STRING }
        assert_eq!(prefix[0], 0x30);
        assert_eq!(usize::from(prefix[1]), prefix.len() - 2 + digest_len);
        assert_eq!(prefix[2], 0x30);
        let algorithm_len = usize::from(prefix[3]);
        assert_eq!(prefix[4], 0x06);
        assert_eq!(usize::from(prefix[5]), oid.len());
        assert_eq!(&prefix[6..6 + oid.len()], oid);
        assert_eq!(&prefix[6 + oid.len()..8 + oid.len()], &[0x05, 0x00]);
        assert_eq!(algorithm_len, 2 + oid.len() + 2);
        assert_eq!(prefix[4 + algorithm_len], 0x04);
        assert_eq!(usize::from(prefix[5 + algorithm_len]), digest_len);
        assert_eq!(prefix.len(), 6 + algorithm_len);
    }

    #[test]
    fn prefixes_are_the_digest_info_of_each_hash() {
        // 1.2.840.113549.2.5
        check::<Md5>(&[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x05]);
        // 1.3.14.3.2.26
        check::<Sha1>(&[0x2b, 0x0e, 0x03, 0x02, 0x1a]);
        // 2.16.840.1.101.3.4.2.n, n = 4, 1, 2, 3, 5, 6
        let sha2 = |n| [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, n];
        check::<Sha224>(&sha2(4));
        check::<Sha256>(&sha2(1));
        check::<Sha384>(&sha2(2));
        check::<Sha512>(&sha2(3));
        check::<Sha512_224>(&sha2(5));
        check::<Sha512_256>(&sha2(6));
    }
}
