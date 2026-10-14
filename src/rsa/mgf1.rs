//! MGF1, the mask generation function of RFC 8017 (appendix B.2.1), which both
//! OAEP and PSS use.

use super::bytes::Wiped;
use crate::Digest;

/// XORs the mask of `seed` into `out`: the mask is
/// `H(seed || 0) || H(seed || 1) || ...`, where the counter is a four-byte
/// big-endian number, cut to the length of `out`.
///
/// The seed of OAEP is secret, so the buffer that holds it next to the counter
/// is wiped.
pub(super) fn mgf1_xor<D: Digest>(out: &mut [u8], seed: &[u8]) {
    let mut input = Wiped::zero(seed.len() + 4);
    input[..seed.len()].copy_from_slice(seed);
    for (counter, chunk) in out.chunks_mut(D::OUTPUT_LEN).enumerate() {
        // RFC 8017 limits the mask to 2^32 digests; no buffer here comes close.
        input[seed.len()..].copy_from_slice(&u32::try_from(counter).unwrap().to_be_bytes());
        let digest = D::digest(&input);
        for (byte, mask) in chunk.iter_mut().zip(digest.as_ref()) {
            *byte ^= mask;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sha1::Sha1;
    use crate::sha2::{Sha256, Sha512};

    fn mask<D: Digest>(seed: &[u8], len: usize) -> Vec<u8> {
        let mut out = vec![0; len];
        mgf1_xor::<D>(&mut out, seed);
        out
    }

    fn hex(bytes: &[u8]) -> String {
        crate::digest::hex(bytes)
    }

    /// Masks computed with Python's `hashlib` from the definition. (The OAEP and
    /// PSS vectors of the other tests, from RSA's, OpenSSL's and Go's, go through
    /// MGF1 as well, with the digests in them.)
    #[test]
    fn known_answers() {
        assert_eq!(hex(&mask::<Sha1>(b"foo", 5)), "1ac9075cd4");
        assert_eq!(
            hex(&mask::<Sha1>(b"bar", 50)),
            "bc0c655e016bc2931d85a2e675181adcef7f581f76df2739da74faac41627be2f7f415c89e983fd0ce80ced9878641cb4876"
        );
        assert_eq!(
            hex(&mask::<Sha256>(b"bar", 50)),
            "382576a7841021cc28fc4c0948753fb8312090cea942ea4c4e735d10dc724b155f9f6069f289d61daca0cb814502ef04eae1"
        );
    }

    #[test]
    fn the_mask_is_xored_in_and_cut_to_the_length() {
        // The mask is a prefix of a longer one, whatever the length is, on and
        // around the multiples of the digest's size.
        let long = mask::<Sha256>(b"seed", 200);
        for len in [0, 1, 31, 32, 33, 63, 64, 65, 199, 200] {
            assert_eq!(mask::<Sha256>(b"seed", len), long[..len], "{len}");
        }
        // Applying it twice gives the input back.
        let mut data: Vec<u8> = (0..100).collect();
        mgf1_xor::<Sha512>(&mut data, b"seed");
        assert_ne!(data, (0..100).collect::<Vec<u8>>());
        mgf1_xor::<Sha512>(&mut data, b"seed");
        assert_eq!(data, (0..100).collect::<Vec<u8>>());
    }
}
