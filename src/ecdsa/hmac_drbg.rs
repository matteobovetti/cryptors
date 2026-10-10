//! HMAC_DRBG (NIST SP 800-90A Rev. 1, section 10.1.2): the deterministic
//! generator that produces the per-message secret numbers of ECDSA, as RFC 6979
//! and FIPS 186-5 (appendix A.3.3) describe.
//!
//! It is built here, on a private HMAC, because the crate has no public one
//! yet. It only generates the candidates for one signature, so it is created
//! for each and dropped after.

use super::curve::sealed::Nonces;
use crate::Digest;
use crate::wipe::wipe;
use core::marker::PhantomData;

/// The longest output of any hash this can be used with (SHA-512), in bytes.
const MAX_OUTPUT_LEN: usize = 64;

/// Bytes that are overwritten with zeros when they go out of scope: the buffers
/// that hold a key or the text a key is mixed into.
struct Secret(Vec<u8>);

impl Secret {
    /// A buffer that can hold `capacity` bytes without moving, so that no copy of
    /// them is left behind in memory it grew out of.
    fn with_capacity(capacity: usize) -> Self {
        Secret(Vec::with_capacity(capacity))
    }
}

impl Drop for Secret {
    fn drop(&mut self) {
        wipe(&mut self.0);
    }
}

/// HMAC (FIPS 198-1, RFC 2104) with the hash `D`, of the concatenation of
/// `parts`, under `key`. The tag is `D::OUTPUT_LEN` bytes, written to `out`.
fn hmac<D: Digest>(key: &[u8], parts: &[&[u8]], out: &mut [u8]) {
    assert_eq!(out.len(), D::OUTPUT_LEN);

    // The key, padded with zeros to a block; a key longer than a block is
    // replaced by its hash first.
    let mut padded = Secret::with_capacity(D::BLOCK_LEN);
    if key.len() > D::BLOCK_LEN {
        padded.0.extend_from_slice(D::digest(key).as_ref());
    } else {
        padded.0.extend_from_slice(key);
    }
    padded.0.resize(D::BLOCK_LEN, 0);

    let text: usize = parts.iter().map(|part| part.len()).sum();
    let mut inner = Secret::with_capacity(D::BLOCK_LEN + text);
    inner.0.extend(padded.0.iter().map(|byte| byte ^ 0x36));
    for part in parts {
        inner.0.extend_from_slice(part);
    }
    let inner_tag = D::digest(&inner.0);

    let mut outer = Secret::with_capacity(D::BLOCK_LEN + D::OUTPUT_LEN);
    outer.0.extend(padded.0.iter().map(|byte| byte ^ 0x5c));
    outer.0.extend_from_slice(inner_tag.as_ref());
    out.copy_from_slice(D::digest(&outer.0).as_ref());
}

/// The seed material of the instantiation: `entropy || nonce`, then each of the
/// `aligned` strings starting at a block boundary of `D`, with zeros before it.
///
/// The seed material is hashed after `V` and one byte, and the padding is counted
/// from the start of that: the key goes into a block of its own, and so does the
/// digest after it. A string that already starts on a boundary has no padding.
fn seed_material<D: Digest>(entropy: &[u8], nonce: &[u8], aligned: &[&[u8]]) -> Secret {
    // Room for the longest padding, so that nothing moves while it is built.
    let capacity = entropy.len()
        + nonce.len()
        + aligned
            .iter()
            .map(|part| part.len() + D::BLOCK_LEN)
            .sum::<usize>();
    let mut seed = Secret::with_capacity(capacity);
    seed.0.extend_from_slice(entropy);
    seed.0.extend_from_slice(nonce);
    let mut written = D::OUTPUT_LEN + 1 + entropy.len() + nonce.len();
    for part in aligned {
        let padding = (D::BLOCK_LEN - written % D::BLOCK_LEN) % D::BLOCK_LEN;
        seed.0.resize(seed.0.len() + padding, 0);
        seed.0.extend_from_slice(part);
        written = part.len();
    }
    seed
}

/// An HMAC_DRBG with the hash `D`.
pub(super) struct HmacDrbg<D: Digest> {
    key: [u8; MAX_OUTPUT_LEN],
    v: [u8; MAX_OUTPUT_LEN],
    hash: PhantomData<D>,
}

impl<D: Digest> HmacDrbg<D> {
    /// `HMAC_DRBG_Instantiate_algorithm` (section 10.1.2.3) with the seed
    /// material `entropy || nonce || personalization`.
    ///
    /// The personalization string is made of the `aligned` strings, each one
    /// starting at a block boundary of the hash, with zeros between them
    /// (draft-irtf-cfrg-det-sigs-with-noise, section 4). That is how the secret
    /// private key and the digest end up in separate blocks of the HMAC input.
    /// With none, the seed material is `entropy || nonce` alone, which is the
    /// instantiation of RFC 6979, section 3.2, steps b to g.
    pub(super) fn new(entropy: &[u8], nonce: &[u8], aligned: &[&[u8]]) -> Self {
        // The state is kept in arrays of the size of the longest digest here, so a
        // longer one is refused when the code is compiled, not when it runs.
        const {
            assert!(
                D::OUTPUT_LEN >= 1 && D::OUTPUT_LEN <= MAX_OUTPUT_LEN,
                "ECDSA supports hash functions with an output of 1 to 64 bytes"
            )
        };
        let mut drbg = Self {
            key: [0x00; MAX_OUTPUT_LEN],
            v: [0x01; MAX_OUTPUT_LEN],
            hash: PhantomData,
        };

        drbg.update(&seed_material::<D>(entropy, nonce, aligned).0);
        drbg
    }

    /// `HMAC_DRBG_Update` (section 10.1.2.2) with `provided` as the provided
    /// data.
    fn update(&mut self, provided: &[u8]) {
        let len = D::OUTPUT_LEN;
        let mut next = [0u8; MAX_OUTPUT_LEN];
        for separator in [0x00u8, 0x01] {
            // K = HMAC(K, V || separator || provided)
            hmac::<D>(
                &self.key[..len],
                &[&self.v[..len], &[separator], provided],
                &mut next[..len],
            );
            self.key = next;
            // V = HMAC(K, V)
            hmac::<D>(&self.key[..len], &[&self.v[..len]], &mut next[..len]);
            self.v = next;
            // Without provided data the second round is skipped.
            if provided.is_empty() {
                break;
            }
        }
        wipe(&mut next);
    }

    /// `HMAC_DRBG_Generate_algorithm` (section 10.1.2.5): fills `out` and moves
    /// the state on, so that the next call gives different bytes. Asking again
    /// is also what RFC 6979, section 3.2, step h does after a candidate was not
    /// a valid number.
    pub(super) fn generate(&mut self, out: &mut [u8]) {
        let len = D::OUTPUT_LEN;
        let mut next = [0u8; MAX_OUTPUT_LEN];
        for chunk in out.chunks_mut(len) {
            // V = HMAC(K, V)
            hmac::<D>(&self.key[..len], &[&self.v[..len]], &mut next[..len]);
            self.v = next;
            chunk.copy_from_slice(&self.v[..chunk.len()]);
        }
        wipe(&mut next);
        self.update(&[]);
    }
}

impl<D: Digest> Nonces for HmacDrbg<D> {
    fn candidate(&mut self, out: &mut [u8]) {
        self.generate(out);
    }
}

impl<D: Digest> Drop for HmacDrbg<D> {
    fn drop(&mut self) {
        wipe(&mut self.key);
        wipe(&mut self.v);
    }
}

#[cfg(test)]
mod tests {
    use super::super::algorithm::shift_right;
    use super::super::curve::Curve;
    use super::super::vectors::{RFC6979, Rfc6979, for_curve, for_hash, unhex};
    use super::*;
    use crate::md5::Md5;
    use crate::sha1::Sha1;
    use crate::sha2::{Sha224, Sha256, Sha384, Sha512};

    /// RFC 6979, appendix A.2: instantiated with the private key and the
    /// digest of the message, the generator's first candidate for the per-message
    /// secret number is the `k` the RFC lists, once the bits that the curve's order
    /// does not have are shifted out.
    fn check_rfc6979_nonce<C: Curve, D: Digest>(row: &Rfc6979) {
        let private = unhex(row.private);
        let len = C::PRIVATE_KEY_LEN;
        let digest = D::digest(row.message.as_bytes());
        let mut octets = vec![0; len];
        C::digest_to_octets(digest.as_ref(), &mut octets);

        let mut drbg = HmacDrbg::<D>::new(&private, &octets, &[]);
        let mut k = vec![0; len];
        drbg.generate(&mut k);
        shift_right(&mut k, C::EXCESS_BITS);
        assert_eq!(
            k,
            unhex(row.k),
            "{} {} {:?}",
            row.curve,
            row.hash,
            row.message
        );
    }

    #[test]
    fn rfc_6979_nonces() {
        for row in &RFC6979 {
            for_curve!(row.curve, C => for_hash!(row.hash, D => check_rfc6979_nonce::<C, D>(row)));
        }
    }

    /// The zeros that put the private key and the digest in blocks of their own
    /// (draft-irtf-cfrg-det-sigs-with-noise, section 4), counted for SHA-256, whose
    /// output is 32 bytes and block 64. `V` and the separator take 33 bytes before
    /// the seed material.
    #[test]
    fn aligned_strings_start_on_block_boundaries() {
        let seed = |entropy: usize, aligned: &[&[u8]]| {
            seed_material::<Sha256>(&vec![1; entropy], &[], aligned)
                .0
                .to_vec()
        };
        let (key, digest) = ([2u8; 32], [3u8; 32]);

        // 33 + 32 bytes of entropy are 65: 63 zeros bring the key to byte 128 of
        // the input, 128 - 33 = 95 of the seed, and the key's 32 bytes end at 160,
        // so 32 zeros bring the digest to 192.
        let got = seed(32, &[&key, &digest]);
        let want = [&[1u8; 32][..], &[0; 63], &key, &[0; 32], &digest].concat();
        assert_eq!(got, want);

        // Entropy of 31 bytes ends the input at 64, exactly a block: no zeros at
        // all, not a block of them.
        let got = seed(31, &[&key]);
        assert_eq!(got, [&[1u8; 31][..], &key].concat());

        // A second string of exactly a block's length is followed by no zeros
        // either.
        let block = [4u8; 64];
        let got = seed(31, &[&block, &digest]);
        assert_eq!(got, [&[1u8; 31][..], &block, &digest].concat());

        // One byte more or fewer than a boundary pads to the next one.
        assert_eq!(seed(30, &[&key])[30..], [&[0u8; 1][..], &key].concat());
        assert_eq!(seed(32, &[&key])[32..32 + 63], [0u8; 63]);

        // No aligned strings, no padding: the seed is the entropy and the nonce.
        let plain = seed_material::<Sha256>(&[1; 20], &[2; 5], &[]).0.to_vec();
        assert_eq!(plain, [&[1u8; 20][..], &[2; 5]].concat());
    }

    /// HMAC against Python's `hmac` for every hash, for keys shorter than, equal
    /// to and longer than the block, and for messages in one and several parts.
    #[test]
    fn hmac_matches_known_answers() {
        fn check<D: Digest>(rows: &[(&str, &str, &str)]) {
            for (key, text, tag) in rows {
                let (key, text) = (key.as_bytes(), text.as_bytes());
                let mut out = vec![0; D::OUTPUT_LEN];
                hmac::<D>(key, &[text], &mut out);
                assert_eq!(
                    crate::digest::hex(&out),
                    *tag,
                    "{}",
                    String::from_utf8_lossy(key)
                );

                // The parts are concatenated.
                let (a, b) = text.split_at(text.len() / 2);
                let mut split = vec![0; D::OUTPUT_LEN];
                hmac::<D>(key, &[a, b, &[]], &mut split);
                assert_eq!(out, split);
            }
        }
        check::<Md5>(&super::super::vectors::HMAC_MD5);
        check::<Sha1>(&super::super::vectors::HMAC_SHA1);
        check::<Sha224>(&super::super::vectors::HMAC_SHA224);
        check::<Sha256>(&super::super::vectors::HMAC_SHA256);
        check::<Sha384>(&super::super::vectors::HMAC_SHA384);
        check::<Sha512>(&super::super::vectors::HMAC_SHA512);
    }
}
