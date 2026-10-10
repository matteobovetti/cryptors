use core::fmt;
use core::marker::PhantomData;

use crate::Digest;
use crate::incremental::{MAX_BLOCK_LEN, State};
use crate::wipe::wipe_bytes;

/// The byte that `ipad` repeats (FIPS 198-1 section 2.3).
const IPAD: u8 = 0x36;

/// The byte that `opad` repeats (FIPS 198-1 section 2.3).
const OPAD: u8 = 0x5c;

/// HMAC (FIPS 198-1) with the hash `D`, keyed once and reusable.
///
/// [`new`](Self::new) hashes the two padded keys of the standard, `K0 ^ ipad`
/// and `K0 ^ opad`, once, and keeps the state of the hash after each (FIPS
/// 198-1 section 6). Every tag starts from those two states, so a tag costs
/// the hashing of the message and of the inner digest, and nothing for the
/// key. `D` is any [`Digest`]: MD5, SHA-1 or one of the six SHA-2 functions.
///
/// The states are worth as much as the key. They are overwritten with zeros
/// when the value is dropped, and `Debug` does not show them.
///
/// ```
/// use cryptors::{hmac::Hmac, sha2::Sha256};
///
/// // RFC 4231, test case 2.
/// let mac = Hmac::<Sha256>::new(b"Jefe");
/// let tag: [u8; 32] = mac.mac(b"what do ya want for nothing?");
/// assert_eq!(tag[..4], [0x5b, 0xdc, 0xc1, 0x46]);
///
/// // The same key verifies, in constant time, as many messages as needed.
/// assert!(mac.verify(b"what do ya want for nothing?", &tag).is_ok());
/// assert!(mac.verify(b"what do ya want for something?", &tag).is_err());
/// ```
pub struct Hmac<D> {
    /// The hash after `K0 ^ ipad` (section 4, step 4): where every inner hash
    /// starts.
    inner: State,
    /// The hash after `K0 ^ opad` (step 7): where every outer hash starts.
    outer: State,
    /// The hash. A function pointer type rather than `D` itself, so that an
    /// `Hmac` is `Send` and `Sync` whatever `D` is: it holds no `D`.
    digest: PhantomData<fn() -> D>,
}

impl<D: Digest> Hmac<D> {
    /// `D::BLOCK_LEN`, `B` in the standard, checked to be one HMAC is
    /// defined for. Every use goes through here, so a hash that fails the
    /// checks is a compile error, not a wrong tag.
    const BLOCK_LEN: usize = {
        assert!(D::OUTPUT_LEN > 0, "HMAC needs a hash with an output");
        // A key longer than a block is replaced by its digest, padded to a
        // block (step 2), which needs the digest to fit.
        assert!(
            D::OUTPUT_LEN <= D::BLOCK_LEN,
            "HMAC needs a hash whose output fits in its block"
        );
        assert!(
            D::BLOCK_LEN <= MAX_BLOCK_LEN,
            "this HMAC supports hash blocks of at most 144 bytes"
        );
        D::BLOCK_LEN
    };

    /// The shortest tag [`verify_truncated`](Self::verify_truncated) accepts,
    /// in bytes: half the output of the hash, rounded up, and no less than 10
    /// bytes (80 bits), the two lower bounds of RFC 2104 section 5. For a hash
    /// with less than 10 bytes of output, that is the whole output.
    ///
    /// | Hash | Tag | Shortest truncated tag |
    /// |------|-----|------------------------|
    /// | MD5 | 16 bytes | 10 bytes |
    /// | SHA-1 | 20 bytes | 10 bytes |
    /// | SHA-224, SHA-512/224 | 28 bytes | 14 bytes |
    /// | SHA-256, SHA-512/256 | 32 bytes | 16 bytes |
    /// | SHA-384 | 48 bytes | 24 bytes |
    /// | SHA-512 | 64 bytes | 32 bytes |
    pub const MIN_TAG_LEN: usize = {
        let half = D::OUTPUT_LEN.div_ceil(2);
        let floor = if half > 10 { half } else { 10 };
        if floor < D::OUTPUT_LEN {
            floor
        } else {
            D::OUTPUT_LEN
        }
    };

    /// Keys HMAC with `key`, which may have any length, including zero.
    ///
    /// A key longer than the hash's block is hashed first, as the standard
    /// requires (FIPS 198-1 section 3), so it is worth no more than a key of
    /// the hash's output length. A key shorter than the output length is
    /// weaker than HMAC can be (RFC 2104 section 3). Either way, the key
    /// should be random: HMAC is not a password hash.
    pub fn new(key: &[u8]) -> Self {
        let block = Self::BLOCK_LEN;

        // Steps 1 to 3: `K0` is the key, or its digest if it is longer than a
        // block, followed by zeros up to a block.
        let mut pad = [0u8; MAX_BLOCK_LEN];
        let hashed;
        let k0 = if key.len() > block {
            hashed = D::digest(key);
            hashed.as_ref()
        } else {
            key
        };
        pad[..k0.len()].copy_from_slice(k0);

        // Step 4, and the hash of its result, once for every tag to come.
        pad[..block].iter_mut().for_each(|byte| *byte ^= IPAD);
        let inner = after_pad::<D>(&pad[..block]);
        // Step 7: XORing with both pads turns `K0 ^ ipad` into `K0 ^ opad`.
        pad[..block]
            .iter_mut()
            .for_each(|byte| *byte ^= IPAD ^ OPAD);
        let outer = after_pad::<D>(&pad[..block]);

        wipe_bytes(&mut pad);
        Self {
            inner,
            outer,
            digest: PhantomData,
        }
    }

    /// Computes the tag of `message`: `H((K0 ^ opad) || H((K0 ^ ipad) ||
    /// message))`, the full output of the hash.
    ///
    /// ```
    /// use cryptors::{hmac::Hmac, sha2::Sha512};
    ///
    /// let tag: [u8; 64] = Hmac::<Sha512>::new(b"key").mac(b"message");
    /// assert_eq!(tag[..4], [0xe4, 0x77, 0x38, 0x4d]);
    /// ```
    ///
    /// # Panics
    ///
    /// Never with the crate's hashes. With a hash from outside the crate, as
    /// [`mac_parts`](Self::mac_parts) says.
    pub fn mac(&self, message: &[u8]) -> D::Output {
        self.mac_parts(&[message])
    }

    /// Computes the tag of the message made of `parts`, one after the other.
    ///
    /// The tag is that of the concatenation, so how the message is split does
    /// not matter. The parts go into the hash one after the other, straight
    /// from the caller's memory, so a message that is a sequence of fields
    /// never needs putting together.
    ///
    /// ```
    /// use cryptors::{hmac::Hmac, sha2::Sha256};
    ///
    /// let mac = Hmac::<Sha256>::new(b"key");
    /// assert_eq!(
    ///     mac.mac_parts(&[b"header.", b"payload"]),
    ///     mac.mac(b"header.payload")
    /// );
    /// ```
    ///
    /// # Panics
    ///
    /// Never with the crate's hashes. A hash implemented outside the crate can
    /// only be given its whole input at once, so for one of those HMAC copies
    /// the padded key and the message into one buffer (which it wipes
    /// afterwards). That panics if they add up to more than `isize::MAX` bytes,
    /// which on a 64-bit target only parts that repeat the same memory can do,
    /// and like any allocation it aborts the process if there is no memory
    /// left: the message has to fit in memory twice.
    pub fn mac_parts(&self, parts: &[&[u8]]) -> D::Output {
        tag::<D>(self.inner.clone(), self.outer.clone(), parts)
    }

    /// Checks that `tag` is the full tag of `message`, comparing in constant
    /// time.
    ///
    /// Only a tag of exactly `D::OUTPUT_LEN` bytes can pass. One of any other
    /// length is rejected as [`VerifyError::WrongLength`] without being
    /// compared; for a protocol that sends truncated tags, use
    /// [`verify_truncated`](Self::verify_truncated).
    ///
    /// ```
    /// use cryptors::{hmac::{Hmac, VerifyError}, sha2::Sha256};
    ///
    /// let mac = Hmac::<Sha256>::new(b"key");
    /// let tag = mac.mac(b"message");
    /// assert_eq!(mac.verify(b"message", &tag), Ok(()));
    /// assert_eq!(mac.verify(b"massage", &tag), Err(VerifyError::Mismatch));
    /// assert_eq!(mac.verify(b"message", &tag[..16]), Err(VerifyError::WrongLength));
    /// ```
    pub fn verify(&self, message: &[u8], tag: &[u8]) -> Result<(), VerifyError> {
        if tag.len() != D::OUTPUT_LEN {
            return Err(VerifyError::WrongLength);
        }
        self.compare(message, tag)
    }

    /// Checks that `tag` is the tag of `message` or its first `tag.len()`
    /// bytes, comparing in constant time.
    ///
    /// FIPS 198-1 section 5 allows a protocol to send only the leftmost bytes
    /// of the tag. A forger then has fewer bits to guess, so this accepts no
    /// fewer than [`MIN_TAG_LEN`](Self::MIN_TAG_LEN) bytes (half the output, and
    /// at least 80 bits), and no more than the full tag. Anything else is
    /// rejected as [`VerifyError::WrongLength`] without being compared; that
    /// includes the empty tag.
    ///
    /// The length of a tag is not authenticated. The protocol must fix it, and
    /// the caller must check the tag against that length, not against the
    /// length the sender chose: otherwise a forger can send the shortest tag
    /// accepted here.
    ///
    /// ```
    /// use cryptors::{hmac::{Hmac, VerifyError}, sha2::Sha256};
    ///
    /// let mac = Hmac::<Sha256>::new(b"key");
    /// let tag = mac.mac(b"message");
    /// // HMAC-SHA-256-128, as IPsec uses it (RFC 4868).
    /// assert_eq!(mac.verify_truncated(b"message", &tag[..16]), Ok(()));
    /// assert_eq!(
    ///     mac.verify_truncated(b"message", &tag[..8]),
    ///     Err(VerifyError::WrongLength)
    /// );
    /// ```
    pub fn verify_truncated(&self, message: &[u8], tag: &[u8]) -> Result<(), VerifyError> {
        if !(Self::MIN_TAG_LEN..=D::OUTPUT_LEN).contains(&tag.len()) {
            return Err(VerifyError::WrongLength);
        }
        self.compare(message, tag)
    }

    /// Computes the tag of `message` and compares its first `tag.len()` bytes
    /// with `tag`. The callers have checked the length.
    fn compare(&self, message: &[u8], tag: &[u8]) -> Result<(), VerifyError> {
        let expected = self.mac(message);
        match expected.as_ref().get(..tag.len()) {
            Some(expected) if constant_time_eq(expected, tag) => Ok(()),
            Some(_) => Err(VerifyError::Mismatch),
            // Only a `Digest` whose output is shorter than its `OUTPUT_LEN`
            // could get here.
            None => Err(VerifyError::WrongLength),
        }
    }
}

/// Computes the HMAC of `message` under `key` with the hash `D`, in one call.
///
/// The same as `Hmac::<D>::new(key).mac(message)`. To compute several tags with
/// one key, build the [`Hmac`] once instead, which hashes the padded key once.
///
/// ```
/// use cryptors::{hmac, md5::Md5, sha1::Sha1};
///
/// // RFC 2202, test case 2.
/// let tag: [u8; 16] = hmac::hmac::<Md5>(b"Jefe", b"what do ya want for nothing?");
/// assert_eq!(tag[..4], [0x75, 0x0c, 0x78, 0x3e]);
/// let tag: [u8; 20] = hmac::hmac::<Sha1>(b"Jefe", b"what do ya want for nothing?");
/// assert_eq!(tag[..4], [0xef, 0xfc, 0xdf, 0x6a]);
/// ```
pub fn hmac<D: Digest>(key: &[u8], message: &[u8]) -> D::Output {
    // The key is used once, so its states are used up rather than copied.
    let Hmac { inner, outer, .. } = Hmac::<D>::new(key);
    tag::<D>(inner, outer, &[message])
}

/// Why [`Hmac::verify`] or [`Hmac::verify_truncated`] rejected a tag.
///
/// Telling the two apart gives nothing away: the length of a tag is public,
/// and so is the fact that it was wrong.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum VerifyError {
    /// The tag has a length the function does not accept, so it was not
    /// compared.
    WrongLength,
    /// The tag has an accepted length, but is not the tag of the message
    /// under this key.
    Mismatch,
}

impl fmt::Display for VerifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::WrongLength => "HMAC tag has the wrong length",
            Self::Mismatch => "HMAC tag does not match the message",
        })
    }
}

impl std::error::Error for VerifyError {}

/// A copy with the same key. Written out rather than derived, which would
/// require `D: Clone`.
impl<D> Clone for Hmac<D> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            outer: self.outer.clone(),
            digest: PhantomData,
        }
    }
}

/// Shows the type and nothing else: the states are the key.
impl<D> fmt::Debug for Hmac<D> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Hmac").finish_non_exhaustive()
    }
}

/// The state of `D` after the padded key `pad`, one block long.
///
/// A hash from outside the crate has no incremental form and can only be given
/// its whole input at once. Its state then holds the pad itself, unhashed, for
/// [`hash_concatenated`] to put in front of each message.
fn after_pad<D: Digest>(pad: &[u8]) -> State {
    match D::INCREMENTAL {
        Some(hash) => {
            let mut state = (hash.init)();
            (hash.update)(&mut state, pad);
            state
        }
        None => State::holding(pad),
    }
}

/// The tag of the message made of `parts`, from `inner` and `outer`, the
/// states of the hash after `K0 ^ ipad` and after `K0 ^ opad`, which it uses
/// up.
fn tag<D: Digest>(mut inner: State, mut outer: State, parts: &[&[u8]]) -> D::Output {
    match D::INCREMENTAL {
        Some(hash) => {
            // Steps 5 and 6: the inner hash, from the state after `K0 ^ ipad`,
            // over the message.
            for part in parts {
                (hash.update)(&mut inner, part);
            }
            let inner = (hash.finish)(inner);
            // Steps 8 and 9: the outer hash, from the state after `K0 ^ opad`,
            // over the inner digest.
            (hash.update)(&mut outer, inner.as_ref());
            (hash.finish)(outer)
        }
        None => {
            let inner = hash_concatenated::<D>(inner.held(), parts);
            hash_concatenated::<D>(outer.held(), &[inner.as_ref()])
        }
    }
}

/// Hashes `pad` and then every part of `parts`, as one input, for a hash that
/// can only be given its whole input at once.
///
/// The pad is the key, XORed with a constant, and the message can be secret as
/// well (HKDF passes its input keying material as the message), so the buffer
/// that holds them is overwritten with zeros before it is freed.
fn hash_concatenated<D: Digest>(pad: &[u8], parts: &[&[u8]]) -> D::Output {
    // Parts that repeat the same memory can add up to more than `usize`
    // holds. Saturating makes `Vec::with_capacity` panic on that, where
    // wrapping around would make a buffer that is too short.
    let len = parts
        .iter()
        .fold(pad.len(), |len, part| len.saturating_add(part.len()));
    let mut buf = Vec::with_capacity(len);
    buf.extend_from_slice(pad);
    for part in parts {
        buf.extend_from_slice(part);
    }
    let out = D::digest(&buf);
    wipe_bytes(&mut buf);
    out
}

/// Whether `a` and `b` are equal, in a time that depends on their length but
/// not on their contents.
///
/// Every pair of bytes is compared, the differences are ORed together, and
/// the only branch is on the result, so there is no early exit at the first
/// difference for an attacker to time. The lengths are public, and checked
/// first.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b) {
        diff |= x ^ y;
    }
    // Hands all of `diff` to a function the optimizer cannot see into, so that
    // it cannot use the fact that only `diff == 0` matters to stop at the first
    // difference. Best effort: the compiler promises nothing about timing, so
    // the code it generates was checked as well (see the module documentation).
    core::hint::black_box(diff) == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::digest::hex;
    use crate::md5::Md5;
    use crate::sha1::Sha1;
    use crate::sha2::{Sha224, Sha256, Sha384, Sha512, Sha512_224, Sha512_256};

    /// `n` bytes of key: 0x00, 0x01, 0x02, ..., as in NIST's HMAC examples.
    fn key(n: usize) -> Vec<u8> {
        (0..n).map(|i| i as u8).collect()
    }

    /// A deterministic message that does not repeat within a block.
    fn pattern(n: usize) -> Vec<u8> {
        (0..n).map(|i| (i % 251) as u8).collect()
    }

    /// The hash `D` as a hash from outside the crate would be: the same
    /// `digest`, but no incremental form, so that HMAC takes its one-shot path.
    struct OneShot<D>(PhantomData<D>);

    impl<D: Digest> Digest for OneShot<D> {
        const BLOCK_LEN: usize = D::BLOCK_LEN;
        const OUTPUT_LEN: usize = D::OUTPUT_LEN;
        type Output = D::Output;

        fn digest(input: &[u8]) -> D::Output {
            D::digest(input)
        }
    }

    /// Checks the tag of `message` under `key` against `expected`, in hex,
    /// through every public way of computing it, and through the one-shot
    /// path that a hash from outside the crate gets.
    fn check<D: Digest>(key: &[u8], message: &[u8], expected: &str, what: &str) {
        assert!(D::INCREMENTAL.is_some() && OneShot::<D>::INCREMENTAL.is_none());

        let tag = hmac::<D>(key, message);
        assert_eq!(hex(tag.as_ref()), expected, "{what}");

        let keyed = Hmac::<D>::new(key);
        assert_eq!(keyed.mac(message).as_ref(), tag.as_ref(), "{what}, mac");
        assert_eq!(
            keyed.mac_parts(&[message]).as_ref(),
            tag.as_ref(),
            "{what}, mac_parts"
        );
        assert_eq!(keyed.verify(message, tag.as_ref()), Ok(()), "{what}");

        let one_shot = hmac::<OneShot<D>>(key, message);
        assert_eq!(one_shot.as_ref(), tag.as_ref(), "{what}, one-shot path");
    }

    /// One input of RFC 4231 section 4, with the tag of each of the six SHA-2
    /// functions.
    struct Rfc4231 {
        key: &'static [u8],
        data: &'static [u8],
        sha224: &'static str,
        sha256: &'static str,
        sha384: &'static str,
        sha512: &'static str,
        sha512_224: &'static str,
        sha512_256: &'static str,
    }

    /// RFC 4231 test cases 1 to 7.
    ///
    /// The RFC gives the tags of SHA-224, SHA-256, SHA-384 and SHA-512, except
    /// in test case 5, where it prints only their first 128 bits
    /// (`truncated_tags` checks those). The other tags, and those of
    /// SHA-512/224 and SHA-512/256, come from Go's crypto/hmac and OpenSSL 3.6,
    /// which agree with each other and with the RFC.
    const RFC4231: [Rfc4231; 7] = [
        Rfc4231 {
            key: &[0x0b; 20],
            data: b"Hi There",
            sha224: "896fb1128abbdf196832107cd49df33f47b4b1169912ba4f53684b22",
            sha256: "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
            sha384: "afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59c\
                     faea9ea9076ede7f4af152e8b2fa9cb6",
            sha512: "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cde\
                     daa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854",
            sha512_224: "b244ba01307c0e7a8ccaad13b1067a4cf6b961fe0c6a20bda3d92039",
            sha512_256: "9f9126c3d9c3c330d760425ca8a217e31feae31bfe70196ff81642b868402eab",
        },
        // A key shorter than the output.
        Rfc4231 {
            key: b"Jefe",
            data: b"what do ya want for nothing?",
            sha224: "a30e01098bc6dbbf45690f3a7e9e6d0f8bbea2a39e6148008fd05e44",
            sha256: "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
            sha384: "af45d2e376484031617f78d2b58a6b1b9c7ef464f5a01b47e42ec3736322445e\
                     8e2240ca5e69e2c78b3239ecfab21649",
            sha512: "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea250554\
                     9758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737",
            sha512_224: "4a530b31a79ebcce36916546317c45f247d83241dfb818fd37254bde",
            sha512_256: "6df7b24630d5ccb2ee335407081a87188c221489768fa2020513b2d593359456",
        },
        // Key and data longer than 64 bytes together.
        Rfc4231 {
            key: &[0xaa; 20],
            data: &[0xdd; 50],
            sha224: "7fb3cb3588c6c1f6ffa9694d7d6ad2649365b0c1f65d69d1ec8333ea",
            sha256: "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe",
            sha384: "88062608d3e6ad8a0aa2ace014c8a86f0aa635d947ac9febe83ef4e55966144b\
                     2a5ab39dc13814b94e3ab6e101a34f27",
            sha512: "fa73b0089d56a284efb0f0756c890be9b1b5dbdd8ee81a3655f83e33b2279d39\
                     bf3e848279a722c806b485a47e67c807b946a337bee8942674278859e13292fb",
            sha512_224: "db34ea525c2c216ee5a6ccb6608bea870bbef12fd9b96a5109e2b6fc",
            sha512_256: "229006391d66c8ecddf43ba5cf8f83530ef221a4e9401840d1bead5137c8a2ea",
        },
        Rfc4231 {
            key: &[
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
                0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19,
            ],
            data: &[0xcd; 50],
            sha224: "6c11506874013cac6a2abc1bb382627cec6a90d86efc012de7afec5a",
            sha256: "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b",
            sha384: "3e8a69b7783c25851933ab6290af6ca77a9981480850009cc5577c6e1f573b4e\
                     6801dd23c4a7d679ccf8a386c674cffb",
            sha512: "b0ba465637458c6990e5a8c5f61d4af7e576d97ff94b872de76f8050361ee3db\
                     a91ca5c11aa25eb4d679275cc5788063a5f19741120c4f2de2adebeb10a298dd",
            sha512_224: "c2391863cda465c6828af06ac5d4b72d0b792109952da530e11a0d26",
            sha512_256: "36d60c8aa1d0be856e10804cf836e821e8733cbafeae87630589fd0b9b0a2f4c",
        },
        // The truncation case, here with the full tags.
        Rfc4231 {
            key: &[0x0c; 20],
            data: b"Test With Truncation",
            sha224: "0e2aea68a90c8d37c988bcdb9fca6fa8099cd857c7ec4a1815cac54c",
            sha256: "a3b6167473100ee06e0c796c2955552bfa6f7c0a6a8aef8b93f860aab0cd20c5",
            sha384: "3abf34c3503b2a23a46efc619baef897f4c8e42c934ce55ccbae9740fcbc1af4\
                     ca62269e2a37cd88ba926341efe4aeea",
            sha512: "415fad6271580a531d4179bc891d87a650188707922a4fbb36663a1eb16da008\
                     711c5b50ddd0fc235084eb9d3364a1454fb2ef67cd1d29fe6773068ea266e96b",
            sha512_224: "1df8eae8baeedd4eddfb555ec0ba768f4b5ba29e9e3d55f08303120f",
            sha512_256: "337f526924766971bf72b82ad19c2c825301791e3ae2d8bb4ec03817dd821f46",
        },
        // A key longer than every block, so it is hashed first.
        Rfc4231 {
            key: &[0xaa; 131],
            data: b"Test Using Larger Than Block-Size Key - Hash Key First",
            sha224: "95e9a0db962095adaebe9b2d6f0dbce2d499f112f2d2b7273fa6870e",
            sha256: "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54",
            sha384: "4ece084485813e9088d2c63a041bc5b44f9ef1012a2b588f3cd11f05033ac4c6\
                     0c2ef6ab4030fe8296248df163f44952",
            sha512: "80b24263c7c1a3ebb71493c1dd7be8b49b46d1f41b4aeec1121b013783f8f352\
                     6b56d037e05f2598bd0fd2215d6a1e5295e64f73f63f0aec8b915a985d786598",
            sha512_224: "29bef8ce88b54d4226c3c7718ea9e32ace2429026f089e38cea9aeda",
            sha512_256: "87123c45f7c537a404f8f47cdbedda1fc9bec60eeb971982ce7ef10e774e6539",
        },
        // A key and data both longer than every block.
        Rfc4231 {
            key: &[0xaa; 131],
            data: b"This is a test using a larger than block-size key and a larger than \
                    block-size data. The key needs to be hashed before being used by the \
                    HMAC algorithm.",
            sha224: "3a854166ac5d9f023f54d517d0b39dbd946770db9c2b95c9f6f565d1",
            sha256: "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2",
            sha384: "6617178e941f020d351e2f254e8fd32c602420feb0b8fb9adccebb82461e99c5\
                     a678cc31e799176d3860e6110c46523e",
            sha512: "e37b6a775dc87dbaa4dfa9f96e5e3ffddebd71f8867289865df5a32d20cdc944\
                     b6022cac3c4982b10d5eeb55c3e4de15134676fb6de0446065c97440fa8c6a58",
            sha512_224: "82a9619b47af0cea73a8b9741355ce902d807ad87ee9078522a246e1",
            sha512_256: "6ea83f8e7315072c0bdaa33b93a26fc1659974637a9db8a887d06c05a7f35a66",
        },
    ];

    #[test]
    fn rfc4231() {
        for (i, case) in RFC4231.iter().enumerate() {
            let what = format!("RFC 4231 test case {}", i + 1);
            let (key, data) = (case.key, case.data);
            check::<Sha224>(key, data, case.sha224, &format!("HMAC-SHA-224, {what}"));
            check::<Sha256>(key, data, case.sha256, &format!("HMAC-SHA-256, {what}"));
            check::<Sha384>(key, data, case.sha384, &format!("HMAC-SHA-384, {what}"));
            check::<Sha512>(key, data, case.sha512, &format!("HMAC-SHA-512, {what}"));
            check::<Sha512_224>(key, data, case.sha512_224, &format!("SHA-512/224, {what}"));
            check::<Sha512_256>(key, data, case.sha512_256, &format!("SHA-512/256, {what}"));
        }
    }

    /// RFC 2202 section 2: HMAC-MD5 test cases 1 to 7, as (key, data, tag).
    const RFC2202_MD5: [(&[u8], &[u8], &str); 7] = [
        (&[0x0b; 16], b"Hi There", "9294727a3638bb1c13f48ef8158bfc9d"),
        (
            b"Jefe",
            b"what do ya want for nothing?",
            "750c783e6ab0b503eaa86e310a5db738",
        ),
        (&[0xaa; 16], &[0xdd; 50], "56be34521d144c88dbb8c733f0e8b3f6"),
        (
            &[
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
                0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19,
            ],
            &[0xcd; 50],
            "697eaf0aca3a3aea3a75164746ffaa79",
        ),
        (
            &[0x0c; 16],
            b"Test With Truncation",
            "56461ef2342edc00f9bab995690efd4c",
        ),
        // Keys longer than the 64-byte block.
        (
            &[0xaa; 80],
            b"Test Using Larger Than Block-Size Key - Hash Key First",
            "6b1ab7fe4bd7bf8f0b62e6ce61b9d0cd",
        ),
        (
            &[0xaa; 80],
            b"Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data",
            "6f630fad67cda0ee1fb1f562db3aa53e",
        ),
    ];

    /// RFC 2202 section 3: HMAC-SHA-1 test cases 1 to 7, as (key, data, tag).
    const RFC2202_SHA1: [(&[u8], &[u8], &str); 7] = [
        (
            &[0x0b; 20],
            b"Hi There",
            "b617318655057264e28bc0b6fb378c8ef146be00",
        ),
        (
            b"Jefe",
            b"what do ya want for nothing?",
            "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79",
        ),
        (
            &[0xaa; 20],
            &[0xdd; 50],
            "125d7342b9ac11cd91a39af48aa17b4f63f175d3",
        ),
        (
            &[
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
                0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19,
            ],
            &[0xcd; 50],
            "4c9007f4026250c6bc8414f9bf50c86c2d7235da",
        ),
        (
            &[0x0c; 20],
            b"Test With Truncation",
            "4c1a03424b55e07fe7f27be1d58bb9324a9a5a04",
        ),
        (
            &[0xaa; 80],
            b"Test Using Larger Than Block-Size Key - Hash Key First",
            "aa4ae5e15272d00e95705637ce8a3b55ed402112",
        ),
        (
            &[0xaa; 80],
            b"Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data",
            "e8e99d0f45237d786d6bbaa7965c7808bbff1a91",
        ),
    ];

    #[test]
    fn rfc2202() {
        for (i, (key, data, tag)) in RFC2202_MD5.iter().enumerate() {
            check::<Md5>(
                key,
                data,
                tag,
                &format!("HMAC-MD5, RFC 2202 test case {}", i + 1),
            );
        }
        for (i, (key, data, tag)) in RFC2202_SHA1.iter().enumerate() {
            check::<Sha1>(
                key,
                data,
                tag,
                &format!("HMAC-SHA-1, RFC 2202 test case {}", i + 1),
            );
        }
    }

    // Tags computed by Go's crypto/hmac and by OpenSSL 3.6, which agree, as
    // (key length, message length, tag): the key is `key(key_len)` and the
    // message `pattern(message_len)`. For each hash, with `B` its block
    // length: the empty key and message; keys of 0, B - 1, B and B + 1 bytes,
    // the last one hashed first; and the two message lengths on either side
    // of the inner hash's padding boundary: one more byte and the length no
    // longer fits in the block, and needs a block of its own (B - 9 and B - 8
    // with a 64-byte block, B - 17 and B - 16 with a 128-byte one).

    const MD5_GENERATED: [(usize, usize, &str); 7] = [
        (0, 0, "74e6f7298a9c2d168935f58c001bad88"),
        (0, 100, "7ccb1f813d5fdea645f6f1c62a30c15f"),
        (63, 100, "073f8435c1533f34d70c0186b8fe66e9"),
        (64, 100, "0395e5e5ea2c9c425aa533e0ede29906"),
        (65, 100, "b7c18a8ce278ad96810cf44134ae268c"),
        (32, 55, "c5b9fb89b9736a6a5339527c20783668"),
        (32, 56, "a5d46d88d988065635ddcd3a1decdb5b"),
    ];

    const SHA1_GENERATED: [(usize, usize, &str); 7] = [
        (0, 0, "fbdb1d1b18aa6c08324b7d64b71fb76370690e1d"),
        (0, 100, "8c497aaa72a3d2ce3d9dfacd0b9d8fa9a16ca3ab"),
        (63, 100, "1c407f67530054f276aa48849ee4d229ceb20b9f"),
        (64, 100, "794fa95b091d4b71849b76024958e3cf35f340b0"),
        (65, 100, "4dac5a73fae3f422f0b49359f834ec69f069b6d5"),
        (32, 55, "bdede8c17ef64523ab14420cc245cb4e8126e812"),
        (32, 56, "8f83f3cee6e993f4aaf25624ede3d334d39ee333"),
    ];

    const SHA224_GENERATED: [(usize, usize, &str); 7] = [
        (
            0,
            0,
            "5ce14f72894662213e2748d2a6ba234b74263910cedde2f5a9271524",
        ),
        (
            0,
            100,
            "b0e1a14fc8de52d23ace4e7f4ec272ae2e83512a9ff0063de800243f",
        ),
        (
            63,
            100,
            "9e462a07c4019ba8dca6237a0e12f366c466a557ffb0f9ab6fa854f9",
        ),
        (
            64,
            100,
            "929cbe983f4b309dc859210dc790f1958388131c9abb28c13625ae9b",
        ),
        (
            65,
            100,
            "3a67d46a8ebba24873541aad38c37db0e1307ac118f89789a46fe9ce",
        ),
        (
            32,
            55,
            "3c2ace87a9aea1e20de0a8502ccba554aff12877dd1c5dbc88274084",
        ),
        (
            32,
            56,
            "6fae0110e4815cd2e6824a4f3bfc8c69e53d2b1814108229e12eaffb",
        ),
    ];

    const SHA256_GENERATED: [(usize, usize, &str); 7] = [
        (
            0,
            0,
            "b613679a0814d9ec772f95d778c35fc5ff1697c493715653c6c712144292c5ad",
        ),
        (
            0,
            100,
            "0da5d92cccf6bc8e19bf718cc7299a5c4ac87f62d2258662241fd5642759eb03",
        ),
        (
            63,
            100,
            "05830d59141b58e273d16624f5ed386b0353bc37f3a9af8504e165d5294ee1a7",
        ),
        (
            64,
            100,
            "e0fc11a31f1f2b329e227864906e9a8b39de647be9e0a456fe509e8b63f111af",
        ),
        (
            65,
            100,
            "b111d1e4b6591f801ff7643c4d592adb08869a9686d44f4217b01405b29830e9",
        ),
        (
            32,
            55,
            "b478e4cbd63871759702a8a4c9828359869bc9e20d3df429ecd08f5a5d3d9340",
        ),
        (
            32,
            56,
            "e5d1f65e9e9359d05c577b6890044f08c9a1f7969b683f1237ef07db70e5f862",
        ),
    ];

    const SHA384_GENERATED: [(usize, usize, &str); 7] = [
        (
            0,
            0,
            "6c1f2ee938fad2e24bd91298474382ca218c75db3d83e114b3d4367776d14d35\
             51289e75e8209cd4b792302840234adc",
        ),
        (
            0,
            100,
            "740ae36efe6bdd476feba8eb19deb752fcae41b38851a10829dd604748be252a\
             f214bbd5a2f28437db09798cebd66aef",
        ),
        (
            127,
            100,
            "d764cfe7efc3ab7c5ea101458fc988def3378fed92634e8282b7bfd7d2b0ff5d\
             9245d4d381e7546cd46efdde526c1f09",
        ),
        (
            128,
            100,
            "4b846d168d071d95064aad5220ed6165ec7aed361696ba519bc66141f54c8312\
             1a5f6dc97707920c874b85a086df1556",
        ),
        (
            129,
            100,
            "110b227fbdb4ed90e3a6f4ee05b14c887bb5c353140221852cbaa3446d51176a\
             e818c90d8de20770f0b2f255959911d4",
        ),
        (
            32,
            111,
            "9652774e6450819c2ac84d5c0b4b6ddfaeb8ddecbb0451baf20bba114209aa11\
             5076337fd9323347a6f24cf591d84ca4",
        ),
        (
            32,
            112,
            "5f37421ae94aeb9fe5d00cf1567e0ea4da779e8dfff644483867b3151b70d632\
             d636ff2966f0c15340b55f73f26e2e4e",
        ),
    ];

    const SHA512_GENERATED: [(usize, usize, &str); 7] = [
        (
            0,
            0,
            "b936cee86c9f87aa5d3c6f2e84cb5a4239a5fe50480a6ec66b70ab5b1f4ac673\
             0c6c515421b327ec1d69402e53dfb49ad7381eb067b338fd7b0cb22247225d47",
        ),
        (
            0,
            100,
            "4c78a810526f715bfe8fcd499c46e56aee9542078c6da9f4cfc19df64a9f0ab7\
             a32a34460bf245bde40b0c825d15c7c79a29a0fd2aa37b5298624eeb374d4c0c",
        ),
        (
            127,
            100,
            "3540817892e7ae265ed8036ff3b51bdb7c770e10418f9a74b67d6b2fe160938c\
             b460c030cc74082f55fb2476801784856f787149c4229dd0022e292bb90520b9",
        ),
        (
            128,
            100,
            "e3e9d216c5faac0ef891f9761c94e52ad2406e4b49891c5ab4cb08ed39dc6a04\
             2dfa15aaf9cbede3834af75ff791799f47f084e4ee595a3c0b1446cc3c83df8f",
        ),
        (
            129,
            100,
            "7a1ea5657ffb7a5a2ab55ace727d8d9ebd0f71b52122e793215b737611c539b8\
             24f8b40472ec02dde3baf80ac591da41991cca1937be3df31a03c39ac4d4397b",
        ),
        (
            32,
            111,
            "51ec934fb13de248666bb496e931427e2f40e0686917558eb6696286e9a01c0f\
             5f069437b76d78278aa13f8c713bf8e11a0057bcc12a7dc48893363c15c1a889",
        ),
        (
            32,
            112,
            "faedee23b6611d17821abe9c6af8dd7f2a0de809a099746f1ef7f54c6f858bef\
             e87393670b6efebff705f63f184abed45a941da04a470c2626cbba6bc6eda30c",
        ),
    ];

    const SHA512_224_GENERATED: [(usize, usize, &str); 7] = [
        (
            0,
            0,
            "de43f6b96f2d08cebe1ee9c02c53d96b68c1e55b6c15d6843b410d4c",
        ),
        (
            0,
            100,
            "018c8e4d8968a9e21dce0225ec0e974d0dee65deb2a73854f96ceefc",
        ),
        (
            127,
            100,
            "dcfaccd0db98b974f71fb22a73b1b8ebe6abae16b2f50ae602a82f46",
        ),
        (
            128,
            100,
            "41c8bbc8e964bbc5a8fb0e3a43e4d40a0c405971f64ca46506f74cfc",
        ),
        (
            129,
            100,
            "f7af6f481571fe9fd62ab14cb182db3955bb6fc991caa4c9f52c715f",
        ),
        (
            32,
            111,
            "bcbf2b16adbf158fbf87bc82dce5f4a3ef7250bc0fde9acd1316ec8b",
        ),
        (
            32,
            112,
            "ac21bfd1c1765274e85bbc00786e719217115cd40985203c551b81d5",
        ),
    ];

    const SHA512_256_GENERATED: [(usize, usize, &str); 7] = [
        (
            0,
            0,
            "b79c9951df595274582dc094a1ba46c33e4a36878b2d83cb8553f0fe467dcdcf",
        ),
        (
            0,
            100,
            "bab2a0a73936ad1d7883b6f6d845572665cdb7944f437a9d27abef8dddc72165",
        ),
        (
            127,
            100,
            "56dcfc2431c1581daeaea10cc3ecafb2cd5c5e1a869d1366e273e06bcfdab9d2",
        ),
        (
            128,
            100,
            "51a8c8e73a61ad8dd0e887d86f8102585f037d2d9d42e4455a1ee7dd021562cb",
        ),
        (
            129,
            100,
            "c0412954bc71c3413ac165e17c6b31f7a93572bbfc404ee56ab14b81270c712d",
        ),
        (
            32,
            111,
            "47939e0d84fcf3ff252a71f94e0c9bd130eab755920521a14b634d7581643ca9",
        ),
        (
            32,
            112,
            "daef629dfeb3d4cc9ca69784644c9089c92e052a4b454b81253d5b714cc75582",
        ),
    ];

    /// Checks one hash's generated vectors, after checking that they still
    /// straddle the boundaries they were chosen for.
    fn check_generated<D: Digest>(name: &str, vectors: &[(usize, usize, &str); 7]) {
        let block = D::BLOCK_LEN;
        let key_lens = vectors.map(|(key_len, _, _)| key_len);
        assert_eq!(key_lens[2..5], [block - 1, block, block + 1], "{name}");
        let tail = if block == 128 { 17 } else { 9 };
        assert_eq!(
            [vectors[5].1, vectors[6].1],
            [block - tail, block - tail + 1],
            "{name}"
        );

        for &(key_len, message_len, tag) in vectors {
            check::<D>(
                &key(key_len),
                &pattern(message_len),
                tag,
                &format!("{name}, {key_len}-byte key, {message_len}-byte message"),
            );
        }
    }

    #[test]
    fn generated_vectors() {
        check_generated::<Md5>("HMAC-MD5", &MD5_GENERATED);
        check_generated::<Sha1>("HMAC-SHA-1", &SHA1_GENERATED);
        check_generated::<Sha224>("HMAC-SHA-224", &SHA224_GENERATED);
        check_generated::<Sha256>("HMAC-SHA-256", &SHA256_GENERATED);
        check_generated::<Sha384>("HMAC-SHA-384", &SHA384_GENERATED);
        check_generated::<Sha512>("HMAC-SHA-512", &SHA512_GENERATED);
        check_generated::<Sha512_224>("HMAC-SHA-512/224", &SHA512_224_GENERATED);
        check_generated::<Sha512_256>("HMAC-SHA-512/256", &SHA512_256_GENERATED);
    }

    /// The truncated tags the RFCs print, through `verify_truncated`.
    #[test]
    fn truncated_tags() {
        /// Checks that `expected` (hex) starts the tag, and whether
        /// `verify_truncated` takes it.
        fn check_truncated<D: Digest>(
            key: &[u8],
            data: &[u8],
            expected: &str,
            verdict: Result<(), VerifyError>,
        ) {
            let mac = Hmac::<D>::new(key);
            let tag = mac.mac(data);
            let truncated = &tag.as_ref()[..expected.len() / 2];
            assert_eq!(hex(truncated), expected);
            assert_eq!(mac.verify_truncated(data, truncated), verdict, "{expected}");
            assert_eq!(mac.verify(data, truncated), Err(VerifyError::WrongLength));
        }

        // RFC 4231 test case 5: 128 bits, half of SHA-256's output but a third
        // of SHA-384's and a quarter of SHA-512's.
        let (key, data) = (&[0x0c; 20], b"Test With Truncation");
        check_truncated::<Sha224>(key, data, "0e2aea68a90c8d37c988bcdb9fca6fa8", Ok(()));
        check_truncated::<Sha256>(key, data, "a3b6167473100ee06e0c796c2955552b", Ok(()));
        check_truncated::<Sha384>(
            key,
            data,
            "3abf34c3503b2a23a46efc619baef897",
            Err(VerifyError::WrongLength),
        );
        check_truncated::<Sha512>(
            key,
            data,
            "415fad6271580a531d4179bc891d87a6",
            Err(VerifyError::WrongLength),
        );

        // RFC 2202 test case 5: 96 bits.
        check_truncated::<Md5>(&[0x0c; 16], data, "56461ef2342edc00f9bab995", Ok(()));
        check_truncated::<Sha1>(&[0x0c; 20], data, "4c1a03424b55e07fe7f27be1", Ok(()));
    }

    /// Checks `verify` and `verify_truncated` for one hash, whose shortest
    /// truncated tag should be `min_tag_len` bytes.
    fn check_verify<D: Digest>(min_tag_len: usize) {
        assert_eq!(Hmac::<D>::MIN_TAG_LEN, min_tag_len);

        let mac = Hmac::<D>::new(b"key");
        let message = b"message";
        let tag = mac.mac(message);
        let tag = tag.as_ref();
        assert_eq!(mac.verify(message, tag), Ok(()));
        assert_eq!(mac.verify(b"massage", tag), Err(VerifyError::Mismatch));
        assert_eq!(
            Hmac::<D>::new(b"kez").verify(message, tag),
            Err(VerifyError::Mismatch)
        );

        // A difference anywhere, even in the last bit, is caught.
        for bit in 0..tag.len() * 8 {
            let mut forged = tag.to_vec();
            forged[bit / 8] ^= 1 << (bit % 8);
            assert_eq!(
                mac.verify(message, &forged),
                Err(VerifyError::Mismatch),
                "bit {bit}"
            );
            let shortest = &forged[..min_tag_len];
            let verdict = if bit < min_tag_len * 8 {
                Err(VerifyError::Mismatch)
            } else {
                Ok(())
            };
            assert_eq!(
                mac.verify_truncated(message, shortest),
                verdict,
                "bit {bit}"
            );
        }

        // Every length from the empty tag to one byte too many, the extra byte
        // after a correct tag.
        let mut longer = tag.to_vec();
        longer.push(0);
        for len in 0..=longer.len() {
            let candidate = &longer[..len];
            let full = if len == tag.len() {
                Ok(())
            } else {
                Err(VerifyError::WrongLength)
            };
            assert_eq!(mac.verify(message, candidate), full, "{len} bytes");
            let truncated = if (min_tag_len..=tag.len()).contains(&len) {
                Ok(())
            } else {
                Err(VerifyError::WrongLength)
            };
            assert_eq!(
                mac.verify_truncated(message, candidate),
                truncated,
                "{len} bytes"
            );
        }
    }

    #[test]
    fn verify_accepts_only_the_tag() {
        check_verify::<Md5>(10);
        check_verify::<Sha1>(10);
        check_verify::<Sha224>(14);
        check_verify::<Sha256>(16);
        check_verify::<Sha384>(24);
        check_verify::<Sha512>(32);
        check_verify::<Sha512_224>(14);
        check_verify::<Sha512_256>(16);
    }

    /// Checks, for one hash, that a message split into parts has the tag of
    /// the whole message, however it is split.
    fn check_parts<D: Digest>() {
        let mac = Hmac::<D>::new(&key(20));
        let block = D::BLOCK_LEN;

        // Two parts, split at every byte, of a message shorter than a block
        // and of one that crosses two block boundaries.
        for len in [block - 1, 2 * block + 1] {
            let message = pattern(len);
            let whole = mac.mac(&message);
            for i in 0..=len {
                let (a, b) = message.split_at(i);
                assert_eq!(
                    mac.mac_parts(&[a, b]).as_ref(),
                    whole.as_ref(),
                    "{i} + {}",
                    len - i
                );
            }
        }

        // Three parts, split at every pair of bytes, over a block and a bit.
        let message = pattern(block + 3);
        let whole = mac.mac(&message);
        for i in 0..=message.len() {
            for j in i..=message.len() {
                let parts = [&message[..i], &message[i..j], &message[j..]];
                assert_eq!(mac.mac_parts(&parts).as_ref(), whole.as_ref(), "{i}, {j}");
            }
        }

        // One part per byte, and no parts or only empty ones for the empty
        // message.
        let bytes: Vec<&[u8]> = message.chunks(1).collect();
        assert_eq!(mac.mac_parts(&bytes).as_ref(), whole.as_ref());
        let empty = mac.mac(b"");
        assert_eq!(mac.mac_parts(&[]).as_ref(), empty.as_ref());
        assert_eq!(mac.mac_parts(&[b"", b"", b""]).as_ref(), empty.as_ref());
    }

    #[test]
    fn parts_match_the_whole_message() {
        // The splitting depends on the block length, not on the hash, and on
        // the path: streaming, or the one-shot path's concatenation.
        check_parts::<Sha256>();
        check_parts::<Sha512>();
        check_parts::<OneShot<Sha256>>();
    }

    /// Dropping an `Hmac` must leave nothing of its key behind, whether it
    /// holds the hash's states (the crate's hashes) or the padded keys
    /// themselves (a hash from outside the crate).
    #[test]
    fn dropping_wipes_the_states() {
        fn check<D: Digest>(name: &str) {
            use core::mem::{MaybeUninit, size_of};

            // Two states and a marker with no size. A state is a chaining
            // value, a block of bytes and two counters, 64 + 144 + 8 + 8 bytes
            // all aligned to 8, so there is no padding: every byte of an
            // `Hmac` belongs to a field.
            assert_eq!(size_of::<Hmac<D>>(), 2 * (64 + MAX_BLOCK_LEN + 8 + 8));

            let mut slot = MaybeUninit::new(Hmac::<D>::new(&[0x42; 32]));
            // One raw pointer does the dropping and the reading, so that the
            // drop does not invalidate the pointer the reads go through.
            let hmac = slot.as_mut_ptr();
            let bytes = hmac.cast::<u8>();
            let read = || -> Vec<u8> {
                (0..size_of::<Hmac<D>>())
                    // SAFETY: the slot is alive and every byte of it was
                    // written, first by `new` and then, if the drop works, by
                    // `wipe`.
                    .map(|i| unsafe { bytes.add(i).read() })
                    .collect()
            };
            assert!(read().iter().any(|&b| b != 0), "{name}: nothing to wipe");

            // SAFETY: the slot holds an initialised `Hmac`, dropped only here.
            unsafe { hmac.drop_in_place() };
            assert!(
                read().iter().all(|&b| b == 0),
                "{name}: the key survives the drop"
            );
        }

        check::<Sha256>("the states of SHA-256");
        check::<OneShot<Sha256>>("the pads of a one-shot hash");
    }

    /// The Debug output must not show the key.
    #[test]
    fn debug_hides_the_key() {
        let mac = Hmac::<Sha256>::new(&[0xab; 32]);
        assert_eq!(format!("{mac:?}"), "Hmac { .. }");
    }

    #[test]
    #[ignore = "manual throughput check: cargo test --release hmac:: -- --ignored --nocapture --test-threads=1"]
    fn throughput() {
        use core::hint::black_box;
        use std::time::Instant;

        const LEN: usize = 64 * 1024 * 1024;
        const SHORT_LEN: usize = 64;
        const SHORT_COUNT: usize = 1_000_000;

        // The same inputs as bench/hmaccmp: a 32-byte key 0x00, 0x01, ...,
        // and a message that does not repeat within a block. The short
        // messages are the first 64,000,000 bytes of the long one, in 64-byte
        // pieces.
        let data = pattern(LEN);
        let key = key(32);
        let mib = LEN as f64 / (1024.0 * 1024.0);

        /// Runs `pass` once to warm up, then five times, and returns the
        /// shortest time in seconds with the last pass's result.
        fn best_of_five<R>(mut pass: impl FnMut() -> R) -> (f64, R) {
            // The first pass over a fresh buffer is slowed down by page faults
            // and CPU clock ramp-up, not just HMAC itself, so it is not timed.
            black_box(pass());
            let mut best = f64::INFINITY;
            let mut out = None;
            for _ in 0..5 {
                let start = Instant::now();
                let result = black_box(pass());
                best = best.min(start.elapsed().as_secs_f64());
                out = Some(result);
            }
            (best, out.expect("five passes ran"))
        }

        fn time<D: Digest>(name: &str, key: &[u8], data: &[u8], mib: f64) {
            let mac = Hmac::<D>::new(key);

            // One long message, against the bare hash over the same bytes.
            let (hmac_secs, tag) = best_of_five(|| mac.mac(data));
            let (hash_secs, _) = best_of_five(|| D::digest(data));
            println!(
                "hmac-{name}, one {mib:.0} MiB message: best {:.1} MiB/s; bare {name} {:.1} MiB/s \
                 (tag {}...)",
                mib / hmac_secs,
                mib / hash_secs,
                hex(&tag.as_ref()[..8])
            );

            // Many short messages under one key, against the bare hash of each
            // message: what a tag costs on top of hashing the message once.
            let messages = &data[..SHORT_COUNT * SHORT_LEN];
            let fold = |tag_of: &dyn Fn(&[u8]) -> D::Output| {
                let mut folded = vec![0u8; D::OUTPUT_LEN];
                for message in messages.chunks_exact(SHORT_LEN) {
                    let tag = tag_of(message);
                    for (f, t) in folded.iter_mut().zip(tag.as_ref()) {
                        *f ^= t;
                    }
                }
                folded
            };
            let (hmac_secs, folded) = best_of_five(|| fold(&|message| mac.mac(message)));
            let (hash_secs, _) = best_of_five(|| fold(&|message| D::digest(message)));
            println!(
                "hmac-{name}, {SHORT_COUNT} x {SHORT_LEN} B messages, keyed once: best {:.0} ops/s; \
                 bare {name} of each message {:.0} ops/s (tags XORed {}...)",
                SHORT_COUNT as f64 / hmac_secs,
                SHORT_COUNT as f64 / hash_secs,
                hex(&folded[..8])
            );

            // The same messages, keyed afresh for each one, as the one-call
            // form (and HKDF) does: the key's two blocks are hashed every time.
            let (keyed_secs, folded) = best_of_five(|| fold(&|message| hmac::<D>(key, message)));
            println!(
                "hmac-{name}, {SHORT_COUNT} x {SHORT_LEN} B messages, keyed for each: best {:.0} ops/s \
                 (tags XORed {}...)",
                SHORT_COUNT as f64 / keyed_secs,
                hex(&folded[..8])
            );
        }

        time::<Sha256>("sha256", &key, &data, mib);
        time::<Sha512>("sha512", &key, &data, mib);
        time::<Sha1>("sha1", &key, &data, mib);
        time::<Md5>("md5", &key, &data, mib);
    }
}
