use core::fmt;
use std::io;

use super::edwards::EdwardsPoint;
use super::scalar::Scalar;
use crate::Digest;
use crate::digest::hex;
use crate::sha2::Sha512;
use crate::wipe::wipe;

/// The longest context Ed25519ctx and Ed25519ph accept, in bytes (RFC 8032
/// section 5.1): its length is written into the hash input as a single byte.
pub const MAX_CONTEXT_LEN: usize = 255;

/// Why an Ed25519 operation failed.
///
/// Verification has a single failure, [`Error::InvalidSignature`], whatever
/// part of the check failed, so that a caller cannot learn more about a forged
/// signature than that it is not valid.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// A slice did not have the length of the type it was converted to: 32
    /// bytes for a [`VerifyingKey`], 64 for a [`Signature`].
    InvalidLength,
    /// The bytes are not a public key: not the canonical encoding of a point
    /// of the curve, or the encoding of one of the eight points of small
    /// order, under which signatures can be forged.
    InvalidPublicKey,
    /// The signature does not verify, under this key, for this message (and
    /// context).
    InvalidSignature,
    /// An Ed25519ctx or Ed25519ph context longer than [`MAX_CONTEXT_LEN`].
    ContextTooLong,
    /// An empty Ed25519ctx context. RFC 8032 says it SHOULD NOT be empty, and
    /// an empty one would be easy to confuse with plain Ed25519, which it is
    /// not (the two give different signatures).
    EmptyContext,
    /// A 64-byte key pair whose second half is not the public key of its
    /// first.
    KeypairMismatch,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Error::InvalidLength => "ed25519: wrong length",
            Error::InvalidPublicKey => "ed25519: invalid public key",
            Error::InvalidSignature => "ed25519: invalid signature",
            Error::ContextTooLong => "ed25519: context longer than 255 bytes",
            Error::EmptyContext => "ed25519: empty Ed25519ctx context",
            Error::KeypairMismatch => "ed25519: public key does not match the seed",
        })
    }
}

impl std::error::Error for Error {}

/// Which of the three schemes of RFC 8032 section 5.1 a signature belongs to.
/// It decides `dom2(phflag, context)`, the prefix of every hash input, which
/// keeps the signatures of one scheme from verifying under another.
#[derive(Clone, Copy)]
enum Scheme<'a> {
    /// Ed25519: no prefix at all.
    Pure,
    /// Ed25519ctx, phflag 0, with a context of 1 to 255 bytes.
    Context(&'a [u8]),
    /// Ed25519ph, phflag 1, with a context of 0 to 255 bytes. The message is
    /// its SHA-512 digest.
    Prehashed(&'a [u8]),
}

impl<'a> Scheme<'a> {
    fn context(context: &'a [u8]) -> Result<Self, Error> {
        match context.len() {
            0 => Err(Error::EmptyContext),
            1..=MAX_CONTEXT_LEN => Ok(Scheme::Context(context)),
            _ => Err(Error::ContextTooLong),
        }
    }

    fn prehashed(context: &'a [u8]) -> Result<Self, Error> {
        if context.len() > MAX_CONTEXT_LEN {
            return Err(Error::ContextTooLong);
        }
        Ok(Scheme::Prehashed(context))
    }

    /// The phflag and the context of dom2, or `None` for plain Ed25519.
    fn dom2(self) -> Option<(u8, &'a [u8])> {
        match self {
            Scheme::Pure => None,
            Scheme::Context(context) => Some((0, context)),
            Scheme::Prehashed(context) => Some((1, context)),
        }
    }
}

/// The first 32 bytes of dom2 (RFC 8032 section 2).
const DOM2_PREFIX: &[u8; 32] = b"SigEd25519 no Ed25519 collisions";

/// `SHA-512(dom2(phflag, context) || secret || public[0] || public[1] || ...)`,
/// the hash of RFC 8032 section 5.1.6, steps 2 and 4, and section 5.1.7.
/// dom2 is empty for Ed25519, and otherwise [`DOM2_PREFIX`], the flag, the
/// length of the context in one byte, and the context.
///
/// The crate's SHA-512 hashes one contiguous slice, so the parts are copied
/// into one buffer first. `secret` is the part that must not outlive the
/// call: its copy is overwritten before the buffer is freed. The message is
/// one of the `public` parts; the caller has its own copy of it anyway.
fn hash(scheme: Scheme<'_>, secret: &[u8], public: &[&[u8]]) -> [u8; 64] {
    let dom2 = scheme.dom2();
    let dom2_len = dom2.map_or(0, |(_, context)| DOM2_PREFIX.len() + 2 + context.len());
    let len = dom2_len + secret.len() + public.iter().map(|p| p.len()).sum::<usize>();

    let mut input = Vec::with_capacity(len);
    if let Some((flag, context)) = dom2 {
        input.extend_from_slice(DOM2_PREFIX);
        // The constructors of `Scheme` keep the context to 255 bytes, so its
        // length fits in the byte.
        input.extend_from_slice(&[flag, context.len() as u8]);
        input.extend_from_slice(context);
    }
    let secret_at = input.len();
    input.extend_from_slice(secret);
    for part in public {
        input.extend_from_slice(part);
    }

    let digest = Sha512::digest(&input);
    wipe(&mut input[secret_at..secret_at + secret.len()]);
    digest
}

/// An Ed25519 signature: the encoding of the point R followed by that of the
/// scalar S, 64 bytes (RFC 8032 section 5.1.6, step 6).
///
/// Any 64 bytes make a `Signature`; whether they are a valid one is up to
/// [`VerifyingKey::verify`], which also rejects an S that is not below the
/// group order.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Signature([u8; 64]);

impl Signature {
    /// The length of a signature in bytes.
    pub const LEN: usize = 64;

    /// Wraps the 64 bytes of a signature.
    pub fn from_bytes(bytes: &[u8; 64]) -> Self {
        Self(*bytes)
    }

    /// The 64 bytes of the signature, R then S.
    pub fn to_bytes(&self) -> [u8; 64] {
        self.0
    }

    /// The first half: the encoding of R.
    fn r_bytes(&self) -> &[u8; 32] {
        self.0.first_chunk().expect("64 bytes have a first 32")
    }

    /// The second half: the encoding of S.
    fn s_bytes(&self) -> &[u8; 32] {
        self.0.last_chunk().expect("64 bytes have a last 32")
    }
}

impl TryFrom<&[u8]> for Signature {
    type Error = Error;

    /// Reads a signature from a slice, which must be exactly 64 bytes long.
    fn try_from(bytes: &[u8]) -> Result<Self, Error> {
        let bytes: &[u8; 64] = bytes.try_into().map_err(|_| Error::InvalidLength)?;
        Ok(Self(*bytes))
    }
}

impl fmt::Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Signature({})", hex(&self.0))
    }
}

/// An Ed25519 public key, used to verify signatures.
///
/// Only the canonical encoding of a point of the curve that is not of small
/// order makes a key (see [`from_bytes`](Self::from_bytes)); the point is
/// decoded once, when the key is made, not at every verification.
#[derive(Clone, Copy)]
pub struct VerifyingKey {
    /// A, decoded.
    point: EdwardsPoint,
    /// The encoding of A, which is part of the hash input.
    bytes: [u8; 32],
}

impl VerifyingKey {
    /// The length of a public key in bytes.
    pub const LEN: usize = 32;

    /// Decodes a public key: the 32-byte encoding of a point A.
    ///
    /// Fails with [`Error::InvalidPublicKey`] unless the bytes are exactly
    /// what RFC 8032 section 5.1.3 decodes, and the point is not of small
    /// order:
    ///
    /// - y, the low 255 bits, must be below p = 2^255 - 19, so that each point
    ///   has a single encoding;
    /// - y must be the y-coordinate of a point of the curve;
    /// - the sign bit must be clear when x = 0;
    /// - and A must not be one of the eight points whose order divides 8. For
    ///   those, `[k]A` takes at most eight values whatever the message, so a
    ///   signature can be made without the private key: under the identity,
    ///   `R = [S]B` verifies for every message.
    ///
    /// A key made by [`SigningKey`] always passes. Go's `crypto/ed25519`
    /// checks only the second condition, and so accepts, and verifies
    /// signatures under, keys that this function rejects.
    ///
    /// ```
    /// use cryptors::ed25519::{Error, VerifyingKey};
    ///
    /// // The public key of RFC 8032 section 7.1, test 1.
    /// let bytes = [
    ///     0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
    ///     0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a,
    /// ];
    /// let key = VerifyingKey::from_bytes(&bytes)?;
    /// assert_eq!(key.to_bytes(), bytes);
    ///
    /// // The identity point, (0, 1), is of small order.
    /// let mut identity = [0u8; 32];
    /// identity[0] = 1;
    /// assert_eq!(VerifyingKey::from_bytes(&identity), Err(Error::InvalidPublicKey));
    /// # Ok::<(), Error>(())
    /// ```
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self, Error> {
        let point = EdwardsPoint::decompress(bytes).ok_or(Error::InvalidPublicKey)?;
        if point.is_small_order() {
            return Err(Error::InvalidPublicKey);
        }
        Ok(Self {
            point,
            bytes: *bytes,
        })
    }

    /// The 32-byte encoding of the key.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.bytes
    }

    /// The 32-byte encoding of the key, borrowed.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }

    /// Verifies an Ed25519 signature on `message` (RFC 8032 section 5.1.7).
    ///
    /// Accepts exactly when S is below the group order ℓ and the encoding of
    /// `[S]B - [k]A` is the R of the signature, byte for byte, where `k` is
    /// SHA-512(R || A || message) reduced modulo ℓ. That is the
    /// cofactorless equation `[S]B = R + [k]A`, which the RFC allows in place
    /// of `[8][S]B = [8]R + [8][k]A`; it is also what Go's `crypto/ed25519`
    /// checks. R is never decoded, so a non-canonical encoding of R cannot
    /// match.
    ///
    /// Every input is public, and the check takes time that depends on them.
    ///
    /// ```
    /// use cryptors::ed25519::{Error, SigningKey};
    ///
    /// let key = SigningKey::from_seed(&[7; 32]);
    /// let signature = key.sign(b"message");
    /// let public = key.verifying_key();
    ///
    /// assert_eq!(public.verify(b"message", &signature), Ok(()));
    /// assert_eq!(public.verify(b"massage", &signature), Err(Error::InvalidSignature));
    /// ```
    pub fn verify(&self, message: &[u8], signature: &Signature) -> Result<(), Error> {
        self.verify_with(Scheme::Pure, message, signature)
    }

    /// Verifies an Ed25519ctx signature on `message` under `context`, which
    /// must be the one the signature was made with. As
    /// [`verify`](Self::verify), with dom2(0, context) in front of the hash
    /// input.
    ///
    /// Fails with [`Error::EmptyContext`] or [`Error::ContextTooLong`] unless
    /// the context is 1 to 255 bytes long.
    ///
    /// ```
    /// use cryptors::ed25519::{Error, SigningKey};
    ///
    /// let key = SigningKey::from_seed(&[7; 32]);
    /// let signature = key.sign_ctx(b"message", b"my protocol, v1")?;
    /// let public = key.verifying_key();
    ///
    /// assert_eq!(public.verify_ctx(b"message", b"my protocol, v1", &signature), Ok(()));
    /// assert_eq!(
    ///     public.verify_ctx(b"message", b"my protocol, v2", &signature),
    ///     Err(Error::InvalidSignature)
    /// );
    /// // An Ed25519ctx signature is not an Ed25519 one.
    /// assert_eq!(public.verify(b"message", &signature), Err(Error::InvalidSignature));
    /// # Ok::<(), Error>(())
    /// ```
    pub fn verify_ctx(
        &self,
        message: &[u8],
        context: &[u8],
        signature: &Signature,
    ) -> Result<(), Error> {
        self.verify_with(Scheme::context(context)?, message, signature)
    }

    /// Verifies an Ed25519ph signature, given the SHA-512 digest of the
    /// message, under `context` (0 to 255 bytes). As
    /// [`verify`](Self::verify), with dom2(1, context) in front of the hash
    /// input and the digest in place of the message.
    ///
    /// Fails with [`Error::ContextTooLong`] if the context is longer than
    /// 255 bytes.
    ///
    /// ```
    /// use cryptors::{Digest, ed25519::SigningKey, sha2::Sha512};
    ///
    /// let key = SigningKey::from_seed(&[7; 32]);
    /// let prehash = Sha512::digest(b"a long message");
    /// let signature = key.sign_prehashed(&prehash, b"")?;
    ///
    /// assert!(key.verifying_key().verify_prehashed(&prehash, b"", &signature).is_ok());
    /// # Ok::<(), cryptors::ed25519::Error>(())
    /// ```
    pub fn verify_prehashed(
        &self,
        prehash: &[u8; 64],
        context: &[u8],
        signature: &Signature,
    ) -> Result<(), Error> {
        self.verify_with(Scheme::prehashed(context)?, prehash, signature)
    }

    /// RFC 8032 section 5.1.7, for any of the three schemes.
    fn verify_with(
        &self,
        scheme: Scheme<'_>,
        message: &[u8],
        signature: &Signature,
    ) -> Result<(), Error> {
        // Step 1: S must be below ℓ. R is not decoded; see step 3.
        let s = Scalar::from_canonical_bytes(signature.s_bytes()).ok_or(Error::InvalidSignature)?;

        // Step 2.
        let r = signature.r_bytes();
        let k = Scalar::from_bytes_wide(&hash(scheme, &[], &[r, &self.bytes, message]));

        // Step 3, as [S]B + [k](-A) = R. Comparing encodings rather than
        // points rejects every R that is not the canonical encoding of the
        // point, which decoding R would have rejected too.
        let expected = EdwardsPoint::vartime_double_mul_base(&k, &self.point.negate(), &s);
        if expected.compress() == *r {
            Ok(())
        } else {
            Err(Error::InvalidSignature)
        }
    }
}

impl TryFrom<&[u8]> for VerifyingKey {
    type Error = Error;

    /// Decodes a public key from a slice, which must be exactly 32 bytes
    /// long. See [`VerifyingKey::from_bytes`].
    fn try_from(bytes: &[u8]) -> Result<Self, Error> {
        let bytes: &[u8; 32] = bytes.try_into().map_err(|_| Error::InvalidLength)?;
        Self::from_bytes(bytes)
    }
}

impl PartialEq for VerifyingKey {
    /// Two keys are equal when their encodings are; each point has only one.
    fn eq(&self, other: &Self) -> bool {
        self.bytes == other.bytes
    }
}

impl Eq for VerifyingKey {}

impl fmt::Debug for VerifyingKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "VerifyingKey({})", hex(&self.bytes))
    }
}

/// An Ed25519 private key, used to sign.
///
/// RFC 8032 calls the 32-byte seed the private key; Go calls it the seed, and
/// so does this crate. Everything else is derived from it: the secret scalar
/// s and the nonce prefix (the two halves of SHA-512(seed), section 5.1.5),
/// and the public key `[s]B`. A `SigningKey` keeps all four, so that signing
/// does not derive them again.
///
/// The seed, the scalar and the prefix are overwritten with zeros when the key
/// is dropped, and `Debug` shows only the public key.
#[derive(Clone)]
pub struct SigningKey {
    seed: [u8; 32],
    /// s: the first half of SHA-512(seed), pruned, reduced modulo ℓ.
    scalar: Scalar,
    /// The second half of SHA-512(seed), from which each signature's nonce
    /// is derived.
    prefix: [u8; 32],
    verifying_key: VerifyingKey,
}

impl SigningKey {
    /// The length of a seed in bytes.
    pub const SEED_LEN: usize = 32;

    /// The length of a key pair, seed then public key, in bytes.
    pub const KEYPAIR_LEN: usize = 64;

    /// Derives the key from its 32-byte seed (RFC 8032 section 5.1.5).
    ///
    /// The seed is the private key: generating a key pair means drawing 32
    /// bytes from a cryptographically secure random number generator and
    /// passing them here, which [`generate`](Self::generate) does with a
    /// reader. This is the function for a seed that was stored. The same seed
    /// always gives the same key.
    ///
    /// Constant time.
    ///
    /// ```
    /// use cryptors::ed25519::SigningKey;
    ///
    /// // RFC 8032 section 7.1, test 1.
    /// let seed = [
    ///     0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
    ///     0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
    /// ];
    /// let key = SigningKey::from_seed(&seed);
    /// assert_eq!(key.verifying_key().to_bytes()[..4], [0xd7, 0x5a, 0x98, 0x01]);
    /// assert_eq!(key.seed(), &seed);
    /// ```
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        let mut h = Sha512::digest(seed);

        // Prune the first half: clear the low three bits, which makes s a
        // multiple of the cofactor 8, clear the top bit and set the one below
        // it. The result is below 2^255, but not necessarily below ℓ; [s]B is
        // the same point either way, since B has order ℓ, so s is kept
        // reduced, as every scalar here is.
        let mut wide = [0u8; 64];
        wide[..32].copy_from_slice(&h[..32]);
        wide[0] &= 248;
        wide[31] &= 127;
        wide[31] |= 64;
        let scalar = Scalar::from_bytes_wide(&wide);

        let mut prefix = [0u8; 32];
        prefix.copy_from_slice(&h[32..]);
        wipe(&mut h);
        wipe(&mut wide);

        let point = EdwardsPoint::mul_base(&scalar);
        Self {
            seed: *seed,
            scalar,
            prefix,
            verifying_key: VerifyingKey {
                point,
                bytes: point.compress(),
            },
        }
    }

    /// Generates a key from `rng`, which has to be a source of
    /// cryptographically secure random bytes: the secrecy of everything that
    /// follows depends on it. The standard library has none that is stable,
    /// so this takes any reader; on Unix, `File::open("/dev/urandom")` is one.
    ///
    /// It reads the 32 bytes of a seed and calls
    /// [`from_seed`](Self::from_seed) with them. Every 32-byte string is a
    /// seed, so, unlike the keys of ECDH and ECDSA, there is nothing to draw
    /// again. The copy of the seed it read is overwritten before it returns.
    ///
    /// # Errors
    ///
    /// Whatever `rng` fails with, including
    /// [`UnexpectedEof`](io::ErrorKind::UnexpectedEof) if it ends before 32
    /// bytes.
    ///
    /// ```no_run
    /// use cryptors::ed25519::SigningKey;
    /// use std::fs::File;
    ///
    /// # fn main() -> std::io::Result<()> {
    /// let key = SigningKey::generate(&mut File::open("/dev/urandom")?)?;
    /// // Publish key.verifying_key().to_bytes(); keep key.seed() secret.
    /// # Ok(())
    /// # }
    /// ```
    pub fn generate<R: io::Read + ?Sized>(rng: &mut R) -> io::Result<Self> {
        let mut seed = [0u8; 32];
        let result = rng.read_exact(&mut seed).map(|()| Self::from_seed(&seed));
        wipe(&mut seed);
        result
    }

    /// Reads a key pair in the 64-byte format of Go's
    /// `ed25519.PrivateKey`: the seed followed by the public key.
    ///
    /// The key is derived from the seed, as by
    /// [`from_seed`](Self::from_seed), and checked against the second half,
    /// failing with [`Error::KeypairMismatch`] if they differ: the bytes are
    /// then corrupt, or were put together from two different keys. The second
    /// half is never used to sign. Signing under a public key that is not the
    /// seed's would be worse than producing signatures that do not verify:
    /// two signatures of one message under two such keys share the nonce,
    /// and reveal the secret scalar to anyone who sees both.
    ///
    /// ```
    /// use cryptors::ed25519::{Error, SigningKey};
    ///
    /// let key = SigningKey::from_seed(&[7; 32]);
    /// let pair = key.to_keypair_bytes();
    /// assert_eq!(SigningKey::from_keypair_bytes(&pair)?.verifying_key(), key.verifying_key());
    ///
    /// let mut wrong = pair;
    /// wrong[63] ^= 1;
    /// assert_eq!(SigningKey::from_keypair_bytes(&wrong).err(), Some(Error::KeypairMismatch));
    /// # Ok::<(), Error>(())
    /// ```
    pub fn from_keypair_bytes(bytes: &[u8; 64]) -> Result<Self, Error> {
        let (seed, public) = bytes.split_at(32);
        let key = Self::from_seed(seed.try_into().expect("32 bytes"));
        // Both sides are public keys, so a comparison that stops at the first
        // byte that differs gives nothing away. (An OR of the differences
        // would not have helped: the compiler turns it into exactly that.)
        if key.verifying_key.bytes[..] == *public {
            Ok(key)
        } else {
            Err(Error::KeypairMismatch)
        }
    }

    /// The key pair in Go's 64-byte format: the seed, then the public key.
    /// The first half is secret.
    pub fn to_keypair_bytes(&self) -> [u8; 64] {
        let mut bytes = [0u8; 64];
        bytes[..32].copy_from_slice(&self.seed);
        bytes[32..].copy_from_slice(&self.verifying_key.bytes);
        bytes
    }

    /// The 32-byte seed: RFC 8032's private key, from which
    /// [`from_seed`](Self::from_seed) rebuilds this key. It is secret.
    pub fn seed(&self) -> &[u8; 32] {
        &self.seed
    }

    /// The public key, `[s]B`.
    pub fn verifying_key(&self) -> VerifyingKey {
        self.verifying_key
    }

    /// Signs `message` with Ed25519 (RFC 8032 section 5.1.6).
    ///
    /// The signature is deterministic: the nonce comes from a hash of the
    /// secret prefix and the message, not from a random number generator, so
    /// the same key and message always give the same signature. The message
    /// is read twice, as the RFC requires.
    ///
    /// Constant time with respect to the key; the time grows with the length
    /// of the message.
    ///
    /// ```
    /// use cryptors::ed25519::SigningKey;
    ///
    /// // RFC 8032 section 7.1, test 2: a one-byte message.
    /// let seed = [
    ///     0x4c, 0xcd, 0x08, 0x9b, 0x28, 0xff, 0x96, 0xda, 0x9d, 0xb6, 0xc3, 0x46, 0xec, 0x11, 0x4e, 0x0f,
    ///     0x5b, 0x8a, 0x31, 0x9f, 0x35, 0xab, 0xa6, 0x24, 0xda, 0x8c, 0xf6, 0xed, 0x4f, 0xb8, 0xa6, 0xfb,
    /// ];
    /// let signature = SigningKey::from_seed(&seed).sign(&[0x72]);
    /// assert_eq!(signature.to_bytes()[..4], [0x92, 0xa0, 0x09, 0xa9]);
    /// assert_eq!(signature.to_bytes()[60..], [0x12, 0xbb, 0x0c, 0x00]);
    /// ```
    pub fn sign(&self, message: &[u8]) -> Signature {
        self.sign_with(Scheme::Pure, message)
    }

    /// Signs `message` with Ed25519ctx, under `context`: 1 to 255 bytes that
    /// name what the signature is for, so that it cannot be taken for a
    /// signature made for anything else. RFC 8032 section 8.3 advises a
    /// constant chosen by the protocol, not anything taken from the message.
    ///
    /// Fails with [`Error::EmptyContext`] or [`Error::ContextTooLong`] unless
    /// the context is 1 to 255 bytes long.
    ///
    /// ```
    /// use cryptors::ed25519::{Error, SigningKey};
    ///
    /// let key = SigningKey::from_seed(&[7; 32]);
    /// assert!(key.sign_ctx(b"message", b"my protocol, v1").is_ok());
    /// assert_eq!(key.sign_ctx(b"message", b"").err(), Some(Error::EmptyContext));
    /// assert_eq!(key.sign_ctx(b"message", &[0; 256]).err(), Some(Error::ContextTooLong));
    /// ```
    pub fn sign_ctx(&self, message: &[u8], context: &[u8]) -> Result<Signature, Error> {
        Ok(self.sign_with(Scheme::context(context)?, message))
    }

    /// Signs with Ed25519ph, given the SHA-512 digest of the message, under
    /// `context` (0 to 255 bytes; the RFC's own example uses none).
    ///
    /// The prehashed variant is for APIs that hash the message before signing
    /// it, so that the message never has to be in memory at once. RFC 8032
    /// section 8.5 says it SHOULD NOT be used: it is only as strong as
    /// SHA-512's collision resistance, which plain Ed25519 does not depend on.
    ///
    /// Fails with [`Error::ContextTooLong`] if the context is longer than
    /// 255 bytes.
    ///
    /// ```
    /// use cryptors::{Digest, ed25519::SigningKey, sha2::Sha512};
    ///
    /// // RFC 8032 section 7.3.
    /// let seed = [
    ///     0x83, 0x3f, 0xe6, 0x24, 0x09, 0x23, 0x7b, 0x9d, 0x62, 0xec, 0x77, 0x58, 0x75, 0x20, 0x91, 0x1e,
    ///     0x9a, 0x75, 0x9c, 0xec, 0x1d, 0x19, 0x75, 0x5b, 0x7d, 0xa9, 0x01, 0xb9, 0x6d, 0xca, 0x3d, 0x42,
    /// ];
    /// let key = SigningKey::from_seed(&seed);
    /// let signature = key.sign_prehashed(&Sha512::digest(b"abc"), b"")?;
    /// assert_eq!(signature.to_bytes()[..4], [0x98, 0xa7, 0x02, 0x22]);
    /// # Ok::<(), cryptors::ed25519::Error>(())
    /// ```
    pub fn sign_prehashed(&self, prehash: &[u8; 64], context: &[u8]) -> Result<Signature, Error> {
        Ok(self.sign_with(Scheme::prehashed(context)?, prehash))
    }

    /// RFC 8032 section 5.1.6, steps 2 to 6, for any of the three schemes.
    /// Step 1 was done by [`from_seed`](Self::from_seed).
    fn sign_with(&self, scheme: Scheme<'_>, message: &[u8]) -> Signature {
        // Step 2: the nonce r, from the secret prefix and the message.
        let mut digest = hash(scheme, &self.prefix, &[message]);
        let mut r = Scalar::from_bytes_wide(&digest);
        wipe(&mut digest);

        // Step 3.
        let big_r = EdwardsPoint::mul_base(&r).compress();

        // Step 4: the challenge k, from R, A and the message.
        let k = Scalar::from_bytes_wide(&hash(
            scheme,
            &[],
            &[&big_r, &self.verifying_key.bytes, message],
        ));

        // Step 5.
        let s = Scalar::mul_add(&k, &self.scalar, &r);
        wipe(&mut r.0);

        // Step 6.
        let mut signature = [0u8; 64];
        signature[..32].copy_from_slice(&big_r);
        signature[32..].copy_from_slice(&s.to_bytes());
        Signature(signature)
    }
}

impl Drop for SigningKey {
    fn drop(&mut self) {
        wipe(&mut self.seed);
        wipe(&mut self.scalar.0);
        wipe(&mut self.prefix);
    }
}

/// Shows the public key and nothing else: the rest is secret.
impl fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SigningKey")
            .field("verifying_key", &self.verifying_key)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sha2::Sha256;

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn array<const N: usize>(s: &str) -> [u8; N] {
        unhex(s).try_into().unwrap()
    }

    /// One example of RFC 8032 section 7: (seed, public key, message,
    /// context, signature), in hex.
    type Vector = (
        &'static str,
        &'static str,
        &'static str,
        &'static str,
        &'static str,
    );

    /// RFC 8032 section 7.1, the Ed25519 examples: tests 1, 2, 3, 1024 (a
    /// 1023-byte message) and SHA(abc) (a 64-byte one).
    const RFC_8032_ED25519: [Vector; 5] = [
        (
            "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
            "",
            "",
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155\
             5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
        ),
        (
            "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
            "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
            "72",
            "",
            "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da\
             085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
        ),
        (
            "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
            "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
            "af82",
            "",
            "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac\
             18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
        ),
        (
            "f5e5767cf153319517630f226876b86c8160cc583bc013744c6bf255f5cc0ee5",
            "278117fc144c72340f67d0f2316e8386ceffbf2b2428c9c51fef7c597f1d426e",
            "08b8b2b733424243760fe426a4b54908632110a66c2f6591eabd3345e3e4eb98\
             fa6e264bf09efe12ee50f8f54e9f77b1e355f6c50544e23fb1433ddf73be84d8\
             79de7c0046dc4996d9e773f4bc9efe5738829adb26c81b37c93a1b270b20329d\
             658675fc6ea534e0810a4432826bf58c941efb65d57a338bbd2e26640f89ffbc\
             1a858efcb8550ee3a5e1998bd177e93a7363c344fe6b199ee5d02e82d522c4fe\
             ba15452f80288a821a579116ec6dad2b3b310da903401aa62100ab5d1a36553e\
             06203b33890cc9b832f79ef80560ccb9a39ce767967ed628c6ad573cb116dbef\
             efd75499da96bd68a8a97b928a8bbc103b6621fcde2beca1231d206be6cd9ec7\
             aff6f6c94fcd7204ed3455c68c83f4a41da4af2b74ef5c53f1d8ac70bdcb7ed1\
             85ce81bd84359d44254d95629e9855a94a7c1958d1f8ada5d0532ed8a5aa3fb2\
             d17ba70eb6248e594e1a2297acbbb39d502f1a8c6eb6f1ce22b3de1a1f40cc24\
             554119a831a9aad6079cad88425de6bde1a9187ebb6092cf67bf2b13fd65f270\
             88d78b7e883c8759d2c4f5c65adb7553878ad575f9fad878e80a0c9ba63bcbcc\
             2732e69485bbc9c90bfbd62481d9089beccf80cfe2df16a2cf65bd92dd597b07\
             07e0917af48bbb75fed413d238f5555a7a569d80c3414a8d0859dc65a46128ba\
             b27af87a71314f318c782b23ebfe808b82b0ce26401d2e22f04d83d1255dc51a\
             ddd3b75a2b1ae0784504df543af8969be3ea7082ff7fc9888c144da2af58429e\
             c96031dbcad3dad9af0dcbaaaf268cb8fcffead94f3c7ca495e056a9b47acdb7\
             51fb73e666c6c655ade8297297d07ad1ba5e43f1bca32301651339e22904cc8c\
             42f58c30c04aafdb038dda0847dd988dcda6f3bfd15c4b4c4525004aa06eeff8\
             ca61783aacec57fb3d1f92b0fe2fd1a85f6724517b65e614ad6808d6f6ee34df\
             f7310fdc82aebfd904b01e1dc54b2927094b2db68d6f903b68401adebf5a7e08\
             d78ff4ef5d63653a65040cf9bfd4aca7984a74d37145986780fc0b16ac451649\
             de6188a7dbdf191f64b5fc5e2ab47b57f7f7276cd419c17a3ca8e1b939ae49e4\
             88acba6b965610b5480109c8b17b80e1b7b750dfc7598d5d5011fd2dcc5600a3\
             2ef5b52a1ecc820e308aa342721aac0943bf6686b64b2579376504ccc493d97e\
             6aed3fb0f9cd71a43dd497f01f17c0e2cb3797aa2a2f256656168e6c496afc5f\
             b93246f6b1116398a346f1a641f3b041e989f7914f90cc2c7fff357876e506b5\
             0d334ba77c225bc307ba537152f3f1610e4eafe595f6d9d90d11faa933a15ef1\
             369546868a7f3a45a96768d40fd9d03412c091c6315cf4fde7cb68606937380d\
             b2eaaa707b4c4185c32eddcdd306705e4dc1ffc872eeee475a64dfac86aba41c\
             0618983f8741c5ef68d3a101e8a3b8cac60c905c15fc910840b94c00a0b9d0",
            "",
            "0aab4c900501b3e24d7cdf4663326a3a87df5e4843b2cbdb67cbf6e460fec350\
             aa5371b1508f9f4528ecea23c436d94b5e8fcd4f681e30a6ac00a9704a188a03",
        ),
        (
            "833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42",
            "ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf",
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a\
             2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
            "",
            "dc2a4459e7369633a52b1bf277839a00201009a3efbf3ecb69bea2186c26b589\
             09351fc9ac90b3ecfdfbc7c66431e0303dca179c138ac17ad9bef1177331a704",
        ),
    ];

    /// RFC 8032 section 7.2, the Ed25519ctx examples "foo", "bar", "foo2"
    /// and "foo3": one key, two contexts and two messages, and a second key.
    const RFC_8032_ED25519CTX: [Vector; 4] = [
        (
            "0305334e381af78f141cb666f6199f57bc3495335a256a95bd2a55bf546663f6",
            "dfc9425e4f968f7f0c29f0259cf5f9aed6851c2bb4ad8bfb860cfee0ab248292",
            "f726936d19c800494e3fdaff20b276a8",
            "666f6f",
            "55a4cc2f70a54e04288c5f4cd1e45a7bb520b36292911876cada7323198dd87a\
             8b36950b95130022907a7fb7c4e9b2d5f6cca685a587b4b21f4b888e4e7edb0d",
        ),
        (
            "0305334e381af78f141cb666f6199f57bc3495335a256a95bd2a55bf546663f6",
            "dfc9425e4f968f7f0c29f0259cf5f9aed6851c2bb4ad8bfb860cfee0ab248292",
            "f726936d19c800494e3fdaff20b276a8",
            "626172",
            "fc60d5872fc46b3aa69f8b5b4351d5808f92bcc044606db097abab6dbcb1aee3\
             216c48e8b3b66431b5b186d1d28f8ee15a5ca2df6668346291c2043d4eb3e90d",
        ),
        (
            "0305334e381af78f141cb666f6199f57bc3495335a256a95bd2a55bf546663f6",
            "dfc9425e4f968f7f0c29f0259cf5f9aed6851c2bb4ad8bfb860cfee0ab248292",
            "508e9e6882b979fea900f62adceaca35",
            "666f6f",
            "8b70c1cc8310e1de20ac53ce28ae6e7207f33c3295e03bb5c0732a1d20dc6490\
             8922a8b052cf99b7c4fe107a5abb5b2c4085ae75890d02df26269d8945f84b0b",
        ),
        (
            "ab9c2853ce297ddab85c993b3ae14bcad39b2c682beabc27d6d4eb20711d6560",
            "0f1d1274943b91415889152e893d80e93275a1fc0b65fd71b4b0dda10ad7d772",
            "f726936d19c800494e3fdaff20b276a8",
            "666f6f",
            "21655b5f1aa965996b3f97b3c849eafba922a0a62992f73b3d1b73106a84ad85\
             e9b86a7b6005ea868337ff2d20a7f5fbd4cd10b0be49a68da2b2e0dc0ad8960f",
        ),
    ];

    /// RFC 8032 section 7.3, the Ed25519ph example: "abc", no context. The
    /// message is the one signed; it is hashed with SHA-512 before signing.
    const RFC_8032_ED25519PH: Vector = (
        "833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42",
        "ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf",
        "616263",
        "",
        "98a70222f0b8121aa9d30f813d683f809e462b469c7ff87639499bb94e6dae41\
         31f85042463c2a355a2003d062adf5aaa10b8c61e636062aaad11c2a26083406",
    );

    /// Checks one example: that the seed gives the public key, that signing
    /// gives the signature, and that the signature verifies under the public
    /// key decoded from its bytes, as a verifier would have it.
    fn assert_vector(
        (seed, public, message, _, signature): Vector,
        sign: impl Fn(&SigningKey, &[u8]) -> Signature,
        verify: impl Fn(&VerifyingKey, &[u8], &Signature) -> Result<(), Error>,
    ) {
        let key = SigningKey::from_seed(&array(seed));
        assert_eq!(hex(key.verifying_key().as_bytes()), public, "seed {seed}");
        let message = unhex(message);
        let ours = sign(&key, &message);
        assert_eq!(hex(&ours.to_bytes()), signature, "seed {seed}");
        let public = VerifyingKey::from_bytes(&array(public)).unwrap();
        assert_eq!(verify(&public, &message, &ours), Ok(()), "seed {seed}");
    }

    #[test]
    fn known_answers() {
        for vector in RFC_8032_ED25519 {
            assert_vector(vector, |k, m| k.sign(m), |k, m, s| k.verify(m, s));
        }
        for vector in RFC_8032_ED25519CTX {
            let context = unhex(vector.3);
            assert_vector(
                vector,
                |k, m| k.sign_ctx(m, &context).unwrap(),
                |k, m, s| k.verify_ctx(m, &context, s),
            );
        }
        assert_vector(
            RFC_8032_ED25519PH,
            |k, m| k.sign_prehashed(&Sha512::digest(m), b"").unwrap(),
            |k, m, s| k.verify_prehashed(&Sha512::digest(m), b"", s),
        );
    }

    /// Go's `crypto/ed25519/testdata/sign.input.gz`, decompressed and
    /// otherwise unchanged: 128 lines of the `sign.input` file that the
    /// authors of Ed25519 published with their software, each
    /// `seed || public key : public key : message : signature || message :`.
    const SIGN_INPUT: &str = include_str!("testdata/sign.input");

    #[test]
    fn go_sign_input() {
        let mut count = 0;
        for (line, text) in SIGN_INPUT.lines().enumerate() {
            let fields: Vec<&str> = text.split(':').collect();
            let [pair, public, message, signed, ""] = fields[..] else {
                panic!("line {line} is not in the expected format");
            };
            let message = unhex(message);
            let signed = unhex(signed);
            let (signature, copy) = signed.split_at(Signature::LEN);
            assert_eq!(copy, message, "line {line}");

            // The 64-byte pair is Go's private key format, so reading it also
            // checks that the seed gives the public key.
            let key = SigningKey::from_keypair_bytes(&array(pair)).expect("matching pair");
            let ours = key.sign(&message);
            assert_eq!(ours.to_bytes()[..], *signature, "line {line}");
            let public = VerifyingKey::from_bytes(&array(public)).unwrap();
            assert_eq!(public.verify(&message, &ours), Ok(()), "line {line}");
            count += 1;
        }
        assert_eq!(count, 128);
    }

    /// The first 32 bytes of SHA-256(`label` || `i` as four big-endian bytes),
    /// as in the AES tests: simple to reproduce in any language.
    fn derive(label: &[u8], i: u32) -> [u8; 32] {
        let mut input = label.to_vec();
        input.extend_from_slice(&i.to_be_bytes());
        Sha256::digest(&input)
    }

    /// SHA-256 of the outputs of `many_keys`, for each scheme, from Go's
    /// `crypto/ed25519`. OpenSSL 3.6 makes the same 765 signatures for
    /// i = 1 to 255; its command line cannot sign the empty message of i = 0.
    const MANY_KEYS: [(&str, &str); 3] = [
        (
            "Ed25519 (public keys and signatures)",
            "61e2c2076500cdf120cd960371e774695e145342d12662560f6b3fddf9c574f6",
        ),
        (
            "Ed25519ctx",
            "4b18e9309e673a78c6385fa5f21e4a2ec0b65990e468abf8e147791c6e536e60",
        ),
        (
            "Ed25519ph",
            "364c585f986f31fc18147f6511c62cdf64e77f52856c2835d5f5d851f9662503",
        ),
    ];

    #[test]
    fn many_keys() {
        // For each i: a key from `derive`, a message of i bytes, an
        // Ed25519ctx context of 1 + i % 255 bytes and an Ed25519ph context of
        // i % 256, so that every context length from 0 to 255 is used and the
        // hash inputs end on both sides of SHA-512's block boundaries.
        let mut outputs = [Vec::new(), Vec::new(), Vec::new()];
        for i in 0..256u32 {
            let key = SigningKey::from_seed(&derive(b"ed25519 seed", i));
            let public = key.verifying_key();
            let message: Vec<u8> = (0..i).map(|j| ((i + j) % 251) as u8).collect();
            let context: Vec<u8> = (0..1 + i % 255).map(|j| (i + 3 * j) as u8).collect();
            let ph_context: Vec<u8> = (0..i % 256).map(|j| (5 * i + j) as u8).collect();
            let prehash = Sha512::digest(&message);

            let pure = key.sign(&message);
            let ctx = key.sign_ctx(&message, &context).unwrap();
            let ph = key.sign_prehashed(&prehash, &ph_context).unwrap();
            assert_eq!(public.verify(&message, &pure), Ok(()), "i = {i}");
            assert_eq!(
                public.verify_ctx(&message, &context, &ctx),
                Ok(()),
                "i = {i}"
            );
            assert_eq!(
                public.verify_prehashed(&prehash, &ph_context, &ph),
                Ok(()),
                "i = {i}"
            );

            outputs[0].extend_from_slice(public.as_bytes());
            outputs[0].extend_from_slice(&pure.to_bytes());
            outputs[1].extend_from_slice(&ctx.to_bytes());
            outputs[2].extend_from_slice(&ph.to_bytes());
        }
        for ((what, expected), output) in MANY_KEYS.iter().zip(&outputs) {
            assert_eq!(hex(&Sha256::digest(output)), *expected, "{what}");
        }
    }

    #[test]
    fn rejects_tampering() {
        // RFC 8032 section 7.1, test 3.
        let (_, public, message, _, signature) = RFC_8032_ED25519[2];
        let public = VerifyingKey::from_bytes(&array(public)).unwrap();
        let message = unhex(message);
        let signature: [u8; 64] = array(signature);
        let valid = Signature::from_bytes(&signature);
        assert_eq!(public.verify(&message, &valid), Ok(()));

        let flip = |bytes: &mut [u8], bit: usize| bytes[bit / 8] ^= 1 << (bit % 8);

        for bit in 0..8 * Signature::LEN {
            let mut bad = signature;
            flip(&mut bad, bit);
            let bad = Signature::from_bytes(&bad);
            assert_eq!(
                public.verify(&message, &bad),
                Err(Error::InvalidSignature),
                "signature bit {bit}"
            );
        }

        for bit in 0..8 * message.len() {
            let mut bad = message.clone();
            flip(&mut bad, bit);
            assert_eq!(
                public.verify(&bad, &valid),
                Err(Error::InvalidSignature),
                "message bit {bit}"
            );
        }
        let longer = [&message[..], &[0]].concat();
        assert_eq!(public.verify(&longer, &valid), Err(Error::InvalidSignature));
        assert_eq!(
            public.verify(&message[1..], &valid),
            Err(Error::InvalidSignature)
        );

        // A changed key either no longer decodes or is a different key, under
        // which the signature does not verify.
        for bit in 0..8 * VerifyingKey::LEN {
            let mut bad = public.to_bytes();
            flip(&mut bad, bit);
            match VerifyingKey::from_bytes(&bad) {
                Err(error) => assert_eq!(error, Error::InvalidPublicKey, "key bit {bit}"),
                Ok(key) => assert_eq!(
                    key.verify(&message, &valid),
                    Err(Error::InvalidSignature),
                    "key bit {bit}"
                ),
            }
        }
    }

    /// ℓ, little-endian.
    const ORDER: [u8; 32] = [
        0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde,
        0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
    ];

    /// `a + b` or `a - b` on 32-byte little-endian integers, modulo 2^256.
    fn add_or_sub(a: &[u8; 32], b: &[u8; 32], subtract: bool) -> [u8; 32] {
        let mut out = [0u8; 32];
        let mut carry = 0i16;
        for ((o, &x), &y) in out.iter_mut().zip(a).zip(b) {
            let y = if subtract {
                -i16::from(y)
            } else {
                i16::from(y)
            };
            let t = i16::from(x) + y + carry;
            *o = t.rem_euclid(256) as u8;
            carry = t.div_euclid(256);
        }
        out
    }

    /// The signature with its S replaced.
    fn with_s(signature: &Signature, s: &[u8; 32]) -> Signature {
        let mut bytes = signature.to_bytes();
        bytes[32..].copy_from_slice(s);
        Signature::from_bytes(&bytes)
    }

    #[test]
    fn rejects_s_not_below_order() {
        // Go's TestMalleability: a signature of "Test" whose S is ℓ more than
        // that of a valid one.
        let public = VerifyingKey::from_bytes(&array(
            "7d4d0e7f6153a69b6242b522abbee685fda4420f8834b108c3bdae369ef549fa",
        ))
        .unwrap();
        let malleated = Signature::from_bytes(&array(
            "7c38e026f29e14aabd059a0f2db8b0cd783040609a8be684db12f82a27774ab0\
             67654bce3832c2d76f8f6f5dafc08d9339d4eef676573336a5c51eb6f946b31d",
        ));
        assert_eq!(
            public.verify(b"Test", &malleated),
            Err(Error::InvalidSignature)
        );
        // Taking ℓ back off gives the valid signature it was made from: S
        // being out of range is the only thing wrong with it.
        let original = with_s(&malleated, &add_or_sub(malleated.s_bytes(), &ORDER, true));
        assert_eq!(public.verify(b"Test", &original), Ok(()));

        // The same done to the signature of RFC 8032 section 7.1, test 1,
        // and S = ℓ and S = 2^256 - 1 on the same R.
        let (_, public, _, _, signature) = RFC_8032_ED25519[0];
        let public = VerifyingKey::from_bytes(&array(public)).unwrap();
        let valid = Signature::from_bytes(&array(signature));
        assert_eq!(public.verify(b"", &valid), Ok(()));
        for s in [
            add_or_sub(valid.s_bytes(), &ORDER, false),
            ORDER,
            [0xff; 32],
        ] {
            assert_eq!(
                public.verify(b"", &with_s(&valid, &s)),
                Err(Error::InvalidSignature),
                "S = {}",
                hex(&s)
            );
        }
    }

    /// A signature of `message` whose R is the identity, encoded as `r`:
    /// S = k s, so that [S]B - [k]A is the identity. Only the holder of s
    /// can make one, and no honest signer would.
    fn identity_r_signature(key: &SigningKey, message: &[u8], r: &[u8; 32]) -> Signature {
        let a = key.verifying_key().to_bytes();
        let k = Scalar::from_bytes_wide(&hash(Scheme::Pure, &[], &[r, &a, message]));
        let s = Scalar::mul_add(&k, &key.scalar, &Scalar([0; 4]));
        let mut bytes = [0u8; 64];
        bytes[..32].copy_from_slice(r);
        bytes[32..].copy_from_slice(&s.to_bytes());
        Signature::from_bytes(&bytes)
    }

    #[test]
    fn rejects_non_canonical_r() {
        let key = SigningKey::from_seed(&[1; 32]);
        let public = key.verifying_key();

        // The identity's own encoding, y = 1: the equation holds and R is
        // canonical, so the signature is valid.
        let mut identity = [0u8; 32];
        identity[0] = 1;
        let canonical = identity_r_signature(&key, b"message", &identity);
        assert_eq!(public.verify(b"message", &canonical), Ok(()));

        // Two other strings that a lax decoder would read as the identity:
        // y = 1 with the sign bit set, though x = 0, and y = p + 1. Each makes
        // a different k, and S is computed for it, so the equation holds for
        // both, but R is not canonical. Go's crypto/ed25519 rejects both too.
        let mut signed = identity;
        signed[31] |= 0x80;
        let mut p_plus_1 = [0xff; 32];
        p_plus_1[0] = 0xee;
        p_plus_1[31] = 0x7f;
        for r in [signed, p_plus_1] {
            let signature = identity_r_signature(&key, b"message", &r);
            assert_eq!(
                public.verify(b"message", &signature),
                Err(Error::InvalidSignature),
                "R = {}",
                hex(&r)
            );
        }
    }

    /// The y-coordinates below 19 that belong to points of the curve,
    /// computed independently of this crate with the RFC's own decoding.
    /// 0 and 1 are the y of points of small order.
    const SMALL_Y_ON_CURVE: [u8; 12] = [0, 1, 3, 4, 5, 6, 9, 10, 14, 15, 16, 18];

    #[test]
    fn rejects_non_canonical_public_keys() {
        // For y0 below 19, y0 + p is below 2^255 and so fits the 255 bits of
        // y: a second encoding of the same y. Go's crypto/ed25519 accepts it
        // whenever y0 is on the curve.
        for y0 in 0u8..19 {
            for sign in [0, 0x80] {
                let mut canonical = [0u8; 32];
                canonical[0] = y0;
                canonical[31] = sign;
                let mut non_canonical = [0xff; 32];
                non_canonical[0] = 0xed + y0;
                non_canonical[31] = 0x7f | sign;

                let on_curve = SMALL_Y_ON_CURVE.contains(&y0);
                // y = 1 and y = 0 with the sign bit set are (0, 1), whose
                // x has only one sign, and the second point of order 4.
                let valid = on_curve && y0 > 1;
                assert_eq!(
                    VerifyingKey::from_bytes(&canonical).is_ok(),
                    valid,
                    "y = {y0}, sign {sign:#x}"
                );
                assert_eq!(
                    VerifyingKey::from_bytes(&non_canonical).err(),
                    Some(Error::InvalidPublicKey),
                    "y = {y0} + p, sign {sign:#x}"
                );
            }
        }

        // x = 0 with the sign bit set, for the other point with x = 0:
        // (0, -1), whose y is p - 1. Its canonical encoding decodes (and is
        // then rejected for its order); with the sign bit, it does not.
        let mut minus_one = [0xff; 32];
        minus_one[0] = 0xec;
        minus_one[31] = 0x7f;
        assert!(EdwardsPoint::decompress(&minus_one).is_some());
        minus_one[31] |= 0x80;
        assert!(EdwardsPoint::decompress(&minus_one).is_none());
        assert_eq!(
            VerifyingKey::from_bytes(&minus_one),
            Err(Error::InvalidPublicKey)
        );
    }

    /// The encodings of the eight points of small order: the identity, the
    /// point of order 2, the two of order 4 and the four of order 8. Their
    /// orders were checked independently of this crate.
    const SMALL_ORDER: [&str; 8] = [
        "0100000000000000000000000000000000000000000000000000000000000000",
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0000000000000000000000000000000000000000000000000000000000000080",
        "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
        "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
    ];

    #[test]
    fn rejects_small_order_public_keys() {
        for encoding in SMALL_ORDER {
            let bytes = array(encoding);
            // They are points of the curve, so the rejection is for their
            // order.
            assert!(EdwardsPoint::decompress(&bytes).is_some(), "{encoding}");
            assert_eq!(
                VerifyingKey::from_bytes(&bytes),
                Err(Error::InvalidPublicKey),
                "{encoding}"
            );
        }

        // Why: with A the identity, [S]B - [k]A is [S]B whatever the message,
        // so R = [S]B makes a valid signature of everything, without any key.
        // Bypassing the check shows it (Go's crypto/ed25519 accepts this).
        let bytes = array(SMALL_ORDER[0]);
        let weak = VerifyingKey {
            point: EdwardsPoint::decompress(&bytes).unwrap(),
            bytes,
        };
        let s = Scalar([42, 0, 0, 0]);
        let mut forged = [0u8; 64];
        forged[..32].copy_from_slice(&EdwardsPoint::mul_base(&s).compress());
        forged[32..].copy_from_slice(&s.to_bytes());
        let forged = Signature::from_bytes(&forged);
        for message in [&b"anything"[..], b"at all"] {
            assert_eq!(weak.verify(message, &forged), Ok(()));
        }
    }

    #[test]
    fn cofactorless_equation() {
        // A key with a component of order 8: A' = [s]B + T, which no honest
        // key generation produces. A signature made with s satisfies
        // [S]B = R + [k]A' - [k]T, so the cofactorless equation holds only
        // when [k]T is the identity, that is when k is a multiple of 8; the
        // cofactored one, [8][S]B = [8]R + [8][k]A', would hold for every k.
        let key = SigningKey::from_seed(&[2; 32]);
        let torsion = EdwardsPoint::decompress(&array(SMALL_ORDER[4])).unwrap();
        let mixed = key.verifying_key.point.add(&torsion);
        let public = VerifyingKey::from_bytes(&mixed.compress()).expect("not of small order");

        let (mut accepted, mut rejected) = (0, 0);
        for i in 0u8..64 {
            let message = [i];
            let r = Scalar([u64::from(i) + 1, 0, 0, 0]);
            let big_r = EdwardsPoint::mul_base(&r).compress();
            let k = Scalar::from_bytes_wide(&hash(
                Scheme::Pure,
                &[],
                &[&big_r, public.as_bytes(), &message],
            ));
            let s = Scalar::mul_add(&k, &key.scalar, &r);
            let mut bytes = [0u8; 64];
            bytes[..32].copy_from_slice(&big_r);
            bytes[32..].copy_from_slice(&s.to_bytes());

            let result = public.verify(&message, &Signature::from_bytes(&bytes));
            if k.0[0].is_multiple_of(8) {
                assert_eq!(result, Ok(()), "i = {i}");
                accepted += 1;
            } else {
                assert_eq!(result, Err(Error::InvalidSignature), "i = {i}");
                rejected += 1;
            }
        }
        // Both cases came up.
        assert!(
            accepted > 0 && rejected > 0,
            "{accepted} accepted, {rejected} rejected"
        );
    }

    #[test]
    fn context_lengths() {
        let key = SigningKey::from_seed(&[4; 32]);
        let public = key.verifying_key();
        let digest = Sha512::digest(b"");
        let longest = [0x5a; MAX_CONTEXT_LEN];
        let too_long = [0x5a; MAX_CONTEXT_LEN + 1];

        let signature = key.sign_ctx(b"m", &longest).unwrap();
        assert_eq!(public.verify_ctx(b"m", &longest, &signature), Ok(()));
        let signature = key.sign_prehashed(&digest, &longest).unwrap();
        assert_eq!(
            public.verify_prehashed(&digest, &longest, &signature),
            Ok(())
        );

        assert_eq!(key.sign_ctx(b"m", &too_long), Err(Error::ContextTooLong));
        assert_eq!(key.sign_ctx(b"m", b""), Err(Error::EmptyContext));
        assert_eq!(
            key.sign_prehashed(&digest, &too_long),
            Err(Error::ContextTooLong)
        );
        assert_eq!(
            public.verify_ctx(b"m", &too_long, &signature),
            Err(Error::ContextTooLong)
        );
        assert_eq!(
            public.verify_ctx(b"m", b"", &signature),
            Err(Error::EmptyContext)
        );
        assert_eq!(
            public.verify_prehashed(&digest, &too_long, &signature),
            Err(Error::ContextTooLong)
        );
    }

    #[test]
    fn wrong_lengths() {
        let key = SigningKey::from_seed(&[5; 32]);
        let public = key.verifying_key().to_bytes();
        let signature = key.sign(b"").to_bytes();

        assert_eq!(
            VerifyingKey::try_from(&public[..]).map(|k| k.to_bytes()),
            Ok(public)
        );
        assert_eq!(
            Signature::try_from(&signature[..]).map(|s| s.to_bytes()),
            Ok(signature)
        );
        let long_key = [&public[..], &[0]].concat();
        for bytes in [&public[..31], &long_key, &[]] {
            assert_eq!(
                VerifyingKey::try_from(bytes),
                Err(Error::InvalidLength),
                "{} bytes",
                bytes.len()
            );
        }
        let long_signature = [&signature[..], &[0]].concat();
        for bytes in [&signature[..63], &long_signature, &[]] {
            assert_eq!(
                Signature::try_from(bytes),
                Err(Error::InvalidLength),
                "{} bytes",
                bytes.len()
            );
        }
    }

    #[test]
    fn generate_reads_a_seed() {
        // The key is the one its 32 bytes make as a seed, and only 32 are read.
        let bytes: Vec<u8> = (0..40).collect();
        let mut reader = &bytes[..];
        let key = SigningKey::generate(&mut reader).unwrap();
        assert_eq!(key.seed()[..], bytes[..32]);
        assert_eq!(
            key.verifying_key(),
            SigningKey::from_seed(&array(&hex(&bytes[..32]))).verifying_key()
        );
        assert_eq!(reader.len(), 8);

        // A reader that runs out is reported, not padded.
        let error = SigningKey::generate(&mut &bytes[..31]).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
    }

    /// Dropping a signing key must leave none of its secrets behind.
    #[test]
    fn dropping_wipes_the_secret_key() {
        use core::mem::{MaybeUninit, offset_of};

        let mut slot = MaybeUninit::new(SigningKey::from_seed(&[0x42; 32]));
        // One raw pointer does the dropping and the reading, so that the drop
        // does not invalidate the pointer the reads go through.
        let key = slot.as_mut_ptr();
        let bytes = key.cast::<u8>();
        let secrets = [
            (offset_of!(SigningKey, seed), 32),
            (offset_of!(SigningKey, scalar), 32),
            (offset_of!(SigningKey, prefix), 32),
        ];
        let read = || -> Vec<u8> {
            secrets
                .iter()
                .flat_map(|&(at, len)| at..at + len)
                // SAFETY: the slot is alive and these bytes, which hold
                // integers and byte arrays, were all written, first by
                // `from_seed` and then, if the drop works, by `wipe`.
                .map(|i| unsafe { bytes.add(i).read() })
                .collect()
        };
        assert!(read().iter().any(|&b| b != 0), "no secrets to wipe");

        // SAFETY: the slot holds an initialised key, dropped only here.
        unsafe { key.drop_in_place() };
        assert!(read().iter().all(|&b| b == 0), "secrets survive the drop");
    }

    /// The Debug output must show the public key and nothing secret.
    #[test]
    fn debug_hides_the_key() {
        let key = SigningKey::from_seed(&[0xab; 32]);
        let public = hex(key.verifying_key().as_bytes());
        assert_eq!(
            format!("{key:?}"),
            format!("SigningKey {{ verifying_key: VerifyingKey({public}), .. }}")
        );
    }

    #[test]
    #[ignore = "manual throughput check: cargo test --release ed25519 -- --ignored --nocapture --test-threads=1"]
    fn throughput() {
        use std::hint::black_box;
        use std::time::{Duration, Instant};

        /// The best of five batches of `op`, in microseconds per call, after a
        /// warm-up call (which also builds the tables of multiples of B, once)
        /// and a pass to size the batches to about 100 ms.
        fn time(mut op: impl FnMut()) -> f64 {
            op();
            let start = Instant::now();
            let mut calls = 0u32;
            while start.elapsed() < Duration::from_millis(50) {
                op();
                calls += 1;
            }
            let batch = (2 * calls).max(1);

            let mut best = f64::MAX;
            for _ in 0..5 {
                let start = Instant::now();
                for _ in 0..batch {
                    op();
                }
                best = best.min(start.elapsed().as_secs_f64() / f64::from(batch));
            }
            best * 1e6
        }

        // The same inputs as bench/ed25519cmp: the seed 0, 1, ..., 31 and a
        // 128-byte message whose byte i is i.
        let seed: [u8; 32] = core::array::from_fn(|i| i as u8);
        let message: Vec<u8> = (0..128).map(|i| i as u8).collect();
        let key = SigningKey::from_seed(&seed);
        let public = key.verifying_key().to_bytes();
        let decoded = key.verifying_key();
        let signature = key.sign(&message);

        // Building a signing key derives its public key: one multiplication
        // of B. Building a verifying key decodes a point. Signing is two hashes
        // and one multiplication of B. Verifying, as Go's ed25519.Verify does
        // it, decodes the key and then checks the equation; the last row
        // leaves the decoding out.
        let rows = [
            (
                "new signing key",
                time(|| drop(black_box(SigningKey::from_seed(black_box(&seed))))),
            ),
            (
                "new verifying key",
                time(|| {
                    black_box(VerifyingKey::from_bytes(black_box(&public)).unwrap());
                }),
            ),
            (
                "sign",
                time(|| {
                    black_box(key.sign(black_box(&message)));
                }),
            ),
            (
                "verify",
                time(|| {
                    let key = VerifyingKey::from_bytes(black_box(&public)).unwrap();
                    key.verify(black_box(&message), black_box(&signature))
                        .unwrap();
                }),
            ),
            (
                "verify, key decoded once",
                time(|| {
                    black_box(&decoded)
                        .verify(black_box(&message), black_box(&signature))
                        .unwrap();
                }),
            ),
        ];
        for (name, micros) in rows {
            println!(
                "ed25519 {name} [cryptors]: best {micros:.2} us/op, {:.0} ops/s (public key {}..., signature {}...)",
                1e6 / micros,
                hex(&public[..8]),
                hex(&signature.to_bytes()[..8]),
            );
        }
    }
}
