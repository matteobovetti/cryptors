//! Public keys and private keys, and the operations on them.

use super::bigmod::{Limbs, Modulus, add, bit_len, eq, is_one, lt, mul, rem, sub};
use super::bytes::Wiped;
use super::error::Error;
use super::hash::Pkcs1Hash;
use super::{keygen, oaep, pkcs1v15, pss};
use crate::Digest;
use crate::ec::ct;
use core::fmt;
use std::io;

/// The smallest modulus accepted, in bits. Smaller ones can be factored.
pub(super) const MIN_BITS: usize = 1024;

/// The largest modulus accepted, in bits: OpenSSL's limit too. A key from outside
/// that is larger could make a verification take minutes.
pub(super) const MAX_BITS: usize = 16384;

/// How long the salt of a PSS signature is.
///
/// RFC 8017 (section 9.1) lets the signer choose, and a verifier that checks the
/// length refuses signatures made with another. The length that the standard
/// recommends and that most protocols fix is the length of the hash's output.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SaltLength {
    /// As long as the output of the hash. FIPS 186-5 (section 5.4) allows no
    /// longer salt, and TLS 1.3 requires this one.
    EqualsHash,

    /// As long as the key allows when signing, and whatever length the signature
    /// turns out to have when verifying, so that it accepts every PSS signature
    /// of the key and the hash.
    Auto,

    /// Exactly this many bytes.
    Len(usize),
}

/// A public key: the modulus `n` and the public exponent `e`.
///
/// Holding one means the numbers passed the checks of [`PublicKey::new`]: an odd
/// modulus of 1,024 to 16,384 bits and an odd exponent from 3 to 2^31 - 1. Nothing
/// about it is secret, and the operations on it do not run in constant time.
#[derive(Clone)]
pub struct PublicKey {
    n: Modulus,
    e: u32,
}

/// A private key: the factors `p` and `q` of the modulus and the numbers that the
/// Chinese remainder theorem makes the private operation fast with, as RFC 8017
/// (section 3.2, the second representation) has them.
///
/// The private operation takes a time that depends on the size of the key and not
/// on its value, and the result is checked before it is released, so that a fault
/// in the computation cannot leak a prime. The numbers of the key are overwritten
/// with zeros when it is dropped, and `Debug` does not show them. That is best
/// effort: the working values of the arithmetic (numbers that depend on the key,
/// on the stack and in registers while it is in use) are not overwritten, and
/// neither is the copy that moving the key (into a `Box` or a `Vec`, say) can
/// leave behind where it was.
#[derive(Clone)]
pub struct PrivateKey {
    public: PublicKey,
    /// The private exponent, below `n`.
    d: Limbs,
    p: Modulus,
    q: Modulus,
    /// `d mod (p - 1)` and `d mod (q - 1)`.
    dp: Limbs,
    dq: Limbs,
    /// `q^-1 mod p`, in Montgomery form modulo `p`.
    q_inv: Limbs,
}

fn invalid_input(error: Error) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, error)
}

impl PublicKey {
    /// Builds a key from the big-endian modulus and the public exponent.
    ///
    /// # Errors
    ///
    /// [`Error::UnsupportedKeySize`] if the modulus has fewer than 1,024 or more
    /// than 16,384 bits, and [`Error::InvalidPublicKey`] if it is even or the
    /// exponent is not odd and from 3 to 2^31 - 1. (A larger exponent is refused:
    /// no key in use has one, and each bit of it costs a squaring in every
    /// verification of a key that came from outside.) Leading zero bytes of the
    /// modulus are ignored.
    pub fn new(modulus: &[u8], exponent: u32) -> Result<Self, Error> {
        Self::build(modulus, exponent, MIN_BITS)
    }

    /// As [`new`](PublicKey::new), with another lower limit on the size of the
    /// modulus. The tests use it to run vectors of keys that the public function
    /// refuses.
    pub(super) fn build(modulus: &[u8], exponent: u32, min_bits: usize) -> Result<Self, Error> {
        let n = Limbs::from_be_bytes(modulus).trimmed();
        let bits = bit_len(&n);
        if bits < min_bits || bits > MAX_BITS {
            return Err(Error::UnsupportedKeySize);
        }
        if exponent < 3 || exponent > i32::MAX as u32 || exponent.is_multiple_of(2) {
            return Err(Error::InvalidPublicKey);
        }
        let n = Modulus::new(n).ok_or(Error::InvalidPublicKey)?;
        Ok(PublicKey { n, e: exponent })
    }

    /// The modulus, as a big-endian number of [`size`](PublicKey::size) bytes.
    pub fn modulus(&self) -> Vec<u8> {
        Limbs::from(self.n.limbs()).to_be_bytes(self.size())
    }

    /// The public exponent.
    pub fn exponent(&self) -> u32 {
        self.e
    }

    /// The size of the modulus in bits.
    pub fn bits(&self) -> usize {
        self.n.bit_len()
    }

    /// The size of the modulus in bytes: the length of every ciphertext and
    /// signature of the key.
    pub fn size(&self) -> usize {
        self.bits().div_ceil(8)
    }

    /// `x^e mod n` for `x` below `n` in as many limbs as `n`: RSAEP and RSAVP1
    /// (RFC 8017, sections 5.1.1 and 5.2.2).
    fn public_op(&self, x: &[u64]) -> Limbs {
        let in_form = self.n.to_mont(x);
        self.n.to_plain(&self.n.pow_u32(&in_form, self.e))
    }

    /// The same on a `size()`-byte big-endian number, or `None` if `input` is not
    /// that long or is not below the modulus.
    fn public_op_bytes(&self, input: &[u8]) -> Option<Vec<u8>> {
        if input.len() != self.size() {
            return None;
        }
        let x = Limbs::from_be_bytes(input);
        if lt(&x, self.n.limbs()) != 1 {
            return None;
        }
        Some(self.public_op(&x).to_be_bytes(self.size()))
    }

    /// Encrypts `message` with RSAES-OAEP (RFC 8017, section 7.1), with `D` as the
    /// hash of the label and of MGF1 alike, which is what almost every
    /// implementation and protocol uses. SHA-256 is a good `D`.
    ///
    /// `label` is data that is not encrypted but bound to the ciphertext: a
    /// ciphertext only decrypts under the label it was made with, which can tell
    /// apart the uses of one key. It is usually empty.
    ///
    /// The ciphertext is random: it needs `D::OUTPUT_LEN` bytes from `rng`, which
    /// has to be a source of cryptographically secure random bytes (the standard
    /// library has none that is stable, so this takes any reader; on Unix,
    /// `File::open("/dev/urandom")` is one, and so is
    /// [`rand::Reader`](crate::rand::Reader)).
    ///
    /// The message can be at most `size() - 2 * D::OUTPUT_LEN - 2` bytes: 190 for
    /// a 2,048-bit key with SHA-256.
    ///
    /// # Errors
    ///
    /// Whatever `rng` fails with, and
    /// [`InvalidInput`](io::ErrorKind::InvalidInput) (carrying
    /// [`Error::MessageTooLong`]) for a message that does not fit.
    pub fn encrypt_oaep<D: Digest, R: io::Read + ?Sized>(
        &self,
        rng: &mut R,
        message: &[u8],
        label: &[u8],
    ) -> io::Result<Vec<u8>> {
        self.encrypt_oaep_mgf1::<D, D, R>(rng, message, label)
    }

    /// As [`encrypt_oaep`](PublicKey::encrypt_oaep), with `D` hashing the label and
    /// `M` the hash of MGF1, which RFC 8017 lets differ. Protocols that fix `M` to
    /// SHA-1 while `D` is stronger exist (the Java default is one), and this reads
    /// them; use the first function if you have the choice.
    pub fn encrypt_oaep_mgf1<D: Digest, M: Digest, R: io::Read + ?Sized>(
        &self,
        rng: &mut R,
        message: &[u8],
        label: &[u8],
    ) -> io::Result<Vec<u8>> {
        let k = self.size();
        let h = D::OUTPUT_LEN;
        if k < 2 * h + 2 || message.len() > k - 2 * h - 2 {
            return Err(invalid_input(Error::MessageTooLong));
        }
        let mut seed = Wiped::zero(h);
        rng.read_exact(&mut seed)?;
        let em = oaep::encode::<D, M>(k, message, label, &seed).map_err(invalid_input)?;
        Ok(self
            .public_op_bytes(&em)
            .expect("a block that starts with a zero byte is below the modulus"))
    }

    /// Encrypts `message` with RSAES-PKCS1-v1_5 (RFC 8017, section 7.2).
    ///
    /// **Do not use this in a new design.** The padding of this scheme lets whoever
    /// can learn whether a ciphertext decrypts decrypt any ciphertext
    /// (Bleichenbacher, 1998, and many variants since, up to 2018), and it has
    /// been the cause of attacks on TLS and on XML encryption again and again. It
    /// is here to read and write the data of protocols that already use it; use
    /// [`encrypt_oaep`](PublicKey::encrypt_oaep) otherwise.
    ///
    /// The message can be at most `size() - 11` bytes. The eight bytes at least of
    /// padding, none of them zero, come from `rng`, as for OAEP.
    ///
    /// # Errors
    ///
    /// Whatever `rng` fails with, and
    /// [`InvalidInput`](io::ErrorKind::InvalidInput) (carrying
    /// [`Error::MessageTooLong`]) for a message that does not fit.
    pub fn encrypt_pkcs1v15<R: io::Read + ?Sized>(
        &self,
        rng: &mut R,
        message: &[u8],
    ) -> io::Result<Vec<u8>> {
        let em = pkcs1v15::encode_encryption(self.size(), message, rng)?;
        Ok(self
            .public_op_bytes(&em)
            .expect("a block that starts with a zero byte is below the modulus"))
    }

    /// Checks the RSASSA-PKCS1-v1_5 signature (RFC 8017, section 8.2) of `message`,
    /// hashed with `D`.
    ///
    /// The signature is accepted only if it is exactly the padded `DigestInfo`
    /// that the standard prescribes for this digest: the block is rebuilt from the
    /// digest and compared, instead of being parsed, which is how the forgeries of
    /// lenient verifiers (Bleichenbacher's, 2006, and its descendants) are
    /// avoided.
    ///
    /// # Errors
    ///
    /// [`Error::VerificationFailed`] if it is not.
    pub fn verify_pkcs1v15<D: Pkcs1Hash>(
        &self,
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), Error> {
        self.verify_pkcs1v15_prehash::<D>(D::digest(message).as_ref(), signature)
    }

    /// As [`verify_pkcs1v15`](PublicKey::verify_pkcs1v15), for the digest of the
    /// message, which has to be as long as the output of `D`.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidDigest`] if it is not, and [`Error::VerificationFailed`]
    /// if the signature is not one of this digest.
    pub fn verify_pkcs1v15_prehash<D: Pkcs1Hash>(
        &self,
        digest: &[u8],
        signature: &[u8],
    ) -> Result<(), Error> {
        if digest.len() != D::OUTPUT_LEN {
            return Err(Error::InvalidDigest);
        }
        let em = self
            .public_op_bytes(signature)
            .ok_or(Error::VerificationFailed)?;
        let expected = pkcs1v15::encode_signature::<D>(self.size(), digest)
            .map_err(|_| Error::VerificationFailed)?;
        if ct::bytes_eq(&em, &expected) {
            Ok(())
        } else {
            Err(Error::VerificationFailed)
        }
    }

    /// Checks the RSASSA-PSS signature (RFC 8017, section 8.1) of `message`,
    /// hashed with `D`, which is also the hash of MGF1, with a salt of the given
    /// length.
    ///
    /// # Errors
    ///
    /// [`Error::VerificationFailed`] if the signature is not a signature of
    /// `message`, or its salt is not as long as `salt` says.
    pub fn verify_pss<D: Digest>(
        &self,
        message: &[u8],
        signature: &[u8],
        salt: SaltLength,
    ) -> Result<(), Error> {
        self.verify_pss_prehash::<D>(D::digest(message).as_ref(), signature, salt)
    }

    /// As [`verify_pss`](PublicKey::verify_pss), for the digest of the message,
    /// which has to be as long as the output of `D`.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidDigest`] if it is not, and [`Error::VerificationFailed`]
    /// if the signature is not one of this digest.
    pub fn verify_pss_prehash<D: Digest>(
        &self,
        digest: &[u8],
        signature: &[u8],
        salt: SaltLength,
    ) -> Result<(), Error> {
        if digest.len() != D::OUTPUT_LEN {
            return Err(Error::InvalidDigest);
        }
        let em = self
            .public_op_bytes(signature)
            .ok_or(Error::VerificationFailed)?;
        // The encoded message has `bits - 1` bits, which fill the modulus's bytes
        // but for one when the size is a multiple of 8 plus 1; the first byte of
        // the block is then zero (RFC 8017, section 8.1.2, note 2).
        let em_bits = self.bits() - 1;
        let skipped = self.size() - em_bits.div_ceil(8);
        if em[..skipped].iter().any(|&byte| byte != 0) {
            return Err(Error::VerificationFailed);
        }
        let mut em = em[skipped..].to_vec();
        let salt_len = match salt {
            SaltLength::Auto => None,
            SaltLength::EqualsHash => Some(D::OUTPUT_LEN),
            SaltLength::Len(len) => Some(len),
        };
        pss::verify::<D>(digest, &mut em, em_bits, salt_len)
    }
}

impl PartialEq for PublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.e == other.e && eq(self.n.limbs(), other.n.limbs()) == 1
    }
}

impl Eq for PublicKey {}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PublicKey")
            .field("bits", &self.bits())
            .field("exponent", &self.e)
            .finish_non_exhaustive()
    }
}

impl PrivateKey {
    /// Generates a key of `bits` bits, with the public exponent 65,537, from
    /// `rng`, which has to be a source of cryptographically secure random bytes:
    /// the secrecy of everything that follows depends on it. The standard library
    /// has none that is stable, so this takes any reader; on Unix,
    /// `File::open("/dev/urandom")` is one, and so is
    /// [`rand::Reader`](crate::rand::Reader).
    ///
    /// The process is that of FIPS 186-5 (appendix A.1.3, "probable primes"), as
    /// c2sp.org/det-keygen specifies it: two primes of `bits / 2` bits, drawn from
    /// `rng` until they pass trial division and Miller-Rabin, with the private
    /// exponent computed modulo `lcm(p - 1, q - 1)`. A deterministic `rng` gives
    /// the same key every time and the same key as every other implementation of
    /// that process.
    ///
    /// It takes a while, and a different while each time, since it is a search for
    /// two primes: doubling the size multiplies the time by about sixteen (twice as
    /// many candidates, and the test of each is eight times the work). It is not
    /// constant-time, and does not need to be.
    ///
    /// # Errors
    ///
    /// Whatever `rng` fails with, and
    /// [`InvalidInput`](io::ErrorKind::InvalidInput) (carrying
    /// [`Error::UnsupportedKeySize`]) for a `bits` below 1,024 or above 16,384.
    /// It also fails with [`InvalidData`](io::ErrorKind::InvalidData) if `rng`
    /// gave the same prime twice, which no good source does.
    pub fn generate<R: io::Read + ?Sized>(rng: &mut R, bits: usize) -> io::Result<Self> {
        if !(MIN_BITS..=MAX_BITS).contains(&bits) {
            return Err(invalid_input(Error::UnsupportedKeySize));
        }
        keygen::generate(rng, bits, MIN_BITS)
    }

    /// Builds a key from the big-endian numbers of its first representation (RFC
    /// 8017, section 3.2): the modulus `n`, the public exponent `e`, the private
    /// exponent `d` and the primes `p` and `q`. The other numbers of the second
    /// representation, `d mod (p - 1)`, `d mod (q - 1)` and `q^-1 mod p`, follow
    /// from them and are computed here; whoever has them can leave them out.
    ///
    /// The key is checked as FIPS 186-5 (appendices A.1.1 and A.1.3) asks: `n` is
    /// `p * q`, each of the primes is odd, `e * d` is 1 modulo `p - 1` and modulo
    /// `q - 1` (so the key decrypts what it encrypts), `q` has an inverse modulo
    /// `p`, `p` and `q` differ by more than `2^(bits / 2 - 100)` (primes that are
    /// close can be found with Fermat's method of factoring, which has been done to
    /// keys in use), and `d` is above `2^(bits / 2)` (Wiener's and Boneh and
    /// Durfee's attacks). It does not test that `p` and `q` are prime, which is a
    /// probabilistic test as costly as generating a key: the numbers are taken to
    /// come from a place that is trusted, a composite `p` is caught by the inverse of
    /// `q` in all but the rarest cases, and neither stops a key that someone built to
    /// pass.
    ///
    /// The checks are made in constant time, as far as the lengths of the numbers
    /// go: their time does not depend on their values. Leading zero bytes are
    /// ignored.
    ///
    /// # Errors
    ///
    /// The errors of [`PublicKey::new`] for `n` and `e`, and
    /// [`Error::InvalidPrivateKey`] for anything else that fails a check.
    pub fn from_components(
        modulus: &[u8],
        exponent: u32,
        d: &[u8],
        p: &[u8],
        q: &[u8],
    ) -> Result<Self, Error> {
        Self::build(modulus, exponent, d, p, q, MIN_BITS)
    }

    /// As [`from_components`](PrivateKey::from_components), with another lower limit
    /// on the size of the modulus, for the tests.
    pub(super) fn build(
        modulus: &[u8],
        exponent: u32,
        d: &[u8],
        p: &[u8],
        q: &[u8],
        min_bits: usize,
    ) -> Result<Self, Error> {
        let public = PublicKey::build(modulus, exponent, min_bits)?;
        let invalid = Error::InvalidPrivateKey;
        let p = Modulus::new(Limbs::from_be_bytes(p).trimmed()).ok_or(invalid)?;
        let q = Modulus::new(Limbs::from_be_bytes(q).trimmed()).ok_or(invalid)?;
        let n = &public.n;

        // n = p * q
        if eq(&mul(p.limbs(), q.limbs()).trimmed(), n.limbs()) != 1 {
            return Err(invalid);
        }

        // d is a number below n
        let d = Limbs::from_be_bytes(d).trimmed();
        if lt(&d, n.limbs()) != 1 {
            return Err(invalid);
        }

        // |p - q| > 2^(bits / 2 - 100), and d > 2^(bits / 2). Leaking the sizes of
        // differences is acceptable: it is not adaptive, and an attacker learns the
        // magnitude of p - q and d, which the key size already bounds.
        let half = n.bit_len() / 2;
        let difference = if lt(p.limbs(), q.limbs()) == 1 {
            sub(q.limbs(), p.limbs()).0
        } else {
            sub(p.limbs(), q.limbs()).0
        };
        if bit_len(&difference) <= half.saturating_sub(100) || bit_len(&d) <= half {
            return Err(invalid);
        }

        // dP = d mod (p - 1) and dQ = d mod (q - 1) are the exponents of the
        // private operation, and e * dP = 1 modulo p - 1 (and the same for q)
        // says that the key decrypts what it encrypts: e * d = 1 modulo
        // lcm(p - 1, q - 1).
        let dp = crt_exponent(&d, &p, exponent).ok_or(invalid)?;
        let dq = crt_exponent(&d, &q, exponent).ok_or(invalid)?;

        // q^-1 mod p by Fermat's little theorem: q^(p - 2). If p is not prime, or
        // shares a factor with q, the product with q is not 1.
        let q_in_p = p.to_mont(q.limbs());
        let q_inv = p.pow(&q_in_p, &sub(p.limbs(), &[2]).0);
        if eq(&p.mul(&q_inv, &q_in_p), p.one()) != 1 {
            return Err(invalid);
        }

        let mut d_full = Limbs::zero(n.len());
        d_full[..d.len()].copy_from_slice(&d);
        Ok(PrivateKey {
            public,
            d: d_full,
            p,
            q,
            dp,
            dq,
            q_inv,
        })
    }

    /// The public key that goes with this one.
    pub fn public_key(&self) -> &PublicKey {
        &self.public
    }

    /// The private exponent `d`, as a big-endian number of
    /// [`size`](PublicKey::size) bytes. The copy is not wiped when it is dropped.
    pub fn d(&self) -> Vec<u8> {
        self.d.to_be_bytes(self.public.size())
    }

    /// The prime `p`, as a big-endian number of the bytes it needs. The copy is not
    /// wiped when it is dropped.
    pub fn p(&self) -> Vec<u8> {
        Limbs::from(self.p.limbs()).to_be_bytes(self.p.bit_len().div_ceil(8))
    }

    /// The prime `q`, as a big-endian number of the bytes it needs. The copy is not
    /// wiped when it is dropped.
    pub fn q(&self) -> Vec<u8> {
        Limbs::from(self.q.limbs()).to_be_bytes(self.q.bit_len().div_ceil(8))
    }

    /// `d mod (p - 1)`, as a big-endian number of as many bytes as `p`. The copy is
    /// not wiped when it is dropped.
    pub fn dp(&self) -> Vec<u8> {
        self.dp.to_be_bytes(self.p.bit_len().div_ceil(8))
    }

    /// `d mod (q - 1)`, as a big-endian number of as many bytes as `q`. The copy is
    /// not wiped when it is dropped.
    pub fn dq(&self) -> Vec<u8> {
        self.dq.to_be_bytes(self.q.bit_len().div_ceil(8))
    }

    /// `q^-1 mod p`, as a big-endian number of as many bytes as `p`. The copy is
    /// not wiped when it is dropped.
    pub fn q_inv(&self) -> Vec<u8> {
        self.p
            .to_plain(&self.q_inv)
            .to_be_bytes(self.p.bit_len().div_ceil(8))
    }

    /// Decrypts a ciphertext of RSAES-OAEP (RFC 8017, section 7.1.2), made with `D`
    /// as the hash of the label and of MGF1 and with the same `label`.
    ///
    /// Every way for a ciphertext to be wrong (its length, its value, the padding
    /// inside it, the label) gives the same [`Error::Decryption`], and the checks
    /// of the padding take the same time whichever fails: that is what keeps the
    /// key from being used as an oracle (Manger's attack on OAEP).
    ///
    /// # Errors
    ///
    /// [`Error::Decryption`].
    pub fn decrypt_oaep<D: Digest>(
        &self,
        ciphertext: &[u8],
        label: &[u8],
    ) -> Result<Vec<u8>, Error> {
        self.decrypt_oaep_mgf1::<D, D>(ciphertext, label)
    }

    /// As [`decrypt_oaep`](PrivateKey::decrypt_oaep), with `D` hashing the label and
    /// `M` the hash of MGF1.
    pub fn decrypt_oaep_mgf1<D: Digest, M: Digest>(
        &self,
        ciphertext: &[u8],
        label: &[u8],
    ) -> Result<Vec<u8>, Error> {
        if self.public.size() < 2 * D::OUTPUT_LEN + 2 {
            return Err(Error::Decryption);
        }
        let mut em = self.private_op(ciphertext).map_err(|_| Error::Decryption)?;
        oaep::decode::<D, M>(&mut em, label)
    }

    /// Decrypts a ciphertext of RSAES-PKCS1-v1_5 (RFC 8017, section 7.2.2).
    ///
    /// **Do not use this in a new design**, for the reasons given at
    /// [`PublicKey::encrypt_pkcs1v15`]; and note that whether this function
    /// returns an error discloses secret information. If an attacker can make it
    /// run on ciphertexts of their choosing and learn whether each one returned
    /// an error, they can decrypt any ciphertext of the key and forge its
    /// signatures. The padding is checked without branches on its bytes, so that
    /// the time says nothing, but the result is the oracle. When a protocol allows
    /// it, use [`decrypt_pkcs1v15_session_key`](PrivateKey::decrypt_pkcs1v15_session_key),
    /// which has no such result, or OAEP.
    ///
    /// # Errors
    ///
    /// [`Error::Decryption`].
    pub fn decrypt_pkcs1v15(&self, ciphertext: &[u8]) -> Result<Vec<u8>, Error> {
        let em = self.private_op(ciphertext).map_err(|_| Error::Decryption)?;
        let (valid, index) = pkcs1v15::locate_message(&em);
        if valid != 1 {
            return Err(Error::Decryption);
        }
        Ok(em[index..].to_vec())
    }

    /// Decrypts a ciphertext of RSAES-PKCS1-v1_5 that holds a session key of the
    /// length of `key`, with the protection against Bleichenbacher's attack that
    /// RFC 3218 (section 2.3.2) describes: if the padding is valid and the
    /// message has exactly that length, it is copied into `key`; if not, `key` is
    /// left as it was, and nothing tells the caller which happened. Both take the
    /// same time and do the same memory accesses.
    ///
    /// The intended use is to fill `key` with random bytes first and to go on
    /// with the protocol whatever happens: a ciphertext with a bad padding
    /// produces a key that nobody has, and the protocol fails later in a way that
    /// does not depend on the padding. That holds only if nothing that is done
    /// with the key afterwards depends on whether it is the random one; and if
    /// `key` is short, an attacker can guess it, and learn which it was. 16 bytes
    /// are enough. The protections are limited and fragile; this is for protocols
    /// that cannot be changed, such as TLS 1.2 and CMS.
    ///
    /// # Errors
    ///
    /// [`Error::Decryption`] if the ciphertext is not as long as the modulus or
    /// is not below it, or if the key is too long for the modulus to hold. These
    /// do not depend on the padding.
    pub fn decrypt_pkcs1v15_session_key(
        &self,
        ciphertext: &[u8],
        key: &mut [u8],
    ) -> Result<(), Error> {
        let k = self.public.size();
        if k < 11 || key.len() > k - 11 {
            return Err(Error::Decryption);
        }
        let em = self.private_op(ciphertext).map_err(|_| Error::Decryption)?;
        let (valid, index) = pkcs1v15::locate_message(&em);
        let fits = ct::eq((k - index) as u64, key.len() as u64);
        let take = ct::mask(valid & fits) as u8;
        let tail = &em[k - key.len()..];
        for (key_byte, &message_byte) in key.iter_mut().zip(tail) {
            *key_byte = (message_byte & take) | (*key_byte & !take);
        }
        Ok(())
    }

    /// Signs `message`, hashed with `D`, with RSASSA-PKCS1-v1_5 (RFC 8017,
    /// section 8.2.1): the signature is `size()` bytes.
    ///
    /// The signature is deterministic: the same key and message give the same
    /// signature, and no random source is needed. That also means that if the set
    /// of messages is small, whoever sees the signatures can tell which message
    /// was signed by trying them; signatures give authenticity, not
    /// confidentiality. For a new design, PSS is the scheme with a proof of
    /// security.
    ///
    /// The hash is a choice, and the verifier has to use the same one. SHA-256 and
    /// up are good; MD5 and SHA-1 are in [`Pkcs1Hash`] for the signatures that
    /// still use them, and a signature is as weak as its hash.
    ///
    /// # Errors
    ///
    /// [`Error::MessageTooLong`] if the key is too short for the `DigestInfo` of
    /// the hash: 94 bytes (a 752-bit modulus) for SHA-512, which the 1,024-bit
    /// minimum of the module covers.
    pub fn sign_pkcs1v15<D: Pkcs1Hash>(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
        self.sign_pkcs1v15_prehash::<D>(D::digest(message).as_ref())
    }

    /// As [`sign_pkcs1v15`](PrivateKey::sign_pkcs1v15), for the digest of the
    /// message, which has to be as long as the output of `D`.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidDigest`] if it is not, and the other errors of
    /// [`sign_pkcs1v15`](PrivateKey::sign_pkcs1v15).
    pub fn sign_pkcs1v15_prehash<D: Pkcs1Hash>(&self, digest: &[u8]) -> Result<Vec<u8>, Error> {
        let em = pkcs1v15::encode_signature::<D>(self.public.size(), digest)?;
        Ok(self.private_op(&em)?.to_vec())
    }

    /// Signs `message`, hashed with `D`, which is also the hash of MGF1, with
    /// RSASSA-PSS (RFC 8017, section 8.1.1): the signature is `size()` bytes.
    ///
    /// The signature is randomized: it carries a salt, `salt` bytes from `rng`,
    /// which has to be a source of cryptographically secure random bytes. The same
    /// message signed twice gives two different signatures, both valid.
    /// [`SaltLength::EqualsHash`] is the usual choice.
    ///
    /// # Errors
    ///
    /// Whatever `rng` fails with, and
    /// [`InvalidInput`](io::ErrorKind::InvalidInput) (carrying
    /// [`Error::MessageTooLong`]) if the salt does not fit in the key with the hash.
    pub fn sign_pss<D: Digest, R: io::Read + ?Sized>(
        &self,
        rng: &mut R,
        message: &[u8],
        salt: SaltLength,
    ) -> io::Result<Vec<u8>> {
        self.sign_pss_prehash::<D, R>(rng, D::digest(message).as_ref(), salt)
    }

    /// As [`sign_pss`](PrivateKey::sign_pss), for the digest of the message, which
    /// has to be as long as the output of `D`.
    ///
    /// # Errors
    ///
    /// [`InvalidInput`](io::ErrorKind::InvalidInput) (carrying
    /// [`Error::InvalidDigest`]) if it is not, and the other errors of
    /// [`sign_pss`](PrivateKey::sign_pss).
    pub fn sign_pss_prehash<D: Digest, R: io::Read + ?Sized>(
        &self,
        rng: &mut R,
        digest: &[u8],
        salt: SaltLength,
    ) -> io::Result<Vec<u8>> {
        if digest.len() != D::OUTPUT_LEN {
            return Err(invalid_input(Error::InvalidDigest));
        }
        let em_bits = self.public.bits() - 1;
        let salt_len = match salt {
            SaltLength::Auto => pss::max_salt_len::<D>(em_bits)
                .ok_or_else(|| invalid_input(Error::MessageTooLong))?,
            SaltLength::EqualsHash => D::OUTPUT_LEN,
            SaltLength::Len(len) => len,
        };
        // Checked before the random source is read, so that the salt of an absurd
        // length is not allocated.
        if pss::max_salt_len::<D>(em_bits).is_none_or(|max| salt_len > max) {
            return Err(invalid_input(Error::MessageTooLong));
        }
        let mut salt = vec![0; salt_len];
        rng.read_exact(&mut salt)?;
        let em = pss::encode::<D>(digest, em_bits, &salt).map_err(invalid_input)?;

        // The encoded message is a byte shorter than the block when the modulus's
        // size is a multiple of 8 plus 1 (RFC 8017, section 8.1.1, note 2).
        let mut block = Wiped::zero(self.public.size());
        let start = block.len() - em.len();
        block[start..].copy_from_slice(&em);
        Ok(self.private_op(&block).map_err(invalid_input)?.to_vec())
    }

    /// The private operation: `c^d mod n` for a big-endian number `c` of
    /// `size()` bytes below the modulus, which is RSADP and RSASP1 (RFC 8017,
    /// sections 5.1.2 and 5.2.1), by the Chinese remainder theorem:
    ///
    /// ```text
    /// m1 = c^dP mod p
    /// m2 = c^dQ mod q
    /// h = qInv * (m1 - m2) mod p
    /// m = m2 + q * h
    /// ```
    ///
    /// Two exponentiations of half the size, each about a third of the work of
    /// the one with `d`. The result is then raised to the public exponent and
    /// compared with `c`: if the computation went wrong (a bit flipped by a
    /// fault, a glitch, an error of the CPU), `m` is a number that is right
    /// modulo one of the primes and wrong modulo the other, and releasing it would
    /// give the factorization away (Boneh, DeMillo and Lipton's attack on the CRT).
    ///
    /// Everything but the checks of the length and of the range of `c`, and the
    /// final comparison, which only say whether there is an answer, is
    /// constant-time.
    ///
    /// # Errors
    ///
    /// [`Error::Decryption`] if `c` is not `size()` bytes or is not below `n`, and
    /// [`Error::InvalidPrivateKey`] if the check fails.
    fn private_op(&self, c: &[u8]) -> Result<Wiped, Error> {
        let k = self.public.size();
        if c.len() != k {
            return Err(Error::Decryption);
        }
        let c = Limbs::from_be_bytes(c);
        let n = self.public.n.limbs();
        if lt(&c, n) != 1 {
            return Err(Error::Decryption);
        }

        let c_p = self.p.to_mont(&c);
        let m1 = self.p.pow(&c_p, &self.dp);
        let c_q = self.q.to_mont(&c);
        let m2 = self.q.to_plain(&self.q.pow(&c_q, &self.dq));
        let m2_in_p = self.p.to_mont(&m2);
        let h = self
            .p
            .to_plain(&self.p.mul(&self.p.sub(&m1, &m2_in_p), &self.q_inv));

        // m = m2 + q * h < p * q: the sum has room for the carry, and the top
        // limbs beyond those of n are zero.
        let (m, carry) = add(&mul(&h, self.q.limbs()), &m2);
        assert_eq!(carry, 0);
        let m = Limbs::from(&m[..self.public.n.len()]);

        if eq(&self.public.public_op(&m), &c) != 1 {
            return Err(Error::InvalidPrivateKey);
        }
        Ok(Wiped::new(m.to_be_bytes(k)))
    }
}

/// `d mod (p - 1)`, if multiplying it by `e` gives 1 modulo `p - 1`.
fn crt_exponent(d: &Limbs, p: &Modulus, e: u32) -> Option<Limbs> {
    let p_minus_one = sub(p.limbs(), &[1]).0;
    let exponent = rem(d, &p_minus_one);
    let product = mul(&exponent, &[u64::from(e)]);
    (is_one(&rem(&product, &p_minus_one)) == 1).then_some(exponent)
}

impl PartialEq for PrivateKey {
    /// Whether the keys have the same modulus, exponent, private exponent and
    /// first prime (so the second too, and in the same order); the comparison of
    /// the secret parts looks at all of their limbs, whatever they hold.
    fn eq(&self, other: &Self) -> bool {
        self.public == other.public
            && eq(&self.d, &other.d) & eq(self.p.limbs(), other.p.limbs()) == 1
    }
}

impl Eq for PrivateKey {}

impl fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateKey")
            .field("bits", &self.public.bits())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::md5::Md5;
    use crate::rsa::bigmod::PRODUCTS;
    use crate::rsa::testutil::{Drbg, Record, Script, hex, private_key, records, unhex};
    use crate::sha1::Sha1;
    use crate::sha2::{Sha224, Sha256, Sha384, Sha512, Sha512_224, Sha512_256};

    const INTEROP: &str = include_str!("testdata/interop.txt");
    const EDGE: &str = include_str!("testdata/edge.txt");

    /// A source of random bytes for a test: the HMAC_DRBG of the generation
    /// vectors, seeded with the name of the test.
    fn rng(name: &str) -> Drbg {
        Drbg::new(name.as_bytes(), b"")
    }

    fn interop_record(name: &str) -> Record<'static> {
        records(INTEROP)
            .into_iter()
            .find(|r| r.kind == "key" && r.text("name") == name)
            .unwrap()
    }

    /// One of the keys that OpenSSL generated, built with the module's own checks.
    fn interop_key(name: &str) -> PrivateKey {
        private_key(&interop_record(name)).unwrap()
    }

    fn edge_record(kind: &str) -> Record<'static> {
        records(EDGE).into_iter().find(|r| r.kind == kind).unwrap()
    }

    /// The key of a record through the public constructor.
    fn from_components(r: &Record<'_>) -> Result<PrivateKey, Error> {
        PrivateKey::from_components(
            &r.bytes("n"),
            r.exponent() as u32,
            &r.bytes("d"),
            &r.bytes("p"),
            &r.bytes("q"),
        )
    }

    fn padded(hex_number: &str, len: usize) -> Vec<u8> {
        let bytes = unhex(hex_number);
        let mut out = vec![0; len - bytes.len()];
        out.extend_from_slice(&bytes);
        out
    }

    #[test]
    fn a_key_gives_back_its_components() {
        for name in [
            "rsa1024", "rsa1025", "rsa1031", "rsa2047", "rsa2048", "rsa3072", "rsa4096",
        ] {
            let r = interop_record(name);
            let key = interop_key(name);
            let public = key.public_key();
            let size = r.int("bits").div_ceil(8);
            assert_eq!(public.bits(), r.int("bits"), "{name}");
            assert_eq!(public.size(), size, "{name}");
            assert_eq!(public.exponent(), 65537);
            assert_eq!(public.modulus(), padded(r.text("n"), size), "{name}");
            assert_eq!(key.d(), padded(r.text("d"), size), "{name}");
            // The primes and the numbers of the CRT take the bytes that they need,
            // and the last three are computed here: OpenSSL's agree.
            let p_len = unhex(r.text("p")).len();
            let q_len = unhex(r.text("q")).len();
            assert_eq!(key.p(), unhex(r.text("p")), "{name}");
            assert_eq!(key.q(), unhex(r.text("q")), "{name}");
            assert_eq!(key.dp(), padded(r.text("dp"), p_len), "{name}");
            assert_eq!(key.dq(), padded(r.text("dq"), q_len), "{name}");
            assert_eq!(key.q_inv(), padded(r.text("q_inv"), p_len), "{name}");
        }
    }

    #[test]
    fn public_keys_are_checked() {
        let n = interop_key("rsa2048").public_key().modulus();
        let public = PublicKey::new(&n, 65537).unwrap();
        assert_eq!(
            (public.bits(), public.size(), public.exponent()),
            (2048, 256, 65537)
        );

        // Leading zero bytes (as in the DER encoding of the integer) do not count.
        let mut padded = vec![0, 0, 0];
        padded.extend_from_slice(&n);
        assert_eq!(PublicKey::new(&padded, 65537).unwrap(), public);

        // The exponents: odd, from 3 to 2^31 - 1.
        for e in [3, 5, 17, 65537, (1 << 31) - 1] {
            assert!(PublicKey::new(&n, e).is_ok(), "{e}");
        }
        for e in [0, 1, 2, 4, 65536, 1 << 31, (1 << 31) + 1, u32::MAX] {
            assert_eq!(PublicKey::new(&n, e), Err(Error::InvalidPublicKey), "{e}");
        }

        // An even modulus is not a modulus.
        let mut even = n.clone();
        *even.last_mut().unwrap() &= !1;
        assert_eq!(PublicKey::new(&even, 65537), Err(Error::InvalidPublicKey));

        // The sizes: 1,024 to 16,384 bits.
        let mut bits1023 = vec![0x7f];
        bits1023.extend_from_slice(&[0xff; 127]);
        assert_eq!(
            PublicKey::new(&bits1023, 65537),
            Err(Error::UnsupportedKeySize)
        );
        let mut bits1024 = vec![0x80];
        bits1024.extend_from_slice(&[0xff; 127]);
        assert!(PublicKey::new(&bits1024, 65537).is_ok());
        let mut bits16384 = vec![0x80];
        bits16384.extend_from_slice(&[0xff; 2047]);
        assert_eq!(PublicKey::new(&bits16384, 65537).unwrap().bits(), 16384);
        let mut bits16385 = vec![1];
        bits16385.extend_from_slice(&[0xff; 2048]);
        assert_eq!(
            PublicKey::new(&bits16385, 65537),
            Err(Error::UnsupportedKeySize)
        );
        assert_eq!(PublicKey::new(&[], 65537), Err(Error::UnsupportedKeySize));
        assert_eq!(PublicKey::new(&[1], 65537), Err(Error::UnsupportedKeySize));
    }

    /// Each rule of the validation of a private key, tested with a key that is right
    /// in every other way, so that the rule is the one that refuses it.
    #[test]
    fn private_keys_are_checked() {
        // The keys that are right in all but one way, made by a script.
        for kind in [
            "close-primes",
            "small-d",
            "composite-p",
            "wrong-n",
            "gap-412",
            "d-512",
        ] {
            let r = edge_record(kind);
            assert_eq!(
                from_components(&r).err(),
                Some(Error::InvalidPrivateKey),
                "{kind}"
            );
        }
        // ...and the ones that are right: two at the edge of each of the rules on the
        // size of |p - q| (one bit more than 2^(512 - 100) is enough) and of d (one
        // bit more than 2^512 is), and one whose primes differ much in size.
        for kind in ["retries-key", "gap-413", "d-513", "unbalanced"] {
            assert!(from_components(&edge_record(kind)).is_ok(), "{kind}");
        }

        let r = interop_record("rsa2048");
        let (n, d, p, q) = (r.bytes("n"), r.bytes("d"), r.bytes("p"), r.bytes("q"));
        let build =
            |n: &[u8], d: &[u8], p: &[u8], q: &[u8]| PrivateKey::from_components(n, 65537, d, p, q);
        assert!(build(&n, &d, &p, &q).is_ok());
        let bad = Some(Error::InvalidPrivateKey);

        // Swapped primes make the same key.
        let swapped = build(&n, &d, &q, &p).unwrap();
        let key = build(&n, &d, &p, &q).unwrap();
        assert_eq!(swapped.d(), key.d());
        let ct = key
            .public_key()
            .encrypt_oaep::<Sha256, _>(&mut rng("swapped"), b"hi", b"")
            .unwrap();
        assert_eq!(swapped.decrypt_oaep::<Sha256>(&ct, b""), Ok(b"hi".to_vec()));

        // Leading zero bytes on any of the numbers do not matter.
        let zeros = |bytes: &[u8]| [&[0u8, 0][..], bytes].concat();
        assert!(build(&zeros(&n), &zeros(&d), &zeros(&p), &zeros(&q)).is_ok());

        // Primes that do not multiply to the modulus.
        assert_eq!(build(&n, &d, &p, &p).err(), bad);
        let mut other_q = q.clone();
        *other_q.last_mut().unwrap() ^= 2;
        assert_eq!(build(&n, &d, &p, &other_q).err(), bad);
        // An even prime, zero, one.
        assert_eq!(build(&n, &d, &[], &q).err(), bad);
        assert_eq!(build(&n, &d, &[1], &q).err(), bad);
        assert_eq!(build(&n, &d, &[2], &q).err(), bad);
        // A private exponent that is not the inverse, one that is not below n, zero.
        let mut wrong_d = d.clone();
        *wrong_d.last_mut().unwrap() ^= 2;
        assert_eq!(build(&n, &wrong_d, &p, &q).err(), bad);
        assert_eq!(build(&n, &n, &p, &q).err(), bad);
        assert_eq!(build(&n, &[], &p, &q).err(), bad);
        // d plus the Carmichael function is another exponent for the same key, but
        // one that is not below the modulus gets refused only if it is not below n;
        // d + (p - 1) * (q - 1) is above it.
        // A private exponent that is right but not below the modulus: d plus
        // (p - 1)(q - 1) has the same remainder modulo p - 1 and modulo q - 1.
        let (p_limbs, q_limbs, d_limbs) = (
            Limbs::from_be_bytes(&p),
            Limbs::from_be_bytes(&q),
            Limbs::from_be_bytes(&d),
        );
        let p_minus_one = sub(&p_limbs, &[1]).0;
        let q_minus_one = sub(&q_limbs, &[1]).0;
        let too_large = add(&d_limbs, &mul(&p_minus_one, &q_minus_one)).0.trimmed();
        assert_eq!(
            build(&n, &too_large.to_be_bytes(too_large.len() * 8), &p, &q).err(),
            bad
        );
        // A private exponent that is right modulo q - 1 and wrong modulo p - 1, and
        // the other way round: each of the two checks refuses one of them.
        for step in [&q_minus_one, &p_minus_one] {
            let wrong = add(&d_limbs, step).0.trimmed();
            assert_eq!(
                build(&n, &wrong.to_be_bytes(wrong.len() * 8), &p, &q).err(),
                bad
            );
        }
        // A public exponent that does not go with the private one.
        assert_eq!(PrivateKey::from_components(&n, 3, &d, &p, &q).err(), bad);
        // The public key's errors come first.
        assert_eq!(
            PrivateKey::from_components(&n, 4, &d, &p, &q).err(),
            Some(Error::InvalidPublicKey)
        );
        assert_eq!(
            PrivateKey::from_components(&n[1..], 65537, &d, &p, &q).err(),
            Some(Error::InvalidPrivateKey)
        );
    }

    #[test]
    fn every_scheme_round_trips() {
        for name in ["rsa1024", "rsa1025", "rsa1031", "rsa2047", "rsa2048"] {
            let key = interop_key(name);
            let public = key.public_key();
            let k = public.size();
            let mut rng = rng(name);

            // OAEP, with the longest message and none.
            let longest = k - 2 * 32 - 2;
            for message in [&b""[..], b"hello", &vec![0xa5; longest][..]] {
                let ct = public
                    .encrypt_oaep::<Sha256, _>(&mut rng, message, b"label")
                    .unwrap();
                assert_eq!(ct.len(), k, "{name}");
                assert_eq!(
                    key.decrypt_oaep::<Sha256>(&ct, b"label"),
                    Ok(message.to_vec()),
                    "{name}"
                );
                assert_eq!(
                    key.decrypt_oaep::<Sha256>(&ct, b"other"),
                    Err(Error::Decryption),
                    "{name}"
                );
                assert_eq!(
                    key.decrypt_oaep::<Sha1>(&ct, b"label"),
                    Err(Error::Decryption),
                    "{name}"
                );
            }
            // Two encryptions of a message differ, and the MGF1 hash may differ from
            // the label's.
            let first = public
                .encrypt_oaep_mgf1::<Sha256, Sha1, _>(&mut rng, b"x", b"")
                .unwrap();
            let second = public
                .encrypt_oaep_mgf1::<Sha256, Sha1, _>(&mut rng, b"x", b"")
                .unwrap();
            assert_ne!(first, second);
            assert_eq!(
                key.decrypt_oaep_mgf1::<Sha256, Sha1>(&first, b""),
                Ok(b"x".to_vec())
            );
            assert_eq!(
                key.decrypt_oaep::<Sha256>(&first, b""),
                Err(Error::Decryption)
            );

            // PKCS #1 v1.5 encryption, with the longest message and none.
            for message in [&b""[..], b"hello", &vec![0x5a; k - 11][..]] {
                let ct = public.encrypt_pkcs1v15(&mut rng, message).unwrap();
                assert_eq!(ct.len(), k);
                assert_eq!(key.decrypt_pkcs1v15(&ct), Ok(message.to_vec()), "{name}");
            }

            // Signatures: v1.5 is deterministic, PSS is not.
            let signature = key.sign_pkcs1v15::<Sha256>(b"message").unwrap();
            assert_eq!(signature.len(), k);
            assert_eq!(key.sign_pkcs1v15::<Sha256>(b"message").unwrap(), signature);
            assert_eq!(
                public.verify_pkcs1v15::<Sha256>(b"message", &signature),
                Ok(())
            );
            assert_eq!(
                public.verify_pkcs1v15::<Sha256>(b"messagf", &signature),
                Err(Error::VerificationFailed)
            );
            assert_eq!(
                public.verify_pkcs1v15::<Sha384>(b"message", &signature),
                Err(Error::VerificationFailed)
            );
            for salt in [
                SaltLength::EqualsHash,
                SaltLength::Auto,
                SaltLength::Len(0),
                SaltLength::Len(7),
            ] {
                let signature = key
                    .sign_pss::<Sha256, _>(&mut rng, b"message", salt)
                    .unwrap();
                assert_eq!(signature.len(), k);
                assert_eq!(
                    public.verify_pss::<Sha256>(b"message", &signature, salt),
                    Ok(()),
                    "{name} {salt:?}"
                );
                assert_eq!(
                    public.verify_pss::<Sha256>(b"message", &signature, SaltLength::Auto),
                    Ok(())
                );
                assert_eq!(
                    public.verify_pss::<Sha256>(b"messagf", &signature, salt),
                    Err(Error::VerificationFailed)
                );
                assert_eq!(
                    public.verify_pss::<Sha384>(b"message", &signature, salt),
                    Err(Error::VerificationFailed)
                );
            }
            let a = key
                .sign_pss::<Sha256, _>(&mut rng, b"message", SaltLength::EqualsHash)
                .unwrap();
            let b = key
                .sign_pss::<Sha256, _>(&mut rng, b"message", SaltLength::EqualsHash)
                .unwrap();
            assert_ne!(a, b);
        }
    }

    #[test]
    fn every_hash_signs() {
        let key = interop_key("rsa2048");
        let public = key.public_key();
        let mut rng = rng("hashes");
        macro_rules! check {
            ($($hash:ty),*) => {$(
                let signature = key.sign_pkcs1v15::<$hash>(b"abc").unwrap();
                assert_eq!(public.verify_pkcs1v15::<$hash>(b"abc", &signature), Ok(()), stringify!($hash));
                let digest = <$hash as crate::Digest>::digest(b"abc");
                assert_eq!(key.sign_pkcs1v15_prehash::<$hash>(digest.as_ref()).unwrap(), signature);
                assert_eq!(public.verify_pkcs1v15_prehash::<$hash>(digest.as_ref(), &signature), Ok(()));
                let signature = key.sign_pss::<$hash, _>(&mut rng, b"abc", SaltLength::EqualsHash).unwrap();
                assert_eq!(public.verify_pss::<$hash>(b"abc", &signature, SaltLength::EqualsHash), Ok(()));
                assert_eq!(key.sign_pss_prehash::<$hash, _>(&mut rng, digest.as_ref(), SaltLength::Auto).map(|s| s.len()).unwrap(), 256);
            )*};
        }
        check!(
            Md5, Sha1, Sha224, Sha256, Sha384, Sha512, Sha512_224, Sha512_256
        );
    }

    #[test]
    fn messages_that_do_not_fit() {
        let key = interop_key("rsa1024");
        let public = key.public_key();
        let mut rng = rng("sizes");
        let too_long = |result: io::Result<Vec<u8>>| {
            let error = result.unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
            assert_eq!(
                error.get_ref().unwrap().to_string(),
                Error::MessageTooLong.to_string()
            );
        };

        // 128 bytes: 62 for OAEP with SHA-256, 94 with SHA-1, 128 - 66 = 62; 117 for v1.5.
        assert!(
            public
                .encrypt_oaep::<Sha256, _>(&mut rng, &[0; 62], b"")
                .is_ok()
        );
        too_long(public.encrypt_oaep::<Sha256, _>(&mut rng, &[0; 63], b""));
        assert!(
            public
                .encrypt_oaep::<Sha1, _>(&mut rng, &[0; 86], b"")
                .is_ok()
        );
        too_long(public.encrypt_oaep::<Sha1, _>(&mut rng, &[0; 87], b""));
        // SHA-512 needs 130 bytes for its two digests and the markers: no message at all.
        too_long(public.encrypt_oaep::<Sha512, _>(&mut rng, b"", b""));
        assert_eq!(
            key.decrypt_oaep::<Sha512>(&[0; 128], b""),
            Err(Error::Decryption)
        );
        assert!(public.encrypt_pkcs1v15(&mut rng, &[0; 117]).is_ok());
        too_long(public.encrypt_pkcs1v15(&mut rng, &[0; 118]));

        // The salt of a PSS signature: 128 - 32 - 2 = 94 bytes at most, for emBits 1,023.
        let sign = |salt, rng: &mut Drbg| key.sign_pss::<Sha256, _>(rng, b"m", salt);
        assert!(sign(SaltLength::Len(94), &mut rng).is_ok());
        too_long(sign(SaltLength::Len(95), &mut rng));
        too_long(sign(SaltLength::Len(usize::MAX), &mut rng));
        let auto = sign(SaltLength::Auto, &mut rng).unwrap();
        assert_eq!(
            public.verify_pss::<Sha256>(b"m", &auto, SaltLength::Len(94)),
            Ok(())
        );
        assert_eq!(
            public.verify_pss::<Sha256>(b"m", &auto, SaltLength::EqualsHash),
            Err(Error::VerificationFailed)
        );

        // The DigestInfo of SHA-512 and 11 bytes of overhead fit in 128 bytes.
        assert!(key.sign_pkcs1v15::<Sha512>(b"m").is_ok());
        // A digest of the wrong length is not a digest of the hash.
        assert_eq!(
            key.sign_pkcs1v15_prehash::<Sha256>(&[0; 31]),
            Err(Error::InvalidDigest)
        );
        assert_eq!(
            public.verify_pkcs1v15_prehash::<Sha256>(&[0; 33], &[0; 128]),
            Err(Error::InvalidDigest)
        );
        assert_eq!(
            public.verify_pss_prehash::<Sha256>(&[], &[0; 128], SaltLength::Auto),
            Err(Error::InvalidDigest)
        );
        let error = key
            .sign_pss_prehash::<Sha256, _>(&mut rng, &[0; 20], SaltLength::Auto)
            .unwrap_err();
        assert_eq!(
            error.get_ref().unwrap().to_string(),
            Error::InvalidDigest.to_string()
        );

        // What cannot be signed is refused before the random source is asked for the
        // salt: a source with nothing in it would fail with `UnexpectedEof` otherwise.
        let mut nothing = Script(Vec::new());
        for result in [
            key.sign_pss::<Sha256, _>(&mut nothing, b"m", SaltLength::Len(95)),
            key.sign_pss_prehash::<Sha256, _>(&mut nothing, &[0; 31], SaltLength::EqualsHash),
            key.sign_pss::<Sha256, _>(&mut nothing, b"m", SaltLength::Len(usize::MAX)),
        ] {
            assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidInput);
        }
    }

    #[test]
    fn a_failing_random_source_is_reported() {
        let key = interop_key("rsa1024");
        let public = key.public_key();
        // Too few bytes for the seed, the padding or the salt.
        let short = |n| Script(vec![7; n]);
        assert_eq!(
            public
                .encrypt_oaep::<Sha256, _>(&mut short(31), b"", b"")
                .unwrap_err()
                .kind(),
            io::ErrorKind::UnexpectedEof
        );
        assert_eq!(
            public
                .encrypt_pkcs1v15(&mut short(10), b"hello")
                .unwrap_err()
                .kind(),
            io::ErrorKind::UnexpectedEof
        );
        assert_eq!(
            key.sign_pss::<Sha256, _>(&mut short(31), b"", SaltLength::EqualsHash)
                .unwrap_err()
                .kind(),
            io::ErrorKind::UnexpectedEof
        );
        // A source that never fills a buffer (here, one that has nothing).
        assert!(
            key.sign_pss::<Sha256, _>(&mut short(0), b"", SaltLength::Len(0))
                .is_ok()
        );
    }

    #[test]
    fn bad_ciphertexts_are_all_the_same_error() {
        let key = interop_key("rsa1024");
        let public = key.public_key();
        let k = public.size();
        let n = public.modulus();
        let ct = public
            .encrypt_oaep::<Sha256, _>(&mut rng("bad"), b"hi", b"")
            .unwrap();

        let mut above_n = n.clone();
        above_n[k - 1] = above_n[k - 1].wrapping_add(2);
        let mut cases: Vec<Vec<u8>> = vec![
            ct[1..].to_vec(),           // one byte short
            [&[0u8][..], &ct].concat(), // one byte long
            Vec::new(),                 // nothing
            vec![0; k],                 // zero
            n.clone(),                  // the modulus itself
            above_n,                    // above it
            vec![0xff; k],              // the largest
        ];
        let mut flipped = ct.clone();
        flipped[k / 2] ^= 0x10;
        cases.push(flipped);
        for case in &cases {
            // The private operation itself, which is where length and range are checked
            // (a flipped bit is a good number and passes it).
            if case.len() != k || case[..] >= n[..] {
                assert_eq!(key.private_op(case).err(), Some(Error::Decryption));
            }
            assert_eq!(
                key.decrypt_oaep::<Sha256>(case, b""),
                Err(Error::Decryption)
            );
            assert_eq!(key.decrypt_pkcs1v15(case), Err(Error::Decryption));
            let mut session = [3u8; 16];
            let result = key.decrypt_pkcs1v15_session_key(case, &mut session);
            // A key that is left alone, and an error for what is not a ciphertext;
            // a ciphertext with a bad padding is not an error.
            assert_eq!(session, [3; 16]);
            if case.len() != k || case[..] >= n[..] {
                assert_eq!(result, Err(Error::Decryption));
            } else {
                assert_eq!(result, Ok(()));
            }
        }
    }

    #[test]
    fn bad_signatures_are_all_the_same_error() {
        let key = interop_key("rsa1024");
        let public = key.public_key();
        let k = public.size();
        let n = Limbs::from_be_bytes(&public.modulus());
        let v15 = key.sign_pkcs1v15::<Sha256>(b"m").unwrap();
        let pss = key
            .sign_pss::<Sha256, _>(&mut rng("sigs"), b"m", SaltLength::EqualsHash)
            .unwrap();

        for (signature, check) in [(&v15, 0), (&pss, 1)] {
            let verify = |s: &[u8]| match check {
                0 => public.verify_pkcs1v15::<Sha256>(b"m", s),
                _ => public.verify_pss::<Sha256>(b"m", s, SaltLength::EqualsHash),
            };
            assert_eq!(verify(signature), Ok(()));
            // A signature that is the right number plus the modulus verifies as the
            // same number under the arithmetic, and must not: it is not `k` bytes
            // of a number below the modulus.
            let bigger = add(&Limbs::from_be_bytes(signature), &n).0;
            assert_eq!(
                verify(&bigger.to_be_bytes(k)),
                Err(Error::VerificationFailed)
            );
            assert_eq!(
                verify(&bigger.to_be_bytes(k + 1)),
                Err(Error::VerificationFailed)
            );
            assert_eq!(verify(&signature[1..]), Err(Error::VerificationFailed));
            assert_eq!(
                verify(&[&[0u8][..], signature].concat()),
                Err(Error::VerificationFailed)
            );
            assert_eq!(verify(&[]), Err(Error::VerificationFailed));
            assert_eq!(verify(&vec![0; k]), Err(Error::VerificationFailed));
            assert_eq!(verify(&vec![0xff; k]), Err(Error::VerificationFailed));
            assert_eq!(verify(&public.modulus()), Err(Error::VerificationFailed));
            for byte in (0..k).step_by(7) {
                let mut changed = signature.clone();
                changed[byte] ^= 1;
                assert_eq!(
                    verify(&changed),
                    Err(Error::VerificationFailed),
                    "byte {byte}"
                );
            }
        }
    }

    /// A signature is `k` bytes: one that leaves out the zero byte it starts with is
    /// the same number, and is refused all the same (RFC 8017, sections 8.1.2 and
    /// 8.2.2). "m76" is a message whose PKCS #1 v1.5 signature by this key starts
    /// with a zero byte (found with OpenSSL, which makes the same signature).
    #[test]
    fn a_signature_without_its_leading_zero_byte_is_refused() {
        let key = interop_key("rsa1024");
        let public = key.public_key();
        let signature = key.sign_pkcs1v15::<Sha256>(b"m76").unwrap();
        assert_eq!(signature[0], 0);
        assert_eq!(public.verify_pkcs1v15::<Sha256>(b"m76", &signature), Ok(()));
        assert_eq!(
            public.verify_pkcs1v15::<Sha256>(b"m76", &signature[1..]),
            Err(Error::VerificationFailed)
        );
    }

    /// With a key of 1,025 bits the encoded message of PSS is 128 bytes and the
    /// modulus 129: the first byte of the signature's number must be zero. A signature
    /// of the same encoded message with a 1 in front of it is a number below the
    /// modulus, and is refused.
    #[test]
    fn a_pss_signature_of_a_block_one_byte_too_long_is_refused() {
        let key = interop_key("rsa1025");
        let public = key.public_key();
        let digest = Sha256::digest(b"m");
        let n = Limbs::from_be_bytes(&public.modulus());
        let mut tried = 0;
        // About one block in four is below the modulus.
        for salt in 0..=255u8 {
            let em = pss::encode::<Sha256>(digest.as_ref(), 1024, &[salt; 32]).unwrap();
            let longer = [&[1u8][..], &em].concat();
            if lt(&Limbs::from_be_bytes(&longer), &n) != 1 {
                continue;
            }
            tried += 1;
            let verify = |signature: &[u8]| {
                public.verify_pss_prehash::<Sha256>(
                    digest.as_ref(),
                    signature,
                    SaltLength::EqualsHash,
                )
            };
            let good = key.private_op(&[&[0u8][..], &em].concat()).unwrap();
            assert_eq!(verify(&good), Ok(()));
            let bad = key.private_op(&longer).unwrap();
            assert_eq!(verify(&bad), Err(Error::VerificationFailed));
            if tried == 3 {
                break;
            }
        }
        assert_eq!(tried, 3);
    }

    /// A key whose primes are of 400 and 624 bits: the Chinese remainder theorem has
    /// to reduce a number of the size of the larger modulo the smaller, and the other
    /// way round, whichever of the two is first.
    #[test]
    fn primes_of_very_different_sizes_work() {
        let r = edge_record("unbalanced");
        let key = from_components(&r).unwrap();
        let swapped = PrivateKey::from_components(
            &r.bytes("n"),
            65537,
            &r.bytes("d"),
            &r.bytes("q"),
            &r.bytes("p"),
        )
        .unwrap();
        assert_eq!((key.p().len(), key.q().len()), (50, 78));
        assert_eq!((swapped.p().len(), swapped.q().len()), (78, 50));
        let mut rng = rng("unbalanced");
        for key in [&key, &swapped] {
            let public = key.public_key();
            let ct = public
                .encrypt_oaep::<Sha256, _>(&mut rng, b"hello", b"")
                .unwrap();
            assert_eq!(key.decrypt_oaep::<Sha256>(&ct, b""), Ok(b"hello".to_vec()));
            let signature = key.sign_pkcs1v15::<Sha256>(b"message").unwrap();
            assert_eq!(
                public.verify_pkcs1v15::<Sha256>(b"message", &signature),
                Ok(())
            );
        }
        // The same signature from both orders of the primes.
        assert_eq!(
            key.sign_pkcs1v15::<Sha256>(b"message"),
            swapped.sign_pkcs1v15::<Sha256>(b"message")
        );
    }

    #[test]
    fn the_session_key_function_keeps_the_key_unless_the_message_is_its_length() {
        let key = interop_key("rsa1024");
        let public = key.public_key();
        let mut rng = rng("session");
        let ct = public
            .encrypt_pkcs1v15(&mut rng, b"0123456789abcdef")
            .unwrap();

        // A message of the length of the key replaces it.
        let mut session = [0u8; 16];
        assert_eq!(key.decrypt_pkcs1v15_session_key(&ct, &mut session), Ok(()));
        assert_eq!(&session, b"0123456789abcdef");
        // A message of another length does not, whether longer or shorter than the key.
        for len in [8, 15, 17, 32] {
            let mut session = vec![9u8; len];
            assert_eq!(key.decrypt_pkcs1v15_session_key(&ct, &mut session), Ok(()));
            assert_eq!(session, vec![9; len]);
        }
        // An empty key: nothing to copy, the message is not empty, nothing happens.
        assert_eq!(key.decrypt_pkcs1v15_session_key(&ct, &mut []), Ok(()));
        let empty = public.encrypt_pkcs1v15(&mut rng, b"").unwrap();
        assert_eq!(key.decrypt_pkcs1v15_session_key(&empty, &mut []), Ok(()));
        // A key too long for the modulus to hold is refused, before anything is done.
        assert_eq!(
            key.decrypt_pkcs1v15_session_key(&ct, &mut [0; 118]),
            Err(Error::Decryption)
        );
        assert_eq!(key.decrypt_pkcs1v15_session_key(&ct, &mut [0; 117]), Ok(()));
    }

    /// If any number of the private operation is wrong, the check at its end fails
    /// and nothing is released: a signature from a faulty computation would give
    /// away a prime.
    #[test]
    fn a_faulty_computation_releases_nothing() {
        let good = interop_key("rsa1024");
        let ct = good
            .public_key()
            .encrypt_oaep::<Sha256, _>(&mut rng("fault"), b"hi", b"")
            .unwrap();
        assert!(good.decrypt_oaep::<Sha256>(&ct, b"").is_ok());
        assert!(good.sign_pkcs1v15::<Sha256>(b"m").is_ok());

        type Fault = fn(&mut PrivateKey);
        let faults: [(&str, Fault); 4] = [
            ("dp", |k| k.dp[0] ^= 1 << 17),
            ("dq", |k| k.dq[3] ^= 1),
            ("q_inv", |k| k.q_inv[2] ^= 1 << 40),
            ("a prime", |k| {
                // A prime that changed in one bit, with the constants of its
                // Montgomery arithmetic computed afresh: still odd, no longer a prime.
                let mut limbs = Limbs::from(k.p.limbs());
                limbs[5] ^= 1 << 9;
                k.p = Modulus::new(limbs).unwrap();
            }),
        ];
        for (name, fault) in faults {
            let mut key = good.clone();
            fault(&mut key);
            let mut rng = rng("fault");
            assert_eq!(
                key.decrypt_oaep::<Sha256>(&ct, b""),
                Err(Error::Decryption),
                "{name}"
            );
            assert_eq!(key.decrypt_pkcs1v15(&ct), Err(Error::Decryption), "{name}");
            assert_eq!(
                key.sign_pkcs1v15::<Sha256>(b"m"),
                Err(Error::InvalidPrivateKey),
                "{name}"
            );
            let error = key
                .sign_pss::<Sha256, _>(&mut rng, b"m", SaltLength::EqualsHash)
                .unwrap_err();
            assert_eq!(
                error.get_ref().unwrap().to_string(),
                Error::InvalidPrivateKey.to_string(),
                "{name}"
            );
        }
    }

    /// The private operation makes the same number of products whatever the
    /// ciphertext: the exponent's bits are never skipped. (A count of products is
    /// not a measurement of time; it is what a branch on a secret would change.)
    #[test]
    fn the_private_operation_does_the_same_work_for_any_input() {
        let key = interop_key("rsa2048");
        let public = key.public_key();
        let k = public.size();
        let count = |input: &[u8]| {
            PRODUCTS.with(|c| c.set(0));
            let result = key.private_op(input);
            (PRODUCTS.with(|c| c.get()), result.is_ok())
        };

        let reference = count(&[&[0u8; 255][..], &[2]].concat());
        assert!(reference.1);
        let mut inputs = vec![
            vec![0; k],
            [&[0u8; 255][..], &[1]].concat(),
            public.encrypt_pkcs1v15(&mut rng("work"), b"x").unwrap(),
            public
                .encrypt_oaep::<Sha256, _>(&mut rng("work"), b"x", b"")
                .unwrap(),
        ];
        let mut below_n = public.modulus();
        below_n[k - 1] -= 1;
        inputs.push(below_n);
        for input in inputs {
            assert_eq!(count(&input), reference, "{}", hex(&input[..4]));
        }

        // The exponentiation by itself: zero, one and all ones in the exponent.
        let modulus = Modulus::new(Limbs::from_be_bytes(&key.p())).unwrap();
        let base = modulus.to_mont(&[0xdead_beef_u64, 5]);
        let products = |exponent: &[u64]| {
            PRODUCTS.with(|c| c.set(0));
            modulus.pow(&base, exponent);
            PRODUCTS.with(|c| c.get())
        };
        let n = modulus.len();
        let expected = 14 + 64 * n + 16 * n;
        assert_eq!(products(&vec![0; n]), expected);
        assert_eq!(products(&vec![1; n]), expected);
        assert_eq!(products(&vec![u64::MAX; n]), expected);
        assert_eq!(products(&vec![0x8000_0000_0000_0000; n]), expected);
    }

    #[test]
    fn keys_compare_clone_and_hide_their_secrets() {
        let a = interop_key("rsa1024");
        let b = interop_key("rsa1024");
        let c = interop_key("rsa1025");
        assert!(a == b && a == a.clone());
        assert!(a != c);
        assert!(a.public_key() == b.public_key());
        assert!(a.public_key() != c.public_key());
        assert!(*a.public_key() != PublicKey::new(&a.public_key().modulus(), 17).unwrap());

        // Keys of the same modulus: with the primes the other way round, and with
        // another private exponent (d plus (p - 1)(q - 1) / 2 is below the modulus and
        // is one, because (p - 1)(q - 1) / 2 is a multiple of lcm(p - 1, q - 1)).
        let r = interop_record("rsa1024");
        let (n, d, p, q) = (r.bytes("n"), r.bytes("d"), r.bytes("p"), r.bytes("q"));
        let swapped = PrivateKey::from_components(&n, 65537, &d, &q, &p).unwrap();
        assert!(swapped != a && swapped.public_key() == a.public_key());
        let p_minus_one = sub(&Limbs::from_be_bytes(&p), &[1]).0;
        let q_minus_one = sub(&Limbs::from_be_bytes(&q), &[1]).0;
        let mut half = p_minus_one.clone();
        for i in 0..half.len() {
            half[i] = (p_minus_one[i] >> 1) | (p_minus_one.get(i + 1).map_or(0, |&x| x << 63));
        }
        let other_d = add(&Limbs::from_be_bytes(&d), &mul(&half, &q_minus_one))
            .0
            .trimmed();
        let other =
            PrivateKey::from_components(&n, 65537, &other_d.to_be_bytes(128), &p, &q).unwrap();
        assert!(other != a && other.public_key() == a.public_key());
        assert_eq!(
            other.sign_pkcs1v15::<Sha256>(b"m"),
            a.sign_pkcs1v15::<Sha256>(b"m")
        );

        // Debug shows the size and the exponent of the public key and nothing of the
        // private one.
        assert_eq!(
            format!("{:?}", a.public_key()),
            "PublicKey { bits: 1024, exponent: 65537, .. }"
        );
        let shown = format!("{a:?}");
        assert_eq!(shown, "PrivateKey { bits: 1024, .. }");
        for number in [a.d(), a.p(), a.q()] {
            assert!(!shown.contains(&hex(&number[..8])));
        }
    }

    #[test]
    fn dropping_wipes_the_private_key() {
        use crate::rsa::testutil::probe::{leaks, needles_of_bytes, needles_of_limbs};

        // A key of its own: another test that holds the numbers of a key it shares
        // (a vector in memory, unwiped) would be counted as a leak when it frees them.
        let original = keygen::generate(
            &mut Drbg::new(b"dropping wipes the private key", &[]),
            1024,
            1024,
        )
        .unwrap();
        let components = |key: &PrivateKey| {
            let mut needles = Vec::new();
            for number in [key.d(), key.p(), key.q(), key.dp(), key.dq(), key.q_inv()] {
                needles.extend(needles_of_bytes(&number));
            }
            for limbs in [
                &key.d[..],
                key.p.limbs(),
                key.q.limbs(),
                &key.dp[..],
                &key.dq[..],
                &key.q_inv[..],
            ] {
                needles.extend(needles_of_limbs(limbs));
            }
            needles
        };
        let needles = components(&original);
        assert!(needles.len() > 100, "{}", needles.len());

        // The control: the probe finds the numbers in memory that is not wiped (the
        // bytes of the accessors are not).
        let copy = original.p();
        assert!(leaks(&needles, || drop(copy)) > 0);

        // Building, using, cloning and dropping a key from its components leaves none.
        // (The caller's own copies of the numbers are theirs to wipe: they are, here.)
        let mut numbers = vec![
            original.public_key().modulus(),
            original.d(),
            original.p(),
            original.q(),
        ];
        let hits = leaks(&needles, || {
            let key = PrivateKey::from_components(
                &numbers[0],
                65537,
                &numbers[1],
                &numbers[2],
                &numbers[3],
            )
            .unwrap();
            for number in &mut numbers {
                crate::wipe::wipe_bytes(number);
            }
            let clone = key.clone();
            let ct = key
                .public_key()
                .encrypt_oaep::<Sha256, _>(&mut rng("wipe"), b"hi", b"")
                .unwrap();
            assert_eq!(clone.decrypt_oaep::<Sha256>(&ct, b""), Ok(b"hi".to_vec()));
            let ct = key
                .public_key()
                .encrypt_pkcs1v15(&mut rng("wipe"), b"hi")
                .unwrap();
            assert_eq!(clone.decrypt_pkcs1v15(&ct), Ok(b"hi".to_vec()));
            let mut session = [0; 2];
            clone
                .decrypt_pkcs1v15_session_key(&ct, &mut session)
                .unwrap();
            assert!(
                clone
                    .sign_pss::<Sha256, _>(&mut rng("wipe"), b"m", SaltLength::Auto)
                    .is_ok()
            );
            assert!(key.sign_pkcs1v15::<Sha512>(b"m").is_ok());
        });
        assert_eq!(hits, 0);
    }

    /// A cheap source of bytes for the randomized operations, so that the time
    /// measured is the operation and not the system's random source.
    struct Noise(u64);

    impl io::Read for Noise {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            for byte in buf.iter_mut() {
                // xorshift64*
                self.0 ^= self.0 >> 12;
                self.0 ^= self.0 << 25;
                self.0 ^= self.0 >> 27;
                *byte = (self.0.wrapping_mul(0x2545_f491_4f6c_dd1d) >> 56) as u8;
            }
            Ok(buf.len())
        }
    }

    #[test]
    #[ignore = "manual throughput check: cargo test --release rsa::keypair -- --ignored --nocapture --test-threads=1"]
    fn throughput() {
        use crate::Digest;
        use std::hint::black_box;
        use std::time::{Duration, Instant};

        /// The best of five batches of `op`, in microseconds per call, after a
        /// warm-up call and a pass to size the batches to about 100 ms.
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

        for bits in [2048, 3072, 4096] {
            let name = format!("rsa{bits}");
            let record = interop_record(&name);
            let (n, d, p, q) = (
                record.bytes("n"),
                record.bytes("d"),
                record.bytes("p"),
                record.bytes("q"),
            );
            let key = PrivateKey::from_components(&n, 65537, &d, &p, &q).unwrap();
            let public = key.public_key();
            let mut noise = Noise(0x9e37_79b9_7f4a_7c15);

            // The inputs of Go's own benchmarks: a message of 13 bytes, the digest
            // of "testing", the ciphertexts of those messages.
            let message = b"Hello Gophers";
            let digest = Sha256::digest(b"testing");
            let digest = digest.as_ref();
            let oaep = public
                .encrypt_oaep::<Sha256, _>(&mut noise, message, b"")
                .unwrap();
            let pkcs1 = public.encrypt_pkcs1v15(&mut noise, message).unwrap();
            let v15 = key.sign_pkcs1v15_prehash::<Sha256>(digest).unwrap();
            let pss = key
                .sign_pss_prehash::<Sha256, _>(&mut noise, digest, SaltLength::EqualsHash)
                .unwrap();

            let rows = [
                (
                    "new private key",
                    time(|| {
                        black_box(
                            PrivateKey::from_components(
                                black_box(&n),
                                65537,
                                black_box(&d),
                                black_box(&p),
                                black_box(&q),
                            )
                            .unwrap(),
                        );
                    }),
                ),
                (
                    "new public key",
                    time(|| {
                        black_box(PublicKey::new(black_box(&n), 65537).unwrap());
                    }),
                ),
                (
                    "OAEP decrypt",
                    time(|| {
                        let plain = key.decrypt_oaep::<Sha256>(black_box(&oaep), b"").unwrap();
                        assert_eq!(plain, message);
                    }),
                ),
                (
                    "OAEP encrypt",
                    time(|| {
                        black_box(
                            public
                                .encrypt_oaep::<Sha256, _>(&mut noise, black_box(message), b"")
                                .unwrap(),
                        );
                    }),
                ),
                (
                    "PKCS1v15 decrypt",
                    time(|| {
                        let plain = key.decrypt_pkcs1v15(black_box(&pkcs1)).unwrap();
                        assert_eq!(plain, message);
                    }),
                ),
                (
                    "PKCS1v15 encrypt",
                    time(|| {
                        black_box(
                            public
                                .encrypt_pkcs1v15(&mut noise, black_box(message))
                                .unwrap(),
                        );
                    }),
                ),
                (
                    "sign PKCS1v15",
                    time(|| {
                        black_box(
                            key.sign_pkcs1v15_prehash::<Sha256>(black_box(digest))
                                .unwrap(),
                        );
                    }),
                ),
                (
                    "verify PKCS1v15",
                    time(|| {
                        public
                            .verify_pkcs1v15_prehash::<Sha256>(black_box(digest), black_box(&v15))
                            .unwrap();
                    }),
                ),
                (
                    "sign PSS",
                    time(|| {
                        black_box(
                            key.sign_pss_prehash::<Sha256, _>(
                                &mut noise,
                                black_box(digest),
                                SaltLength::EqualsHash,
                            )
                            .unwrap(),
                        );
                    }),
                ),
                (
                    "verify PSS",
                    time(|| {
                        public
                            .verify_pss_prehash::<Sha256>(
                                black_box(digest),
                                black_box(&pss),
                                SaltLength::EqualsHash,
                            )
                            .unwrap();
                    }),
                ),
            ];
            for (what, micros) in rows {
                println!(
                    "rsa-{bits} {what} [cryptors]: best {micros:.1} us/op, {:.0} ops/s (signature {}...)",
                    1e6 / micros,
                    hex(&v15[..8])
                );
            }
        }

        // Key generation from the candidates of c2sp.org/CCTV/keygen's benchmark,
        // which make a generation of average length.
        let mut candidates = Vec::new();
        for line in include_str!("testdata/candidates2048.txt")
            .lines()
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
        {
            candidates.extend(unhex(line));
        }
        let micros = time(|| {
            black_box(keygen::generate(&mut Script(candidates.clone()), 2048, 2048).unwrap());
        });
        println!(
            "rsa-2048 generate key [cryptors]: best {micros:.1} us/op, {:.2} ops/s",
            1e6 / micros
        );
    }

    /// A coarse check that the private operation takes the same time whatever the
    /// ciphertext, in the manner of dudect (Reparaz, Balasch and Verbauwhede,
    /// 2017): the times of two classes of input, measured interleaved in random
    /// order, are compared with Welch's t-test, after dropping the slowest tenth
    /// of each (interrupts and the like). A difference in time that depends on the
    /// input would show as a large `t`; dudect's threshold is 4.5, and a program
    /// that branched on the bits of the exponent or of the input would be far
    /// above it. It is one machine's measurement, not a proof, and it needs the
    /// machine to be quiet.
    #[test]
    #[ignore = "manual timing check, on a quiet machine: cargo test --release rsa::keypair::tests::timing -- --ignored --nocapture"]
    fn timing_does_not_depend_on_the_input() {
        use std::time::Instant;

        let key = interop_key("rsa2048");
        let k = key.public_key().size();
        let n = key.public_key().modulus();

        // Class 0: inputs with little in them (zero limbs, a few set bits). Class 1:
        // random inputs below the modulus.
        let mut noise = Noise(0x2545_f491_4f6c_dd1d);
        let random_below_n = |noise: &mut Noise| {
            let mut c = vec![0u8; k];
            io::Read::read_exact(noise, &mut c).unwrap();
            c[0] &= 0x7f; // below the modulus, which has its top bit set
            c
        };
        let mut sparse = vec![0u8; k];
        sparse[k - 1] = 2;
        let inputs: [Vec<Vec<u8>>; 2] = [
            (0..64)
                .map(|i| {
                    let mut c = sparse.clone();
                    c[k - 2 - (i % 8)] = (i / 8) as u8;
                    c
                })
                .collect(),
            (0..64).map(|_| random_below_n(&mut noise)).collect(),
        ];
        assert!(inputs[0][0][..] < n[..] && inputs[1][0][..] < n[..]);

        const ROUNDS: usize = 6000;
        let mut samples: [Vec<f64>; 2] = [Vec::with_capacity(ROUNDS), Vec::with_capacity(ROUNDS)];
        let mut choice = 0x9e37_79b9_7f4a_7c15u64;
        let mut counts = [0usize; 2];
        while counts[0] < ROUNDS || counts[1] < ROUNDS {
            choice ^= choice << 13;
            choice ^= choice >> 7;
            choice ^= choice << 17;
            let class = (choice & 1) as usize;
            if counts[class] >= ROUNDS {
                continue;
            }
            let input = &inputs[class][counts[class] % 64];
            let start = Instant::now();
            std::hint::black_box(key.private_op(std::hint::black_box(input)).unwrap());
            samples[class].push(start.elapsed().as_nanos() as f64);
            counts[class] += 1;
        }

        let crop = |v: &mut Vec<f64>| {
            v.sort_by(|a, b| a.partial_cmp(b).unwrap());
            v.truncate(v.len() * 9 / 10);
        };
        let stats = |v: &[f64]| {
            let mean = v.iter().sum::<f64>() / v.len() as f64;
            let var = v.iter().map(|x| (x - mean) * (x - mean)).sum::<f64>() / (v.len() - 1) as f64;
            (mean, var, v.len() as f64)
        };
        for v in &mut samples {
            crop(v);
        }
        let (m0, v0, n0) = stats(&samples[0]);
        let (m1, v1, n1) = stats(&samples[1]);
        let t = (m0 - m1) / (v0 / n0 + v1 / n1).sqrt();
        println!(
            "private operation, 2048 bits: sparse inputs {m0:.0} ns, random inputs {m1:.0} ns, difference {:.3}%, t = {t:.2}",
            100.0 * (m0 - m1) / m1
        );
        assert!(t.abs() < 10.0, "t = {t}");
    }
}
