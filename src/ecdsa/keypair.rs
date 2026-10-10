//! Private keys and public keys, and the operations on them.

use super::algorithm::shift_right;
use super::curve::sealed::Nonces;
use super::curve::{Curve, Error, MAX_PRIVATE_KEY_LEN, MAX_PUBLIC_KEY_LEN, MAX_SIGNATURE_LEN};
use super::hmac_drbg::HmacDrbg;
use super::signature::Signature;
use crate::Digest;
use crate::digest::hex;
use crate::ec::ct;
use crate::sha2::Sha512;
use crate::wipe::wipe;
use core::fmt;
use core::marker::PhantomData;
use std::io;

/// A private key of the curve `C`: the secret that signs.
///
/// It holds the public key that goes with it, so [`public_key`] is free. The
/// bytes of the key are overwritten with zeros when it is dropped, and `Debug`
/// does not show them. That is best effort: the working values of the
/// arithmetic (numbers that depend on the key, on the stack and in registers
/// while it is in use) are not overwritten, and neither is the copy that moving
/// the key (into a `Box` or a `Vec`, say) can leave behind where it was.
///
/// [`public_key`]: PrivateKey::public_key
pub struct PrivateKey<C: Curve> {
    bytes: [u8; MAX_PRIVATE_KEY_LEN],
    public: PublicKey<C>,
}

/// A public key of the curve `C`: what a verifier needs to know.
///
/// Holding one means the bytes passed the checks of the curve: an uncompressed
/// point, both coordinates reduced, on the curve.
pub struct PublicKey<C: Curve> {
    bytes: [u8; MAX_PUBLIC_KEY_LEN],
    curve: PhantomData<C>,
}

/// The digest, if it is one a signature can be made of or checked against.
fn check_digest(digest: &[u8]) -> Result<(), Error> {
    if digest.is_empty() {
        return Err(Error::InvalidDigest);
    }
    Ok(())
}

impl<C: Curve> PrivateKey<C> {
    /// Generates a key from `rng`, which has to be a source of cryptographically
    /// secure random bytes: the secrecy of everything that follows depends on
    /// it. The standard library has none that is stable, so this takes any
    /// reader; on Unix, `File::open("/dev/urandom")` is one.
    ///
    /// It draws as many bytes as the key has and keeps the leftmost bits of
    /// them that the order has (all of them, but for P-521), then tries again
    /// for the (very rare) candidates that are zero or not below the order of
    /// the curve. That is the key generation by rejection sampling of FIPS
    /// 186-5 (appendix A.2.2), except that it draws again where the standard
    /// reports an error, and that it takes the candidate itself as the key where
    /// the standard (appendix A.4.2) adds one to it; both give every key the same
    /// probability.
    ///
    /// # Errors
    ///
    /// Whatever `rng` fails with. It also gives up, with
    /// [`InvalidData`](io::ErrorKind::InvalidData), after 64 candidates in a
    /// row that are not keys: a good source gets one wrong with a probability
    /// of about 2^-32 for P-256 and much less for the others, so 64 in a row
    /// means the source is stuck (a reader that only returns zeros, say), and
    /// looping on it would never end.
    pub fn generate<R: io::Read + ?Sized>(rng: &mut R) -> io::Result<Self> {
        const ATTEMPTS: usize = 64;

        let mut buffer = [0u8; MAX_PRIVATE_KEY_LEN];
        let mut result = Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "ecdsa: the random source did not produce a private key",
        ));
        for _ in 0..ATTEMPTS {
            if let Err(error) = rng.read_exact(&mut buffer[..C::PRIVATE_KEY_LEN]) {
                result = Err(error);
                break;
            }
            shift_right(&mut buffer[..C::PRIVATE_KEY_LEN], C::EXCESS_BITS);
            if C::check_private(&buffer[..C::PRIVATE_KEY_LEN]) {
                result = Ok(Self::new(&buffer[..C::PRIVATE_KEY_LEN]));
                break;
            }
        }
        wipe(&mut buffer);
        result
    }

    /// Builds a key from its encoding: [`Curve::PRIVATE_KEY_LEN`] bytes, the
    /// scalar `d` as a big-endian number (SEC 1, section 2.3.8), which has to
    /// be at least 1 and below the order of the curve (FIPS 186-5, appendix
    /// A.2); zero is refused because the matching public key would be the point
    /// at infinity.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if !C::check_private(bytes) {
            return Err(Error::InvalidPrivateKey);
        }
        Ok(Self::new(bytes))
    }

    /// `bytes` must have passed `C::check_private`.
    fn new(bytes: &[u8]) -> Self {
        let mut key = Self {
            bytes: [0; MAX_PRIVATE_KEY_LEN],
            public: PublicKey {
                bytes: [0; MAX_PUBLIC_KEY_LEN],
                curve: PhantomData,
            },
        };
        key.bytes[..C::PRIVATE_KEY_LEN].copy_from_slice(bytes);
        C::public_key(bytes, &mut key.public.bytes[..C::PUBLIC_KEY_LEN]);
        key
    }

    /// The encoding of the key, in the form [`from_bytes`] takes.
    ///
    /// [`from_bytes`]: PrivateKey::from_bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..C::PRIVATE_KEY_LEN]
    }

    /// The public key that verifies this key's signatures.
    pub fn public_key(&self) -> &PublicKey<C> {
        &self.public
    }

    /// Signs `message`, hashed with `D`, with a signature that is randomized
    /// and does not depend on the quality of `rng` alone. Most applications
    /// should use this one.
    ///
    /// The hash is the choice of the caller, and the verifier has to use the
    /// same one: FIPS 186-5 approves the SHA-2 and SHA-3 families and says that
    /// one weaker than the curve shall not be used (section 6.1.1). See
    /// [`sign_prehash`](PrivateKey::sign_prehash) for what `rng` is used for, and
    /// for the errors.
    pub fn sign<D: Digest, R: io::Read + ?Sized>(
        &self,
        rng: &mut R,
        message: &[u8],
    ) -> io::Result<Signature<C>> {
        self.sign_prehash(rng, D::digest(message).as_ref())
    }

    /// Signs `digest`, which is the hash of the message, with a signature that
    /// is randomized: `rng` supplies `PRIVATE_KEY_LEN` bytes that are mixed
    /// with the private key and the digest into the per-message secret number,
    /// by the construction of draft-irtf-cfrg-det-sigs-with-noise (section 4)
    /// on an HMAC_DRBG with SHA-512, whatever hash made the digest.
    ///
    /// This is the "hedged" construction. A signature needs a per-message
    /// secret number that is never repeated and never guessable, or the private
    /// key follows from the signatures; if `rng` were the only source of that
    /// number, a broken generator would give the key away. Here the number is
    /// also derived from the key and the digest, so a generator that repeats or
    /// is predictable costs the randomization and not the key: the signature is
    /// then as strong as a [deterministic] one. `rng` must still be secret and
    /// come from a cryptographically secure generator.
    ///
    /// A digest longer than the order of the curve is cut to its leftmost bits,
    /// as FIPS 186-5 (section 6.4.1) says.
    ///
    /// [deterministic]: PrivateKey::sign_prehash_deterministic
    ///
    /// # Errors
    ///
    /// Whatever `rng` fails with, and
    /// [`InvalidInput`](io::ErrorKind::InvalidInput) (carrying
    /// [`Error::InvalidDigest`]) for an empty digest.
    pub fn sign_prehash<R: io::Read + ?Sized>(
        &self,
        rng: &mut R,
        digest: &[u8],
    ) -> io::Result<Signature<C>> {
        check_digest(digest).map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;

        let len = C::PRIVATE_KEY_LEN;
        let mut entropy = [0u8; MAX_PRIVATE_KEY_LEN];
        let mut octets = [0u8; MAX_PRIVATE_KEY_LEN];
        let read = rng.read_exact(&mut entropy[..len]);
        let signature = read.map(|()| {
            C::digest_to_octets(digest, &mut octets[..len]);
            let mut drbg =
                HmacDrbg::<Sha512>::new(&entropy[..len], &[], &[self.as_bytes(), &octets[..len]]);
            self.sign_with(&mut drbg, digest)
        });
        wipe(&mut entropy);
        wipe(&mut octets);
        signature
    }

    /// Signs `message`, hashed with `D`, with a signature that is the same
    /// every time: the per-message secret number is derived from the private key
    /// and the digest alone (RFC 6979, which is what FIPS 186-5, appendix A.3.3,
    /// describes), through an HMAC_DRBG on `D`.
    ///
    /// `D` can be any [`Digest`] with an output of 1 to 64 bytes, which every hash
    /// function of this crate has; a longer one does not compile:
    ///
    /// ```compile_fail,E0080
    /// use cryptors::Digest;
    /// use cryptors::ecdsa::{P256, PrivateKey};
    ///
    /// struct Wide;
    /// impl Digest for Wide {
    ///     const BLOCK_LEN: usize = 128;
    ///     const OUTPUT_LEN: usize = 128;
    ///     type Output = [u8; 128];
    ///     fn digest(_: &[u8]) -> [u8; 128] {
    ///         [0; 128]
    ///     }
    /// }
    ///
    /// let key = PrivateKey::<P256>::from_bytes(&[1; 32]).unwrap();
    /// let _ = key.sign_deterministic::<Wide>(b"message");
    /// ```
    ///
    /// It needs no source of randomness, so a bad generator cannot break it, and
    /// it gives the same signature for the same key and message, which makes it
    /// easy to test. The price is that the computation is the same every time
    /// too: an attacker who can induce a fault in one of two computations of the
    /// same signature gets two results that share a secret number, and that can
    /// give the key away. [`sign`](PrivateKey::sign) mixes in fresh randomness
    /// against that.
    ///
    /// If `r` or `s` comes out zero, which has a probability of about `1/n`,
    /// this goes on to the next candidate for the secret number, as RFC 6979
    /// (section 3.2, step h) does, where FIPS 186-5 (section 6.4.1, step 11)
    /// calls it a failure. That is why it cannot fail.
    pub fn sign_deterministic<D: Digest>(&self, message: &[u8]) -> Signature<C> {
        self.sign_prehash_deterministic::<D>(D::digest(message).as_ref())
            .expect("a digest has the length of the output of its hash")
    }

    /// Signs `digest`, which is the output of `D` for the message, the way
    /// [`sign_deterministic`](PrivateKey::sign_deterministic) does. `D` is the
    /// hash that made the digest: RFC 6979 uses it for the generator too.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidDigest`] if the digest is not exactly the length of the
    /// output of `D`.
    pub fn sign_prehash_deterministic<D: Digest>(
        &self,
        digest: &[u8],
    ) -> Result<Signature<C>, Error> {
        check_digest(digest)?;
        if digest.len() != D::OUTPUT_LEN {
            return Err(Error::InvalidDigest);
        }

        let len = C::PRIVATE_KEY_LEN;
        let mut octets = [0u8; MAX_PRIVATE_KEY_LEN];
        C::digest_to_octets(digest, &mut octets[..len]);
        let mut drbg = HmacDrbg::<D>::new(self.as_bytes(), &octets[..len], &[]);
        wipe(&mut octets);
        Ok(self.sign_with(&mut drbg, digest))
    }

    /// Signs `digest` with the candidates for the per-message secret number
    /// that `nonces` produces.
    fn sign_with(&self, nonces: &mut dyn Nonces, digest: &[u8]) -> Signature<C> {
        let mut bytes = [0u8; MAX_SIGNATURE_LEN];
        let bytes = &mut bytes[..C::SIGNATURE_LEN];
        C::sign(self.as_bytes(), digest, nonces, bytes);
        Signature::new(bytes)
    }
}

impl<C: Curve> PublicKey<C> {
    /// Builds a key from its encoding: [`Curve::PUBLIC_KEY_LEN`] bytes, an
    /// uncompressed point (SEC 1, section 2.3.3): the byte `0x04` and the two
    /// coordinates as big-endian numbers of equal length.
    ///
    /// Compressed points and the point at infinity are refused, and so are
    /// coordinates that are not below the prime of the field (a second encoding
    /// of the same point) and points that are not on the curve. That is the
    /// public key validation that FIPS 186-5 (section 6.4.2) asks for, as
    /// NIST SP 800-186 (appendix D.1) and NIST SP 800-89 (section 5.3.2) describe
    /// it. On a curve of prime order it is complete: the order of every point
    /// of the curve but infinity is `n`.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if !C::check_public(bytes) {
            return Err(Error::InvalidPublicKey);
        }
        let mut key = Self {
            bytes: [0; MAX_PUBLIC_KEY_LEN],
            curve: PhantomData,
        };
        key.bytes[..C::PUBLIC_KEY_LEN].copy_from_slice(bytes);
        Ok(key)
    }

    /// The encoding of the key, in the form [`from_bytes`] takes.
    ///
    /// [`from_bytes`]: PublicKey::from_bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..C::PUBLIC_KEY_LEN]
    }

    /// Checks that `signature` is a signature of `message`, hashed with `D`, by
    /// the private key of this public key.
    ///
    /// `D` has to be the hash the signer used: the same message with another
    /// hash is another digest. See
    /// [`verify_prehash`](PublicKey::verify_prehash).
    ///
    /// # Errors
    ///
    /// [`Error::VerificationFailed`], and [`Error::InvalidDigest`] for a hash
    /// whose digest is empty.
    pub fn verify<D: Digest>(&self, message: &[u8], signature: &Signature<C>) -> Result<(), Error> {
        self.verify_prehash(D::digest(message).as_ref(), signature)
    }

    /// Checks that `signature` is a signature of `digest`, the hash of a
    /// message, by the private key of this public key (FIPS 186-5, section
    /// 6.4.2). A digest longer than the order of the curve is cut to its
    /// leftmost bits.
    ///
    /// Nothing here is secret, and the time it takes depends on the inputs.
    ///
    /// # Errors
    ///
    /// [`Error::VerificationFailed`] if the signature is not one of this digest
    /// by this key, and [`Error::InvalidDigest`] for an empty digest.
    pub fn verify_prehash(&self, digest: &[u8], signature: &Signature<C>) -> Result<(), Error> {
        check_digest(digest)?;
        if C::verify(self.as_bytes(), digest, signature.as_bytes()) {
            Ok(())
        } else {
            Err(Error::VerificationFailed)
        }
    }
}

impl<C: Curve> Drop for PrivateKey<C> {
    fn drop(&mut self) {
        wipe(&mut self.bytes);
    }
}

impl<C: Curve> Clone for PrivateKey<C> {
    fn clone(&self) -> Self {
        Self {
            bytes: self.bytes,
            public: self.public.clone(),
        }
    }
}

impl<C: Curve> Clone for PublicKey<C> {
    fn clone(&self) -> Self {
        Self {
            bytes: self.bytes,
            curve: PhantomData,
        }
    }
}

/// Compares in constant time: two private keys are equal if their encodings
/// are, and the time it takes does not say where they differ.
impl<C: Curve> PartialEq for PrivateKey<C> {
    fn eq(&self, other: &Self) -> bool {
        ct::bytes_eq(self.as_bytes(), other.as_bytes())
    }
}

impl<C: Curve> Eq for PrivateKey<C> {}

/// Two public keys are equal if their encodings are.
impl<C: Curve> PartialEq for PublicKey<C> {
    fn eq(&self, other: &Self) -> bool {
        self.as_bytes() == other.as_bytes()
    }
}

impl<C: Curve> Eq for PublicKey<C> {}

impl<C: Curve> fmt::Debug for PrivateKey<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PrivateKey<{}> {{ .. }}", C::NAME)
    }
}

impl<C: Curve> fmt::Debug for PublicKey<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PublicKey<{}>({})", C::NAME, hex(self.as_bytes()))
    }
}

#[cfg(test)]
mod tests {
    use super::super::vectors::*;
    use super::super::{P224, P256, P384, P521};
    use super::*;
    use crate::sha1::Sha1;
    use crate::sha2::{Sha224, Sha256, Sha384, Sha512};
    use crate::sha3;

    /// A reader that returns the bytes it was given, in order, then fails.
    struct Script<'a>(&'a [u8]);

    impl io::Read for Script<'_> {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let n = buf.len().min(self.0.len());
            buf[..n].copy_from_slice(&self.0[..n]);
            self.0 = &self.0[n..];
            Ok(n)
        }
    }

    /// A reader that returns the same bytes for ever, and counts what it gave.
    struct Stuck {
        byte: u8,
        reads: usize,
    }

    impl io::Read for Stuck {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.reads += 1;
            buf.fill(self.byte);
            Ok(buf.len())
        }
    }

    /// `r || s` of an RFC 6979 row.
    fn rfc_signature(row: &Rfc6979) -> Vec<u8> {
        let mut bytes = unhex(row.r);
        bytes.extend(unhex(row.s));
        bytes
    }

    /// One signature of RFC 6979, appendix A.2, through the whole API: the key,
    /// its public key, the deterministic signature of the message (hashed in
    /// the call and passed as a digest), and its verification.
    fn check_rfc_6979<C: Curve, D: Digest>(row: &Rfc6979) {
        let what = format!("{} {} {:?}", row.curve, row.hash, row.message);
        let message = row.message.as_bytes();

        let private = PrivateKey::<C>::from_bytes(&unhex(row.private)).unwrap();
        assert_eq!(private.as_bytes(), unhex(row.private), "{what}");
        assert_eq!(private.public_key().as_bytes(), unhex(row.public), "{what}");

        let signature = private.sign_deterministic::<D>(message);
        assert_eq!(signature.as_bytes(), rfc_signature(row), "{what}");
        let digest = D::digest(message);
        assert_eq!(
            private
                .sign_prehash_deterministic::<D>(digest.as_ref())
                .unwrap(),
            signature,
            "{what}: the digest form"
        );

        let public = PublicKey::<C>::from_bytes(&unhex(row.public)).unwrap();
        assert_eq!(public.verify::<D>(message, &signature), Ok(()), "{what}");
        assert_eq!(
            public.verify_prehash(digest.as_ref(), &signature),
            Ok(()),
            "{what}"
        );
        assert_eq!(
            public.verify::<D>(b"another message", &signature),
            Err(Error::VerificationFailed),
            "{what}"
        );

        // The numbers of the RFC are the same ones in DER.
        let parsed = Signature::<C>::from_bytes(&rfc_signature(row)).unwrap();
        assert_eq!(parsed, signature, "{what}");
        assert_eq!(
            Signature::<C>::from_der(&signature.to_der()).unwrap(),
            signature,
            "{what}"
        );
    }

    #[test]
    fn rfc_6979_known_answers() {
        for row in &RFC6979 {
            for_curve!(row.curve, C => for_hash!(row.hash, D => check_rfc_6979::<C, D>(row)));
        }
    }

    /// The digest of `message` under the hash that a test vector names, which may be
    /// one of the SHA-3 functions: they are not a `Digest` yet, and the
    /// `verify_prehash` form takes their output all the same.
    fn digest_named(name: &str, message: &[u8]) -> Vec<u8> {
        match name {
            "SHA-1" => Sha1::digest(message).to_vec(),
            "SHA-224" => Sha224::digest(message).to_vec(),
            "SHA-256" => Sha256::digest(message).to_vec(),
            "SHA-384" => Sha384::digest(message).to_vec(),
            "SHA-512" => Sha512::digest(message).to_vec(),
            "SHA3-224" => sha3::sha3_224(message).to_vec(),
            "SHA3-256" => sha3::sha3_256(message).to_vec(),
            "SHA3-384" => sha3::sha3_384(message).to_vec(),
            "SHA3-512" => sha3::sha3_512(message).to_vec(),
            other => panic!("no hash named {other}"),
        }
    }

    /// Project Wycheproof's cases, a selection of them (all 9,767 were run once
    /// and agree). Each group has a public key, and each case a message, a
    /// signature in DER or as `r || s`, and whether it is valid. A signature that
    /// does not parse counts as rejected, and one that does parse has to encode
    /// back to the very bytes it came from.
    fn check_wycheproof<C: Curve>(group: &WycheproofGroup) {
        let public = PublicKey::<C>::from_bytes(&unhex(group.public)).unwrap_or_else(|e| {
            panic!(
                "{} {}: the key of a group is refused: {e}",
                group.curve, group.hash
            )
        });
        for case in group.cases {
            let what = format!(
                "{} {} {} test {} ({})",
                group.curve,
                group.hash,
                if group.p1363 { "p1363" } else { "der" },
                case.id,
                case.flags
            );
            let encoded = unhex(case.sig);
            let parsed = if group.p1363 {
                Signature::<C>::from_bytes(&encoded)
            } else {
                Signature::<C>::from_der(&encoded)
            };
            let accepted = match parsed {
                Ok(signature) => {
                    let again = if group.p1363 {
                        signature.as_bytes().to_vec()
                    } else {
                        signature.to_der()
                    };
                    assert_eq!(again, encoded, "{what}: encodes back to other bytes");

                    let message = unhex(case.msg);
                    let digest = digest_named(group.hash, &message);
                    let by_digest = public.verify_prehash(&digest, &signature);
                    // The form that hashes the message agrees, where the hash is a `Digest`.
                    if !group.hash.starts_with("SHA3") {
                        let by_message =
                            for_hash!(group.hash, D => public.verify::<D>(&message, &signature));
                        assert_eq!(by_message, by_digest, "{what}");
                    }
                    by_digest.is_ok()
                }
                Err(error) => {
                    assert_eq!(error, Error::InvalidSignature, "{what}");
                    false
                }
            };
            assert_eq!(accepted, case.valid, "{what}");
        }
    }

    #[test]
    fn wycheproof() {
        for group in &WYCHEPROOF {
            for_curve!(group.curve, C => check_wycheproof::<C>(group));
        }
    }

    /// NIST's CAVP cases: a message, a key and `(r, s)` that verify, or that do
    /// not for the reason given. A key or a signature that is not even valid
    /// (the CAVP changes bits of them) is rejected on the way in.
    fn check_cavp<C: Curve>(row: &Cavp) {
        let what = format!("{} {} ({})", row.curve, row.hash, row.why);
        let digest = digest_named(row.hash, &unhex(row.msg));
        let public = PublicKey::<C>::from_bytes(&unhex(&format!("04{}{}", row.qx, row.qy)));
        let signature = Signature::<C>::from_bytes(&unhex(&format!("{}{}", row.r, row.s)));
        let accepted = match (public, signature) {
            (Ok(public), Ok(signature)) => public.verify_prehash(&digest, &signature).is_ok(),
            _ => false,
        };
        assert_eq!(accepted, row.pass, "{what}");
    }

    #[test]
    fn nist_cavp_signature_verification() {
        for row in &CAVP {
            for_curve!(row.curve, C => check_cavp::<C>(row));
        }
        // Every pair of curve and hash is there, with both outcomes.
        assert_eq!(CAVP.len(), 40);
        for curve in ["P-224", "P-256", "P-384", "P-521"] {
            for hash in ["SHA-1", "SHA-224", "SHA-256", "SHA-384", "SHA-512"] {
                let rows = || {
                    CAVP.iter()
                        .filter(|row| row.curve == curve && row.hash == hash)
                };
                assert!(
                    rows().any(|row| row.pass),
                    "{curve} {hash}: no signature that verifies"
                );
                assert!(
                    rows().any(|row| !row.pass),
                    "{curve} {hash}: no signature that fails"
                );
            }
        }
    }

    /// Randomized signatures against another implementation of the same
    /// construction, fed the same random bytes: the key, the digest and the
    /// bytes the signer reads decide the DER signature. This is what pins down the
    /// way the private key and the digest go into the HMAC_DRBG, each in a block
    /// of its own.
    #[test]
    fn hedged_known_answers() {
        fn check<C: Curve>(row: &Hedged) {
            let what = format!("{} digest of {} bytes", row.curve, row.digest.len() / 2);
            let key = PrivateKey::<C>::from_bytes(&unhex(row.private)).unwrap();
            let mut entropy = Script(&[]);
            let bytes = unhex(row.entropy);
            entropy.0 = &bytes;
            let signature = key.sign_prehash(&mut entropy, &unhex(row.digest)).unwrap();
            assert!(
                entropy.0.is_empty(),
                "{what}: exactly the key's length is read"
            );
            assert_eq!(signature.to_der(), unhex(row.signature), "{what}");
            assert_eq!(
                key.public_key()
                    .verify_prehash(&unhex(row.digest), &signature),
                Ok(()),
                "{what}"
            );
        }
        for row in &HEDGED {
            for_curve!(row.curve, C => check::<C>(row));
        }

        // The digests are shorter than, as long as and longer than the order, for
        // every curve: the rules of FIPS 186-5 (section 6.4.1, step 2) are all used.
        for (curve, order_len) in [("P-224", 28), ("P-256", 32), ("P-384", 48), ("P-521", 66)] {
            let lengths: Vec<usize> = HEDGED
                .iter()
                .filter(|row| row.curve == curve)
                .map(|row| row.digest.len() / 2)
                .collect();
            assert!(
                lengths.iter().any(|&l| l < order_len),
                "{curve}: no shorter digest"
            );
            assert!(
                lengths.contains(&order_len),
                "{curve}: no digest as long as the order"
            );
            assert!(
                lengths.iter().any(|&l| l > order_len),
                "{curve}: no longer digest"
            );
        }
    }

    /// The derivation of the chained test: a key from `state`, trying again with
    /// the next counter for the rare candidate that is not a valid key.
    fn derive<C: Curve>(state: &[u8]) -> PrivateKey<C> {
        for counter in 0..=255 {
            let mut material = Vec::new();
            for part in 0..2 {
                let mut input = state.to_vec();
                input.extend([0, counter, part]);
                material.extend(Sha512::digest(&input));
            }
            let mut candidate = material[..C::PRIVATE_KEY_LEN].to_vec();
            candidate[0] &= 0xffu8 >> C::EXCESS_BITS;
            if let Ok(key) = PrivateKey::<C>::from_bytes(&candidate) {
                return key;
            }
        }
        unreachable!("256 candidates in a row were refused");
    }

    /// Rounds of a derived key signing the state with deterministic ECDSA, each
    /// round seeded by the hash of the last, compared with what OpenSSL gets from
    /// the same keys. A wrong carry in one multiplication among the hundreds of
    /// thousands that these signatures make changes every value after it.
    fn check_chain<C: Curve, D: Digest>(expected: &[&str; 2]) {
        let mut state =
            Sha512::digest(format!("cryptors ecdsa chain {}", C::NAME).as_bytes()).to_vec();
        for round in 0..CHAIN_STEPS {
            let key = derive::<C>(&state);
            let signature = key.sign_deterministic::<D>(&state);
            assert_eq!(
                key.public_key().verify::<D>(&state, &signature),
                Ok(()),
                "{}: round {round} does not verify",
                C::NAME
            );

            let mut input = state.clone();
            input.extend(signature.as_bytes());
            input.extend(key.public_key().as_bytes());
            state = Sha512::digest(&input).to_vec();
            if round == 0 {
                assert_eq!(state, unhex(expected[0]), "{} after one round", C::NAME);
            }
        }
        assert_eq!(
            state,
            unhex(expected[1]),
            "{} after {CHAIN_STEPS} rounds",
            C::NAME
        );
    }

    #[test]
    fn chained_signatures() {
        for (curve, hash, expected) in &CHAINS {
            for_curve!(*curve, C => for_hash!(*hash, D => check_chain::<C, D>(expected)));
        }
    }

    /// The smallest and the largest private keys are keys: 1 and 2, and n - 1,
    /// the largest number below the order. They sign, and the signatures verify.
    #[test]
    fn edge_scalars_are_keys() {
        fn check<C: Curve>(vectors: &[[&str; 2]; 3]) {
            for [private, public] in vectors {
                let key = PrivateKey::<C>::from_bytes(&unhex(private))
                    .unwrap_or_else(|e| panic!("{} {private}: {e}", C::NAME));
                assert_eq!(
                    key.public_key().as_bytes(),
                    unhex(public),
                    "{} {private}",
                    C::NAME
                );

                let signature = key.sign_deterministic::<Sha512>(b"edge");
                assert_eq!(
                    key.public_key().verify::<Sha512>(b"edge", &signature),
                    Ok(())
                );
                let hedged = key
                    .sign::<Sha512, _>(&mut Script(&[5; 66]), b"edge")
                    .unwrap();
                assert_eq!(key.public_key().verify::<Sha512>(b"edge", &hedged), Ok(()));
            }
        }
        for (curve, vectors) in &EDGE_SCALARS {
            for_curve!(*curve, C => check::<C>(vectors));
        }
    }

    /// A key of `len` bytes that is valid on every curve here.
    fn scalar(len: usize, seed: usize) -> Vec<u8> {
        let mut bytes: Vec<u8> = (0..len).map(|i| (seed + i * 37) as u8).collect();
        bytes[0] = if len == 66 { 0x01 } else { 0x7f };
        bytes
    }

    /// Signing and verifying agree with each other, whatever the key, the
    /// message and the randomness; and they disagree about anything else.
    fn check_round_trip<C: Curve>() {
        let len = C::PRIVATE_KEY_LEN;
        let key = PrivateKey::<C>::from_bytes(&scalar(len, 5)).unwrap();
        let other = PrivateKey::<C>::from_bytes(&scalar(len, 6)).unwrap();
        let message = b"the message that is signed";

        let hedged = key
            .sign::<Sha384, _>(&mut Script(&[7; 66]), message)
            .unwrap();
        let other_noise = key
            .sign::<Sha384, _>(&mut Script(&[8; 66]), message)
            .unwrap();
        let fixed = key.sign_deterministic::<Sha384>(message);
        // Fresh randomness changes the signature; none changes nothing.
        assert_ne!(hedged, other_noise);
        assert_ne!(hedged, fixed);
        assert_eq!(fixed, key.sign_deterministic::<Sha384>(message));
        assert_eq!(
            hedged,
            key.sign::<Sha384, _>(&mut Script(&[7; 66]), message)
                .unwrap(),
            "the same randomness gives the same signature"
        );

        for signature in [&hedged, &other_noise, &fixed] {
            assert_eq!(
                key.public_key().verify::<Sha384>(message, signature),
                Ok(())
            );
            // Another message, another key, another hash.
            assert_eq!(
                key.public_key()
                    .verify::<Sha384>(b"the message that is signeD", signature),
                Err(Error::VerificationFailed)
            );
            assert_eq!(
                other.public_key().verify::<Sha384>(message, signature),
                Err(Error::VerificationFailed)
            );
            assert_eq!(
                key.public_key().verify::<Sha256>(message, signature),
                Err(Error::VerificationFailed)
            );
            // A change to either number of the signature.
            for position in [0, len - 1, len, 2 * len - 1] {
                let mut bytes = signature.as_bytes().to_vec();
                bytes[position] ^= 1;
                if let Ok(forged) = Signature::<C>::from_bytes(&bytes) {
                    assert_eq!(
                        key.public_key().verify::<Sha384>(message, &forged),
                        Err(Error::VerificationFailed),
                        "byte {position}"
                    );
                }
            }
        }
    }

    #[test]
    fn signatures_verify_and_only_those() {
        check_round_trip::<P224>();
        check_round_trip::<P256>();
        check_round_trip::<P384>();
        check_round_trip::<P521>();
    }

    /// The digest rules of FIPS 186-5, section 6.4.1: a digest longer than the
    /// order is cut to its leftmost bits (so it is only those that count), and a
    /// shorter one is the number it encodes.
    fn check_digest_lengths<C: Curve>() {
        let len = C::PRIVATE_KEY_LEN;
        let key = PrivateKey::<C>::from_bytes(&scalar(len, 9)).unwrap();
        let public = key.public_key();

        for digest_len in [1, 16, len - 1, len, len + 1, 64, 100] {
            let digest: Vec<u8> = (0..digest_len).map(|i| (i * 11 + 1) as u8).collect();
            let signature = key.sign_prehash(&mut Script(&[3; 66]), &digest).unwrap();
            assert_eq!(
                public.verify_prehash(&digest, &signature),
                Ok(()),
                "{digest_len}"
            );

            // Anything past the leftmost `len` bytes is not part of the number.
            if digest_len > len {
                let mut changed = digest.clone();
                *changed.last_mut().unwrap() ^= 0xff;
                assert_eq!(
                    public.verify_prehash(&changed, &signature),
                    Ok(()),
                    "{digest_len}"
                );
            }
            // The last byte that is, is: bits other than the unused ones of the
            // curve (P-521 uses 521 of 528 bits) change the number.
            let mut changed = digest.clone();
            let last = digest_len.min(len) - 1;
            changed[last] ^= 0x80;
            assert_eq!(
                public.verify_prehash(&changed, &signature),
                Err(Error::VerificationFailed),
                "{digest_len}"
            );
        }

        // For P-521 the seven lowest bits of the 66th byte are cut off; for
        // the others the whole of it counts.
        let digest = vec![0x55u8; len];
        let signature = key.sign_prehash(&mut Script(&[3; 66]), &digest).unwrap();
        let mut changed = digest.clone();
        changed[len - 1] ^= 0x01;
        let result = public.verify_prehash(&changed, &signature);
        if C::EXCESS_BITS == 7 {
            assert_eq!(result, Ok(()), "the low bits of a P-521 digest are cut");
        } else {
            assert_eq!(result, Err(Error::VerificationFailed));
        }
    }

    #[test]
    fn digests_of_any_length() {
        check_digest_lengths::<P224>();
        check_digest_lengths::<P256>();
        check_digest_lengths::<P384>();
        check_digest_lengths::<P521>();
    }

    #[test]
    fn the_message_and_digest_forms_agree() {
        let key = PrivateKey::<P256>::from_bytes(&scalar(32, 1)).unwrap();
        let digest = Sha256::digest(b"abc");
        let message = key
            .sign::<Sha256, _>(&mut Script(&[1; 32]), b"abc")
            .unwrap();
        let prehash = key.sign_prehash(&mut Script(&[1; 32]), &digest).unwrap();
        assert_eq!(message, prehash);
        assert_eq!(key.public_key().verify::<Sha256>(b"abc", &prehash), Ok(()));
    }

    #[test]
    fn digests_that_are_not_digests() {
        let key = PrivateKey::<P256>::from_bytes(&scalar(32, 1)).unwrap();
        let signature = key.sign_deterministic::<Sha256>(b"abc");

        let error = key.sign_prehash(&mut Script(&[1; 32]), &[]).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert_eq!(
            error.get_ref().unwrap().to_string(),
            Error::InvalidDigest.to_string()
        );
        assert_eq!(
            key.sign_prehash_deterministic::<Sha256>(&[]),
            Err(Error::InvalidDigest)
        );
        assert_eq!(
            key.public_key().verify_prehash(&[], &signature),
            Err(Error::InvalidDigest)
        );

        // The hash named for a deterministic signature has to be the one that
        // made the digest, or at least produce one of its length.
        assert_eq!(
            key.sign_prehash_deterministic::<Sha256>(&[1; 31]),
            Err(Error::InvalidDigest)
        );
        assert_eq!(
            key.sign_prehash_deterministic::<Sha256>(&[1; 33]),
            Err(Error::InvalidDigest)
        );
        assert_eq!(
            key.sign_prehash_deterministic::<Sha384>(&Sha256::digest(b"abc")),
            Err(Error::InvalidDigest)
        );
        assert!(key.sign_prehash_deterministic::<Sha256>(&[1; 32]).is_ok());
    }

    #[test]
    fn a_failing_random_source_is_reported() {
        let key = PrivateKey::<P384>::from_bytes(&scalar(48, 1)).unwrap();
        // The hedged signature needs as many random bytes as the key has.
        let error = key
            .sign::<Sha384, _>(&mut Script(&[7; 47]), b"abc")
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
        let mut exact = Script(&[7; 48]);
        assert!(key.sign::<Sha384, _>(&mut exact, b"abc").is_ok());
        assert!(exact.0.is_empty(), "exactly as many bytes as the key has");
    }

    #[test]
    fn rejects_invalid_private_keys() {
        fn check<C: Curve>(order: &str) {
            let len = C::PRIVATE_KEY_LEN;
            for bad in [0, 1, len - 1, len + 1, 200] {
                assert_eq!(
                    PrivateKey::<C>::from_bytes(&vec![0x01; bad]).unwrap_err(),
                    Error::InvalidPrivateKey,
                    "{bad} bytes for {}",
                    C::NAME
                );
            }
            let order = unhex(order);
            assert_eq!(order.len(), len);
            let mut order_minus_1 = order.clone();
            *order_minus_1.last_mut().unwrap() -= 1;
            let mut order_plus_1 = order.clone();
            *order_plus_1.last_mut().unwrap() += 1;
            for bad in [vec![0; len], order.clone(), order_plus_1] {
                assert_eq!(
                    PrivateKey::<C>::from_bytes(&bad).unwrap_err(),
                    Error::InvalidPrivateKey
                );
            }
            // All ones is above the order on every curve, and the largest
            // number below it is fine.
            assert!(PrivateKey::<C>::from_bytes(&vec![0xff; len]).is_err());
            assert!(PrivateKey::<C>::from_bytes(&order_minus_1).is_ok());
        }
        for (curve, order) in ORDERS {
            for_curve!(curve, C => check::<C>(order));
        }
    }

    #[test]
    fn rejects_invalid_public_keys() {
        fn check<C: Curve>(valid: &str) {
            let valid = unhex(valid);
            assert!(PublicKey::<C>::from_bytes(&valid).is_ok());
            for bad in [0, 1, C::PUBLIC_KEY_LEN - 1, C::PUBLIC_KEY_LEN + 1, 200] {
                assert_eq!(
                    PublicKey::<C>::from_bytes(&vec![0x04; bad]).unwrap_err(),
                    Error::InvalidPublicKey,
                    "{bad} bytes for {}",
                    C::NAME
                );
            }
            // A valid point stops being one when its tag, or a coordinate,
            // changes. (Tag 0 is the point at infinity; 2 and 3 compressed.)
            for tag in [0, 1, 2, 3, 5, 6, 7] {
                let mut bytes = valid.clone();
                bytes[0] = tag;
                assert!(PublicKey::<C>::from_bytes(&bytes).is_err(), "tag {tag}");
            }
            for position in [
                1,
                C::PUBLIC_KEY_LEN / 2,
                C::PUBLIC_KEY_LEN / 2 + 1,
                C::PUBLIC_KEY_LEN - 1,
            ] {
                let mut bytes = valid.clone();
                bytes[position] ^= 1;
                assert!(
                    PublicKey::<C>::from_bytes(&bytes).is_err(),
                    "byte {position}"
                );
            }
            // Coordinates of 0xff..ff are above every prime here.
            let mut bytes = vec![0xff; C::PUBLIC_KEY_LEN];
            bytes[0] = 4;
            assert!(PublicKey::<C>::from_bytes(&bytes).is_err());
        }
        for row in RFC6979.iter().filter(|row| row.hash == "SHA-256") {
            for_curve!(row.curve, C => check::<C>(row.public));
        }
    }

    #[test]
    fn rejects_invalid_signatures() {
        fn check<C: Curve>(order: &str) {
            let len = C::PRIVATE_KEY_LEN;
            let order = unhex(order);
            let mut one = vec![0; len];
            one[len - 1] = 1;
            let join = |r: &[u8], s: &[u8]| [r, s].concat();
            let zero = vec![0; len];

            assert!(Signature::<C>::from_bytes(&join(&one, &one)).is_ok());
            let mut order_minus_1 = order.clone();
            *order_minus_1.last_mut().unwrap() -= 1;
            assert!(Signature::<C>::from_bytes(&join(&order_minus_1, &order_minus_1)).is_ok());

            for bad in [
                join(&zero, &one),
                join(&one, &zero),
                join(&order, &one),
                join(&one, &order),
                join(&vec![0xff; len], &one),
                join(&one, &vec![0xff; len]),
                vec![],
                vec![1; 2 * len - 1],
                vec![1; 2 * len + 1],
                one.clone(),
            ] {
                assert_eq!(
                    Signature::<C>::from_bytes(&bad).unwrap_err(),
                    Error::InvalidSignature,
                    "{bad:02x?}"
                );
                // The same numbers in DER are refused for the same reason (the
                // ones that DER can express at all).
                if bad.len() == 2 * len {
                    let mut der = vec![0x30];
                    let body = [&integer(&bad[..len])[..], &integer(&bad[len..])[..]].concat();
                    der.push(body.len() as u8);
                    der.extend(body);
                    assert!(Signature::<C>::from_der(&der).is_err(), "{bad:02x?}");
                }
            }
        }
        /// An INTEGER holding the big-endian number `bytes` (no padding rules
        /// followed beyond the top bit; the zero and the long ones are the
        /// point of the test). At most 127 bytes, so one length byte.
        fn integer(bytes: &[u8]) -> Vec<u8> {
            let first = bytes
                .iter()
                .position(|&b| b != 0)
                .unwrap_or(bytes.len() - 1);
            let digits = &bytes[first..];
            let mut out = vec![2, 0];
            if digits[0] & 0x80 != 0 {
                out.push(0);
            }
            out.extend(digits);
            out[1] = (out.len() - 2) as u8;
            out
        }
        for (curve, order) in ORDERS {
            for_curve!(curve, C => check::<C>(order));
        }
    }

    /// The sizes of a signature in DER that the documentation gives: from 8 bytes
    /// (`r = s = 1`) to the size of `(n - 1, n - 1)`, the largest numbers there are.
    /// P-521 is the one that does not need a zero byte in front of its numbers,
    /// because its order starts with a byte below 0x80.
    #[test]
    fn der_sizes_are_the_documented_ones() {
        fn check<C: Curve>(order: &str, largest: usize) {
            let len = C::PRIVATE_KEY_LEN;
            let mut n_minus_1 = unhex(order);
            *n_minus_1.last_mut().unwrap() -= 1;
            let signature =
                Signature::<C>::from_bytes(&[n_minus_1.clone(), n_minus_1].concat()).unwrap();
            assert_eq!(signature.to_der().len(), largest, "{}", C::NAME);

            let mut one = vec![0; len];
            one[len - 1] = 1;
            let smallest = Signature::<C>::from_bytes(&[one.clone(), one].concat()).unwrap();
            assert_eq!(smallest.to_der().len(), 8, "{}", C::NAME);
        }
        for (curve, order) in ORDERS {
            let largest = match curve {
                "P-224" => 64,
                "P-256" => 72,
                "P-384" => 104,
                "P-521" => 139,
                other => panic!("{other}"),
            };
            for_curve!(curve, C => check::<C>(order, largest));
        }
    }

    #[test]
    fn encoding_lengths() {
        fn check<C: Curve>(private: usize, public: usize, signature: usize) {
            assert_eq!(C::PRIVATE_KEY_LEN, private, "{}", C::NAME);
            assert_eq!(C::PUBLIC_KEY_LEN, public, "{}", C::NAME);
            assert_eq!(C::SIGNATURE_LEN, signature, "{}", C::NAME);
            assert!(private <= MAX_PRIVATE_KEY_LEN);
            assert!(public <= MAX_PUBLIC_KEY_LEN);
            assert!(signature <= MAX_SIGNATURE_LEN);
        }
        check::<P224>(28, 57, 56);
        check::<P256>(32, 65, 64);
        check::<P384>(48, 97, 96);
        check::<P521>(66, 133, 132);
        assert_eq!(<P224 as Curve>::NAME, "P-224");
        assert_eq!(<P256 as Curve>::NAME, "P-256");
        assert_eq!(<P384 as Curve>::NAME, "P-384");
        assert_eq!(<P521 as Curve>::NAME, "P-521");
    }

    #[test]
    fn generate_draws_one_key_from_the_reader() {
        let bytes: Vec<u8> = (1..=66).collect();

        // A valid key is used as it comes, and nothing more than its length is read.
        for (len, expect_left) in [(28, 66 - 28), (32, 66 - 32), (48, 66 - 48)] {
            let mut reader = Script(&bytes);
            let key = match len {
                28 => PrivateKey::<P224>::generate(&mut reader)
                    .unwrap()
                    .as_bytes()
                    .to_vec(),
                32 => PrivateKey::<P256>::generate(&mut reader)
                    .unwrap()
                    .as_bytes()
                    .to_vec(),
                _ => PrivateKey::<P384>::generate(&mut reader)
                    .unwrap()
                    .as_bytes()
                    .to_vec(),
            };
            assert_eq!(key, &bytes[..len]);
            assert_eq!(reader.0.len(), expect_left);
        }

        // Only P-521 masks the first byte: for the other curves every bit of it
        // is part of the key, the high one too.
        let mut high = bytes.clone();
        high[0] = 0xfe;
        let key = PrivateKey::<P256>::generate(&mut Script(&high)).unwrap();
        assert_eq!(key.as_bytes(), &high[..32]);
        let key = PrivateKey::<P224>::generate(&mut Script(&high)).unwrap();
        assert_eq!(key.as_bytes(), &high[..28]);

        // P-521 draws 66 bytes and keeps the leftmost 521 of their 528 bits:
        // the number shifted right by 7 (computed here as the integer divided
        // by 128, the bytes 1 to 66 giving this).
        let mut reader = Script(&bytes);
        let key = PrivateKey::<P521>::generate(&mut reader).unwrap();
        assert_eq!(
            key.as_bytes(),
            unhex(concat!(
                "00020406080a0c0e10121416181a1c1e20222426282a2c2e30323436383a3c3e4042",
                "4446484a4c4e50525456585a5c5e60626466686a6c6e70727476787a7c7e8082"
            ))
        );
        assert!(reader.0.is_empty());
        // A single bit in the 7th place from the right is the least significant
        // one that is kept.
        let mut low = vec![0; 66];
        low[65] = 0x80;
        assert_eq!(
            PrivateKey::<P521>::generate(&mut Script(&low))
                .unwrap()
                .as_bytes()[65],
            1
        );
    }

    #[test]
    fn generate_skips_candidates_that_are_not_keys() {
        let good: Vec<u8> = (1..=66).collect();

        // Zero, then the order itself, then a valid key.
        let order = unhex(ORDERS[1].1);
        let mut input = vec![0; 32];
        input.extend(&order);
        input.extend(&good[..32]);
        let mut reader = Script(&input);
        let key = PrivateKey::<P256>::generate(&mut reader).unwrap();
        assert_eq!(key.as_bytes(), &good[..32]);
        assert!(reader.0.is_empty(), "all three candidates were drawn");

        // For P-521, 0xff.. is shifted to 0x01ff..ff, above the order. Without
        // the shift a candidate would be too big about 99% of the time (it is a
        // number of 528 bits and the order has 521); with it, 5 << 7 becomes 5.
        let mut input = vec![0xff; 66];
        let mut small = vec![0; 66];
        small[64] = 0x02;
        small[65] = 0x80;
        input.extend(&small);
        let mut reader = Script(&input);
        let key = PrivateKey::<P521>::generate(&mut reader).unwrap();
        let mut expected = vec![0; 66];
        expected[65] = 5;
        assert_eq!(key.as_bytes(), expected);
        assert!(reader.0.is_empty(), "both candidates were drawn");
    }

    /// The random source of c2sp.org/det-keygen: an HMAC_DRBG on SHA-256, which
    /// gives the next bytes of its output to each read.
    struct Drbg(HmacDrbg<Sha256>);

    impl io::Read for Drbg {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.0.generate(buf);
            Ok(buf.len())
        }
    }

    /// Key generation from a seed, against the vectors of c2sp.org/det-keygen
    /// (made with OpenSSL's reading of the same keys). Among them are the
    /// P-256 seed that makes the first candidate overflow the order, so that
    /// generation draws again, and P-521, whose candidates are 521 of 528 bits.
    #[test]
    fn deterministic_key_generation_vectors() {
        fn check<C: Curve>(row: &DetKeygen) {
            let personalization = format!("det ECDSA key gen {}", C::NAME);
            let mut rng = Drbg(HmacDrbg::<Sha256>::new(
                &unhex(row.seed),
                personalization.as_bytes(),
                &[],
            ));
            let key = PrivateKey::<C>::generate(&mut rng).unwrap();
            assert_eq!(
                key.as_bytes(),
                unhex(row.private),
                "{} {}",
                row.curve,
                row.seed
            );
            assert_eq!(key.public_key().as_bytes(), unhex(row.public));
        }
        for row in &DET_KEYGEN {
            for_curve!(row.curve, C => check::<C>(row));
        }
        assert!(
            DET_KEYGEN
                .iter()
                .any(|row| row.seed == "b432f9be30890480298218510559aed7"),
            "the seed that makes P-256 draw twice"
        );
    }

    #[test]
    fn generate_reports_a_reader_that_fails() {
        // Too few bytes for a key.
        let error = PrivateKey::<P384>::generate(&mut Script(&[7; 47])).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
        // A refused candidate and then nothing.
        let error = PrivateKey::<P256>::generate(&mut Script(&[0; 32])).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn generate_gives_up_on_a_source_that_never_gives_a_key() {
        // Zero is not a key: 64 tries, then an error, not a loop.
        let mut zeros = Stuck { byte: 0, reads: 0 };
        let error = PrivateKey::<P256>::generate(&mut zeros).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(zeros.reads, 64);

        // All ones is masked to 0x01ff..ff for P-521, above the order.
        let mut ones = Stuck {
            byte: 0xff,
            reads: 0,
        };
        assert!(PrivateKey::<P521>::generate(&mut ones).is_err());
        assert_eq!(ones.reads, 64);
        let mut ones = Stuck {
            byte: 0xff,
            reads: 0,
        };
        assert!(PrivateKey::<P384>::generate(&mut ones).is_err());
    }

    /// A generated key signs, and the signature verifies under the public key
    /// that came with it.
    #[test]
    fn a_generated_key_works() {
        let noise: Vec<u8> = (0..200).map(|i| (i * 7 + 3) as u8).collect();
        let key = PrivateKey::<P384>::generate(&mut Script(&noise)).unwrap();
        let signature = key
            .sign::<Sha384, _>(&mut Script(&noise[48..]), b"hello")
            .unwrap();
        let public = PublicKey::<P384>::from_bytes(key.public_key().as_bytes()).unwrap();
        assert_eq!(public.verify::<Sha384>(b"hello", &signature), Ok(()));
    }

    #[test]
    fn equality_and_cloning() {
        let a = PrivateKey::<P256>::from_bytes(&[1; 32]).unwrap();
        let b = PrivateKey::<P256>::from_bytes(&[2; 32]).unwrap();
        assert_eq!(a, a.clone());
        assert_ne!(a, b);
        assert_eq!(a.public_key(), &a.public_key().clone());
        assert_ne!(a.public_key(), b.public_key());

        let s = a.sign_deterministic::<Sha256>(b"abc");
        assert_eq!(s, s.clone());
        assert_ne!(s, b.sign_deterministic::<Sha256>(b"abc"));
        assert_ne!(s, a.sign_deterministic::<Sha256>(b"abd"));
        assert_eq!(s.as_ref(), s.as_bytes());
    }

    /// A private key must leave no byte behind.
    #[test]
    fn dropping_wipes_the_private_key() {
        use core::mem::MaybeUninit;

        // One raw pointer does the dropping and the reading, so that the drop
        // does not invalidate the pointer the reads go through.
        let mut private = MaybeUninit::new(PrivateKey::<P384>::from_bytes(&[0x42; 48]).unwrap());
        let private = private.as_mut_ptr();
        // SAFETY: `private` is a valid pointer to the live key; this takes the
        // address of a field and reads nothing.
        let bytes = unsafe { &raw const (*private).bytes };
        let read = || {
            // SAFETY: the slot stays allocated, and every byte of the array was
            // written by `new` and then, if the drop works, by `wipe`.
            unsafe { bytes.read() }
        };
        assert!(read().iter().any(|&b| b != 0), "nothing to wipe");
        // SAFETY: the key is initialised and dropped only here.
        unsafe { private.drop_in_place() };
        assert!(
            read().iter().all(|&b| b == 0),
            "the private key survives the drop"
        );
    }

    #[test]
    fn debug_hides_the_secrets() {
        let row = RFC6979
            .iter()
            .find(|row| row.curve == "P-256" && row.hash == "SHA-256" && row.message == "sample")
            .unwrap();
        let private = PrivateKey::<P256>::from_bytes(&unhex(row.private)).unwrap();
        assert_eq!(format!("{private:?}"), "PrivateKey<P-256> { .. }");

        // A public key and a signature are public, and show.
        assert_eq!(
            format!("{:?}", private.public_key()),
            format!("PublicKey<P-256>({})", row.public)
        );
        let signature = private.sign_deterministic::<Sha256>(row.message.as_bytes());
        assert_eq!(
            format!("{signature:?}"),
            format!("Signature<P-256>({}{})", row.r, row.s)
        );
    }

    /// Hash types that are not the ones of the standards' examples work too:
    /// SHA-224 with P-256 (a hash shorter than the order) and the digest of a
    /// hash longer than the order.
    #[test]
    fn any_digest_hash_works() {
        let key = PrivateKey::<P256>::from_bytes(&scalar(32, 2)).unwrap();
        let signature = key.sign_deterministic::<Sha224>(b"abc");
        assert_eq!(
            key.public_key().verify::<Sha224>(b"abc", &signature),
            Ok(())
        );
        let signature = key.sign_deterministic::<crate::sha2::Sha512>(b"abc");
        assert_eq!(
            key.public_key()
                .verify::<crate::sha2::Sha512>(b"abc", &signature),
            Ok(())
        );
    }

    /// A cheap source of bytes for the randomized signature, so that the time
    /// measured is the signing and not the system's random source.
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
    #[ignore = "manual throughput check: cargo test --release ecdsa:: -- --ignored --nocapture --test-threads=1"]
    fn throughput() {
        use std::hint::black_box;
        use std::time::{Duration, Instant};

        /// The best of five batches of `op`, in microseconds per call, after a
        /// warm-up call (which also builds the table of multiples of the
        /// generator, once) and a pass to size the batches to about 100 ms.
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

        fn run<C: Curve, D: Digest>() {
            let private = scalar(C::PRIVATE_KEY_LEN, 11);
            let key = PrivateKey::<C>::from_bytes(&private).unwrap();
            let public = key.public_key().as_bytes().to_vec();
            let public_key = PublicKey::<C>::from_bytes(&public).unwrap();

            // The message is hashed once, outside the timed calls: both sides sign
            // and verify a digest. The signature is DER, which is what a program
            // sends and receives, so encoding and decoding it is part of the work.
            let message: Vec<u8> = (0..64).collect();
            let digest = D::digest(&message);
            let digest = digest.as_ref();
            let der = key
                .sign_prehash_deterministic::<D>(digest)
                .unwrap()
                .to_der();
            let mut noise = Noise(0x9e37_79b9_7f4a_7c15);

            let rows = [
                (
                    "new private key",
                    time(|| {
                        drop(black_box(
                            PrivateKey::<C>::from_bytes(black_box(&private)).unwrap(),
                        ))
                    }),
                ),
                (
                    "new public key",
                    time(|| {
                        black_box(PublicKey::<C>::from_bytes(black_box(&public)).unwrap());
                    }),
                ),
                (
                    "sign",
                    time(|| {
                        let signature = key.sign_prehash(&mut noise, black_box(digest)).unwrap();
                        black_box(signature.to_der());
                    }),
                ),
                (
                    "sign deterministic",
                    time(|| {
                        let signature = key
                            .sign_prehash_deterministic::<D>(black_box(digest))
                            .unwrap();
                        black_box(signature.to_der());
                    }),
                ),
                (
                    "verify",
                    time(|| {
                        let signature = Signature::<C>::from_der(black_box(&der)).unwrap();
                        public_key
                            .verify_prehash(black_box(digest), &signature)
                            .unwrap();
                    }),
                ),
            ];
            for (name, micros) in rows {
                println!(
                    "{} {name} [cryptors]: best {micros:.1} us/op, {:.0} ops/s (signature {}...)",
                    C::NAME,
                    1e6 / micros,
                    hex(&der[..8])
                );
            }
        }

        run::<P224, Sha256>();
        run::<P256, Sha256>();
        run::<P384, Sha384>();
        run::<P521, crate::sha2::Sha512>();
    }
}
