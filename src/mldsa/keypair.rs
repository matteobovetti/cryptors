//! Private keys, public keys and signatures, and the operations on them.

use super::algorithm::{
    Expanded, key_gen, message_representative, public_key_hash, sign as sign_mu_internal,
    verify as verify_mu_internal,
};
use super::error::Error;
use super::pack::unpack_hint;
use super::params::{Parameters, SEED_LEN};
use super::prehash::PreHash;
use crate::ec::ct;
use crate::wipe::wipe;
use core::fmt;
use core::marker::PhantomData;
use std::io;

/// The longest context that FIPS 204 allows, in bytes.
pub const MAX_CONTEXT_LEN: usize = 255;

/// A private key of the parameter set `P`: the secret that signs.
///
/// It is the 32-byte seed of FIPS 204's `ML-DSA.KeyGen`, and it holds what the
/// seed expands to (the matrix `A`, the secret vectors `s1` and `s2` and `t0`,
/// in the form that signing multiplies by), so that signing does not make
/// them again, and the public key that goes with it. The expanded form takes
/// 28 KiB for ML-DSA-44, 47 KiB for ML-DSA-65 and 79 KiB for ML-DSA-87, on the
/// heap.
///
/// The seed and the secret vectors are overwritten with zeros when the key is
/// dropped, and `Debug` does not show them. That is best effort: the working
/// values of the arithmetic (numbers that depend on the key, on the stack and in
/// registers while it is in use) are not all overwritten, and neither is the copy
/// that moving a key (into a `Box` or a `Vec`, say) can leave behind where it was.
pub struct PrivateKey<P: Parameters> {
    seed: [u8; SEED_LEN],
    expanded: Expanded<P>,
    public: PublicKey<P>,
}

/// A public key of the parameter set `P`: what a verifier needs to know.
///
/// Every byte string of the right length is a public key, so holding one means
/// only that. The key holds its encoding and the hash of it that every message
/// representative starts with.
pub struct PublicKey<P: Parameters> {
    bytes: Box<[u8]>,
    /// `tr`, the hash of the encoding (FIPS 204, algorithm 6, line 10).
    tr: [u8; 64],
    parameters: PhantomData<P>,
}

/// A signature of the parameter set `P`.
///
/// Holding one means that the bytes are as long as a signature of the set is and
/// that the hint at the end is encoded the one way that FIPS 204 allows.
/// That the signature is a signature of anything is for
/// [`PublicKey::verify`] to say.
pub struct Signature<P: Parameters> {
    bytes: Box<[u8]>,
    parameters: PhantomData<P>,
}

/// `M'` of a signature of a message: `0 || |ctx| || ctx || M` (algorithm 2,
/// line 10), hashed with the public key's hash into `mu`.
fn pure_mu(tr: &[u8; 64], message: &[u8], context: &[u8]) -> Result<[u8; 64], Error> {
    let Ok(len) = u8::try_from(context.len()) else {
        return Err(Error::ContextTooLong);
    };
    Ok(message_representative(tr, &[&[0, len], context, message]))
}

/// `M'` of a signature of a digest: `1 || |ctx| || ctx || OID || PH(M)`
/// (algorithm 4, line 23).
fn prehash_mu(
    tr: &[u8; 64],
    hash: PreHash,
    digest: &[u8],
    context: &[u8],
) -> Result<[u8; 64], Error> {
    let Ok(len) = u8::try_from(context.len()) else {
        return Err(Error::ContextTooLong);
    };
    if digest.len() != hash.digest_len() {
        return Err(Error::InvalidDigest);
    }
    Ok(message_representative(
        tr,
        &[&[1, len], context, &hash.oid(), digest],
    ))
}

fn invalid_input(error: Error) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, error)
}

impl<P: Parameters> PrivateKey<P> {
    /// Generates a key from `rng`, which has to be a source of cryptographically
    /// secure random bytes: the secrecy of everything that follows depends on
    /// it. The standard library has none that is stable, so this takes any
    /// reader; on Unix, `File::open("/dev/urandom")` is one.
    ///
    /// It reads the 32 bytes of the seed `xi` (`ML-DSA.KeyGen`, FIPS 204
    /// algorithm 1) and expands them with [`from_seed`](Self::from_seed).
    ///
    /// # Errors
    ///
    /// Whatever `rng` fails with.
    pub fn generate<R: io::Read + ?Sized>(rng: &mut R) -> io::Result<Self> {
        let mut seed = [0u8; SEED_LEN];
        let result = rng.read_exact(&mut seed).map(|()| Self::from_seed(&seed));
        wipe(&mut seed);
        result
    }

    /// The key that a seed makes (`ML-DSA.KeyGen_internal`, FIPS 204 algorithm
    /// 6). Any 32 bytes are a seed. The same seed gives the same key, on every
    /// platform and in every implementation of FIPS 204.
    pub fn from_seed(seed: &[u8; SEED_LEN]) -> Self {
        let (expanded, public_key) = key_gen::<P>(seed);
        let tr = expanded.tr;
        Self {
            seed: *seed,
            expanded,
            public: PublicKey {
                bytes: public_key.into_boxed_slice(),
                tr,
                parameters: PhantomData,
            },
        }
    }

    /// The seed: the whole private key in 32 bytes, in the form
    /// [`from_seed`](Self::from_seed) takes. Keep it secret.
    pub fn seed(&self) -> &[u8; SEED_LEN] {
        &self.seed
    }

    /// The public key that verifies this key's signatures.
    pub fn public_key(&self) -> &PublicKey<P> {
        &self.public
    }

    /// What signing works from, for the tests that check it.
    #[cfg(test)]
    pub(super) fn expanded(&self) -> &Expanded<P> {
        &self.expanded
    }

    /// Signs `message` under `context` (0 to 255 bytes) with a hedged
    /// signature, the default of FIPS 204 (`ML-DSA.Sign`, algorithm 2): `rng`
    /// supplies 32 bytes, `rnd`, that go into the masks of the signature.
    ///
    /// Two signatures of the same message differ. If `rng` is bad, even a
    /// constant, the signature is still as strong as a [deterministic] one:
    /// the masks come from the private key and the message too. A good `rng`
    /// is what protects against an attacker who can induce faults in the
    /// computation, which a deterministic signature leaves open.
    ///
    /// The context separates the uses of a key: a signature made under one
    /// context does not verify under another. It is empty unless an
    /// application says otherwise, and the verifier has to use the same one.
    ///
    /// ```
    /// use cryptors::mldsa::{MlDsa65, PrivateKey};
    ///
    /// let key = PrivateKey::<MlDsa65>::from_seed(&[7; 32]);
    /// // A fixed string of "random" bytes, which a real program does not use.
    /// let mut rng: &[u8] = &[42; 32];
    /// let signature = key.sign(&mut rng, b"a message", b"my protocol, v1")?;
    ///
    /// assert!(key.public_key().verify(b"a message", b"my protocol, v1", &signature).is_ok());
    /// assert!(key.public_key().verify(b"a message", b"my protocol, v2", &signature).is_err());
    /// # Ok::<(), std::io::Error>(())
    /// ```
    ///
    /// [deterministic]: PrivateKey::sign_deterministic
    ///
    /// # Errors
    ///
    /// Whatever `rng` fails with, and
    /// [`InvalidInput`](io::ErrorKind::InvalidInput) (carrying
    /// [`Error::ContextTooLong`]) for a context of more than 255 bytes.
    pub fn sign<R: io::Read + ?Sized>(
        &self,
        rng: &mut R,
        message: &[u8],
        context: &[u8],
    ) -> io::Result<Signature<P>> {
        let mu = pure_mu(&self.public.tr, message, context).map_err(invalid_input)?;
        self.sign_mu(rng, &mu)
    }

    /// Signs `message` under `context` with a deterministic signature
    /// (`ML-DSA.Sign` with `rnd` all zeros, as FIPS 204 allows): the same key,
    /// message and context give the same signature every time, and no random
    /// source is needed, so a failing one cannot hurt.
    ///
    /// The price is that the computation is the same every time too: an
    /// attacker who can induce a fault in one of two computations of the same
    /// signature may learn something about the key from the difference.
    /// [`sign`](PrivateKey::sign) mixes in fresh randomness against that.
    ///
    /// # Errors
    ///
    /// [`Error::ContextTooLong`] for a context of more than 255 bytes.
    pub fn sign_deterministic(
        &self,
        message: &[u8],
        context: &[u8],
    ) -> Result<Signature<P>, Error> {
        let mu = pure_mu(&self.public.tr, message, context)?;
        Ok(self.sign_mu_deterministic(&mu))
    }

    /// Signs the digest of a message with HashML-DSA (FIPS 204 algorithm 4), with
    /// a hedged signature as [`sign`](PrivateKey::sign) makes: `digest` is the
    /// output of `hash` on the message, which the caller computes (with
    /// [`PreHash::digest`] if it has the whole message), and it is the digest and
    /// the identifier of `hash` that are signed.
    ///
    /// FIPS 204 prefers the signature of the message itself (section 5.4): use
    /// this where the message is too large or too secret to be sent to the
    /// signer, or where the hash is done elsewhere.
    ///
    /// # Errors
    ///
    /// Whatever `rng` fails with, and
    /// [`InvalidInput`](io::ErrorKind::InvalidInput) (carrying
    /// [`Error::ContextTooLong`] or [`Error::InvalidDigest`]) for a context of
    /// more than 255 bytes or a digest that is not [`PreHash::digest_len`]
    /// bytes.
    pub fn sign_prehash<R: io::Read + ?Sized>(
        &self,
        rng: &mut R,
        hash: PreHash,
        digest: &[u8],
        context: &[u8],
    ) -> io::Result<Signature<P>> {
        let mu = prehash_mu(&self.public.tr, hash, digest, context).map_err(invalid_input)?;
        self.sign_mu(rng, &mu)
    }

    /// As [`sign_prehash`](PrivateKey::sign_prehash), with a deterministic
    /// signature as [`sign_deterministic`](PrivateKey::sign_deterministic)
    /// makes.
    ///
    /// # Errors
    ///
    /// [`Error::ContextTooLong`] or [`Error::InvalidDigest`].
    pub fn sign_prehash_deterministic(
        &self,
        hash: PreHash,
        digest: &[u8],
        context: &[u8],
    ) -> Result<Signature<P>, Error> {
        let mu = prehash_mu(&self.public.tr, hash, digest, context)?;
        Ok(self.sign_mu_deterministic(&mu))
    }

    /// Signs a message representative `mu` that the caller computed (with
    /// [`PublicKey::message_representative`]) with a hedged signature: the
    /// "external mu" mode of RFC 9881 (appendix D), in which the message is hashed
    /// where it is, and only 64 bytes go to the signer.
    ///
    /// The signature is the one that [`sign`](PrivateKey::sign) makes for the
    /// message and context that `mu` stands for.
    ///
    /// # Errors
    ///
    /// Whatever `rng` fails with.
    pub fn sign_mu<R: io::Read + ?Sized>(
        &self,
        rng: &mut R,
        mu: &[u8; 64],
    ) -> io::Result<Signature<P>> {
        let mut rnd = [0u8; 32];
        let read = rng.read_exact(&mut rnd);
        let signature = read.map(|()| self.sign_with(mu, &rnd));
        wipe(&mut rnd);
        signature
    }

    /// As [`sign_mu`](PrivateKey::sign_mu), with a deterministic signature.
    pub fn sign_mu_deterministic(&self, mu: &[u8; 64]) -> Signature<P> {
        self.sign_with(mu, &[0; 32])
    }

    fn sign_with(&self, mu: &[u8; 64], rnd: &[u8; 32]) -> Signature<P> {
        Signature {
            bytes: sign_mu_internal(&self.expanded, mu, rnd).into_boxed_slice(),
            parameters: PhantomData,
        }
    }
}

impl<P: Parameters> PublicKey<P> {
    /// Reads a public key from its encoding (FIPS 204 algorithm 22, `pkEncode`):
    /// the 32 bytes `rho` and the 10-bit coefficients of `t1`, as long as
    /// [`Parameters::PUBLIC_KEY_LEN`].
    ///
    /// # Errors
    ///
    /// [`Error::InvalidPublicKey`] if `bytes` has any other length.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != P::PUBLIC_KEY_LEN {
            return Err(Error::InvalidPublicKey);
        }
        Ok(Self {
            bytes: bytes.into(),
            tr: public_key_hash(bytes),
            parameters: PhantomData,
        })
    }

    /// The encoding of the key, in the form [`from_bytes`](Self::from_bytes) takes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// The message representative `mu` of `message` under `context`, which
    /// starts from the hash of this public key (FIPS 204 algorithm 2 line 6), as
    /// [`PrivateKey::sign_mu`] and [`verify_mu`](Self::verify_mu) take it.
    ///
    /// # Errors
    ///
    /// [`Error::ContextTooLong`] for a context of more than 255 bytes.
    pub fn message_representative(
        &self,
        message: &[u8],
        context: &[u8],
    ) -> Result<[u8; 64], Error> {
        pure_mu(&self.tr, message, context)
    }

    /// Verifies that `signature` is a signature of `message` under `context`
    /// by this key's private key (`ML-DSA.Verify`, FIPS 204 algorithm 3).
    ///
    /// ```
    /// use cryptors::mldsa::{Error, MlDsa44, PrivateKey, PublicKey};
    ///
    /// let key = PrivateKey::<MlDsa44>::from_seed(&[1; 32]);
    /// let signature = key.sign_deterministic(b"message", b"")?;
    ///
    /// let public = PublicKey::<MlDsa44>::from_bytes(key.public_key().as_bytes())?;
    /// assert_eq!(public.verify(b"message", b"", &signature), Ok(()));
    /// assert_eq!(public.verify(b"massage", b"", &signature), Err(Error::VerificationFailed));
    /// # Ok::<(), Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::ContextTooLong`] for a context of more than 255 bytes, and
    /// [`Error::VerificationFailed`] if the signature is not of this message by
    /// this key.
    pub fn verify(
        &self,
        message: &[u8],
        context: &[u8],
        signature: &Signature<P>,
    ) -> Result<(), Error> {
        let mu = pure_mu(&self.tr, message, context)?;
        self.verify_mu(&mu, signature)
    }

    /// Verifies a signature made with HashML-DSA (FIPS 204 algorithm 5), as
    /// [`PrivateKey::sign_prehash`] makes: `digest` is the output of `hash` on the
    /// message, and both have to be the signer's.
    ///
    /// # Errors
    ///
    /// [`Error::ContextTooLong`], [`Error::InvalidDigest`] and
    /// [`Error::VerificationFailed`].
    pub fn verify_prehash(
        &self,
        hash: PreHash,
        digest: &[u8],
        context: &[u8],
        signature: &Signature<P>,
    ) -> Result<(), Error> {
        let mu = prehash_mu(&self.tr, hash, digest, context)?;
        self.verify_mu(&mu, signature)
    }

    /// Verifies that `signature` is a signature of the message representative
    /// `mu`, as [`message_representative`](Self::message_representative) makes
    /// it.
    ///
    /// # Errors
    ///
    /// [`Error::VerificationFailed`].
    pub fn verify_mu(&self, mu: &[u8; 64], signature: &Signature<P>) -> Result<(), Error> {
        if verify_mu_internal::<P>(&self.bytes, mu, &signature.bytes) {
            Ok(())
        } else {
            Err(Error::VerificationFailed)
        }
    }
}

impl<P: Parameters> Signature<P> {
    /// Reads a signature from its encoding (FIPS 204 algorithm 26, `sigEncode`):
    /// the commitment hash, the packed vector `z` and the hint, as long as
    /// [`Parameters::SIGNATURE_LEN`].
    ///
    /// # Errors
    ///
    /// [`Error::InvalidSignature`] if `bytes` has any other length, or if the hint
    /// is not encoded as FIPS 204 requires (algorithm 21, `HintBitUnpack`).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != P::SIGNATURE_LEN {
            return Err(Error::InvalidSignature);
        }
        let hint = &bytes[P::SIGNATURE_LEN - P::HINT_LEN..];
        if unpack_hint::<P>(hint).is_none() {
            return Err(Error::InvalidSignature);
        }
        Ok(Self {
            bytes: bytes.into(),
            parameters: PhantomData,
        })
    }

    /// The encoding of the signature, in the form [`from_bytes`](Self::from_bytes)
    /// takes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl<P: Parameters> Drop for PrivateKey<P> {
    fn drop(&mut self) {
        wipe(&mut self.seed);
        self.expanded.wipe_secrets();
    }
}

impl<P: Parameters> Clone for PrivateKey<P> {
    fn clone(&self) -> Self {
        Self {
            seed: self.seed,
            expanded: self.expanded.clone(),
            public: self.public.clone(),
        }
    }
}

impl<P: Parameters> Clone for PublicKey<P> {
    fn clone(&self) -> Self {
        Self {
            bytes: self.bytes.clone(),
            tr: self.tr,
            parameters: PhantomData,
        }
    }
}

impl<P: Parameters> Clone for Signature<P> {
    fn clone(&self) -> Self {
        Self {
            bytes: self.bytes.clone(),
            parameters: PhantomData,
        }
    }
}

/// Compares in constant time: two private keys are equal if their seeds are, and
/// the time it takes does not say where they differ.
impl<P: Parameters> PartialEq for PrivateKey<P> {
    fn eq(&self, other: &Self) -> bool {
        ct::bytes_eq(&self.seed, &other.seed)
    }
}

impl<P: Parameters> Eq for PrivateKey<P> {}

/// Two public keys are equal if their encodings are.
impl<P: Parameters> PartialEq for PublicKey<P> {
    fn eq(&self, other: &Self) -> bool {
        self.bytes == other.bytes
    }
}

impl<P: Parameters> Eq for PublicKey<P> {}

impl<P: Parameters> PartialEq for Signature<P> {
    fn eq(&self, other: &Self) -> bool {
        self.bytes == other.bytes
    }
}

impl<P: Parameters> Eq for Signature<P> {}

impl<P: Parameters> TryFrom<&[u8]> for PublicKey<P> {
    type Error = Error;

    fn try_from(bytes: &[u8]) -> Result<Self, Error> {
        Self::from_bytes(bytes)
    }
}

impl<P: Parameters> TryFrom<&[u8]> for Signature<P> {
    type Error = Error;

    fn try_from(bytes: &[u8]) -> Result<Self, Error> {
        Self::from_bytes(bytes)
    }
}

impl<P: Parameters> fmt::Debug for PrivateKey<P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PrivateKey<{}> {{ .. }}", P::NAME)
    }
}

/// Shows the first bytes of the hash of the key, which is enough to tell keys
/// apart in a log, and not the 1312 to 2592 bytes of the key.
impl<P: Parameters> fmt::Debug for PublicKey<P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PublicKey<{}> {{ tr: ", P::NAME)?;
        for byte in &self.tr[..8] {
            write!(f, "{byte:02x}")?;
        }
        f.write_str("... }")
    }
}

impl<P: Parameters> fmt::Debug for Signature<P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Signature<{}>({} bytes)", P::NAME, self.bytes.len())
    }
}

#[cfg(test)]
mod tests {
    use super::super::params::{MlDsa44, MlDsa65, MlDsa87};
    use super::super::testutil::hex;
    use super::*;
    use crate::sha3::Shake128;

    /// The "accumulated" known answers of C2SP's CCTV (`ML-DSA/accumulated`): a
    /// stream of seeds from SHAKE128, a key made from each, the deterministic
    /// signature of the empty message, both written to a second SHAKE128 whose
    /// first 32 bytes are compared. Every signature is verified on the way.
    fn accumulated<P: Parameters>(rounds: usize, expected: &str) {
        let mut seeds = Shake128::new();
        let mut out = Shake128::new();
        let mut seed = [0u8; SEED_LEN];
        for _ in 0..rounds {
            seeds.read(&mut seed);
            let key = PrivateKey::<P>::from_seed(&seed);
            let public = key.public_key().as_bytes();
            out.absorb(public);
            let signature = key.sign_deterministic(b"", b"").unwrap();
            out.absorb(signature.as_bytes());
            let reread = PublicKey::<P>::from_bytes(public).unwrap();
            assert_eq!(reread.verify(b"", b"", &signature), Ok(()));
        }
        let mut sum = [0u8; 32];
        out.read(&mut sum);
        assert_eq!(hex(&sum), expected, "{}", P::NAME);
    }

    #[test]
    fn accumulated_100() {
        accumulated::<MlDsa44>(
            100,
            "d51148e1f9f4fa1a723a6cf42e25f2a99eb5c1b378b3d2dbbd561b1203beeae4",
        );
        accumulated::<MlDsa65>(
            100,
            "8358a1843220194417cadbc2651295cd8fc65125b5a5c1a239a16dc8b57ca199",
        );
        accumulated::<MlDsa87>(
            100,
            "8c3ad714777622b8f21ce31bb35f71394f23bc0fcf3c78ace5d608990f3b061b",
        );
    }

    #[test]
    #[ignore = "ten thousand keys and signatures on each set: cargo test --release mldsa:: -- --ignored"]
    fn accumulated_10000() {
        accumulated::<MlDsa44>(
            10_000,
            "e7fd21f6a59bcba60d65adc44404bb29a7c00e5d8d3ec06a732c00a306a7d143",
        );
        accumulated::<MlDsa65>(
            10_000,
            "5ff5e196f0b830c3b10a9eb5358e7c98a3a20136cb677f3ae3b90175c3ace329",
        );
        accumulated::<MlDsa87>(
            10_000,
            "80a8cf39317f7d0be0e24972c51ac152bd2a3e09bc0c32ce29dd82c4e7385e60",
        );
    }

    use super::super::algorithm::sign as sign_internal;
    use crate::sha3::shake256;
    use crate::wipe::bytes_around_drop;

    const ALL_HASHES: [PreHash; 12] = [
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

    /// Runs `$body` once for each parameter set, with `$p` naming it.
    macro_rules! each_set {
        ($p:ident => $body:block) => {{
            fn run<$p: Parameters>() $body
            run::<MlDsa44>();
            run::<MlDsa65>();
            run::<MlDsa87>();
        }};
    }

    /// A reader that fails.
    struct Broken;

    impl io::Read for Broken {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::other("no entropy"))
        }
    }

    fn key_of<P: Parameters>(byte: u8) -> PrivateKey<P> {
        PrivateKey::from_seed(&core::array::from_fn(|i| byte.wrapping_add(i as u8)))
    }

    #[test]
    fn sizes() {
        each_set!(P => {
            let key = key_of::<P>(1);
            assert_eq!(key.public_key().as_bytes().len(), P::PUBLIC_KEY_LEN);
            let signature = key.sign_deterministic(b"m", b"").unwrap();
            assert_eq!(signature.as_bytes().len(), P::SIGNATURE_LEN);
            assert_eq!(key.seed().len(), SEED_LEN);
        });
    }

    /// The ways to sign one message and context make one signature or related
    /// ones: a hedged signature with `rnd` all zeros is the deterministic one;
    /// signing the representative is signing the message; and the 32 bytes of
    /// `rnd` are the first 32 that the reader gives, and no more.
    #[test]
    fn modes_agree() {
        each_set!(P => {
            let key = key_of::<P>(2);
            let public = key.public_key();
            let (message, context) = (b"the message".as_slice(), b"the context".as_slice());
            let deterministic = key.sign_deterministic(message, context).unwrap();
            assert_eq!(public.verify(message, context, &deterministic), Ok(()));

            let mut zeros: &[u8] = &[0; 40];
            assert_eq!(key.sign(&mut zeros, message, context).unwrap(), deterministic);
            assert_eq!(zeros.len(), 8, "reads exactly 32 bytes");

            let mu = public.message_representative(message, context).unwrap();
            assert_eq!(key.sign_mu_deterministic(&mu), deterministic);
            assert_eq!(public.verify_mu(&mu, &deterministic), Ok(()));

            let rnd: [u8; 32] = core::array::from_fn(|i| i as u8 + 1);
            let mut reader: &[u8] = &rnd;
            let hedged = key.sign(&mut reader, message, context).unwrap();
            assert_ne!(hedged, deterministic);
            assert_eq!(public.verify(message, context, &hedged), Ok(()));
            assert_eq!(hedged.as_bytes(), sign_internal(key.expanded(), &mu, &rnd));
            let mut reader: &[u8] = &rnd;
            assert_eq!(key.sign_mu(&mut reader, &mu).unwrap(), hedged);

            // The same with the same bytes, and not with others.
            let mut reader: &[u8] = &[9; 32];
            let other = key.sign(&mut reader, message, context).unwrap();
            assert_ne!(other, hedged);
            assert_eq!(public.verify(message, context, &other), Ok(()));
        });
    }

    #[test]
    fn a_failing_reader_is_reported() {
        each_set!(P => {
            let key = key_of::<P>(3);
            assert_eq!(key.sign(&mut Broken, b"m", b"").unwrap_err().to_string(), "no entropy");
            assert_eq!(key.sign_mu(&mut Broken, &[0; 64]).unwrap_err().to_string(), "no entropy");
            assert_eq!(
                key.sign_prehash(&mut Broken, PreHash::Sha256, &[0; 32], b"")
                    .unwrap_err()
                    .to_string(),
                "no entropy"
            );
            assert_eq!(PrivateKey::<P>::generate(&mut Broken).unwrap_err().to_string(), "no entropy");
            // A reader that has fewer than 32 bytes ends early.
            let mut short: &[u8] = &[1; 31];
            let error = key.sign(&mut short, b"m", b"").unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
            let mut short: &[u8] = &[1; 31];
            assert_eq!(
                PrivateKey::<P>::generate(&mut short).unwrap_err().kind(),
                io::ErrorKind::UnexpectedEof
            );
        });
    }

    #[test]
    fn generate_reads_the_seed() {
        each_set!(P => {
            let bytes: [u8; 40] = core::array::from_fn(|i| (i * 7) as u8);
            let mut reader: &[u8] = &bytes;
            let key = PrivateKey::<P>::generate(&mut reader).unwrap();
            assert_eq!(reader.len(), 8);
            assert_eq!(key.seed(), &bytes[..32]);
            assert!(key == PrivateKey::<P>::from_seed(bytes[..32].try_into().unwrap()));
            assert!(key != key_of::<P>(0));
        });
    }

    /// The context is up to 255 bytes, and a signature binds it.
    #[test]
    fn context() {
        each_set!(P => {
            let key = key_of::<P>(4);
            let public = key.public_key();
            let longest = [b'c'; MAX_CONTEXT_LEN];
            let too_long = [b'c'; MAX_CONTEXT_LEN + 1];
            let signature = key.sign_deterministic(b"m", &longest).unwrap();
            assert_eq!(public.verify(b"m", &longest, &signature), Ok(()));
            assert_eq!(public.verify(b"m", &longest[..254], &signature), Err(Error::VerificationFailed));
            assert_eq!(public.verify(b"m", b"", &signature), Err(Error::VerificationFailed));

            assert_eq!(key.sign_deterministic(b"m", &too_long), Err(Error::ContextTooLong));
            assert_eq!(public.verify(b"m", &too_long, &signature), Err(Error::ContextTooLong));
            assert_eq!(public.message_representative(b"m", &too_long), Err(Error::ContextTooLong));
            assert_eq!(
                key.sign_prehash_deterministic(PreHash::Sha256, &[0; 32], &too_long),
                Err(Error::ContextTooLong)
            );
            assert_eq!(
                public.verify_prehash(PreHash::Sha256, &[0; 32], &too_long, &signature),
                Err(Error::ContextTooLong)
            );
            // The error from a randomized signature is an `InvalidInput` that
            // carries the module's error, and it asks nothing of the reader.
            let mut reader: &[u8] = &[1; 32];
            let error = key.sign(&mut reader, b"m", &too_long).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
            assert_eq!(
                error.get_ref().and_then(|e| e.downcast_ref::<Error>()),
                Some(&Error::ContextTooLong)
            );
            assert_eq!(reader.len(), 32);
            let error = key.sign_prehash(&mut reader, PreHash::Sha256, &[0; 32], &too_long).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
            assert_eq!(reader.len(), 32);
        });
    }

    /// A message of any length: around the rates of SHAKE256 and past many
    /// blocks of it.
    #[test]
    fn message_lengths() {
        let key = key_of::<MlDsa44>(5);
        let public = key.public_key();
        let message: Vec<u8> = (0..70_000).map(|i| (i * 31 % 251) as u8).collect();
        for len in [0, 1, 7, 8, 135, 136, 137, 271, 272, 273, 1000, 70_000] {
            let signature = key.sign_deterministic(&message[..len], b"").unwrap();
            assert_eq!(
                public.verify(&message[..len], b"", &signature),
                Ok(()),
                "{len}"
            );
            if len > 0 {
                assert!(
                    public.verify(&message[..len - 1], b"", &signature).is_err(),
                    "{len}"
                );
            }
        }
    }

    /// HashML-DSA: a signature of a digest binds the digest, the function and the
    /// context, and is not a signature of the message.
    #[test]
    fn prehash() {
        each_set!(P => {
            let key = key_of::<P>(6);
            let public = key.public_key();
            let message = b"a message to hash";
            for hash in ALL_HASHES {
                let digest = hash.digest(message);
                let signature = key.sign_prehash_deterministic(hash, &digest, b"ctx").unwrap();
                assert_eq!(public.verify_prehash(hash, &digest, b"ctx", &signature), Ok(()), "{hash:?}");
                assert!(public.verify_prehash(hash, &digest, b"", &signature).is_err());
                // Not as the message, nor as the message's digest.
                assert!(public.verify(message, b"ctx", &signature).is_err());
                assert!(public.verify(&digest, b"ctx", &signature).is_err());
                // Another function with a digest of the same size is another
                // signature: the identifier of the function is signed.
                for other in ALL_HASHES {
                    if other != hash && other.digest_len() == hash.digest_len() {
                        assert!(
                            public.verify_prehash(other, &digest, b"ctx", &signature).is_err(),
                            "{hash:?} as {other:?}"
                        );
                    }
                }
                // The hedged form agrees with the deterministic one for zero bytes.
                let mut zeros: &[u8] = &[0; 32];
                assert_eq!(
                    key.sign_prehash(&mut zeros, hash, &digest, b"ctx").unwrap(),
                    signature
                );
                // A digest of the wrong length is refused whatever the function.
                for wrong in [0, 1, hash.digest_len() - 1, hash.digest_len() + 1] {
                    assert_eq!(
                        key.sign_prehash_deterministic(hash, &vec![0; wrong], b""),
                        Err(Error::InvalidDigest)
                    );
                    assert_eq!(
                        public.verify_prehash(hash, &vec![0; wrong], b"", &signature),
                        Err(Error::InvalidDigest)
                    );
                }
                let mut reader: &[u8] = &[1; 32];
                let error = key
                    .sign_prehash(&mut reader, hash, &[], b"")
                    .unwrap_err();
                assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
                assert_eq!(reader.len(), 32);
            }
        });
    }

    /// The message `M'` that a signature signs, written out for each of the two
    /// kinds from algorithms 2 and 4, against the functions that build it.
    #[test]
    fn what_is_signed() {
        let key = key_of::<MlDsa65>(7);
        let tr = key.expanded().tr;
        let mu = |m_prime: &[u8]| {
            let mut xof = Vec::from(tr);
            xof.extend(m_prime);
            let mut out = [0u8; 64];
            shake256(&xof, &mut out);
            out
        };
        let context = b"ctx";
        let mut pure = vec![0, 3];
        pure.extend(context);
        pure.extend(b"message");
        assert_eq!(
            key.public_key().message_representative(b"message", context),
            Ok(mu(&pure))
        );

        let digest = PreHash::Sha256.digest(b"message");
        let mut prehash = vec![1, 3];
        prehash.extend(context);
        prehash.extend([
            0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
        ]);
        prehash.extend(&digest);
        assert_eq!(
            key.sign_prehash_deterministic(PreHash::Sha256, &digest, context)
                .unwrap(),
            key.sign_mu_deterministic(&mu(&prehash))
        );
    }

    /// Changing any part of a signature, or its message, key or context, makes it
    /// fail: the commitment, the vector `z` and the hint.
    #[test]
    fn tampering() {
        each_set!(P => {
            let key = key_of::<P>(8);
            let public = key.public_key();
            let signature = key.sign_deterministic(b"message", b"").unwrap();
            let bytes = signature.as_bytes();
            let hint_start = P::SIGNATURE_LEN - P::HINT_LEN;
            // Every byte of the commitment hash, the ends of each polynomial of
            // `z`, the whole of the hint's counts, and a spread of the rest.
            let z_start = P::C_TILDE_LEN;
            let positions: Vec<usize> = (0..bytes.len())
                .filter(|&i| {
                    i % 23 == 0
                        || i < z_start
                        || (z_start..hint_start).contains(&i)
                            && ((i - z_start) % P::Z_LEN < 2 || (i - z_start) % P::Z_LEN >= P::Z_LEN - 2)
                        || i >= hint_start - 3
                })
                .collect();
            for position in positions {
                for bit in [0x01, 0x80] {
                    let mut changed = bytes.to_vec();
                    changed[position] ^= bit;
                    let accepted = Signature::<P>::from_bytes(&changed)
                        .and_then(|s| public.verify(b"message", b"", &s));
                    assert!(accepted.is_err(), "{} byte {position} bit {bit:#x}", P::NAME);
                }
            }
            // Another message, another key, another set's key bytes.
            assert!(public.verify(b"massage", b"", &signature).is_err());
            assert!(key_of::<P>(9).public_key().verify(b"message", b"", &signature).is_err());
            let mut zeros = vec![0u8; P::PUBLIC_KEY_LEN];
            let zero_key = PublicKey::<P>::from_bytes(&zeros).unwrap();
            assert!(zero_key.verify(b"message", b"", &signature).is_err());
            zeros[0] = 1;
            assert!(PublicKey::<P>::from_bytes(&zeros).unwrap().verify(b"message", b"", &signature).is_err());
        });
    }

    #[test]
    fn encodings_are_checked() {
        each_set!(P => {
            let key = key_of::<P>(10);
            let public = key.public_key();
            let signature = key.sign_deterministic(b"m", b"").unwrap();

            // The public key: only the length is a rule.
            for len in [0, 1, P::PUBLIC_KEY_LEN - 1, P::PUBLIC_KEY_LEN + 1, 2 * P::PUBLIC_KEY_LEN] {
                assert_eq!(PublicKey::<P>::from_bytes(&vec![5; len]), Err(Error::InvalidPublicKey));
            }
            assert_eq!(PublicKey::<P>::from_bytes(public.as_bytes()).as_ref(), Ok(public));
            assert_eq!(PublicKey::<P>::try_from(public.as_bytes()).as_ref(), Ok(public));

            // The signature: the length, and the hint.
            let bytes = signature.as_bytes();
            for len in [0, 1, bytes.len() - 1, bytes.len() + 1] {
                let mut resized = bytes.to_vec();
                resized.resize(len, 0);
                assert_eq!(Signature::<P>::from_bytes(&resized), Err(Error::InvalidSignature));
            }
            assert_eq!(Signature::<P>::from_bytes(bytes).as_ref(), Ok(&signature));
            assert_eq!(Signature::<P>::try_from(bytes).as_ref(), Ok(&signature));
            let mut bad_hint = bytes.to_vec();
            *bad_hint.last_mut().unwrap() = 0xff;
            assert_eq!(Signature::<P>::from_bytes(&bad_hint), Err(Error::InvalidSignature));
        });
    }

    #[test]
    fn keys_compare_clone_and_hide_their_secrets() {
        each_set!(P => {
            let key = key_of::<P>(11);
            let copy = key.clone();
            assert!(key == copy);
            assert!(key != key_of::<P>(12));
            assert_eq!(key.public_key(), copy.public_key());
            assert_ne!(key.public_key(), key_of::<P>(12).public_key());

            // A clone owns its working data: the original can go.
            let signature = key.sign_deterministic(b"m", b"").unwrap();
            drop(key);
            assert_eq!(copy.sign_deterministic(b"m", b"").unwrap(), signature);
            assert_eq!(copy.public_key().clone().verify(b"m", b"", &signature), Ok(()));

            // Debug says the set and not the key.
            let shown = format!("{copy:?}");
            assert_eq!(shown, format!("PrivateKey<{}> {{ .. }}", P::NAME));
            let seed = hex(copy.seed());
            assert!(!shown.contains(&seed));
            let public = format!("{:?}", copy.public_key());
            assert!(public.starts_with(&format!("PublicKey<{}> {{ tr: ", P::NAME)));
            assert!(public.len() < 80, "{public}");
            let shown = format!("{signature:?}");
            assert_eq!(shown, format!("Signature<{}>({} bytes)", P::NAME, P::SIGNATURE_LEN));
        });
    }

    /// A private key is overwritten when dropped: the seed, and `K`, the part of
    /// the key that the seed expands to and the masks depend on.
    #[test]
    fn dropping_a_key_wipes_it() {
        let seed = [0xa5u8; 32];
        let key = PrivateKey::<MlDsa44>::from_seed(&seed);
        // K is the last 32 of the 128 bytes that the seed expands to first.
        let mut xof = Vec::from(seed);
        xof.extend([4, 4]);
        let mut expansion = [0u8; 128];
        shake256(&xof, &mut expansion);
        let k = &expansion[96..];

        let contains =
            |haystack: &[u8], needle: &[u8]| haystack.windows(needle.len()).any(|w| w == needle);
        // SAFETY: the type has no padding (its fields are arrays and boxes, whose
        // sizes add up to the size of the type, which the assertion checks).
        assert_eq!(
            size_of::<PrivateKey<MlDsa44>>(),
            32 + (32 + 32 + 64 + 16) + (16 + 64)
        );
        let (before, after) = unsafe { bytes_around_drop(key) };
        assert!(contains(&before, &seed));
        assert!(contains(&before, k));
        assert!(!contains(&after, &seed));
        assert!(!contains(&after, k));
    }

    /// The vectors and matrices behind the key are overwritten too: `wipe_secrets`
    /// is what the drop calls.
    #[test]
    fn the_secret_vectors_are_wiped() {
        each_set!(P => {
            let mut key = key_of::<P>(13);
            assert!(!key.expanded.secrets_are_zero());
            key.expanded.wipe_secrets();
            assert!(key.expanded.secrets_are_zero());
        });
    }

    /// A cheap source of bytes for the hedged signature, so that the time
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
    #[ignore = "manual throughput check: cargo test --release mldsa:: -- --ignored --nocapture --test-threads=1"]
    fn throughput() {
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

        /// 256 messages of 64 bytes, which the signing rows go through in turn:
        /// how many attempts a signature takes depends on the message, and so
        /// one message would time that message and not the average. A batch of
        /// about 100 ms holds more signatures than that, so every batch signs
        /// all of them.
        fn messages() -> Vec<Vec<u8>> {
            (0..256usize)
                .map(|i| (0..64usize).map(|j| (3 * i + j) as u8).collect())
                .collect()
        }

        fn run<P: Parameters>() {
            let seed: [u8; 32] = core::array::from_fn(|i| (i * 37 + 11) as u8);
            let key = PrivateKey::<P>::from_seed(&seed);
            let public = key.public_key().as_bytes().to_vec();
            let public_key = PublicKey::<P>::from_bytes(&public).unwrap();
            let messages = messages();
            let signature = key.sign_deterministic(&messages[0], b"").unwrap();
            let mut noise = Noise(0x9e37_79b9_7f4a_7c15);
            let (mut next_hedged, mut next_deterministic) = (0, 0);

            let rows = [
                (
                    "new private key",
                    time(|| {
                        drop(black_box(PrivateKey::<P>::from_seed(black_box(&seed))));
                    }),
                ),
                (
                    "new public key",
                    time(|| {
                        black_box(PublicKey::<P>::from_bytes(black_box(&public)).unwrap());
                    }),
                ),
                (
                    "sign",
                    time(|| {
                        next_hedged = (next_hedged + 1) % messages.len();
                        let signature = key
                            .sign(&mut noise, black_box(&messages[next_hedged]), b"")
                            .unwrap();
                        black_box(signature);
                    }),
                ),
                (
                    "sign deterministic",
                    time(|| {
                        next_deterministic = (next_deterministic + 1) % messages.len();
                        let signature = key
                            .sign_deterministic(black_box(&messages[next_deterministic]), b"")
                            .unwrap();
                        black_box(signature);
                    }),
                ),
                (
                    "verify",
                    time(|| {
                        public_key
                            .verify(black_box(&messages[0]), b"", black_box(&signature))
                            .unwrap();
                    }),
                ),
            ];
            for (name, micros) in rows {
                println!(
                    "{} {name} [cryptors]: best {micros:.1} us/op, {:.0} ops/s (signature {}...)",
                    P::NAME,
                    1e6 / micros,
                    hex(&signature.as_bytes()[..8])
                );
            }
        }

        run::<MlDsa44>();
        run::<MlDsa65>();
        run::<MlDsa87>();
    }
}
