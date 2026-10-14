//! Decapsulation keys, encapsulation keys, ciphertexts and shared secrets, and
//! the operations on them.

use super::algorithm::{
    Generated, decapsulate, decode_encapsulation_key, encapsulate, encode_encapsulation_key,
    expand_matrix, hash_h, key_gen,
};
use super::error::Error;
use super::field::Poly;
use super::params::{Parameters, SEED_LEN, SHARED_SECRET_LEN};
use crate::ec::ct;
use crate::wipe::{wipe, wipe_bytes};
use core::fmt;
use core::marker::PhantomData;
use std::io;

/// A decapsulation key of the parameter set `P`: the secret that opens
/// ciphertexts.
///
/// It is the 64-byte seed `d || z` of FIPS 203's `ML-KEM.KeyGen`, and it holds
/// what the seed expands to (the secret vector `s` in the form that decryption
/// multiplies by, and the encapsulation key that goes with it, with its
/// matrix `A`), so that decapsulating does not expand them again. That takes
/// 5 KiB for ML-KEM-512, 9 KiB for ML-KEM-768 and 14 KiB for ML-KEM-1024, on the
/// heap.
///
/// The seed and the secret vector are overwritten with zeros when the key is
/// dropped, and `Debug` does not show them. That is best effort: the working
/// values of the arithmetic (numbers that depend on the key, on the stack and in
/// registers while it is in use) are not all overwritten, and neither is the copy
/// that moving a key (into a `Box` or a `Vec`, say) can leave behind where it was.
pub struct DecapsulationKey<P: Parameters> {
    seed: [u8; SEED_LEN],
    s: Box<[Poly]>,
    public: EncapsulationKey<P>,
}

/// An encapsulation key of the parameter set `P`: what a sender needs to know to
/// make a shared secret that only the holder of the decapsulation key can
/// find.
///
/// Holding one means that the bytes passed the checks of FIPS 203 (section
/// 7.2): they are as long as an encapsulation key is, and every coefficient is
/// below `q`. The key holds its encoding, the hash of it that every
/// encapsulation starts from, and the vector and the matrix in the form that
/// encryption multiplies by: 4 KiB for ML-KEM-512, 7 KiB for ML-KEM-768 and
/// 12 KiB for ML-KEM-1024, on the heap.
pub struct EncapsulationKey<P: Parameters> {
    bytes: Box<[u8]>,
    /// `H(ek)`, SHA3-256 of the encoding.
    hash: [u8; 32],
    /// `A`, row by row.
    matrix: Box<[Poly]>,
    /// `t`.
    t: Box<[Poly]>,
    parameters: PhantomData<P>,
}

/// A ciphertext of the parameter set `P`: what the sender gives the holder of
/// the decapsulation key, who finds the shared secret in it.
///
/// Holding one means only that the bytes are as long as a ciphertext of the set
/// is. Every string of that length is a ciphertext, for the sake of implicit
/// rejection: whether it is the one of an encapsulation for this key is for
/// [`DecapsulationKey::decapsulate`] to hide, not to say.
pub struct Ciphertext<P: Parameters> {
    bytes: Box<[u8]>,
    parameters: PhantomData<P>,
}

/// The shared secret `K` that encapsulation and decapsulation agree on: 32
/// bytes that are uniformly random, to anyone who does not have the
/// decapsulation key. It is the input of a key derivation function, or a key.
///
/// The bytes are overwritten with zeros when it is dropped, and `Debug` does
/// not show them.
pub struct SharedSecret<P: Parameters> {
    bytes: [u8; SHARED_SECRET_LEN],
    parameters: PhantomData<P>,
}

impl<P: Parameters> DecapsulationKey<P> {
    /// Generates a key from `rng`, which has to be a source of cryptographically
    /// secure random bytes: the secrecy of everything that follows depends on
    /// it. The standard library has none that is stable, so this takes any
    /// reader; on Unix, `File::open("/dev/urandom")` is one.
    ///
    /// It reads the 64 bytes of the seed, `d` and then `z` (`ML-KEM.KeyGen`,
    /// FIPS 203 algorithm 19), and expands them with [`from_seed`](Self::from_seed).
    ///
    /// # Errors
    ///
    /// Whatever `rng` fails with.
    pub fn generate<R: io::Read + ?Sized>(rng: &mut R) -> io::Result<Self> {
        let mut seed = [0u8; SEED_LEN];
        let result = rng.read_exact(&mut seed).map(|()| Self::from_seed(&seed));
        wipe_bytes(&mut seed);
        result
    }

    /// The key that a seed makes (`ML-KEM.KeyGen_internal`, FIPS 203 algorithm
    /// 16): `d` is the first 32 bytes, the input of `K-PKE.KeyGen`, and `z` the
    /// last 32, which implicit rejection hashes with a ciphertext that is not
    /// good. Any 64 bytes are a seed. The same seed gives the same key, on every
    /// platform and in every implementation of FIPS 203.
    pub fn from_seed(seed: &[u8; SEED_LEN]) -> Self {
        let (d, _) = seed.split_first_chunk::<32>().unwrap();
        Self::from_generated(seed, key_gen::<P>(d))
    }

    /// The key for `seed` of which `K-PKE.KeyGen` made `generated`.
    pub(super) fn from_generated(seed: &[u8; SEED_LEN], generated: Generated) -> Self {
        let bytes = encode_encapsulation_key::<P>(&generated.t, &generated.rho);
        let hash = hash_h(&bytes);
        Self {
            seed: *seed,
            s: generated.s,
            public: EncapsulationKey {
                bytes: bytes.into_boxed_slice(),
                hash,
                matrix: generated.matrix,
                t: generated.t,
                parameters: PhantomData,
            },
        }
    }

    /// The seed: the whole decapsulation key in 64 bytes, in the form
    /// [`from_seed`](Self::from_seed) takes. Keep it secret.
    pub fn seed(&self) -> &[u8; SEED_LEN] {
        &self.seed
    }

    /// The encapsulation key that goes with this key: the one to send to
    /// whoever will encapsulate a shared secret for it.
    pub fn encapsulation_key(&self) -> &EncapsulationKey<P> {
        &self.public
    }

    /// Finds the shared secret in `ciphertext` (`ML-KEM.Decaps`, FIPS 203
    /// algorithm 21).
    ///
    /// It never fails, and it does not say whether the ciphertext is one of an
    /// encapsulation for this key. If it is not (it was made for another key, or
    /// changed on the way) the result is a secret all the same, which looks
    /// random and which the sender does not have: `J(z || c)`, a function of the
    /// ciphertext and of the secret `z` in the key. This is the "implicit
    /// rejection" that makes the scheme secure against an attacker who can see
    /// what the receiver does with a ciphertext of their choosing, and the first
    /// use of the wrong secret (a message that does not authenticate, a
    /// handshake that does not finish) is where the failure shows.
    ///
    /// ```
    /// use cryptors::mlkem::{DecapsulationKey, MlKem768};
    ///
    /// let key = DecapsulationKey::<MlKem768>::from_seed(&[1; 64]);
    /// // A fixed string of "random" bytes, which a real program does not use.
    /// let mut rng: &[u8] = &[42; 32];
    /// let (secret, ciphertext) = key.encapsulation_key().encapsulate(&mut rng)?;
    ///
    /// assert_eq!(key.decapsulate(&ciphertext), secret);
    /// # Ok::<(), std::io::Error>(())
    /// ```
    pub fn decapsulate(&self, ciphertext: &Ciphertext<P>) -> SharedSecret<P> {
        let (_, z) = self.seed.split_last_chunk::<32>().unwrap();
        let mut k = decapsulate::<P>(
            &self.s,
            &self.public.matrix,
            &self.public.t,
            &self.public.hash,
            z,
            ciphertext.as_bytes(),
        );
        let secret = SharedSecret::new(k);
        wipe_bytes(&mut k);
        secret
    }

    /// Overwrites the secrets with zeros: what the drop does.
    fn wipe_secrets(&mut self) {
        wipe_bytes(&mut self.seed);
        for s_i in self.s.iter_mut() {
            wipe(s_i);
        }
    }

    /// Whether the seed and the secret vector are all zeros.
    #[cfg(test)]
    pub(super) fn secrets_are_zero(&self) -> bool {
        ct::bytes_are_zero(&self.seed) && self.s.iter().all(|s_i| s_i.iter().all(|&c| c == 0))
    }

    /// The secret vector, for the tests that expand a key by hand.
    #[cfg(test)]
    pub(super) fn secret_vector(&self) -> &[Poly] {
        &self.s
    }
}

impl<P: Parameters> DecapsulationKey<P> {
    /// The key as FIPS 203 encodes it (algorithm 16, line 3): `dkPKE || ek ||
    /// H(ek) || z`, `768 * k + 96` bytes. The crate has no use for it, and the
    /// tests have: NIST's and C2SP's vectors are written in it.
    #[cfg(test)]
    pub(super) fn to_expanded(&self) -> Vec<u8> {
        use super::pack::byte_encode;
        let mut bytes = vec![0; P::VECTOR_LEN];
        for (s_i, out) in self.s.iter().zip(bytes.chunks_exact_mut(384)) {
            byte_encode(s_i, out);
        }
        bytes.extend_from_slice(&self.public.bytes);
        bytes.extend_from_slice(&self.public.hash);
        bytes.extend_from_slice(&self.seed[32..]);
        bytes
    }

    /// The key that `bytes` encode, with the checks of FIPS 203 section 7.3 (the
    /// length, and the hash of the encapsulation key inside it) and the
    /// modulus check of that encapsulation key. The seed is not in the
    /// encoding: `d` is zeros here, so [`seed`](Self::seed) is not the key's.
    #[cfg(test)]
    pub(super) fn from_expanded(bytes: &[u8]) -> Result<Self, ExpandedError> {
        use super::pack::byte_decode;
        if bytes.len() != 2 * P::VECTOR_LEN + 96 {
            return Err(ExpandedError::Length);
        }
        let (dk_pke, rest) = bytes.split_at(P::VECTOR_LEN);
        let (ek, rest) = rest.split_at(P::ENCAPSULATION_KEY_LEN);
        let (hash, z) = rest.split_at(32);
        let public = EncapsulationKey::<P>::from_bytes(ek).map_err(|_| ExpandedError::Key)?;
        if hash != public.hash {
            return Err(ExpandedError::Hash);
        }
        let mut s = vec![[0; 256]; P::K];
        for (s_i, chunk) in s.iter_mut().zip(dk_pke.chunks_exact(384)) {
            if !byte_decode(chunk, s_i) {
                return Err(ExpandedError::Secret);
            }
        }
        let mut seed = [0; SEED_LEN];
        seed[32..].copy_from_slice(z);
        Ok(Self {
            seed,
            s: s.into_boxed_slice(),
            public,
        })
    }
}

/// Why `from_expanded` refused a key.
#[cfg(test)]
#[derive(Debug, PartialEq, Eq)]
pub(super) enum ExpandedError {
    Length,
    Key,
    Hash,
    Secret,
}

impl<P: Parameters> EncapsulationKey<P> {
    /// Reads an encapsulation key from its encoding (`ByteEncode_12` of each
    /// polynomial of `t`, then `rho`), as long as
    /// [`Parameters::ENCAPSULATION_KEY_LEN`], and does the check that FIPS 203
    /// asks for before an encapsulation (section 7.2): every coefficient of
    /// `t` must be below `q`, which is the same as the bytes being what
    /// encoding the decoding of them gives.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidEncapsulationKey`] if `bytes` has any other length, or if
    /// a coefficient is not below `q`.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != P::ENCAPSULATION_KEY_LEN {
            return Err(Error::InvalidEncapsulationKey);
        }
        let (t, rho) =
            decode_encapsulation_key::<P>(bytes).ok_or(Error::InvalidEncapsulationKey)?;
        Ok(Self {
            bytes: bytes.into(),
            hash: hash_h(bytes),
            matrix: expand_matrix::<P>(&rho),
            t,
            parameters: PhantomData,
        })
    }

    /// The encoding of the key, in the form [`from_bytes`](Self::from_bytes) takes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Makes a shared secret and the ciphertext that lets the holder of the
    /// decapsulation key find it (`ML-KEM.Encaps`, FIPS 203 algorithm 20). The
    /// ciphertext is for them, and the secret is for the caller to keep.
    ///
    /// `rng` has to be a source of cryptographically secure random bytes, as for
    /// [`DecapsulationKey::generate`]: it supplies the 32 bytes `m` from which
    /// the secret and everything random in the ciphertext are derived, and so
    /// the secrecy of the secret depends on them. A reader of fixed bytes makes
    /// the same ciphertext and secret every time, which is for tests and for
    /// nothing else.
    ///
    /// ```
    /// use cryptors::mlkem::{DecapsulationKey, EncapsulationKey, MlKem768};
    ///
    /// let key = DecapsulationKey::<MlKem768>::from_seed(&[7; 64]);
    /// // The sender has the bytes of the encapsulation key...
    /// let public = EncapsulationKey::<MlKem768>::from_bytes(key.encapsulation_key().as_bytes())?;
    /// // ... and makes a secret for it, from a fixed string of "random" bytes
    /// // that a real program does not use.
    /// let mut rng: &[u8] = &[0x2a; 32];
    /// let (secret, ciphertext) = public.encapsulate(&mut rng)?;
    /// assert_eq!(ciphertext.as_bytes().len(), 1088);
    ///
    /// // The holder of the decapsulation key finds the same secret.
    /// assert_eq!(key.decapsulate(&ciphertext), secret);
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    ///
    /// # Errors
    ///
    /// Whatever `rng` fails with.
    pub fn encapsulate<R: io::Read + ?Sized>(
        &self,
        rng: &mut R,
    ) -> io::Result<(SharedSecret<P>, Ciphertext<P>)> {
        let mut m = [0u8; 32];
        let result = rng.read_exact(&mut m).map(|()| self.encapsulate_with(&m));
        wipe_bytes(&mut m);
        result
    }

    /// `ML-KEM.Encaps_internal` (FIPS 203 algorithm 17): the secret and the
    /// ciphertext of the message `m`. FIPS 203 does not let an application make
    /// `m` itself, so this is for the tests.
    pub(super) fn encapsulate_with(&self, m: &[u8; 32]) -> (SharedSecret<P>, Ciphertext<P>) {
        let mut ciphertext = vec![0; P::CIPHERTEXT_LEN];
        let mut k = encapsulate::<P>(&self.matrix, &self.t, &self.hash, m, &mut ciphertext);
        let secret = SharedSecret::new(k);
        wipe_bytes(&mut k);
        (
            secret,
            Ciphertext {
                bytes: ciphertext.into_boxed_slice(),
                parameters: PhantomData,
            },
        )
    }
}

impl<P: Parameters> Ciphertext<P> {
    /// Reads a ciphertext from its encoding (`c1 || c2` of FIPS 203 algorithm
    /// 14), as long as [`Parameters::CIPHERTEXT_LEN`].
    ///
    /// # Errors
    ///
    /// [`Error::InvalidCiphertext`] if `bytes` has any other length.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != P::CIPHERTEXT_LEN {
            return Err(Error::InvalidCiphertext);
        }
        Ok(Self {
            bytes: bytes.into(),
            parameters: PhantomData,
        })
    }

    /// The encoding of the ciphertext, in the form [`from_bytes`](Self::from_bytes) takes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl<P: Parameters> SharedSecret<P> {
    fn new(bytes: [u8; SHARED_SECRET_LEN]) -> Self {
        Self {
            bytes,
            parameters: PhantomData,
        }
    }

    /// The secret: [`SHARED_SECRET_LEN`] bytes.
    pub fn as_bytes(&self) -> &[u8; SHARED_SECRET_LEN] {
        &self.bytes
    }
}

impl<P: Parameters> AsRef<[u8]> for SharedSecret<P> {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

impl<P: Parameters> Drop for DecapsulationKey<P> {
    fn drop(&mut self) {
        self.wipe_secrets();
    }
}

impl<P: Parameters> Drop for SharedSecret<P> {
    fn drop(&mut self) {
        wipe_bytes(&mut self.bytes);
    }
}

impl<P: Parameters> Clone for DecapsulationKey<P> {
    fn clone(&self) -> Self {
        Self {
            seed: self.seed,
            s: self.s.clone(),
            public: self.public.clone(),
        }
    }
}

impl<P: Parameters> Clone for EncapsulationKey<P> {
    fn clone(&self) -> Self {
        Self {
            bytes: self.bytes.clone(),
            hash: self.hash,
            matrix: self.matrix.clone(),
            t: self.t.clone(),
            parameters: PhantomData,
        }
    }
}

impl<P: Parameters> Clone for Ciphertext<P> {
    fn clone(&self) -> Self {
        Self {
            bytes: self.bytes.clone(),
            parameters: PhantomData,
        }
    }
}

impl<P: Parameters> Clone for SharedSecret<P> {
    fn clone(&self) -> Self {
        Self::new(self.bytes)
    }
}

/// Compares in constant time: two decapsulation keys are equal if their seeds
/// are, and the time it takes does not say where they differ.
impl<P: Parameters> PartialEq for DecapsulationKey<P> {
    fn eq(&self, other: &Self) -> bool {
        ct::bytes_eq(&self.seed, &other.seed)
    }
}

impl<P: Parameters> Eq for DecapsulationKey<P> {}

/// Two encapsulation keys are equal if their encodings are.
impl<P: Parameters> PartialEq for EncapsulationKey<P> {
    fn eq(&self, other: &Self) -> bool {
        self.bytes == other.bytes
    }
}

impl<P: Parameters> Eq for EncapsulationKey<P> {}

impl<P: Parameters> PartialEq for Ciphertext<P> {
    fn eq(&self, other: &Self) -> bool {
        self.bytes == other.bytes
    }
}

impl<P: Parameters> Eq for Ciphertext<P> {}

/// Compares in constant time.
impl<P: Parameters> PartialEq for SharedSecret<P> {
    fn eq(&self, other: &Self) -> bool {
        ct::bytes_eq(&self.bytes, &other.bytes)
    }
}

impl<P: Parameters> Eq for SharedSecret<P> {}

impl<P: Parameters> TryFrom<&[u8]> for EncapsulationKey<P> {
    type Error = Error;

    fn try_from(bytes: &[u8]) -> Result<Self, Error> {
        Self::from_bytes(bytes)
    }
}

impl<P: Parameters> TryFrom<&[u8]> for Ciphertext<P> {
    type Error = Error;

    fn try_from(bytes: &[u8]) -> Result<Self, Error> {
        Self::from_bytes(bytes)
    }
}

impl<P: Parameters> fmt::Debug for DecapsulationKey<P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DecapsulationKey<{}> {{ .. }}", P::NAME)
    }
}

/// Shows the first bytes of the hash of the key, which is enough to tell keys
/// apart in a log, and not the 800 to 1568 bytes of the key.
impl<P: Parameters> fmt::Debug for EncapsulationKey<P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "EncapsulationKey<{}> {{ hash: ", P::NAME)?;
        for byte in &self.hash[..8] {
            write!(f, "{byte:02x}")?;
        }
        f.write_str("... }")
    }
}

impl<P: Parameters> fmt::Debug for Ciphertext<P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Ciphertext<{}>({} bytes)", P::NAME, self.bytes.len())
    }
}

impl<P: Parameters> fmt::Debug for SharedSecret<P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SharedSecret<{}> {{ .. }}", P::NAME)
    }
}

#[cfg(test)]
mod tests {
    use super::super::params::{MlKem512, MlKem768, MlKem1024};
    use super::super::testutil::{draft_key, hex};
    use super::*;
    use crate::Digest;
    use crate::sha2::Sha256;
    use crate::sha3::{Shake128, shake256};
    use crate::wipe::bytes_around_drop;

    /// The "accumulated" test of Go's `crypto/mlkem`: a stream of seeds, messages
    /// and invalid ciphertexts from one SHAKE128, and the hash of the keys,
    /// ciphertexts and secrets that come out. The expected values were made
    /// with Go (768 and 1024) and with OpenSSL 3.6 (all three, which agree),
    /// and every ciphertext decapsulates to the secret that made it.
    fn accumulated_go<P: Parameters>(rounds: usize, expected: &str) {
        let mut seeds = Shake128::new();
        let mut out = Shake128::new();
        for _ in 0..rounds {
            let mut seed = [0u8; SEED_LEN];
            seeds.read(&mut seed);
            let key = DecapsulationKey::<P>::from_seed(&seed);
            let ek = key.encapsulation_key();
            out.absorb(ek.as_bytes());

            let mut m = [0u8; 32];
            seeds.read(&mut m);
            let (secret, ciphertext) = ek.encapsulate_with(&m);
            out.absorb(ciphertext.as_bytes());
            out.absorb(secret.as_bytes());
            assert_eq!(key.decapsulate(&ciphertext), secret);

            let mut bad = vec![0u8; P::CIPHERTEXT_LEN];
            seeds.read(&mut bad);
            let rejected = key.decapsulate(&Ciphertext::from_bytes(&bad).unwrap());
            out.absorb(rejected.as_bytes());
        }
        let mut sum = [0u8; 32];
        out.read(&mut sum);
        assert_eq!(hex(&sum), expected, "{}", P::NAME);
    }

    /// The accumulated vectors of C2SP's CCTV (`ML-KEM/README.md`), which are
    /// those of the draft of FIPS 203: the same stream, and a hash that also takes
    /// the expanded decapsulation key.
    fn accumulated_cctv<P: Parameters>(rounds: usize, expected: &str) {
        let mut stream = Shake128::new();
        let mut out = Shake128::new();
        for _ in 0..rounds {
            let mut seed = [0u8; SEED_LEN];
            let mut m = [0u8; 32];
            let mut bad = vec![0u8; P::CIPHERTEXT_LEN];
            stream.read(&mut seed);
            stream.read(&mut m);
            stream.read(&mut bad);

            let key = draft_key::<P>(&seed);
            out.absorb(key.encapsulation_key().as_bytes());
            out.absorb(&key.to_expanded());
            let (secret, ciphertext) = key.encapsulation_key().encapsulate_with(&m);
            out.absorb(ciphertext.as_bytes());
            out.absorb(secret.as_bytes());
            assert_eq!(key.decapsulate(&ciphertext), secret);
            let rejected = key.decapsulate(&Ciphertext::from_bytes(&bad).unwrap());
            out.absorb(rejected.as_bytes());
        }
        let mut sum = [0u8; 32];
        out.read(&mut sum);
        assert_eq!(hex(&sum), expected, "{}", P::NAME);
    }

    #[test]
    fn accumulated_100() {
        accumulated_go::<MlKem512>(
            100,
            "86b1b4703b8ffef6f7f3290c6dbce4ad954498a0673ded401a94828e8c519a59",
        );
        accumulated_go::<MlKem768>(
            100,
            "1114b1b6699ed191734fa339376afa7e285c9e6acf6ff0177d346696ce564415",
        );
        accumulated_go::<MlKem1024>(
            100,
            "800018fec3e2723f73f1d657fe239b4d5d8782efaade297e8cd448e54cc2ac00",
        );
    }

    #[test]
    #[ignore = "ten thousand rounds on each set: cargo test --release mlkem:: -- --ignored"]
    fn accumulated_10000() {
        accumulated_cctv::<MlKem512>(
            10_000,
            "845913ea5a308b803c764a9ed8e9d814ca1fd9c82ba43c7b1e64b79c7a6ec8e4",
        );
        accumulated_cctv::<MlKem768>(
            10_000,
            "f7db260e1137a742e05fe0db9525012812b004d29040a5b606aad3d134b548d3",
        );
        accumulated_cctv::<MlKem1024>(
            10_000,
            "47ac888fe61544efc0518f46094b4f8a600965fc89822acb06dc7169d24f3543",
        );
    }

    /// The key, ciphertext and secret of the benchmark's seed and message
    /// (`bench/mlkemcmp` makes the same with Go's `crypto/mlkem`, which has no
    /// ML-KEM-512): made with Go for 768 and 1024, and with OpenSSL 3.6 for all
    /// three, which agree.
    #[test]
    fn the_benchmark_inputs_have_the_answers_of_go_and_openssl() {
        fn check<P: Parameters>(ek: &str, c: &str, k: &str) {
            let sha256 = |bytes: &[u8]| hex(&Sha256::digest(bytes));
            let seed: [u8; 64] = core::array::from_fn(|i| (i * 37 + 11) as u8);
            let m: [u8; 32] = core::array::from_fn(|i| (i * 7 + 3) as u8);
            let key = DecapsulationKey::<P>::from_seed(&seed);
            assert_eq!(
                sha256(key.encapsulation_key().as_bytes()),
                ek,
                "{}",
                P::NAME
            );
            let (secret, ciphertext) = key.encapsulation_key().encapsulate_with(&m);
            assert_eq!(sha256(ciphertext.as_bytes()), c, "{}", P::NAME);
            assert_eq!(hex(secret.as_bytes()), k, "{}", P::NAME);
        }
        check::<MlKem512>(
            "fb4793757bccece79eee5d55e5c978d6f6ffe531907738c4ca6364a68b0ef248",
            "6fe4279708d4aa3f185b6e9317415715f9fb79c64213fe51a949b564e74bbfee",
            "f7b18db6add8592a63d47f5dca650bd83b4a0fd74752da41c9e5b6e3cfd31fcc",
        );
        check::<MlKem768>(
            "3551836042378fc51134435724fcf6d3ac6531d5d22a4d1fc75c8fe26f3dfea2",
            "5df7b3192c32af799acc6c9293f1c4249f550b92f40de6b7e3dea8e2b2c08a90",
            "c94802d6a83178e950663f680924c90a81d942500a2b78311f30a4a65d4e86d5",
        );
        check::<MlKem1024>(
            "58ac67963c019909dc04bc575bc07ca0b2812fc20e38323a50e3b0b6fb23664b",
            "7bcbe35dbf7b276145cbb53eeb2f9e75472933e903477237d7cd4b99d785e6c4",
            "1f7a3dcc9117d97a0f5c4f442472084283825c9b3fef98b67117ead40fb2854f",
        );
    }

    /// Runs `$body` once for each parameter set, with `$p` naming it.
    macro_rules! each_set {
        ($p:ident => $body:block) => {{
            fn run<$p: Parameters>() $body
            run::<MlKem512>();
            run::<MlKem768>();
            run::<MlKem1024>();
        }};
    }

    /// A reader that fails.
    struct Broken;

    impl io::Read for Broken {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::other("no entropy"))
        }
    }

    fn key_of<P: Parameters>(byte: u8) -> DecapsulationKey<P> {
        DecapsulationKey::from_seed(&core::array::from_fn(|i| byte.wrapping_add(i as u8)))
    }

    /// The whole exchange through the public API, with the encapsulation key sent
    /// as bytes and the ciphertext too, and the key kept as its seed.
    #[test]
    fn a_key_exchange() {
        each_set!(P => {
            let mut rng: &[u8] = &[0x5a; 64 + 32 + 32];
            let key = DecapsulationKey::<P>::generate(&mut rng).unwrap();
            assert_eq!(key.seed(), &[0x5a; 64]);

            // The sender parses the key it received and sends a ciphertext.
            let sent = EncapsulationKey::<P>::from_bytes(key.encapsulation_key().as_bytes()).unwrap();
            assert_eq!(&sent, key.encapsulation_key());
            let (secret, ciphertext) = sent.encapsulate(&mut rng).unwrap();
            assert_eq!(secret.as_ref(), &secret.as_bytes()[..]);
            assert_eq!(secret.as_bytes().len(), 32);
            assert_eq!(ciphertext.as_bytes().len(), P::CIPHERTEXT_LEN);
            let received = Ciphertext::<P>::from_bytes(ciphertext.as_bytes()).unwrap();

            // The receiver, from the stored seed, finds the same secret.
            let restored = DecapsulationKey::<P>::from_seed(key.seed());
            assert!(restored == key);
            assert_eq!(restored.decapsulate(&received), secret);
            assert_eq!(restored.encapsulation_key(), key.encapsulation_key());

            // Another encapsulation is another secret and another ciphertext.
            let (other_secret, other_ciphertext) = sent.encapsulate(&mut &[7u8; 32][..]).unwrap();
            assert_ne!(other_secret, secret);
            assert_ne!(other_ciphertext, ciphertext);
        });
    }

    /// A reader of fixed bytes is the way to a known answer through the public
    /// API: the 32 bytes it gives are the message `m` of FIPS 203, unchanged.
    #[test]
    fn the_reader_gives_the_message() {
        each_set!(P => {
            let key = key_of::<P>(3);
            let m = [0x42; 32];
            let (secret, ciphertext) = key.encapsulation_key().encapsulate_with(&m);
            let mut rng: &[u8] = &m;
            let (read_secret, read_ciphertext) = key.encapsulation_key().encapsulate(&mut rng).unwrap();
            assert_eq!(read_secret, secret);
            assert_eq!(read_ciphertext, ciphertext);
            // Exactly 32 bytes were taken.
            assert!(rng.is_empty());
            let mut longer: &[u8] = &[0x42; 40];
            key.encapsulation_key().encapsulate(&mut longer).unwrap();
            assert_eq!(longer.len(), 8);
        });
    }

    #[test]
    fn a_failing_reader_is_reported() {
        each_set!(P => {
            assert!(DecapsulationKey::<P>::generate(&mut Broken).is_err());
            assert!(key_of::<P>(4).encapsulation_key().encapsulate(&mut Broken).is_err());
            // A reader that runs out before the bytes are all there.
            let mut short: &[u8] = &[1; 63];
            let error = DecapsulationKey::<P>::generate(&mut short).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
            let mut short: &[u8] = &[1; 31];
            let error = key_of::<P>(4).encapsulation_key().encapsulate(&mut short).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
        });
    }

    /// A ciphertext that is not the one the key was sent decapsulates to the
    /// secret of implicit rejection, `J(z || c)` (FIPS 203 algorithm 18), without
    /// an error, for a change in any part of it, and the same one every time.
    #[test]
    fn implicit_rejection() {
        each_set!(P => {
            let key = key_of::<P>(5);
            let (secret, ciphertext) = key.encapsulation_key().encapsulate_with(&[6; 32]);
            let z = &key.seed()[32..];

            let u_end = P::U_LEN;
            // The first and last bytes of `u`, of `v`, and one in the middle.
            for index in [0, 1, u_end - 1, u_end, P::CIPHERTEXT_LEN / 2, P::CIPHERTEXT_LEN - 1] {
                let mut bytes = ciphertext.as_bytes().to_vec();
                bytes[index] ^= 1;
                let changed = Ciphertext::<P>::from_bytes(&bytes).unwrap();

                let rejected = key.decapsulate(&changed);
                let mut expected = [0u8; 32];
                shake256(&[z, &bytes].concat(), &mut expected);
                assert_eq!(rejected.as_bytes(), &expected, "byte {index}");
                assert_ne!(rejected, secret);
                assert_eq!(key.decapsulate(&changed), rejected);
            }

            // The secret does not depend on `z` when the ciphertext is good.
            let mut seed = *key.seed();
            seed[40] ^= 1;
            assert_eq!(DecapsulationKey::<P>::from_seed(&seed).decapsulate(&ciphertext), secret);
            // And a ciphertext made for another key is rejected.
            let other = key_of::<P>(9);
            assert_ne!(other.decapsulate(&ciphertext), secret);
        });
    }

    #[test]
    fn encodings_are_checked() {
        each_set!(P => {
            let key = key_of::<P>(7);
            let bytes = key.encapsulation_key().as_bytes();

            // Every length near the right one, and a few far from it.
            for len in (0..8).chain([bytes.len() - 1, bytes.len() + 1, 2 * bytes.len()]) {
                let mut other = bytes.to_vec();
                other.resize(len, 0);
                assert_eq!(
                    EncapsulationKey::<P>::from_bytes(&other),
                    Err(Error::InvalidEncapsulationKey),
                    "{len}"
                );
            }
            // A coefficient that is not below q, in the last polynomial: the
            // check covers the whole vector.
            let mut unreduced = bytes.to_vec();
            let last = 384 * (P::ENCAPSULATION_KEY_LEN / 384 - 1);
            unreduced[last] = 0x01;
            unreduced[last + 1] = 0x0d; // 0xd01 = 3329 = q
            assert_eq!(
                EncapsulationKey::<P>::from_bytes(&unreduced),
                Err(Error::InvalidEncapsulationKey)
            );
            // The same bytes with 3328, the largest coefficient, are a key.
            unreduced[last] = 0x00;
            assert!(EncapsulationKey::<P>::from_bytes(&unreduced).is_ok());
            assert_eq!(EncapsulationKey::<P>::try_from(bytes).as_ref(), Ok(key.encapsulation_key()));

            let (_, ciphertext) = key.encapsulation_key().encapsulate_with(&[1; 32]);
            let c = ciphertext.as_bytes();
            for len in (0..4).chain([c.len() - 1, c.len() + 1]) {
                let mut other = c.to_vec();
                other.resize(len, 0);
                assert_eq!(Ciphertext::<P>::from_bytes(&other), Err(Error::InvalidCiphertext), "{len}");
                assert_eq!(Ciphertext::<P>::try_from(&other[..]), Err(Error::InvalidCiphertext));
            }
            assert_eq!(Ciphertext::<P>::try_from(c).as_ref(), Ok(&ciphertext));
        });
    }

    #[test]
    fn keys_compare_clone_and_hide_their_secrets() {
        each_set!(P => {
            let key = key_of::<P>(11);
            let copy = key.clone();
            assert!(key == copy);
            assert!(key != key_of::<P>(12));
            assert_eq!(key.encapsulation_key(), copy.encapsulation_key());
            assert_ne!(key.encapsulation_key(), key_of::<P>(12).encapsulation_key());

            // A clone owns its working data: the original can go.
            let (secret, ciphertext) = key.encapsulation_key().clone().encapsulate_with(&[8; 32]);
            drop(key);
            assert_eq!(copy.decapsulate(&ciphertext), secret);
            assert_eq!(secret.clone(), secret);

            // Debug says the set and not the key.
            let shown = format!("{copy:?}");
            assert_eq!(shown, format!("DecapsulationKey<{}> {{ .. }}", P::NAME));
            assert!(!shown.contains(&hex(copy.seed())));
            let public = format!("{:?}", copy.encapsulation_key());
            assert!(public.starts_with(&format!("EncapsulationKey<{}> {{ hash: ", P::NAME)));
            assert!(public.len() < 80, "{public}");
            let shown = format!("{ciphertext:?}");
            assert_eq!(shown, format!("Ciphertext<{}>({} bytes)", P::NAME, P::CIPHERTEXT_LEN));
            let shown = format!("{secret:?}");
            assert_eq!(shown, format!("SharedSecret<{}> {{ .. }}", P::NAME));
            assert!(!shown.contains(&hex(secret.as_bytes())));
        });
    }

    /// A decapsulation key is overwritten when dropped: the seed, which holds
    /// `z`. (The secret vector is on the heap, where the next test looks.)
    #[test]
    fn dropping_a_key_wipes_it() {
        let seed: [u8; 64] = core::array::from_fn(|i| 0xa0 + i as u8);
        let key = DecapsulationKey::<MlKem768>::from_seed(&seed);
        // SAFETY: the type has no padding (its fields are an array, boxes and a
        // hash, whose sizes add up to the size of the type, which the assertion
        // checks).
        assert_eq!(
            size_of::<DecapsulationKey<MlKem768>>(),
            64 + 16 + (16 + 32 + 16 + 16)
        );
        let (before, after) = unsafe { bytes_around_drop(key) };
        let contains =
            |haystack: &[u8], needle: &[u8]| haystack.windows(needle.len()).any(|w| w == needle);
        assert!(contains(&before, &seed));
        assert!(!contains(&after, &seed[..32]));
        assert!(!contains(&after, &seed[32..]));
    }

    #[test]
    fn dropping_a_shared_secret_wipes_it() {
        let secret = SharedSecret::<MlKem768>::new([0x6b; 32]);
        // SAFETY: the type is 32 bytes and a zero-sized marker, with no padding.
        assert_eq!(size_of::<SharedSecret<MlKem768>>(), 32);
        let (before, after) = unsafe { bytes_around_drop(secret) };
        assert_eq!(before, [0x6b; 32]);
        assert_eq!(after, [0; 32]);
    }

    /// The secret vector is overwritten too: `wipe_secrets` is what the drop
    /// calls.
    #[test]
    fn the_secret_vector_is_wiped() {
        each_set!(P => {
            let mut key = key_of::<P>(13);
            assert!(!key.secrets_are_zero());
            assert!(key.secret_vector().iter().all(|s_i| s_i.iter().any(|&c| c != 0)));
            key.wipe_secrets();
            assert!(key.secrets_are_zero());
            assert!(key.secret_vector().iter().all(|s_i| s_i.iter().all(|&c| c == 0)));
        });
    }

    /// A cheap source of bytes for the encapsulation, so that the time measured
    /// is the encapsulation and not the system's random source.
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
    #[ignore = "manual throughput check: cargo test --release mlkem:: -- --ignored --nocapture --test-threads=1"]
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

        fn run<P: Parameters>() {
            let seed: [u8; 64] = core::array::from_fn(|i| (i * 37 + 11) as u8);
            let key = DecapsulationKey::<P>::from_seed(&seed);
            let public = key.encapsulation_key().as_bytes().to_vec();
            let encapsulation_key = EncapsulationKey::<P>::from_bytes(&public).unwrap();
            // The secret the benchmark's message makes, which other implementations make too.
            let m: [u8; 32] = core::array::from_fn(|i| (i * 7 + 3) as u8);
            let (secret, ciphertext) = encapsulation_key.encapsulate_with(&m);
            let mut noise = Noise(0x9e37_79b9_7f4a_7c15);

            let rows = [
                (
                    "new decapsulation key",
                    time(|| {
                        drop(black_box(DecapsulationKey::<P>::from_seed(black_box(
                            &seed,
                        ))));
                    }),
                ),
                (
                    "new encapsulation key",
                    time(|| {
                        black_box(EncapsulationKey::<P>::from_bytes(black_box(&public)).unwrap());
                    }),
                ),
                (
                    "encapsulate",
                    time(|| {
                        black_box(encapsulation_key.encapsulate(&mut noise).unwrap());
                    }),
                ),
                (
                    "decapsulate",
                    time(|| {
                        black_box(key.decapsulate(black_box(&ciphertext)));
                    }),
                ),
            ];
            for (name, micros) in rows {
                println!(
                    "{} {name} [cryptors]: best {micros:.1} us/op, {:.0} ops/s (secret {}...)",
                    P::NAME,
                    1e6 / micros,
                    hex(&secret.as_bytes()[..8])
                );
            }
        }

        run::<MlKem512>();
        run::<MlKem768>();
        run::<MlKem1024>();
    }
}
