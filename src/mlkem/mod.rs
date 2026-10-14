//! From-scratch implementation of the Module-Lattice-Based Key-Encapsulation
//! Mechanism (ML-KEM), as FIPS 203 defines it: one party, the sender, uses the
//! public key of another to make a random secret and a ciphertext that holds it,
//! and only the holder of the matching private key can find the secret in the
//! ciphertext. The two then share a secret that nobody who saw the ciphertext
//! knows, which is what a key exchange is for. It is the standard form of
//! CRYSTALS-Kyber, and a post-quantum scheme: it rests on a lattice problem that
//! no known quantum algorithm solves, where [`ecdh`](crate::ecdh) rests on
//! discrete logarithms, which Shor's algorithm solves on a large quantum
//! computer. That matters now and not when such a computer exists: an attacker can
//! record the key exchange today and open it later.
//!
//! | Parameter set | Type | Security category | Decapsulation key | Encapsulation key | Ciphertext | Shared secret |
//! |---------------|------|-------------------|-------------------|-------------------|------------|---------------|
//! | ML-KEM-512 | [`MlKem512`] | 1 | 64 bytes | 800 bytes | 768 bytes | 32 bytes |
//! | ML-KEM-768 | [`MlKem768`] | 3 | 64 bytes | 1,184 bytes | 1,088 bytes | 32 bytes |
//! | ML-KEM-1024 | [`MlKem1024`] | 5 | 64 bytes | 1,568 bytes | 1,568 bytes | 32 bytes |
//!
//! The keys are [`DecapsulationKey`] and [`EncapsulationKey`], and the other two
//! values are a [`Ciphertext`] and a [`SharedSecret`]; all four are generic over
//! the parameter set, which is one of the three types of the table, and which
//! implement [`Parameters`]. The categories are NIST's: 1 is as hard to break as a
//! key search on AES-128, 3 as one on AES-192 and 5 as one on AES-256. ML-KEM-768
//! is the one most protocols use.
//!
//! # How it works
//!
//! Everything happens in the ring `R_q` of polynomials of degree below 256 whose
//! coefficients are integers modulo `q = 3329`, with `X^256 = -1`. The private
//! key is a seed of two parts, `d` and `z`, 32 bytes each. From `d` the key is
//! expanded (FIPS 203, algorithm 13): a public matrix `A` of `k` by `k`
//! polynomials, made from a public seed `rho`; and two vectors `s` and `e` of `k`
//! polynomials with small coefficients, between `-eta` and `eta`, of which `s` is
//! the secret. The encapsulation key is `rho` and `t = A * s + e`. Recovering `s`
//! from `A` and `t` is the problem that the scheme rests on. Encryption of a
//! message `m` of 32 bytes to that key (algorithm 14) picks small vectors `y` and
//! `e1` and a small polynomial `e2`, and computes
//!
//! 1. `u = A^T * y + e1`, and
//! 2. `v = t^T * y + e2 + mu`, where `mu` has a coefficient of `q / 2`, rounded, for
//!    each bit of `m` that is set;
//!
//! the ciphertext is `u` and `v`, each coefficient rounded to `du` or `dv` bits.
//! Whoever has `s` computes `v - s^T * u`, which is `mu` plus noise that is too small
//! to turn a bit into the other, and so finds `m` (algorithm 15). The products are made
//! with a number-theoretic transform, which is what makes the polynomial arithmetic
//! fast. That much is a public-key encryption scheme, K-PKE, which is secure only
//! against an attacker who sees ciphertexts. ML-KEM makes it secure against one who
//! can also have ciphertexts of their choice decapsulated, with the transform of
//! Fujisaki and Okamoto:
//!
//! - **Encapsulation** (algorithm 17) takes 32 random bytes `m`, and derives from it
//!   and from the hash of the encapsulation key the shared secret `K` and the
//!   randomness `r` that the encryption of `m` uses: `(K, r) = G(m || H(ek))`.
//! - **Decapsulation** (algorithm 18) finds `m'` in the ciphertext `c`, derives
//!   `(K', r')` from it in the same way, and encrypts `m'` again with `r'`. If the
//!   result is `c` the secret is `K'`. If not, the ciphertext was not made by an
//!   encapsulation, and the secret is `J(z || c)`, a hash of `c` and of the secret
//!   `z` in the key. This is "implicit rejection": decapsulation never fails and
//!   never says that it found something wrong. The caller's next step, whatever uses
//!   the secret, fails instead, as it would for an attacker who guessed.
//!
//! # Using it
//!
//! The receiver builds a [`DecapsulationKey`], either with
//! [`DecapsulationKey::generate`] from a source of secure random bytes or with
//! [`DecapsulationKey::from_seed`] from a seed it stored, and sends the encoding of
//! its [`DecapsulationKey::encapsulation_key`] to the sender. The sender turns the
//! bytes into an [`EncapsulationKey`] with [`EncapsulationKey::from_bytes`] and calls
//! [`EncapsulationKey::encapsulate`], which gives a [`SharedSecret`] to keep and a
//! [`Ciphertext`] to send, written as bytes with [`Ciphertext::as_bytes`]. The
//! receiver reads them back with [`Ciphertext::from_bytes`] and calls
//! [`DecapsulationKey::decapsulate`], which gives the same [`SharedSecret`].
//!
//! - **A key belongs to one parameter set, and the compiler knows which.** A
//!   `Ciphertext<MlKem768>` is opened only by a `DecapsulationKey<MlKem768>`. Mixing
//!   sets does not compile, where a library that picks the set at run time can only
//!   return an error.
//! - **The decapsulation key is the seed.** FIPS 203 also defines a decapsulation key
//!   of 1,632, 2,400 or 3,168 bytes, which is what the seed expands to. It is not
//!   accepted here: the seed is much smaller, and anything else would have to be
//!   checked for being what the seed makes. [`DecapsulationKey::seed`] gives it back.
//! - **The encapsulation key is checked when it is read.** The bytes must be as long
//!   as a key of the set, and every coefficient of the vector in them must be below
//!   `q`, which is the "modulus check" of FIPS 203 (section 7.2). A key that fails is
//!   refused with [`Error::InvalidEncapsulationKey`]; one that passes is not known to
//!   be anything but well formed, as any 12-bit string of the right length and below
//!   `q` is a key.
//! - **Decapsulation cannot fail, and does not say whether the ciphertext was good.**
//!   The ciphertext is checked for its length when it is read
//!   ([`Error::InvalidCiphertext`]), as every string of the right length is one. After
//!   that [`DecapsulationKey::decapsulate`] always gives a secret, and for a
//!   ciphertext that is not one of an encapsulation for this key (made for another
//!   key, changed on the way, or random) it is `J(z || c)`, which looks random and
//!   which the sender does not have.
//! - **The random bytes are the caller's.** The standard library has no secure
//!   random source that is stable, so [`DecapsulationKey::generate`] and
//!   [`EncapsulationKey::encapsulate`] take any [`io::Read`](std::io::Read). On Unix,
//!   a `File::open("/dev/urandom")` is one. A key or a secret from a predictable
//!   reader is guessable. FIPS 203 asks for a generator whose strength is at least
//!   that of the parameter set: 128, 192 and 256 bits (section 3.3). A reader of fixed
//!   bytes makes the same secret every time, which is for tests.
//! - **The secret is not a protocol.** It is 32 bytes that are uniform for anyone who
//!   does not have the decapsulation key, and they say nothing about who the other side
//!   is: ML-KEM authenticates nobody, so a man in the middle is possible unless
//!   something binds the keys to identities. The usual next step is a key derivation
//!   function over the secret and what the two sides have said so far, such as
//!   [`hkdf`](crate::hkdf).
//!
//! A decapsulation key is overwritten with zeros when it is dropped, and so is the
//! vector it expands to, and so is a shared secret; the `Debug` output of none of them
//! shows a secret. That is best effort: the working values of the arithmetic (numbers
//! that depend on a key or a secret, on the stack and in registers while it is in use)
//! are not all overwritten, and neither is the copy that moving a key (into a `Box` or
//! a `Vec`, say) can leave behind where it was.
//!
//! # Implementation
//!
//! No x86 or Arm CPU has instructions for the arithmetic of lattices, so there is
//! nothing to select at run time here, as there is for the ciphers and the
//! hashes: one portable implementation runs on every target, in safe Rust. Outside
//! its tests, the one `unsafe` it needs is the volatile write that wipes a key
//! when it is dropped, which the compiler would otherwise delete as a store
//! nobody reads. Much of the work is in SHAKE and SHA-3, which expand the seeds and
//! hash the keys, and that is the crate's [`sha3`](crate::sha3), on whichever of its
//! backends the CPU has.
//!
//! | Step | How |
//! |------|-----|
//! | numbers modulo `q` | `i16`, not reduced after each sum or difference but at the steps that need it, with Montgomery's reduction for products (`R = 2^16`) and Barrett's for the rest |
//! | `NTT` and its inverse | the transform of FIPS 203 on 256 coefficients, in seven layers of butterflies, with the roots of unity computed when the crate is compiled |
//! | `A * s`, `A^T * y` | the products of the terms summed in 32 bits, and reduced once for each pair of coefficients |
//! | `A` | made once for a key and kept, in both of its kinds, so that encapsulating and decapsulating do not make it again |
//! | `Compress` and `Decompress` | a multiplication and a shift in place of a division by `q`, checked against the definition for every number modulo `q` |
//! | SHAKE | streaming SHAKE128 for `A`, SHAKE256 for the noise and for implicit rejection, SHA3-256 and SHA3-512 for `H` and `G`, over the crate's Keccak |
//!
//! ## Trust
//!
//! The tests check this implementation against sources that share nothing with
//! it. For the whole scheme: the "accumulated" known answers of Go's `crypto/mlkem`
//! (a stream of seeds, messages and ciphertexts that are not good, from one SHAKE128,
//! of which the keys, ciphertexts and secrets are hashed), with 100 rounds for each
//! set, whose values Go and OpenSSL 3.6 make and agree on; the accumulated vectors
//! of C2SP's CCTV, 10,000 rounds for each set, in a test that is run on demand (they
//! are those of the draft of FIPS 203, whose key generation hashes `d` without `k`, and
//! the tests make keys that way for them); all 240 vectors of NIST's ACVP for ML-KEM
//! (75 of key generation, 75 of encapsulation, 30 of decapsulation, and 60 checks of
//! keys), of which a selection is run in the tests and all of them were run once; the
//! 1,725 cases of Project Wycheproof for ML-KEM (keys from seeds, decapsulations with
//! ciphertexts that are random, changed, too long or too short, and with the corner
//! cases of C2SP's `strcmp` and of malleable ciphertexts, encapsulations with keys that
//! are not reduced or have the wrong length, and decapsulations with expanded keys
//! that are corrupted), of which a selection is run in the tests and 1,665 were run
//! once (the other 60 give a seed of the wrong length, which `from_seed` refuses to
//! compile); and C2SP's vectors that need `SampleNTT` to read an unusual amount of
//! SHAKE128. OpenSSL 3.6 makes the same keys from the same seeds, the same
//! encapsulations from the same messages, and the same secret when it decapsulates a
//! ciphertext that is not good. The parts are checked on their own as well: the transform
//! and the product of `T_q` against the algorithms of the specification written out,
//! with the tables of its appendix A, and against the product of polynomials by the
//! definition, at the extremes of the ranges that the bounds on the intermediate
//! values allow; `Compress` and `Decompress` against the definitions with a true
//! division, for every number modulo `q`; the encodings against the bit strings of the
//! specification, and the modulus check for every number from `q` to 4095; and the two
//! samplers against the algorithms written out.
//!
//! ## Side channels
//!
//! Nothing that depends on a decapsulation key or on a secret is used as a memory
//! address or as a branch condition, with one exception. The transform, the products,
//! the reductions, the compression and the sampling of the noise are additions,
//! subtractions, multiplications, shifts and masks; the only tables are those of the
//! roots of unity, which are read in the order of the loops and not by a secret. The
//! comparison of the ciphertext with the one that decapsulation makes again ORs the
//! differences of all the bytes, and the choice of the secret is made with a mask, so
//! that the time does not say whether they were the same. SHAKE and SHA-3 read no table
//! but the round constants. The exception is `SampleNTT`, which draws a variable amount
//! from a stream: its seed is the public `rho`, so what its length reveals is
//! public, and the amount of the sampling of the noise is fixed.
//!
//! The assembly that `rustc` produced for `aarch64` and `x86_64` was inspected for
//! this, for ML-KEM-768's key generation, encapsulation and decapsulation: the
//! conditional jumps are loops with fixed counts, comparisons with the constant sizes
//! of the polynomials and of the buffers, checks of public lengths and of an
//! allocation, and the loops that overwrite buffers. There is none that a coefficient, a byte of a seed or of a
//! message, or the result of the comparison of ciphertexts decides, and the choice of
//! the secret is the arithmetic of the mask. That is a check of one compiler's output
//! for two targets, not a proof for all, and no timing measurements on real hardware
//! back it up. Nothing is protected against attacks that read power consumption or
//! inject faults. Encapsulating handles a secret message, and takes the same time for
//! every message; the encapsulation key it handles is public.
//!
//! # Example
//!
//! ```
//! use cryptors::mlkem::{Ciphertext, DecapsulationKey, EncapsulationKey, Error, MlKem768};
//!
//! // The receiver's key, from a seed of 64 bytes.
//! let seed: [u8; 64] = core::array::from_fn(|i| (i * 37 + 11) as u8);
//! let key = DecapsulationKey::<MlKem768>::from_seed(&seed);
//! assert_eq!(key.encapsulation_key().as_bytes()[..8], [0xa6, 0xd5, 0x10, 0xac, 0xe0, 0x7b, 0xbc, 0x1a]);
//!
//! // The sender has the bytes of the encapsulation key (this is where a key of the wrong
//! // length, or with a coefficient that is not below q, is refused)...
//! let public = EncapsulationKey::<MlKem768>::from_bytes(key.encapsulation_key().as_bytes())?;
//!
//! // ... and makes a secret and a ciphertext for it. A real program passes a source of
//! // secure random bytes; this is the 32 bytes of the message m, fixed, so that the
//! // answer is known.
//! let m: [u8; 32] = core::array::from_fn(|i| (i * 7 + 3) as u8);
//! let (secret, ciphertext) = public.encapsulate(&mut &m[..])?;
//! assert_eq!(secret.as_bytes()[..8], [0xc9, 0x48, 0x02, 0xd6, 0xa8, 0x31, 0x78, 0xe9]);
//! assert_eq!(ciphertext.as_bytes()[..8], [0x37, 0xee, 0x65, 0x93, 0xa3, 0x1a, 0x5e, 0x0e]);
//!
//! // The receiver reads the ciphertext and finds the same secret.
//! let received = Ciphertext::<MlKem768>::from_bytes(ciphertext.as_bytes())?;
//! assert_eq!(key.decapsulate(&received), secret);
//!
//! // A ciphertext that has been changed is not refused. It gives a secret that is not the
//! // sender's, and the same one every time.
//! let mut changed = ciphertext.as_bytes().to_vec();
//! changed[0] ^= 1;
//! let rejected = key.decapsulate(&Ciphertext::<MlKem768>::from_bytes(&changed)?);
//! assert_ne!(rejected, secret);
//! assert_eq!(rejected.as_bytes()[..8], [0xee, 0xed, 0x44, 0x54, 0x9a, 0x81, 0x00, 0xf1]);
//!
//! // A ciphertext of the wrong length is.
//! assert_eq!(Ciphertext::<MlKem768>::from_bytes(&changed[1..]), Err(Error::InvalidCiphertext));
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! Keys come from [`DecapsulationKey::generate`] in practice, which needs a source of
//! secure random bytes of your own (this one only compiles, as there is no source
//! that works on every platform):
//!
//! ```no_run
//! use cryptors::mlkem::{DecapsulationKey, EncapsulationKey, MlKem768};
//! use std::fs::File;
//!
//! # fn main() -> std::io::Result<()> {
//! let mut rng = File::open("/dev/urandom")?;
//!
//! // The receiver: store key.seed(), and send the encapsulation key to the sender.
//! let key = DecapsulationKey::<MlKem768>::generate(&mut rng)?;
//! let to_send = key.encapsulation_key().as_bytes();
//! assert_eq!(to_send.len(), 1184);
//!
//! // The sender, which has those bytes: send the ciphertext, and keep the secret.
//! let public = EncapsulationKey::<MlKem768>::from_bytes(to_send).expect("a key of the right size");
//! let (secret, ciphertext) = public.encapsulate(&mut rng)?;
//! assert_eq!(ciphertext.as_bytes().len(), 1088);
//! assert_eq!(secret.as_bytes().len(), 32);
//! # Ok(())
//! # }
//! ```
//!
//! A ciphertext of one parameter set cannot be opened with a key of another:
//!
//! ```compile_fail,E0308
//! use cryptors::mlkem::{DecapsulationKey, MlKem512, MlKem768};
//!
//! let key = DecapsulationKey::<MlKem768>::from_seed(&[1; 64]);
//! let other = DecapsulationKey::<MlKem512>::from_seed(&[1; 64]);
//! let (_, ciphertext) = other.encapsulation_key().encapsulate(&mut &[2u8; 32][..]).unwrap();
//! let _ = key.decapsulate(&ciphertext);
//! ```

mod algorithm;
#[cfg(test)]
mod conformance;
mod error;
mod field;
mod keypair;
mod pack;
mod params;
mod sample;
#[cfg(test)]
mod testutil;

pub use error::Error;
pub use keypair::{Ciphertext, DecapsulationKey, EncapsulationKey, SharedSecret};
pub use params::{MlKem512, MlKem768, MlKem1024, Parameters, SEED_LEN, SHARED_SECRET_LEN};
