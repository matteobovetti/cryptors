//! From-scratch implementation of the Module-Lattice-Based Digital Signature
//! Algorithm (ML-DSA), as FIPS 204 defines it: the holder of a private key makes
//! a signature of a message, and anyone who has the matching public key can check
//! that the signature is of that message and was made by that holder. Nobody
//! without the private key can make one. It is the standard form of
//! CRYSTALS-Dilithium, and a post-quantum scheme: it rests on lattice problems
//! that no known quantum algorithm solves, where [`ecdsa`](crate::ecdsa) and
//! [`ed25519`](crate::ed25519) rest on discrete logarithms, which Shor's
//! algorithm solves on a large quantum computer.
//!
//! | Parameter set | Type | Security category | Private key | Public key | Signature |
//! |---------------|------|-------------------|-------------|------------|-----------|
//! | ML-DSA-44 | [`MlDsa44`] | 2 | 32 bytes | 1,312 bytes | 2,420 bytes |
//! | ML-DSA-65 | [`MlDsa65`] | 3 | 32 bytes | 1,952 bytes | 3,309 bytes |
//! | ML-DSA-87 | [`MlDsa87`] | 5 | 32 bytes | 2,592 bytes | 4,627 bytes |
//!
//! The keys are [`PrivateKey`] and [`PublicKey`], and a signature is a
//! [`Signature`]; all three are generic over the parameter set, which is one of
//! the three types of the table, and which implement [`Parameters`]. The
//! categories are NIST's: 2 is as hard to break as a collision search on
//! SHA-256, 3 as a key search on AES-192 and 5 as one on AES-256.
//!
//! # How it works
//!
//! Everything happens in the ring `R_q` of polynomials of degree below 256 whose
//! coefficients are integers modulo `q = 8380417`, with `X^256 = -1`. The private
//! key is a seed `xi`, from which the key is expanded (FIPS 204, algorithm 6):
//! a public matrix `A` of `k` by `l` polynomials, made from a public seed `rho`;
//! two vectors `s1` and `s2` of polynomials with small coefficients, between
//! `-eta` and `eta`, which are the secret; and a key `K` for the signer's own use.
//! The public key is `rho` and `t1`, the high bits of `t = A * s1 + s2`.
//! Recovering `s1` and `s2` from `A` and `t` is the problem that the scheme
//! rests on. A signature is made like this (algorithm 7):
//!
//! 1. Hash the public key into `tr`, and `tr` and the message into a
//!    representative `mu`.
//! 2. Pick a vector `y` of polynomials with coefficients up to `gamma1`: the
//!    mask. It comes from `K`, `mu` and 32 random bytes (or zeros), so that it is
//!    never repeated and never guessable.
//! 3. Compute `w = A * y` and keep its high bits `w1`: the commitment. Hash `mu`
//!    and `w1` into `c_tilde`, and let `c` be the challenge it stands for: a
//!    polynomial with `tau` coefficients of `1` or `-1` and the others zero.
//! 4. Compute the response `z = y + c * s1`.
//! 5. If `z`, or the low bits of `w - c * s2`, or `c * t0` (the low bits that the
//!    public key left out) is large enough that it would give `s1`, `s2` or `t0`
//!    away, or if the hint needs more than `omega` ones, throw the attempt away
//!    and start again at step 2 with another mask. This is the "rejection
//!    sampling" of the scheme, and it takes about four or five attempts.
//! 6. The signature is `c_tilde`, `z` and the hint `h`, which tells the verifier
//!    where the high bits of `A * z - c * t` differ from those of `w`.
//!
//! To check a signature (algorithm 8) the verifier decodes it, checks that `z`
//! is small, computes `A * z - c * t1 * 2^13`, uses the hint to turn its high
//! bits into `w1`, and accepts if the hash of `mu` and that `w1` is `c_tilde`.
//! The products are made with a number-theoretic transform, which is what makes
//! the polynomial arithmetic fast.
//!
//! # Using it
//!
//! The signer builds a [`PrivateKey`], either with [`PrivateKey::generate`] from
//! a source of secure random bytes or with [`PrivateKey::from_seed`] from a seed
//! it stored, and sends the encoding of its [`PrivateKey::public_key`] to whoever
//! will check its signatures. The verifier turns the bytes into a [`PublicKey`]
//! with [`PublicKey::from_bytes`].
//!
//! | The signer has | Hedged | Deterministic |
//! |----------------|--------|---------------|
//! | the message | [`PrivateKey::sign`] | [`PrivateKey::sign_deterministic`] |
//! | the digest of the message | [`PrivateKey::sign_prehash`] | [`PrivateKey::sign_prehash_deterministic`] |
//! | the representative `mu` | [`PrivateKey::sign_mu`] | [`PrivateKey::sign_mu_deterministic`] |
//!
//! They return a [`Signature`], which is written as bytes with
//! [`Signature::as_bytes`] and read back with [`Signature::from_bytes`]. The
//! verifier calls [`PublicKey::verify`] with the message, the context and the
//! signature, or [`PublicKey::verify_prehash`] or [`PublicKey::verify_mu`] for the
//! other two.
//!
//! - **A key belongs to one parameter set, and the compiler knows which.** A
//!   `Signature<MlDsa65>` is checked only by a `PublicKey<MlDsa65>`. Mixing sets
//!   does not compile, where a library that picks the set at run time can only
//!   return an error.
//! - **The private key is the seed.** FIPS 204 also defines a private key of
//!   2,560, 4,032 or 4,896 bytes, which is what the seed expands to. It is not
//!   accepted here: the seed is much smaller, anything else that a key has to be
//!   checked against it, and RFC 9881 recommends it as the format to store and
//!   exchange keys in. [`PrivateKey::seed`] gives it back.
//! - **Hedged is the default, and deterministic is for when there is no
//!   random source.** A hedged signature mixes 32 bytes from the caller's reader
//!   into the mask, so two signatures of one message differ and a fault in one
//!   computation of a signature does not repeat in the next. If the reader is
//!   bad, even a constant, the mask is still derived from the key and the
//!   message, and the signature is as strong as a deterministic one
//!   (FIPS 204, section 3.4). A deterministic signature is the same every time,
//!   and an attacker who can induce a fault in one of two computations of it
//!   may learn something about the key, and the time it takes leaks information
//!   about the message, though not about the key (FIPS 204, section 3.6.1,
//!   footnote 3).
//! - **A context binds a signature to a use.** Every function takes a context of
//!   0 to 255 bytes, which the verifier has to repeat; a signature made under one
//!   context does not verify under another. Pass `b""` for none. It should be a
//!   constant of the protocol and not something derived from the message.
//! - **Pre-hashing is the exception.** FIPS 204 prefers signing the message
//!   itself (section 5.4). HashML-DSA ([`PrivateKey::sign_prehash`]) signs a
//!   digest of the message instead, with the identifier of the hash function in
//!   what is signed, so that a signature of a digest is not one of the message
//!   and is not one of another function's digest. Which function to use is a
//!   choice for the caller: the standard wants a collision strength of at least
//!   `lambda` bits, that is 128, 192 and 256 for the three sets. See [`PreHash`].
//!   RFC 9881 does not use HashML-DSA in X.509, and uses the external `mu`
//!   (appendix D) instead.
//! - **External `mu` splits the work.** The message representative `mu` is a
//!   hash of the public key's hash, the context and the message. A client that
//!   has a large message can compute it with [`PublicKey::message_representative`]
//!   and hand only these 64 bytes to the signer ([`PrivateKey::sign_mu`]); the
//!   signature is the one that the message would have had.
//! - **The random bytes are the caller's.** The standard library has no secure
//!   random source that is stable, so [`PrivateKey::generate`] and the hedged
//!   signatures take any [`io::Read`](std::io::Read). On Unix, a
//!   `File::open("/dev/urandom")` is one. A key from a predictable reader is
//!   guessable. FIPS 204 asks for a generator of at least 192 bits of strength
//!   for ML-DSA-65, 256 for ML-DSA-87 and, for ML-DSA-44, 128 bits and ideally
//!   192 (section 3.6.1).
//! - **Lengths are checked.** A public key and a signature of the wrong length
//!   are refused (section 3.6.2), and so is a signature whose hint is encoded in
//!   any way but the one that FIPS 204 produces, so a signature has one
//!   encoding. Every string of the right length is a public key.
//!
//! A private key is overwritten with zeros when it is dropped, and so are the
//! vectors it expands to; its `Debug` output does not show it. That is best
//! effort: the working values of the arithmetic (numbers that depend on a key, on
//! the stack and in registers while it is in use) are not all overwritten, and
//! neither is the copy that moving a key (into a `Box` or a `Vec`, say) can leave
//! behind where it was.
//!
//! # Implementation
//!
//! No x86 or Arm CPU has instructions for the arithmetic of lattices, so there is
//! nothing to select at run time here, as there is for the ciphers and the
//! hashes: one portable implementation runs on every target, in safe Rust. Outside
//! its tests, the one `unsafe` it needs is the volatile write that wipes a key
//! when it is dropped, which the compiler would otherwise delete as a store
//! nobody reads. Most of the work is in SHAKE, which expands the seeds and hashes
//! the messages, and that is the crate's [`sha3`](crate::sha3), on whichever of
//! its backends the CPU has.
//!
//! | Step | How |
//! |------|-----|
//! | numbers modulo `q` | `i32`, not reduced after each sum or difference but at the steps that need it, with Montgomery's reduction for products (`R = 2^32`) |
//! | `NTT` and its inverse | the transform of FIPS 204 on 256 coefficients, in eight layers of butterflies, with the roots of unity computed at compile time |
//! | `A * y`, `A * z` | the products summed in 64 bits and reduced once for each coefficient |
//! | `A` | made once for a private key and kept; a public key keeps only its bytes, so verifying makes the rows of `A` as it needs them and keeps none |
//! | the high and low bits | `Decompose` with a multiplication in place of a division, checked against the definition for every number modulo `q` |
//! | SHAKE | streaming SHAKE128 for `A` and SHAKE256 for everything else, over the crate's Keccak |
//!
//! ## Trust
//!
//! The tests check this implementation against sources that share nothing with
//! it. For the whole scheme: the accumulated known answers of C2SP's CCTV, which
//! make 100 keys and signatures for each set and compare a hash of all of them
//! (10,000 for each, in a test that is run on demand); all 615 vectors of NIST's
//! ACVP for ML-DSA (75 of key generation, 360 of signature generation and 180 of
//! signature verification, over the external, pre-hash and internal interfaces,
//! hedged and deterministic), of which a selection is run in the tests and all of
//! them were run once; the 27 known answers that NIST publishes for the
//! rejection loop of signing, which reach each of its four ways to reject, and
//! the ones that need up to 100 rejections; and the 1,138 cases of Project
//! Wycheproof for ML-DSA (287 of signing from a seed, 220 of signing from an
//! expanded key and 631 of verifying, among them encodings of the hint that are
//! not the right one, signatures at the edge of the norm bounds and keys of all
//! zeros), of which a selection is run in the tests and 1,129 were run once (the
//! other nine give a seed of the wrong length, which `from_seed` refuses to
//! compile). OpenSSL
//! 3.6 makes the same public keys from the same seeds, the same deterministic
//! signatures (with and without a context), and verifies the hedged ones this
//! crate makes. The parts are checked on their own as well: the transform
//! against a schoolbook product of polynomials, at the extremes of the ranges
//! that its bounds allow; the high and low bits and the hints, for every number
//! modulo `q`; the samplers against the algorithms
//! written out in the tests; and the streaming SHAKE against the one-shot one.
//!
//! ## Side channels
//!
//! Nothing that depends on a private key or on the mask is used as a memory
//! address or as a branch condition, with the exceptions listed here. The
//! transform, the products, the reductions and the rounding are additions,
//! subtractions, multiplications, shifts and masks; the only table is that of
//! the roots of unity, which is read in the order of the loops and not by a
//! secret. The checks of the norms accumulate with masks. SHAKE reads no table
//! but the round constants. The exceptions are the ones the design of the scheme
//! has: whether an attempt at a signature was rejected, and which check
//! rejected it, which the signature does not depend on and the Dilithium
//! specification (section 5.5) shows to be safe to reveal, and how many bytes the
//! sampler of `s1` and `s2` reads from the seed `rho_prime`, which reveals which
//! of its candidates were thrown away and not the ones that were kept. A
//! deterministic signature takes a time that depends on the message, though not
//! on the private key (FIPS 204, section 3.6.1, footnote 3), so a signer that
//! wants the message to stay private should sign hedged.
//!
//! The assembly that `rustc` produced for `aarch64` and `x86_64` was inspected
//! for this: the conditional jumps in the code that signs and in key generation
//! are loops with fixed counts, checks of public lengths and of an allocation,
//! the management of the SHAKE buffer, the decision to reject an attempt (the
//! test of a mask that the check of a norm accumulates), the packing of the hint
//! of a signature that has been accepted, and the candidates of the sampler that
//! were thrown away. That is a check of one compiler's output for two targets,
//! not a proof for all, and no timing measurements on real hardware back it up.
//! Nothing is protected against attacks that read power consumption or inject
//! faults; the hedged signature makes the faults that exploit a repeated mask
//! harder, and does not stop one that skips an instruction. Verifying a
//! signature handles no secret, and the time it takes depends on its inputs.
//!
//! # Example
//!
//! ```
//! use cryptors::mldsa::{Error, MlDsa44, PrivateKey, PublicKey, Signature};
//!
//! // A key from a seed of 32 bytes of 0x2a, and the deterministic signature of
//! // "Hello world" with no context: a case of Project Wycheproof.
//! let key = PrivateKey::<MlDsa44>::from_seed(&[0x2a; 32]);
//! assert_eq!(key.public_key().as_bytes()[..8], [0xdb, 0x9a, 0xc6, 0x77, 0x08, 0xf2, 0xba, 0x0f]);
//! let signature = key.sign_deterministic(b"Hello world", b"")?;
//! assert_eq!(signature.as_bytes()[..8], [0x1a, 0xa6, 0x9c, 0xb5, 0xed, 0x35, 0x20, 0x45]);
//!
//! // The verifier has the public key and the signature as bytes (this is where
//! // a key or a signature of the wrong length is refused)...
//! let public = PublicKey::<MlDsa44>::from_bytes(key.public_key().as_bytes())?;
//! let received = Signature::<MlDsa44>::from_bytes(signature.as_bytes())?;
//!
//! // ...and checks the signature against the message and the context.
//! assert_eq!(public.verify(b"Hello world", b"", &received), Ok(()));
//! assert_eq!(public.verify(b"Hello world!", b"", &received), Err(Error::VerificationFailed));
//! assert_eq!(public.verify(b"Hello world", b"v2", &received), Err(Error::VerificationFailed));
//!
//! // A hedged signature takes 32 random bytes from a reader, here a fixed string;
//! // it is another signature of the same message, and just as valid.
//! let mut noise: &[u8] = &[7; 32];
//! let hedged = key.sign(&mut noise, b"Hello world", b"")?;
//! assert_ne!(hedged, signature);
//! assert_eq!(public.verify(b"Hello world", b"", &hedged), Ok(()));
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! Keys come from [`PrivateKey::generate`] in practice, which needs a source of
//! secure random bytes of your own (this one only compiles, as there is no source
//! that works on every platform):
//!
//! ```no_run
//! use cryptors::mldsa::{MlDsa65, PrivateKey};
//! use std::fs::File;
//!
//! # fn main() -> std::io::Result<()> {
//! let mut rng = File::open("/dev/urandom")?;
//! let key = PrivateKey::<MlDsa65>::generate(&mut rng)?;
//! let signature = key.sign(&mut rng, b"a message", b"")?;
//! // Store key.seed(); send key.public_key().as_bytes(), the message and
//! // signature.as_bytes().
//! assert_eq!(signature.as_bytes().len(), 3309);
//! # Ok(())
//! # }
//! ```
//!
//! A signature of one parameter set cannot be checked with a key of another:
//!
//! ```compile_fail,E0308
//! use cryptors::mldsa::{MlDsa44, MlDsa65, PrivateKey};
//!
//! let signature = PrivateKey::<MlDsa44>::from_seed(&[1; 32])
//!     .sign_deterministic(b"message", b"")
//!     .unwrap();
//! let public = PrivateKey::<MlDsa65>::from_seed(&[1; 32]).public_key().clone();
//! let _ = public.verify(b"message", b"", &signature);
//! ```

mod algorithm;
#[cfg(test)]
mod conformance;
mod error;
mod field;
mod keypair;
mod pack;
mod params;
mod prehash;
mod rounding;
mod sample;
#[cfg(test)]
mod testutil;

pub use error::Error;
pub use keypair::{MAX_CONTEXT_LEN, PrivateKey, PublicKey, Signature};
pub use params::{MlDsa44, MlDsa65, MlDsa87, Parameters, SEED_LEN};
pub use prehash::PreHash;
