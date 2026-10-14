//! From-scratch implementation of Ed25519 (RFC 8032): the holder of a private
//! key signs a message, and anyone with the matching public key can check that
//! the signature is of that message and was made with that key, which nobody
//! without the private key can do. It is EdDSA, the Edwards-curve Digital
//! Signature Algorithm, on edwards25519 with SHA-512, in the three schemes the
//! RFC defines for that curve.
//!
//! | Scheme | Signs | Context | Sign | Verify |
//! |--------|-------|---------|------|--------|
//! | Ed25519 | the message | none | [`SigningKey::sign`] | [`VerifyingKey::verify`] |
//! | Ed25519ctx | the message | 1 to 255 bytes | [`SigningKey::sign_ctx`] | [`VerifyingKey::verify_ctx`] |
//! | Ed25519ph | its SHA-512 digest | 0 to 255 bytes | [`SigningKey::sign_prehashed`] | [`VerifyingKey::verify_prehashed`] |
//!
//! A private key is a 32-byte seed, a public key 32 bytes and a [`Signature`]
//! 64 bytes, the same for all three schemes; the keys are [`SigningKey`] and
//! [`VerifyingKey`], and every failure is an [`Error`]. There is one curve and
//! the hash is part of the algorithm, so unlike [ECDH](crate::ecdh) and
//! [ECDSA](crate::ecdsa) nothing here is generic.
//!
//! # How it works
//!
//! edwards25519 is the curve `-x^2 + y^2 = 1 + d x^2 y^2` modulo the prime
//! `p = 2^255 - 19`, the twisted Edwards form of the curve of X25519. Its points
//! form a group of `8 ℓ` elements, with `ℓ` a prime a little above `2^252`, and
//! the base point `B` generates the subgroup of order `ℓ`. Adding a point to
//! itself `s` times gives `[s]B`, which takes a short chain of doublings and
//! additions even for an `s` of 253 bits; going back, from `[s]B` to `s`, is
//! the discrete logarithm problem, which takes about `2^126` steps here.
//!
//! The private key is a 32-byte seed. Its SHA-512 digest has two halves: the
//! first, with a few bits fixed ("pruned"), is the secret scalar `s`, and the
//! second is a prefix kept for making per-message secrets. The public key is
//! `A = [s]B`, encoded in 32 bytes: the y-coordinate, with the low bit of x in
//! the top bit (RFC 8032, section 5.1.2).
//!
//! To sign a message `M`, the signer hashes the prefix with `M` into a secret
//! `r`, computes `R = [r]B`, hashes `R`, `A` and `M` into a challenge `k`, and
//! sends `R` and `S = r + k s` modulo `ℓ`: 64 bytes. The verifier, who knows
//! `A` but not `s`, recomputes `k` and checks that `[S]B = R + [k]A`, which
//! holds because `[S]B = [r]B + [k][s]B`. Because `r` comes from the message,
//! signing needs no randomness, and the same message always gets the same
//! signature. Ed25519ctx and Ed25519ph put a prefix that names the scheme, and
//! the context, in front of every hash input (`dom2`, RFC 8032 section 2), so a
//! signature made under one of the three schemes does not verify under another.
//!
//! # Using it
//!
//! The signer makes a [`SigningKey`], either with [`SigningKey::generate`] from
//! a source of secure random bytes or with [`SigningKey::from_seed`] from a seed
//! it stored, and publishes the encoding of its [`SigningKey::verifying_key`].
//! A verifier turns those bytes into a [`VerifyingKey`] with
//! [`VerifyingKey::from_bytes`], which is where an invalid key is refused, and
//! calls one of its `verify` methods with the message and the signature.
//!
//! - **Key generation needs random bytes this crate cannot supply.** The
//!   standard library has no secure random source that is stable, so
//!   `generate` takes any [`io::Read`](std::io::Read). On Unix, a
//!   `File::open("/dev/urandom")` is one. A reader that is predictable makes
//!   every key it produced guessable. Nothing after that is random.
//! - **The rules of verification are strict, and spelled out.** S must be below
//!   `ℓ` (RFC 8032, section 8.4: otherwise `S + ℓ` would be a second signature
//!   of the same message); R is compared byte for byte with the encoding of
//!   `[S]B - [k]A`, so only the canonical encoding of the right point matches;
//!   and the equation is the cofactorless `[S]B = R + [k]A`, which the RFC
//!   allows in place of `[8][S]B = [8]R + [8][k]A`. That much is what Go's
//!   `crypto/ed25519` does. [`VerifyingKey::from_bytes`] is stricter than Go:
//!   it refuses encodings that the RFC's decoding refuses (y of `p` or more,
//!   the sign bit set when x = 0), which Go accepts, and the eight points of
//!   small order, under which signatures can be made without the private key
//!   and which Go accepts too. Every signature that this module accepts, Go
//!   accepts; the reverse fails only for those keys, which no key generation
//!   produces.
//! - **Plain Ed25519 is the one to use.** A context should be a constant of a
//!   protocol that asks for one (RFC 8032, section 8.3), and an empty
//!   Ed25519ctx context is refused, as OpenSSL refuses it. The RFC says that
//!   Ed25519ph SHOULD NOT be used (section 8.5): it is only as strong as
//!   SHA-512's collision resistance, which Ed25519 does not rely on.
//! - **A deterministic signature does not resist faults.** Someone who can make
//!   one computation of a signature go wrong, and see it beside a correct one,
//!   can work out the key. Nothing here protects against that.
//!
//! A signing key is overwritten with zeros when it is dropped, and its `Debug`
//! output shows only the public key. That is best effort: the working values of
//! the arithmetic (points and numbers that depend on a key, on the stack and in
//! registers while it is in use), what SHA-512 copies onto its own stack, and
//! the copy that moving a key (into a `Box` or a `Vec`, say) can leave behind
//! where it was are not overwritten.
//!
//! Ed25519 does not resist a large quantum computer: Shor's algorithm finds `s`
//! from `[s]B`. A signature that has to stay trustworthy after such a machine
//! exists needs a post-quantum scheme, such as [ML-DSA](crate::mldsa), alongside or instead.
//! Ed448, the other curve of RFC 8032, is not implemented.
//!
//! # Implementation
//!
//! No x86 or Arm CPU has instructions for elliptic curve arithmetic, so there
//! is nothing to select at run time: one portable implementation runs on every
//! target, and all it asks of the CPU is a 64-bit multiplication with a 128-bit
//! result, which Rust's `u128` provides. The one part with a hardware path is
//! the hash, [`Sha512`](crate::sha2::Sha512), which uses FEAT_SHA512 on aarch64
//! where the CPU has it. It is written in safe Rust. Outside its tests, the one
//! `unsafe` it needs is the volatile write that wipes a key when it is dropped,
//! in `src/wipe.rs`, which the compiler would otherwise delete as a store
//! nobody reads.
//!
//! | Layer | Representation |
//! |-------|----------------|
//! | numbers modulo `2^255 - 19` | 5 limbs of 51 bits, sums not carried: the field of X25519, shared with it |
//! | numbers modulo `ℓ` | 4 words of 64 bits, Barrett reduction |
//! | points | extended coordinates (X : Y : Z : T), complete formulas; added in the form (Y + X, Y - X, Z, 2 d T) |
//! | `[s]B`, to sign and to make a key | signed digits of 4 bits, a table of 32 x 8 multiples of `B` (30 KiB), read in full |
//! | `[S]B - [k]A`, to verify | non-adjacent forms of width 5 for `A` (8 odd multiples per call) and 8 for `B` (64, 7.5 KiB), one chain of doublings |
//!
//! - **Five limbs of 51 bits**, as in Go's
//!   `crypto/internal/fips140/edwards25519`. The field is the one X25519 uses
//!   too: one crate-private module, `src/ec/fe25519.rs`, serves both, with the
//!   parts only Ed25519 needs (a square root of a ratio, the sign of a number,
//!   its negation) added to it. Five such limbs leave 13 bits free in each
//!   word, so the five products of a column of a multiplication add up in a
//!   `u128`, and a carry out of the top limb, a multiple of `2^255`, folds into
//!   the bottom one multiplied by 19. Sums are not carried at all: a product
//!   takes limbs up to `2^54`, so the sum of two results goes straight into it,
//!   which saves a carry at every addition of the point formulas.
//! - **Barrett reduction.** A 512-bit digest is reduced modulo `ℓ` with a
//!   precomputed `2^512 / ℓ`: a multiplication estimates the quotient, and one
//!   subtraction by mask corrects it.
//! - **Complete formulas.** The addition and doubling of RFC 8032 (section
//!   5.1.4, from Hisil, Wong, Carter and Dawson, 2008) give the right answer for
//!   every pair of points of the curve, the identity and equal points included,
//!   so the code that multiplies a point has no special case to branch on.
//! - **A table for every window of the scalar.** `[s]B` writes `s` in 64 signed
//!   digits from -8 to 8, and a table built on first use holds the first eight
//!   multiples of `256^i B` for each `i`. The multiplication is then 64
//!   additions and four doublings. Each lookup reads all eight entries of its
//!   row and keeps one with masks, so which one it wanted does not show in an
//!   address, and negating the entry for a negative digit is a masked swap.
//! - **One chain of doublings for both products.** Verifying handles no secret,
//!   so `[S]B - [k]A` takes both scalars in non-adjacent form, where at most one
//!   digit in every `w` is nonzero, and doubles once for the two of them. The
//!   multiples of `A` are computed for each verification, those of `B` once.
//!
//! The two tables are kept for the life of the process and shared by all
//! threads, and building them is a delay in the first key or signature a process
//! makes.
//!
//! ## Trust
//!
//! The tests check this implementation against sources that share nothing with
//! it: every example of RFC 8032 for the three schemes, the 128 vectors that Go's
//! `crypto/ed25519` tests with (from the software of the authors of Ed25519),
//! and 768 signatures under 256 keys from Go, which OpenSSL makes too. Each rule
//! of verification has a test of its own, with signatures made for the purpose:
//! a non-canonical R, an S of `ℓ` or more, every non-canonical encoding of a
//! public key, the points of small order, and a key with a component of small
//! order, which tells the cofactorless equation from the other. Under them, the
//! field (whose tests are with it, in `src/ec/fe25519.rs`, and are X25519's
//! too) is checked against the generic field of the NIST curves, the reduction
//! of scalars against one done a bit at a time, and the double multiplication
//! against plain double-and-add.
//!
//! ## Side channels
//!
//! Nothing that depends on the seed, the secret scalar, the prefix or a
//! per-message secret is used as a memory address or as a branch condition. The
//! scalar goes through a table lookup that reads every entry and a negation
//! done with masks, and the arithmetic below them has no conditional jump or
//! table of its own: the final subtraction of `p` is `p` times a carry of 0 or
//! 1, that of `ℓ` a selection by a mask, and the inverse that encodes a point
//! is a power with a fixed exponent. A compiler is free to turn such a selection
//! back into a jump, and the masks go through `core::hint::black_box` to make
//! that less likely, which is a request, not a guarantee (it costs about 2.5%
//! of a signature). The assembly that `rustc` 1.95 produced for
//! `aarch64-apple-darwin` and `x86_64-unknown-linux-gnu`, in a release build,
//! was inspected for this, and the conditional jumps in the code that derives
//! a key and signs are of these kinds only: loops over a public number of
//! windows, table entries, words or squarings; the check of whether a table has
//! been built; checks of public lengths and of an allocation; and the
//! comparison of the two public halves of a key pair in
//! [`SigningKey::from_keypair_bytes`]. The hashing is SHA-512, whose work and
//! memory accesses depend only on the length of its input. That is a check of
//! one compiler's output for two targets, not a proof for all, and no timing
//! measurements on real hardware back it up.
//!
//! The things that are not hidden are public by nature. Verifying, and decoding
//! a public key, take a time that depends on the key, the message and the
//! signature, none of which is secret. The time to sign grows with the length
//! of the message. Nothing here is protected against attacks that read power
//! consumption or inject faults.
//!
//! # Example
//!
//! ```
//! # fn unhex(s: &str) -> Vec<u8> {
//! #     (0..s.len() / 2).map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap()).collect()
//! # }
//! use cryptors::ed25519::{Error, Signature, SigningKey, VerifyingKey};
//!
//! // RFC 8032, section 7.1, test 1: a seed, its public key, and the signature
//! // of the empty message.
//! let seed: [u8; 32] = unhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
//!     .try_into()
//!     .unwrap();
//! let key = SigningKey::from_seed(&seed);
//! assert_eq!(
//!     key.verifying_key().as_bytes()[..],
//!     unhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
//! );
//! let signature = key.sign(b"");
//! assert_eq!(
//!     signature.to_bytes()[..],
//!     unhex(concat!(
//!         "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155",
//!         "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
//!     ))
//! );
//!
//! // The verifier has the public key and the signature as bytes...
//! let public = VerifyingKey::try_from(&key.verifying_key().to_bytes()[..])?;
//! let received = Signature::try_from(&signature.to_bytes()[..])?;
//!
//! // ...and checks the signature against the message.
//! assert_eq!(public.verify(b"", &received), Ok(()));
//! assert_eq!(public.verify(b"x", &received), Err(Error::InvalidSignature));
//!
//! // A context names what a signature is for, and must match.
//! let signature = key.sign_ctx(b"message", b"my protocol, v1")?;
//! assert_eq!(public.verify_ctx(b"message", b"my protocol, v1", &signature), Ok(()));
//! assert_eq!(
//!     public.verify_ctx(b"message", b"my protocol, v2", &signature),
//!     Err(Error::InvalidSignature)
//! );
//!
//! // The identity, (0, 1), is a point of the curve but of small order, and is
//! // refused as a key.
//! let mut identity = [0u8; 32];
//! identity[0] = 1;
//! assert_eq!(VerifyingKey::from_bytes(&identity), Err(Error::InvalidPublicKey));
//! # Ok::<(), Error>(())
//! ```
//!
//! Keys come from [`SigningKey::generate`] in practice, which needs a source of
//! secure random bytes of your own (this one only compiles, as there is no
//! source that works on every platform):
//!
//! ```no_run
//! use cryptors::ed25519::SigningKey;
//! use std::fs::File;
//!
//! # fn main() -> std::io::Result<()> {
//! let mut rng = File::open("/dev/urandom")?;
//! let key = SigningKey::generate(&mut rng)?;
//! let signature = key.sign(b"a message");
//! // Send `key.verifying_key().to_bytes()`, the message and
//! // `signature.to_bytes()` to the other side.
//! assert!(key.verifying_key().verify(b"a message", &signature).is_ok());
//! # Ok(())
//! # }
//! ```
//!
//! Ed25519ph signs a SHA-512 digest, and the type says so: a digest of any
//! other length, such as SHA-256's, does not compile.
//!
//! ```compile_fail,E0308
//! use cryptors::{Digest, ed25519::SigningKey, sha2::Sha256};
//!
//! let key = SigningKey::from_seed(&[1; 32]);
//! let _ = key.sign_prehashed(&Sha256::digest(b"a message"), b"");
//! ```

mod edwards;
mod scalar;
mod signature;

pub use signature::{Error, MAX_CONTEXT_LEN, Signature, SigningKey, VerifyingKey};
