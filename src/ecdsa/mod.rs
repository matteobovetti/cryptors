//! From-scratch implementation of the Elliptic Curve Digital Signature Algorithm
//! (ECDSA), as FIPS 186-5 defines it: the holder of a private key makes a
//! signature of a message, and anyone who has the matching public key can check
//! that the signature is of that message and was made by that holder. Nobody
//! without the private key can make one. It works over the four NIST curves
//! P-224, P-256, P-384 and P-521.
//!
//! | Curve | Type | Defined in | Private key | Public key | Signature as `r \|\| s` | Signature in DER |
//! |-------|------|------------|-------------|------------|-----------------------|------------------|
//! | NIST P-224 | [`P224`] | NIST SP 800-186, SEC 2, FIPS 186-5 | 28 bytes | 57 bytes | 56 bytes | 8 to 64 bytes |
//! | NIST P-256 | [`P256`] | the same | 32 bytes | 65 bytes | 64 bytes | 8 to 72 bytes |
//! | NIST P-384 | [`P384`] | the same | 48 bytes | 97 bytes | 96 bytes | 8 to 104 bytes |
//! | NIST P-521 | [`P521`] | the same | 66 bytes | 133 bytes | 132 bytes | 8 to 139 bytes |
//!
//! The keys are [`PrivateKey`] and [`PublicKey`], and a signature is a
//! [`Signature`]; all three are generic over the curve. The four curves are the
//! four types of the table, which implement [`Curve`]. They are the types that
//! [`ecdh`](crate::ecdh) uses for its NIST curves, but a key made for one
//! algorithm is not a key of the other (see below), and P-224 is only here.
//!
//! # How it works
//!
//! A private key is a number `d` from 1 to `n - 1`, where `n` is the order of the
//! curve (the number of points that the generator `G` makes), and the public key
//! is the point `Q = d * G`, as in ECDH. A signature is two numbers `(r, s)` from
//! 1 to `n - 1`, made like this (FIPS 186-5, section 6.4.1):
//!
//! 1. Hash the message to `H`, and let `e` be the number that the leftmost bits
//!    of `H` make, as many as `n` has (all of `H` if it is shorter).
//! 2. Choose a number `k` from 1 to `n - 1` that nobody else knows and that is
//!    never used for a second signature.
//! 3. Compute the point `R = k * G`, and let `r` be its x-coordinate modulo `n`.
//! 4. Compute `s = k^-1 * (e + r * d) mod n`.
//! 5. If `r` or `s` is zero, start again from step 2 with another `k`.
//!
//! To check a signature (section 6.4.2): see that `r` and `s` are from 1 to
//! `n - 1`; compute `e` from the message the same way; compute `w = s^-1`,
//! `u = e * w` and `v = r * w`, all modulo `n`; compute the point
//! `R = u * G + v * Q`; and accept if `R` is not the point at infinity and its
//! x-coordinate modulo `n` is `r`. It works because `s * k = e + r * d`, so
//! `k = u + v * d`, and `u * G + v * Q = (u + v * d) * G = k * G`.
//!
//! The number `k` is the delicate part. From a signature, `d = (s * k - e) / r`,
//! so whoever learns `k` has the private key; two signatures that share a `k`
//! give it away, because the two equations have two unknowns; and many
//! signatures whose `k` have a few bits in common or a few bits that can be
//! guessed give it away too, by a lattice attack. Signatures need a `k` that is
//! as secret and as unpredictable as the key. There are two ways to get one, and
//! both are here:
//!
//! - **Hedged** ([`PrivateKey::sign`], [`PrivateKey::sign_prehash`]): `k` comes
//!   from an HMAC_DRBG that is seeded with random bytes from the caller, the
//!   private key and the digest, in the construction of
//!   draft-irtf-cfrg-det-sigs-with-noise (section 4), except that it runs on
//!   SHA-512 whatever the hash of the message is, where the draft uses the hash
//!   of the signature, which a digest does not say. Two signatures of the same
//!   message differ. If the random bytes are bad, even a constant, `k` is still
//!   as unpredictable as it would be in a deterministic signature, so a failing
//!   random source costs the randomization and not the key. The randomization is
//!   what stops an attacker who can induce faults from getting two computations
//!   that share a `k`.
//! - **Deterministic** ([`PrivateKey::sign_deterministic`],
//!   [`PrivateKey::sign_prehash_deterministic`]): `k` comes from the same
//!   generator seeded with the private key and the digest alone (RFC 6979;
//!   FIPS 186-5, appendix A.3.3). The same key and message give the same
//!   signature, no random source is needed, and nothing can go wrong with one.
//!
//! # Using it
//!
//! The signer builds a [`PrivateKey`], either with [`PrivateKey::generate`] from
//! a source of secure random bytes or with [`PrivateKey::from_bytes`] from a key
//! it stored, and sends the encoding of its [`PrivateKey::public_key`] to whoever
//! will check its signatures. The verifier turns the bytes into a [`PublicKey`]
//! with [`PublicKey::from_bytes`], which is where an invalid key is refused.
//!
//! | The signer has | Randomized | Deterministic |
//! |----------------|------------|---------------|
//! | the message | [`PrivateKey::sign`] | [`PrivateKey::sign_deterministic`] |
//! | the digest of the message | [`PrivateKey::sign_prehash`] | [`PrivateKey::sign_prehash_deterministic`] |
//!
//! They return a [`Signature`], which is written as bytes with
//! [`Signature::as_bytes`] (`r || s`) or [`Signature::to_der`], and read back
//! with [`Signature::from_bytes`] or [`Signature::from_der`]. The verifier calls
//! [`PublicKey::verify`] with the message, or [`PublicKey::verify_prehash`] with
//! its digest.
//!
//! - **A key belongs to one curve, and the compiler knows which.** A
//!   `Signature<P256>` is checked only by a `PublicKey<P256>`. Mixing curves
//!   does not compile, where a library that picks the curve at run time can only
//!   return an error.
//! - **A signing key is not a key-agreement key.** FIPS 186-5 (sections 6 and
//!   6.2) says that ECDSA keys shall not be used for any other purpose. The keys of this
//!   module are types of their own, so that an ECDH key cannot be handed to it by
//!   accident; the encodings are the same, and
//!   `PrivateKey::from_bytes(ecdh_key.as_bytes())` is the explicit way, for
//!   whoever means to do it.
//! - **The hash is a choice, and it matters.** Pass the hash function as the
//!   type `D` of `sign` and `verify`; the verifier has to use the same one. FIPS
//!   186-5 approves the SHA-2 and SHA-3 families, recommends one whose strength
//!   is the same as the curve's, and says that one that is weaker "shall not be
//!   used" (section 6.1.1). SHA-256 suits P-224 and P-256, SHA-384 suits P-384,
//!   and SHA-512 suits P-521. This module does not stop a caller from naming
//!   another [`Digest`](crate::Digest), SHA-1 or MD5 included, and the signature
//!   is then as weak as that choice. SHA-3 is not a `Digest` yet, and its output
//!   goes through the `_prehash` functions.
//! - **A digest longer than the order is cut.** FIPS 186-5 uses only the
//!   leftmost bits of the digest, as many as `n` has: all 224, 256, 384 or 521
//!   of them. The rest of a longer digest, SHA-512's for P-256, plays no part in
//!   the signature.
//! - **The random bytes are the caller's.** The standard library has no secure
//!   random source that is stable, so [`PrivateKey::generate`] and the
//!   randomized signatures take any [`io::Read`](std::io::Read). On Unix, a
//!   `File::open("/dev/urandom")` is one. A key from a predictable reader is
//!   guessable. For a signature, the reader needs to be secret and made by a
//!   cryptographically secure generator, but it does not need to be perfect:
//!   draft-irtf-cfrg-det-sigs-with-noise (section 5) shows that a repeated one
//!   leaves the signature as strong as a deterministic one.
//! - **A signature is not unique.** If `(r, s)` is a signature then so is
//!   `(r, n - s)`, and anyone can make the second from the first without the
//!   key. It is not a forgery, as both are signatures of the same message, but a
//!   program that identifies a signature by its bytes (a transaction identifier,
//!   a cache key) must not assume there is only one. The randomized form gives a
//!   different signature each time, and the deterministic one only the same.
//! - **The DER form is strict.** [`Signature::from_der`] accepts one encoding of
//!   each pair of numbers and nothing else: no extra bytes, no length written in
//!   a longer form than needed, no padding zeros, no negative integers. Lenient
//!   readers (BER) make one signature valid in several forms.
//!
//! A private key is overwritten with zeros when it is dropped; its `Debug`
//! output does not show it. That is best effort: the working values of the
//! arithmetic (numbers that depend on a key, on the stack and in registers while
//! it is in use) are not overwritten, and neither is the copy that moving a key
//! (into a `Box` or a `Vec`, say) can leave behind where it was.
//!
//! The NIST curves do not resist a large quantum computer: Shor's algorithm
//! finds `d` from `d * G` in polynomial time, and anything signed by a key that
//! has to stay trustworthy past the arrival of such a machine needs a
//! post-quantum scheme, such as ML-DSA, alongside or instead.
//!
//! # Implementation
//!
//! No x86 or Arm CPU has instructions for elliptic curve arithmetic, so there is
//! nothing to select at run time here, as there is for the ciphers and the
//! hashes: one portable implementation runs on every target. It is the
//! arithmetic of [`ecdh`](crate::ecdh) on the same curves, with the order of the
//! curve as the modulus where ECDH has the prime. All it asks of the CPU is a
//! 64-bit multiplication with a 128-bit result, which Rust's `u128` provides. It
//! is written in safe Rust. Outside its tests, the one `unsafe` it needs is the
//! volatile write that wipes a key when it is dropped, which the compiler would
//! otherwise delete as a store nobody reads.
//!
//! | Step | How |
//! |------|-----|
//! | `e`, `r`, `s` and the other numbers modulo `n` | 4, 6 and 9 limbs of 64 bits, in Montgomery form, with the same routines as the field of the curve and the order as the modulus |
//! | `k * G` | the table of 15 multiples of `G` for each four-bit window, shared with the public keys of `ecdh` and built on first use: one addition per window and no doubling |
//! | `k^-1`, `s^-1` | the number to the power `n - 2` (Fermat's little theorem), which is a fixed exponent, so the steps do not depend on the number |
//! | `u * G + v * Q` | `u * G` from the same table, `v * Q` with a four-bit window, then one addition with the complete formulas of Renes, Costello and Batina |
//! | `k` | an HMAC_DRBG (NIST SP 800-90A Rev. 1, section 10.1.2) on a small private HMAC, since the crate does not have a public one yet |
//!
//! - **Montgomery form for the order too.** The arithmetic modulo a prime in
//!   `ecdh` is written for any modulus, as a function of the number of limbs and
//!   of constants it derives from the modulus at compile time, so the order of
//!   each curve is one more instance of it. The digest and the x-coordinate are
//!   reduced modulo `n` with one conditional subtraction, as both are below
//!   `2 * n` on all four curves.
//! - **A candidate for `k` is the leftmost bits.** The generator produces as many
//!   bytes as `n` has, and for P-521, whose order has 521 bits and not 528, the
//!   seven bits at the end are shifted out; what is left is tested to be from 1
//!   to `n - 1`, and the next candidate is drawn if it is not (FIPS 186-5,
//!   appendices A.3.2 and A.3.3). The same rule makes a private key from random
//!   bytes in [`PrivateKey::generate`].
//! - **The deterministic signature does not fail.** FIPS 186-5 (section 6.4.1,
//!   step 11) says that a deterministic signature with `r` or `s` equal to zero
//!   is a failure; RFC 6979 (section 3.2, step h) goes on to the next candidate.
//!   This does the second, which is why [`PrivateKey::sign_deterministic`]
//!   returns a signature and not a result. The event has a probability of about
//!   `1/n` per signature: less than `2^-223` on every curve.
//!
//! ## Trust
//!
//! The tests check this implementation against sources that share nothing with
//! it. For the signatures: the 40 signatures of RFC 6979, appendix A.2 (the `k`
//! of each one too), which the deterministic signature has to reproduce bit for
//! bit; NIST's CAVP vectors for verification, for every pair of curve and hash;
//! and the cases of Project Wycheproof, 9,767 in 21 files that go after the
//! places where implementations break (arithmetic edge cases such as a `u1` or a
//! `u2` that is zero or a point that doubles, public keys with special
//! coordinates, small and huge `r` and `s`, every way to write a signature in
//! DER that is not the right one, and digests chosen to be special values), of
//! which a selection is run in the tests and all of them were run once.
//! Chains of 16 signatures on each curve, whose values come from OpenSSL, check
//! that long computations agree. The randomized signatures are compared with the
//! output of another implementation of the same construction, given the same
//! random bytes, for digests shorter than, as long as and longer than the order.
//! The generation of keys is checked against the deterministic vectors of
//! c2sp.org/det-keygen, among them the seed that makes P-256 draw twice and the
//! P-521 ones whose candidates are cut to 521 bits. The HMAC is checked against
//! Python's `hmac` module, and the branch of the algorithm that a random `k`
//! never reaches (a zero `s`) is reached on purpose.
//!
//! ## Side channels
//!
//! Nothing that depends on a private key or on `k` is used as a memory address or
//! as a branch condition, with the exceptions listed here. `k * G` goes through a
//! table lookup that reads every entry; the inverse of `k` is a power with a
//! fixed exponent; the products, sums and differences are the branch-free
//! arithmetic of `ecdh`, where every comparison that decides between two numbers
//! is a selection by a mask. A compiler is free to turn such a selection back
//! into a jump, and the masks go through `core::hint::black_box` to make that
//! less likely, which is a request, not a guarantee. The assembly that `rustc`
//! produced for `aarch64` and `x86_64` was inspected for this, and the
//! conditional jumps in the code that signs are of these kinds only: loops over a
//! public number of limbs, windows, bytes or bits of a fixed exponent; checks of
//! public lengths and of whether the table has been built; checks that a result
//! which cannot fail did not (an `expect`); the choice to draw another candidate
//! for `k`, which depends on the candidates that were refused and not on the one
//! that was accepted; and the test of whether `r` or `s` is zero, which is true
//! with a probability of about `1/n` (less than `2^-223`) and only says that
//! this `k` is thrown away. That is a check of one compiler's output for two targets, not a proof
//! for all, and no timing measurements on real hardware back it up. The hash
//! inside the generator runs over the private key: the SHA-2 functions are
//! additions, rotations and boolean operations on words, and their only table is
//! of round constants read by round number.
//!
//! Verifying a signature handles no secret, and the time it takes depends on its
//! inputs. The things that are not hidden are public by nature: the digest, `r`
//! and `s`, and the number of random bytes that [`PrivateKey::generate`] consumes
//! (which depends on how many candidates were refused, and says nothing about
//! the key it returns). Nothing here is protected against attacks that read power
//! consumption or inject faults; the hedged signature makes the faults that
//! exploit a repeated `k` harder, and does not stop one that skips an
//! instruction.
//!
//! # Example
//!
//! ```
//! # fn unhex(s: &str) -> Vec<u8> {
//! #     (0..s.len() / 2).map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap()).collect()
//! # }
//! use cryptors::ecdsa::{Error, P256, PrivateKey, PublicKey, Signature};
//! use cryptors::sha2::Sha256;
//!
//! // RFC 6979, appendix A.2.5: a P-256 key, and the deterministic signature of
//! // "sample" with SHA-256.
//! let key = PrivateKey::<P256>::from_bytes(&unhex(
//!     "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721",
//! ))
//! .unwrap();
//! let signature = key.sign_deterministic::<Sha256>(b"sample");
//! assert_eq!(
//!     signature.as_bytes(),
//!     unhex(concat!(
//!         "efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716",
//!         "f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8"
//!     ))
//! );
//!
//! // The verifier has the public key and the signature as bytes...
//! let public = PublicKey::<P256>::from_bytes(key.public_key().as_bytes()).unwrap();
//! let received = Signature::<P256>::from_der(&signature.to_der()).unwrap();
//!
//! // ...and checks the signature against the message.
//! assert_eq!(public.verify::<Sha256>(b"sample", &received), Ok(()));
//! assert_eq!(
//!     public.verify::<Sha256>(b"sampled", &received),
//!     Err(Error::VerificationFailed)
//! );
//!
//! // The randomized signature takes random bytes, here a fixed string; it is
//! // another signature of the same message, and just as valid.
//! let mut noise: &[u8] = &[7; 32];
//! let hedged = key.sign::<Sha256, _>(&mut noise, b"sample").unwrap();
//! assert_ne!(hedged, signature);
//! assert_eq!(public.verify::<Sha256>(b"sample", &hedged), Ok(()));
//! ```
//!
//! Keys come from [`PrivateKey::generate`] in practice, which needs a source of
//! secure random bytes of your own (this one only compiles, as there is no source
//! that works on every platform):
//!
//! ```no_run
//! use cryptors::ecdsa::{P384, PrivateKey};
//! use cryptors::sha2::Sha384;
//! use std::fs::File;
//!
//! # fn main() -> std::io::Result<()> {
//! let mut rng = File::open("/dev/urandom")?;
//! let key = PrivateKey::<P384>::generate(&mut rng)?;
//! let signature = key.sign::<Sha384, _>(&mut rng, b"a message")?;
//! // Send `key.public_key().as_bytes()`, the message and `signature.to_der()`.
//! assert!(signature.to_der().len() <= 104);
//! # Ok(())
//! # }
//! ```
//!
//! A signature of one curve cannot be checked with a key of another:
//!
//! ```compile_fail,E0308
//! use cryptors::ecdsa::{P256, P384, PrivateKey, PublicKey};
//! use cryptors::sha2::Sha256;
//!
//! let signature = PrivateKey::<P256>::from_bytes(&[1; 32])
//!     .unwrap()
//!     .sign_deterministic::<Sha256>(b"message");
//! let public: PublicKey<P384> = PrivateKey::<P384>::from_bytes(&[1; 48])
//!     .unwrap()
//!     .public_key()
//!     .clone();
//! let _ = public.verify::<Sha256>(b"message", &signature);
//! ```

mod algorithm;
mod curve;
mod der;
mod hmac_drbg;
mod keypair;
mod nist;
mod signature;
#[cfg(test)]
mod vectors;

pub use crate::ec::{P224, P256, P384, P521};
pub use curve::{Curve, Error};
pub use keypair::{PrivateKey, PublicKey};
pub use signature::Signature;
