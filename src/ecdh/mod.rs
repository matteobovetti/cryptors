//! From-scratch implementation of Elliptic Curve Diffie-Hellman (ECDH): two
//! parties each make a key pair, swap the public halves over a channel that
//! anyone can read, and both compute the same secret, which nobody who saw only
//! the public keys can. It works over the three NIST curves and over
//! Curve25519.
//!
//! | Curve | Type | Defined in | Private key | Public key | Shared secret |
//! |-------|------|------------|-------------|------------|---------------|
//! | NIST P-256 | [`P256`] | NIST SP 800-186, SEC 1, NIST SP 800-56A | 32 bytes | 65 bytes | 32 bytes |
//! | NIST P-384 | [`P384`] | the same | 48 bytes | 97 bytes | 48 bytes |
//! | NIST P-521 | [`P521`] | the same | 66 bytes | 133 bytes | 66 bytes |
//! | Curve25519 | [`X25519`] | RFC 7748 | 32 bytes | 32 bytes | 32 bytes |
//!
//! The keys are [`PrivateKey`] and [`PublicKey`], generic over the curve, and
//! the result of an exchange is a [`SharedSecret`]. The four curves are the
//! four types of the table, which implement [`Curve`].
//!
//! # How it works
//!
//! A curve is a set of points with an addition. Adding a point `P` to itself
//! `d` times gives `d * P`, which takes a short chain of doublings and additions
//! even for a `d` of 256 bits. Going back, from `P` and `d * P` to `d`, is the
//! discrete logarithm problem, and the best attacks known on these curves take
//! about the square root of the size of the group in steps. A private key is
//! such a number `d`, and the public key is `d * G` for the point `G` that
//! everyone using the curve shares. Alice, with `a`, sends `a * G`; Bob, with
//! `b`, sends `b * G`. Alice computes `a * (b * G)` and Bob `b * (a * G)`, and
//! those are the same point `(a * b) * G`. Someone who has `a * G` and `b * G`
//! and neither number has no known way to that point.
//!
//! **The NIST curves** are the curves `y^2 = x^3 - 3x + b` over the integers
//! modulo a prime of 256, 384 or 521 bits (for P-521, `2^521 - 1`). A public
//! key is a point, sent as the byte `0x04` followed by its two coordinates
//! (SEC 1, section 2.3.3), and the shared secret is the x-coordinate of the
//! shared point (SEC 1, section 3.3.1). The group of each has a prime number of
//! points, so every point but the point at infinity generates all of it.
//!
//! A public key from the network is checked when it is turned into a
//! [`PublicKey`]: both coordinates must be below the prime, and the point must
//! satisfy the curve equation (NIST SP 800-56A Rev. 3, sections 5.6.2.3.3 and
//! 5.6.2.3.4; the full routine also checks that the point has order `n`, which
//! on these curves every point but infinity has). Without that check, the sender can choose a point that is on a different,
//! weaker curve and learn from the result what the private key is modulo a
//! small number, one exchange after another (an invalid-curve attack). The
//! point at infinity and the compressed form of a point are refused too.
//!
//! **Curve25519** is a different kind of curve, `v^2 = u^3 + 486662 u^2 + u`
//! modulo `2^255 - 19`, and X25519 is a function of its `u` coordinate alone:
//! the Montgomery ladder takes the `u` of a point and a scalar and returns the
//! `u` of the multiple (RFC 7748, section 5). A private key is 32 bytes of any
//! value, clamped when it is used so that the scalar is a multiple of 8 with
//! bit 254 set, and a public key is any 32 bytes. Nothing needs checking
//! except one thing: a handful of points have a small order, and a peer who
//! sends one forces the shared secret to be all zeros whatever our key is.
//! [`PrivateKey::diffie_hellman`] returns an error in that case, which RFC 7748
//! (section 6.1) allows an implementation to do.
//!
//! # Using it
//!
//! Each side builds a [`PrivateKey`], either with [`PrivateKey::generate`] from
//! a source of secure random bytes or with [`PrivateKey::from_bytes`] from a
//! key it stored, and sends the encoding of its [`PrivateKey::public_key`]. The
//! other side turns the bytes it received into a [`PublicKey`] with
//! [`PublicKey::from_bytes`], which is where an invalid key is refused, and
//! calls [`PrivateKey::diffie_hellman`] with it.
//!
//! - **A key belongs to one curve, and the compiler knows which.** A
//!   `PrivateKey<P256>` takes only a `PublicKey<P256>`. Mixing curves does not
//!   compile, where a library that picks the curve at run time can only return
//!   an error.
//! - **Key generation needs random bytes this crate cannot supply.** The
//!   standard library has no secure random source that is stable, so
//!   `generate` takes any [`io::Read`](std::io::Read). On Unix, a
//!   `File::open("/dev/urandom")` is one. A reader that is predictable makes
//!   every key it produced guessable.
//! - **The shared secret is not a key.** It is a point's coordinate, which has
//!   structure, and both sides see it. Run it through a key derivation function
//!   and include both public keys in what it hashes, as RFC 7748 (section 6.1)
//!   describes and its section 7 explains the need for, before using any of it
//!   as a key. This crate does not have one yet.
//! - **ECDH does not authenticate.** Someone who sits between the two sides can
//!   play each to the other and end up with a secret in common with both.
//!   Binding the keys to an identity (signatures, certificates, a pre-shared
//!   secret) is a separate step.
//! - **Use a fresh key pair for each exchange where you can.** A key that is
//!   reused makes every exchange with it a target for an attack on that one key.
//!
//! A private key is overwritten with zeros when it is dropped, and so is a
//! shared secret; their `Debug` output does not show them. That is best effort:
//! the working values of the arithmetic (numbers that depend on a key, on the
//! stack and in registers while it is in use) are not overwritten, and neither
//! is the copy that moving a key (into a `Box` or a `Vec`, say) can leave
//! behind where it was.
//!
//! Neither Curve25519 nor the NIST curves resist a large quantum computer:
//! Shor's algorithm finds `d` from `d * G` in polynomial time. Key exchange
//! that has to outlast such a machine needs a post-quantum scheme, such as
//! ML-KEM, alongside or instead.
//!
//! # Implementation
//!
//! No x86 or Arm CPU has instructions for elliptic curve arithmetic, so there
//! is nothing to select at run time here, as there is for the ciphers and the
//! hashes: one portable implementation runs on every target. All it asks of the
//! CPU is a 64-bit multiplication with a 128-bit result, which Rust's `u128`
//! provides. It is written in safe Rust. Outside its tests, the one `unsafe`
//! it needs is the volatile write that wipes a key when it is dropped, which
//! the compiler would otherwise delete as a store nobody reads.
//!
//! | Curve | Numbers modulo the prime | Points |
//! |-------|--------------------------|--------|
//! | P-256, P-384, P-521 | 4, 6 and 9 limbs of 64 bits, in Montgomery form | complete formulas in projective coordinates, a four-bit window |
//! | X25519 | 5 limbs of 51 bits | the Montgomery ladder |
//!
//! - **Montgomery form.** A number `x` is stored as `x * R mod p`, with `R` a
//!   power of 2^64. A product is then Montgomery's reduction of the product of
//!   the limbs, which divides out `R` by shifting whole limbs instead of
//!   dividing by `p`, so one routine serves all three primes. Its constants are
//!   computed from the prime at compile time, and so are the curve parameters
//!   in Montgomery form. The inverse (needed once, to turn a point back into
//!   coordinates) is the number to the power `p - 2`.
//! - **Complete formulas.** The addition and doubling of Renes, Costello and
//!   Batina (Eurocrypt 2016) give the right answer for every pair of points of
//!   the curve, including two equal points, opposite points and the point at
//!   infinity. The code that multiplies a point therefore has no special case
//!   to branch on, and a secret scalar never chooses between two paths.
//! - **A four-bit window.** The scalar is taken four bits at a time, from the
//!   top: four doublings, then one addition of a multiple of the point from 0
//!   to 15 times it, looked up in a table. The lookup reads every entry of the
//!   table and keeps the one it wants, so which entry that is does not show in
//!   an address. A product with the generator `G` has no doublings: a table
//!   built on first use holds `j * 16^i * G` for every window `i` and every `j`
//!   from 1 to 15, and the product is one addition per window. It is kept for
//!   the life of the process and shared by all threads, and takes 90 KiB for
//!   P-256, 200 KiB for P-384 and 420 KiB for P-521, and building it is a
//!   delay in the first key of that curve that a process makes.
//! - **Five limbs of 51 bits.** Curve25519's prime is `2^255 - 19`, and a
//!   number in five limbs of 51 bits leaves 13 bits free in each word, so
//!   the products of limbs can pile up in 128 bits and the carries wait until
//!   the end of a multiplication. A carry out of the top limb is a multiple of
//!   `2^255`, which is 19, so it folds into the bottom one with a single
//!   multiplication; that is the entire reduction.
//!
//! ## Trust
//!
//! The tests check this implementation against sources that share nothing with
//! it: NIST's published vectors for the three curves, the vectors of RFC 7748
//! (including the thousand-step chain of section 5.2), the hundreds of cases of
//! Project Wycheproof that go after the places where implementations break
//! (points on other curves, non-canonical coordinates, compressed points, the
//! small-order points, scalars with unusual bit patterns), and chains of
//! exchanges whose values come from OpenSSL. The X25519 field also has to give
//! the same answers as a second implementation, the generic one that the NIST
//! curves use, on the same inputs.
//!
//! ## Side channels
//!
//! Nothing that depends on a private key is used as a memory address or as a
//! branch condition. The scalar goes through a table lookup that reads every
//! entry and a conditional swap done by masks, and the arithmetic below them has
//! no conditional jump or table of its own: every comparison that decides
//! between two numbers (the final subtraction of the prime, say) is a selection
//! by a mask. A compiler is free to turn such a selection back into a jump, and
//! the masks go through `core::hint::black_box` to make that less likely, which
//! is a request, not a guarantee. The assembly that `rustc` produced for
//! `aarch64` and `x86_64` was inspected for this, and the conditional jumps in
//! the code that handles a secret are of these kinds only: loops over a public
//! number of limbs, of windows or of bits of the exponent that inverts a
//! number; checks of public lengths; and two checks of a result. One asks
//! whether the shared point is the point at infinity, which for a valid key it
//! never is, and the other whether an X25519 secret is all zeros, which the
//! peer's point decides whatever our key is. That is a check of one compiler's
//! output for two targets, not a proof for all, and no timing measurements on
//! real hardware back it up.
//!
//! The things that are not hidden are public by nature. Checking a received
//! public key takes a time that depends on the key, which is not secret. The
//! number of random bytes `generate` consumes depends on how many candidates
//! were refused, which says nothing about the key it returns. Nothing here is
//! protected against attacks that read power consumption or inject faults.
//!
//! # Example
//!
//! ```
//! # fn unhex(s: &str) -> Vec<u8> {
//! #     (0..s.len() / 2).map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap()).collect()
//! # }
//! use cryptors::ecdh::{P256, PrivateKey, PublicKey, X25519};
//!
//! // RFC 7748, section 6.1: Alice and Bob each make a key from 32 bytes...
//! let alice = PrivateKey::<X25519>::from_bytes(&unhex(
//!     "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
//! ))
//! .unwrap();
//! let bob = PrivateKey::<X25519>::from_bytes(&unhex(
//!     "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb",
//! ))
//! .unwrap();
//! assert_eq!(
//!     alice.public_key().as_bytes(),
//!     unhex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
//! );
//!
//! // ...send each other the public half, as bytes...
//! let bobs_public = PublicKey::<X25519>::from_bytes(bob.public_key().as_bytes()).unwrap();
//!
//! // ...and both arrive at the same secret.
//! let from_alice = alice.diffie_hellman(&bobs_public).unwrap();
//! let from_bob = bob.diffie_hellman(alice.public_key()).unwrap();
//! assert_eq!(from_alice, from_bob);
//! assert_eq!(
//!     from_alice.as_bytes(),
//!     unhex("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")
//! );
//!
//! // The NIST curves work the same way. This is a vector from NIST's CAVS for
//! // P-256: a private key, the public key of the other side as it arrives on the
//! // wire (an uncompressed point), and the secret both get.
//! let private = PrivateKey::<P256>::from_bytes(&unhex(
//!     "7d7dc5f71eb29ddaf80d6214632eeae03d9058af1fb6d22ed80badb62bc1a534",
//! ))
//! .unwrap();
//! let peer = PublicKey::<P256>::from_bytes(&unhex(concat!(
//!     "04700c48f77f56584c5cc632ca65640db91b6bacce3a4df6b42ce7cc838833d287",
//!     "db71e509e3fd9b060ddb20ba5c51dcc5948d46fbf640dfe0441782cab85fa4ac",
//! )))
//! .unwrap();
//! assert_eq!(
//!     private.diffie_hellman(&peer).unwrap().as_bytes(),
//!     unhex("46fc62106420ff012e54a434fbdd2d25ccc5852060561e68040dd7778997bd7b")
//! );
//!
//! // A point that is not on the curve is refused when the key is built.
//! let mut off_the_curve = peer.as_bytes().to_vec();
//! off_the_curve[64] ^= 1;
//! assert!(PublicKey::<P256>::from_bytes(&off_the_curve).is_err());
//! ```
//!
//! Keys come from [`PrivateKey::generate`] in practice, which needs a source of
//! secure random bytes of your own (this one only compiles, as there is no
//! source that works on every platform):
//!
//! ```no_run
//! use cryptors::ecdh::{P384, PrivateKey};
//! use std::fs::File;
//!
//! # fn main() -> std::io::Result<()> {
//! let mut rng = File::open("/dev/urandom")?;
//! let key = PrivateKey::<P384>::generate(&mut rng)?;
//! // Send `key.public_key().as_bytes()` to the other side.
//! assert_eq!(key.public_key().as_bytes().len(), 97);
//! # Ok(())
//! # }
//! ```
//!
//! A private key of one curve cannot be paired with a public key of another:
//!
//! ```compile_fail,E0308
//! use cryptors::ecdh::{P256, P384, PrivateKey, PublicKey};
//!
//! let private = PrivateKey::<P256>::from_bytes(&[1; 32]).unwrap();
//! let public: PublicKey<P384> = PrivateKey::<P384>::from_bytes(&[1; 48])
//!     .unwrap()
//!     .public_key()
//!     .clone();
//! let _ = private.diffie_hellman(&public);
//! ```

mod ct;
mod curve;
mod fe25519;
mod field;
mod keypair;
mod nist;
#[cfg(test)]
mod vectors;
mod weierstrass;
mod x25519;

pub use curve::{Curve, Error};
pub use keypair::{PrivateKey, PublicKey, SharedSecret};
pub use nist::{P256, P384, P521};
pub use x25519::X25519;
