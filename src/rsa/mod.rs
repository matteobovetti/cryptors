//! From-scratch implementation of RSA as PKCS #1 version 2.2 (RFC 8017) defines it:
//! public-key encryption, which anyone can do to the holder of a private key and
//! only the holder can undo, and public-key signatures, which only the holder can
//! make and anyone can check. RSA is a single operation, raising a number to a
//! power modulo the product of two primes; the four schemes of the standard are four
//! ways to turn a message into a number that is safe to raise to it.
//!
//! | Scheme | For | With the public key | With the private key | Defined in |
//! |--------|-----|---------------------|----------------------|------------|
//! | RSAES-OAEP | encryption | [`PublicKey::encrypt_oaep`] | [`PrivateKey::decrypt_oaep`] | RFC 8017, section 7.1 |
//! | RSASSA-PSS | signatures | [`PublicKey::verify_pss`] | [`PrivateKey::sign_pss`] | section 8.1 |
//! | RSAES-PKCS1-v1_5 | encryption, for old protocols | [`PublicKey::encrypt_pkcs1v15`] | [`PrivateKey::decrypt_pkcs1v15`] | section 7.2 |
//! | RSASSA-PKCS1-v1_5 | signatures, as most certificates have them | [`PublicKey::verify_pkcs1v15`] | [`PrivateKey::sign_pkcs1v15`] | section 8.2 |
//!
//! The first two are the ones for a new design. The keys are [`PublicKey`] and
//! [`PrivateKey`], which are built from numbers, or generated; a failure is an
//! [`Error`]. The modulus of a key has 1,024 to 16,384 bits:
//!
//! | Modulus | Security (NIST SP 800-57) | Ciphertext and signature | OAEP with SHA-256 holds | PKCS #1 v1.5 holds |
//! |---------|---------------------------|--------------------------|-------------------------|--------------------|
//! | 1,024 bits | 80 bits, broken for practical purposes: old data only | 128 bytes | 62 bytes | 117 bytes |
//! | 2,048 bits | 112 bits | 256 bytes | 190 bytes | 245 bytes |
//! | 3,072 bits | 128 bits | 384 bytes | 318 bytes | 373 bytes |
//! | 4,096 bits | about 140 bits | 512 bytes | 446 bytes | 501 bytes |
//! | 7,680 bits | 192 bits | 960 bytes | 894 bytes | 949 bytes |
//! | 15,360 bits | 256 bits | 1,920 bytes | 1,854 bytes | 1,909 bytes |
//!
//! What goes through RSA is a key, not a document: RSA encrypts a few hundred bytes
//! at most and takes milliseconds to do it with a private key, so a message is
//! encrypted with a key that RSA carries (to a symmetric cipher such as
//! [AES](crate::aes), or by [HPKE](crate::hpke), which does it with a key agreement
//! instead), and a document is signed by signing its hash.
//!
//! # How it works
//!
//! A key pair is two primes `p` and `q` and the modulus `n = p * q`. The public
//! exponent `e` is a small odd number (65,537 for every key made here), and the
//! private exponent `d` is its inverse modulo `lcm(p - 1, q - 1)`. The public key is
//! `(n, e)` and is not secret; the private key is `d` (and the primes, which
//! give it away: whoever factors `n` has `d`). With a number `m` below `n`:
//!
//! ```text
//! c = m^e mod n            the public operation   (RSAEP and RSAVP1, RFC 8017 sections 5.1.1 and 5.2.2)
//! m = c^d mod n            the private operation  (RSADP and RSASP1, sections 5.1.2 and 5.2.1)
//! ```
//!
//! because `e * d` is 1 modulo `p - 1` and modulo `q - 1`, so that `m^(e * d)` is `m`
//! modulo `p` and modulo `q`, and so modulo `n`. The private operation is made with
//! the Chinese remainder theorem (section 3.2, the second representation of a private
//! key), in two exponentiations of half the size:
//!
//! ```text
//! m1 = c^dP mod p         dP = d mod (p - 1)
//! m2 = c^dQ mod q         dQ = d mod (q - 1)
//! h = qInv * (m1 - m2) mod p          qInv = q^-1 mod p
//! m = m2 + q * h
//! ```
//!
//! which is about four times less work than one exponentiation by `d`: the two
//! exponents and the two moduli have half the bits, and the cost of an
//! exponentiation goes with the exponent's bits times the square of the modulus's.
//!
//! The bare operation is not an encryption or a signature: it is deterministic, so
//! it reveals when the same message is sent twice; it is multiplicative, so that
//! `(m1 * m2)^e = m1^e * m2^e`, which lets an attacker make a ciphertext or a
//! signature from others; and a small message raised to a small power does not even
//! wrap around the modulus. The schemes make a number out of the message, by a
//! padding, that does not have these properties:
//!
//! - **OAEP** (the Optimal Asymmetric Encryption Padding) builds a block of the
//!   length of the modulus from the hash of a label, zero bytes, a 0x01 byte, the
//!   message, and a random seed that is hashed into masks for both halves of the
//!   block with MGF1 (a hash used as a stream, RFC 8017 appendix B.2.1). The seed
//!   makes the ciphertext different every time, and anyone who changes a bit of the
//!   ciphertext gets a block in which the checks of the zero bytes and of the label's
//!   hash fail. The label is not encrypted, but it has to be the same to decrypt.
//! - **PSS** (the Probabilistic Signature Scheme) hashes the message, then hashes
//!   that digest together with a random salt, and masks the salt and the padding
//!   with MGF1 of the second hash. A signature is different every time, and its
//!   security is proven (in the random oracle model) from the hardness of RSA.
//! - **PKCS #1 v1.5 encryption** is `0x00 0x02`, random non-zero bytes, `0x00` and the
//!   message. It has no integrity check in the padding, and a service that answers
//!   whether a ciphertext decrypts is an oracle with which an attacker decrypts any
//!   ciphertext (Bleichenbacher, 1998: "the million message attack", and the same
//!   attack against implementations again and again since, for TLS and for XML
//!   encryption). Use OAEP.
//! - **PKCS #1 v1.5 signatures** are `0x00 0x01`, `0xff` bytes, `0x00` and the DER
//!   encoding of the hash's name and digest (a `DigestInfo`). They are deterministic,
//!   and are the signatures of most certificates and of TLS 1.2. No attack on the
//!   scheme itself is known, but verifiers that parsed the block instead of rebuilding
//!   it have been forged (Bleichenbacher, 2006, and again in Mozilla's NSS in 2014); this one
//!   rebuilds it and compares.
//!
//! # Using it
//!
//! A public key is a [`PublicKey`], made with [`PublicKey::new`] from the modulus (as
//! big-endian bytes) and the exponent. A private key is a [`PrivateKey`], made with
//! [`PrivateKey::generate`] from a source of random bytes, or with
//! [`PrivateKey::from_components`] from a modulus, exponent, private exponent and the
//! two primes that were stored; the constructor checks all of them against each other
//! (the checks that FIPS 186-5 asks for), so that a key that is wrong, from a bug
//! or from damage, is refused instead of used. The module speaks
//! numbers, not encodings: PKCS #1's `RSAPrivateKey` and `RSAPublicKey`, PKCS #8 and
//! SubjectPublicKeyInfo are ASN.1, which belongs to the layer that parses
//! certificates, and which this crate does not have yet.
//!
//! - **OAEP and PSS for a new design.** [`PublicKey::encrypt_oaep`] and
//!   [`PrivateKey::sign_pss`] take the hash as a type: SHA-256 is a good choice for
//!   a key of 2,048 or 3,072 bits, and SHA-384 or SHA-512 for larger ones. A
//!   decryption has to name the same hash, and the same label; a verification, the
//!   same hash. For OAEP with a separate hash for MGF1, which some protocols fix
//!   (Java's default is SHA-256 for the label and SHA-1 for MGF1), there is
//!   [`PublicKey::encrypt_oaep_mgf1`] and [`PrivateKey::decrypt_oaep_mgf1`]; PSS always
//!   uses one hash for both.
//! - **The salt of a PSS signature.** [`SaltLength::EqualsHash`] is the length that
//!   standards and protocols use (TLS 1.3 requires it); a verifier that names the
//!   length refuses signatures with another, and one that names [`SaltLength::Auto`]
//!   accepts any.
//! - **Randomness is the caller's.** Key generation, OAEP encryption, PKCS #1 v1.5
//!   encryption and PSS signing take any [`io::Read`](std::io::Read) of
//!   cryptographically secure random bytes, as every module of the crate does;
//!   [`rand::Reader`](crate::rand::Reader) is the operating system's. A key made from
//!   a predictable reader is guessable, and an OAEP ciphertext made from one reveals
//!   whether two messages are equal.
//! - **Every error of a decryption is the same error.** [`Error::Decryption`] does
//!   not say whether the ciphertext was too short, too large, had a wrong label or a
//!   bad padding, and the checks of the padding take the same time whichever fails.
//!   A program that tells its peer more (a different error message, or a different
//!   delay) hands over the oracle of Manger's attack on OAEP and Bleichenbacher's on
//!   PKCS #1 v1.5. Return one error, after one time.
//! - **The hash of a v1.5 signature** is one of the eight of the crate (MD5, SHA-1 and
//!   the six of SHA-2) because the standard puts its name in the signature, and a name
//!   is a constant that the type has to know: [`Pkcs1Hash`] is sealed. MD5 and SHA-1
//!   are there for signatures that still use them, and are as weak as they are.
//!   SHA-3 is not a [`Digest`](crate::Digest) yet, and so has no v1.5 signature here.
//!   [`PrivateKey::sign_pkcs1v15_prehash`] and its relatives take a digest that was
//!   made elsewhere.
//! - **One key for one purpose.** FIPS 186-5 and SP 800-56B say that a key used to
//!   sign shall not be used to decrypt. The types do not stop a program from doing
//!   both, but a key pair is cheap and the two uses interact in attacks.
//! - **Keys are 1,024 to 16,384 bits.** Smaller ones can be factored today (NIST's
//!   guidance is 2,048 bits and up, and 1,024 is as far down as this goes), and larger
//!   ones would let a key from outside make a verification take minutes. Moduli with
//!   more than two prime factors (the "multi-prime" RSA of RFC 8017) are not offered:
//!   they are a rarity in the wild, and not recommended.
//! - **A private key is overwritten with zeros when it is dropped**, and `Debug` does
//!   not show it. That is best effort: the working values of the arithmetic (numbers
//!   that depend on a key, on the stack and in registers while it is in use) are not
//!   overwritten, and neither is the copy that moving a key (into a `Box` or a `Vec`,
//!   say) can leave behind where it was. The bytes that [`PrivateKey::d`] and its
//!   relatives return are the caller's to wipe.
//!
//! RSA does not resist a large quantum computer: Shor's algorithm factors `n` in
//! polynomial time. What has to stay secret past the arrival of such a machine needs
//! a post-quantum scheme, such as [ML-KEM](crate::mlkem) for keys and
//! [ML-DSA](crate::mldsa) for signatures, alongside or instead.
//!
//! # Implementation
//!
//! No x86 or Arm CPU has an instruction for big-number multiplication beyond the
//! 64 by 64 to 128 bit product that Rust's `u128` compiles to, so there is nothing
//! to select at run time, as there is for the ciphers and the hashes: one portable
//! implementation runs everywhere. It is written in safe Rust. Outside its tests, the
//! one `unsafe` it needs is the volatile write that wipes a key when it is dropped,
//! which the compiler would otherwise delete as a store nobody reads.
//!
//! | Step | How |
//! |------|-----|
//! | Numbers | `Vec`s of 64-bit limbs, as many as the modulus has (the size of a key is public), wiped when dropped |
//! | Arithmetic modulo `n`, `p` and `q` | Montgomery's form with `R = 2^(64 * limbs)`, and a product of the CIOS method that does both halves of a round in one pass over the limbs, with two independent carries |
//! | Constants of a modulus | `R mod m` and `R^2 mod m` by doubling and squaring (a time that depends on the length), `-m^-1 mod 2^64` by Newton's iteration |
//! | A number longer than the modulus (`c mod p`) | cut in pieces of the modulus's length and combined by Horner's rule in Montgomery form, with two products a piece, so no division is ever made |
//! | The private exponentiations | a four-bit window: four squarings and one product by an entry of the table of 16 powers, which is read in full to find it, whatever the four bits are |
//! | The public exponentiation | squarings and products along the bits of the exponent: 17 squarings and one product for 65,537 |
//! | The result of a private operation | raised to `e` and compared with the input before it is released |
//! | Padding | OAEP and PKCS #1 v1.5 are unpadded without a branch on a byte, and with every byte read; PSS and the v1.5 signature are public |
//! | Key generation | FIPS 186-5 appendix A.1.3, as c2sp.org/det-keygen has it: candidates of `bits / 2` bits from the reader with the top two and the low three bits set, trial division by the first 255 odd primes, then Miller-Rabin rounds (3 to 34 by size, as BoringSSL's table for key generation) |
//!
//! - **Why the result is checked.** If a fault (a flipped bit, a glitch on the power
//!   line, an error of the CPU) damages one of the two exponentiations of the CRT, the
//!   result is right modulo one prime and wrong modulo the other, and `gcd(m - m', n)`
//!   is that prime (Boneh, DeMillo and Lipton, 1997). A signature or a plaintext that
//!   fails the check is not released. It costs one public exponentiation, which is
//!   cheap beside the private ones.
//! - **Blinding is not used.** The older implementations multiplied the input by a
//!   random number before the private operation, to hide the time and power of the
//!   exponentiation from an attacker who chooses the input. The operation here takes
//!   the same time for every input, so there is nothing to hide with it.
//! - **The constants of a key are computed once.** Building a [`PublicKey`] makes the
//!   constants of its modulus, and a [`PrivateKey`] those of both primes and the checks
//!   of its numbers (a Fermat exponentiation for `qInv` is most of it, and the
//!   remainders modulo `p - 1` and `q - 1` are made a bit at a time, in a time that
//!   depends only on the lengths). Keep a key and use it, as with every key of the
//!   crate.
//! - **The Miller-Rabin bases are not from the reader.** They are stretches of SHA-512 of
//!   the candidate. For a candidate drawn at random, as here, the bound on the error
//!   holds for a base that does not depend on the way the candidate was drawn, a hash
//!   of it is one, and it keeps the bytes that a deterministic reader is asked for the
//!   candidates alone (which c2sp.org/det-keygen's vectors rely on).
//!
//! ## Trust
//!
//! The tests check this implementation against sources that share nothing with it.
//! For the schemes: the cases of Project Wycheproof, 8,043 in 66 files of OAEP
//! decryption (every hash and MGF1 hash of the files), PKCS #1 v1.5 decryption,
//! v1.5 signature verification and generation, and PSS verification, which probe the
//! places where implementations break (padding of every wrong shape, BER lengths and
//! missing NULLs in a `DigestInfo`, tiny and huge signature values, ciphertexts of
//! the wrong length, special salt lengths), of which a selection is run in the tests and
//! all of them were run once; RSA Laboratories' vectors for OAEP (the ciphertext of each
//! message from the vector's own seed, bit for bit) and for PSS (60 signatures by keys
//! of 1,024 to 1,031, 1,536 and 2,048 bits, which are the keys whose encoded message is
//! a byte shorter than the modulus, verified and reproduced from their salts); and
//! 315 ciphertexts and signatures that OpenSSL made, with keys of 1,024, 1,025,
//! 1,031, 2,047, 2,048, 3,072 and 4,096 bits and every hash that OpenSSL offers for
//! the scheme, which another implementation (Go's `crypto/rsa`) reads the same way.
//! For key generation: the deterministic vectors of c2sp.org/det-keygen, in which an HMAC_DRBG seeded as the vector says must give
//! the key the vector has (21 of 2,048, 2,064, 3,072, 4,096 and 8,192 bits, made with
//! another implementation), and the 708 candidates of c2sp.org/CCTV/keygen's benchmark,
//! whose two primes this and Python and Go all find at the same lines. The
//! arithmetic modulo a number of any size is checked against Python's integers, in
//! moduli of 1 to 32 limbs of the shapes that stress carries, and the validation of keys
//! against keys that are wrong in exactly one way. Each test that does not read a
//! published vector was checked against a set of mutants of the code (see the README).
//!
//! ## Side channels
//!
//! Nothing that depends on a private key is used as a memory address or as a branch
//! condition in the private operation, the padding checks of decryption, or the
//! comparison of keys, with the exceptions listed here. The exponentiation reads
//! every entry of its table to find the one it needs; its number of rounds is the
//! length of the prime, which is public; the products, sums and differences are
//! branch-free, where every comparison that decides between two numbers is a selection
//! by a mask. A compiler is free to turn such a selection back into a jump, and the
//! masks go through `core::hint::black_box` to make that less likely, which is a
//! request, not a guarantee. The assembly that `rustc` produced for `aarch64` and
//! `x86_64` was inspected for the product, the table lookup of the exponentiation and
//! the search for the message in a decrypted block, and the conditional jumps there
//! are of these kinds only: loops over a public number of limbs, windows or bytes, and
//! checks of public lengths; the selections are conditional moves and bit operations.
//! The rest is covered by tests: the number of products is the same for every input,
//! and a coarse timing test (`timing_does_not_depend_on_the_input`, run by hand) finds
//! no difference between inputs with little in them and random ones. That is a check of
//! one compiler's output for two targets and of one machine's clock, not a proof for
//! all.
//!
//! What is **not** constant-time, by nature: key generation (the candidates that are
//! refused, the trial divisions and the Miller-Rabin rounds on them, the greatest
//! common divisor of the primes), which reveals the work that was done and never the
//! key it ends with; the sizes of the numbers, which are the sizes of the key;
//! whether a decryption succeeded, and the length of the message it returned, which
//! the caller learns anyway; the public operation, and so the verification, which
//! handles no secret; and the checks of the components of a key, whose sizes
//! (not their values) decide how long they take, but which also reveal the number of
//! bits of `|p - q|` and `d`, which the key size already bounds. Nothing here is
//! protected against attacks that read power consumption, and the check of the result
//! makes a fault on the private operation fail instead of leak, but does not stop one
//! that skips the check.
//!
//! # Example
//!
//! ```
//! # fn unhex(s: &str) -> Vec<u8> {
//! #     (0..s.len() / 2).map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap()).collect()
//! # }
//! use cryptors::rsa::{Error, PrivateKey, PublicKey, SaltLength};
//! use cryptors::sha1::Sha1;
//! use cryptors::sha2::Sha256;
//!
//! // The first key of RSA Laboratories' PKCS #1 test vectors, 1,024 bits: the
//! // modulus, the private exponent and the two primes.
//! let key = PrivateKey::from_components(
//!     &unhex(concat!(
//!         "a8b3b284af8eb50b387034a860f146c4919f318763cd6c5598c8ae4811a1e0ab",
//!         "c4c7e0b082d693a5e7fced675cf4668512772c0cbc64a742c6c630f533c8cc72",
//!         "f62ae833c40bf25842e984bb78bdbf97c0107d55bdb662f5c4e0fab9845cb514",
//!         "8ef7392dd3aaff93ae1e6b667bb3d4247616d4f5ba10d4cfd226de88d39f16fb"
//!     )),
//!     65537,
//!     &unhex(concat!(
//!         "53339cfdb79fc8466a655c7316aca85c55fd8f6dd898fdaf119517ef4f52e8fd",
//!         "8e258df93fee180fa0e4ab29693cd83b152a553d4ac4d1812b8b9fa5af0e7f55",
//!         "fe7304df41570926f3311f15c4d65a732c483116ee3d3d2d0af3549ad9bf7cbf",
//!         "b78ad884f84d5beb04724dc7369b31def37d0cf539e9cfcdd3de653729ead5d1"
//!     )),
//!     &unhex(concat!(
//!         "d32737e7267ffe1341b2d5c0d150a81b586fb3132bed2f8d5262864a9cb9f30a",
//!         "f38be448598d413a172efb802c21acf1c11c520c2f26a471dcad212eac7ca39d"
//!     )),
//!     &unhex(concat!(
//!         "cc8853d1d54da630fac004f471f281c7b8982d8224a490edbeb33d3e3d5cc93c",
//!         "4765703d1dd791642f1f116a0dd852be2419b2af72bfe9a030e860b0288b5d77"
//!     )),
//! )
//! .unwrap();
//!
//! // The sender has the public key as numbers, and encrypts with OAEP. The random
//! // seed is the one of the vector, so that the ciphertext is the vector's too.
//! let public = PublicKey::new(&key.public_key().modulus(), key.public_key().exponent()).unwrap();
//! let message = unhex("6628194e12073db03ba94cda9ef9532397d50dba79b987004afefe34");
//! let mut seed: &[u8] = &unhex("18b776ea21069d69776a33e96bad48e1dda0a5ef");
//! let ciphertext = public.encrypt_oaep::<Sha1, _>(&mut seed, &message, b"").unwrap();
//! assert_eq!(
//!     ciphertext[..16],
//!     unhex("354fe67b4a126d5d35fe36c777791a3f")[..]
//! );
//!
//! // The holder of the private key decrypts, with the same hash and label...
//! assert_eq!(key.decrypt_oaep::<Sha1>(&ciphertext, b""), Ok(message));
//! // ...and nothing else decrypts it: a label, a hash or a changed bit is the same error.
//! assert_eq!(key.decrypt_oaep::<Sha1>(&ciphertext, b"other"), Err(Error::Decryption));
//! assert_eq!(key.decrypt_oaep::<Sha256>(&ciphertext, b""), Err(Error::Decryption));
//! let mut changed = ciphertext.clone();
//! changed[40] ^= 1;
//! assert_eq!(key.decrypt_oaep::<Sha1>(&changed, b""), Err(Error::Decryption));
//!
//! // Signatures: PSS is randomized (here with a fixed string for random bytes)...
//! let mut noise: &[u8] = &[7; 32];
//! let signature = key
//!     .sign_pss::<Sha256, _>(&mut noise, b"a message", SaltLength::EqualsHash)
//!     .unwrap();
//! let verify = |message: &[u8]| public.verify_pss::<Sha256>(message, &signature, SaltLength::EqualsHash);
//! assert_eq!(verify(b"a message"), Ok(()));
//! assert_eq!(verify(b"another"), Err(Error::VerificationFailed));
//!
//! // ...and PKCS #1 v1.5 is not: the same message gives the same signature.
//! let signature = key.sign_pkcs1v15::<Sha256>(b"a message").unwrap();
//! assert_eq!(key.sign_pkcs1v15::<Sha256>(b"a message").unwrap(), signature);
//! assert_eq!(public.verify_pkcs1v15::<Sha256>(b"a message", &signature), Ok(()));
//! ```
//!
//! Real keys come from [`PrivateKey::generate`], which needs a source of secure random
//! bytes, as encrypting and PSS signing do ([`rand::Reader`](crate::rand::Reader) is
//! the operating system's; this one only compiles, as a key of this size takes
//! seconds to make in a build without optimizations):
//!
//! ```no_run
//! use cryptors::rand::Reader;
//! use cryptors::rsa::{PrivateKey, PublicKey};
//! use cryptors::sha2::Sha256;
//!
//! # fn main() -> std::io::Result<()> {
//! let mut rng = Reader;
//! let key = PrivateKey::generate(&mut rng, 2048)?;
//!
//! // Send the public key's numbers; the other side builds the key and encrypts to it.
//! let public = key.public_key();
//! let received = PublicKey::new(&public.modulus(), public.exponent()).unwrap();
//! let ciphertext = received.encrypt_oaep::<Sha256, _>(&mut rng, b"a 32-byte session key goes here", b"")?;
//! assert_eq!(ciphertext.len(), 256);
//! assert_eq!(
//!     key.decrypt_oaep::<Sha256>(&ciphertext, b"").unwrap(),
//!     b"a 32-byte session key goes here"
//! );
//! # Ok(())
//! # }
//! ```
//!
//! The hash of a PKCS #1 v1.5 signature has to be one the standard names, so one from
//! outside the crate does not compile:
//!
//! ```compile_fail,E0277
//! use cryptors::Digest;
//! use cryptors::rsa::PrivateKey;
//!
//! struct MyHash;
//!
//! impl Digest for MyHash {
//!     const BLOCK_LEN: usize = 64;
//!     const OUTPUT_LEN: usize = 32;
//!     type Output = [u8; 32];
//!     fn digest(_: &[u8]) -> [u8; 32] {
//!         [0; 32]
//!     }
//! }
//!
//! fn sign(key: &PrivateKey) {
//!     let _ = key.sign_pkcs1v15::<MyHash>(b"message");
//! }
//! ```

mod bigmod;
mod bytes;
mod error;
mod hash;
mod keygen;
mod keypair;
mod mgf1;
mod oaep;
mod pkcs1v15;
mod pss;

pub use error::Error;
pub use hash::Pkcs1Hash;
pub use keypair::{PrivateKey, PublicKey, SaltLength};

#[cfg(test)]
mod conformance;
#[cfg(test)]
mod testutil;
