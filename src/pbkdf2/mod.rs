//! From-scratch implementation of PBKDF2, the Password-Based Key Derivation
//! Function 2 of RFC 8018 (PKCS #5 version 2.1): it turns a password, which
//! has little entropy, into a key, and makes every guess at the password cost
//! an attacker as much work as it costs the owner, by repeating a keyed hash
//! as many times as the caller chooses. It works with every hash of the crate
//! that implements [`Digest`](crate::Digest), through
//! [`Hmac`](crate::hmac::Hmac).
//!
//! | Hash | Call | HashLen | Block | Longest key ((2^32 − 1) × HashLen) |
//! |------|------|---------|-------|------------------------------------|
//! | MD5 | `derive::<Md5>` | 16 bytes | 64 bytes | 68,719,476,720 bytes |
//! | SHA-1 | `derive::<Sha1>` | 20 bytes | 64 bytes | 85,899,345,900 bytes |
//! | SHA-224 | `derive::<Sha224>` | 28 bytes | 64 bytes | 120,259,084,260 bytes |
//! | SHA-256 | `derive::<Sha256>` | 32 bytes | 64 bytes | 137,438,953,440 bytes |
//! | SHA-384 | `derive::<Sha384>` | 48 bytes | 128 bytes | 206,158,430,160 bytes |
//! | SHA-512 | `derive::<Sha512>` | 64 bytes | 128 bytes | 274,877,906,880 bytes |
//! | SHA-512/224 | `derive::<Sha512_224>` | 28 bytes | 128 bytes | 120,259,084,260 bytes |
//! | SHA-512/256 | `derive::<Sha512_256>` | 32 bytes | 128 bytes | 137,438,953,440 bytes |
//!
//! The one function is [`derive()`], generic over the hash, and what can go wrong
//! is an [`Error`]. SHA-3 exposes free functions rather than implementing
//! `Digest`, so there is no PBKDF2-HMAC-SHA3 yet.
//!
//! # How it works
//!
//! PBKDF2 (RFC 8018 section 5.2) uses a pseudorandom function PRF, which here is
//! HMAC (RFC 2104) keyed with the password: whoever does not know the password
//! cannot tell `HMAC(password, m)` from random bytes, for any `m`. HashLen is
//! the length of one output of the hash.
//!
//! The derived key is cut into blocks of HashLen bytes, `T(1) | T(2) | ...`,
//! the last one cut short to the length asked for. Each block is the XOR of
//! `c` chained outputs of the function, where `c` is the iteration count:
//!
//! - `U(1) = PRF(password, salt | INT(i))`, with `INT(i)` the number of the
//!   block as a 32-bit big-endian integer, counting from 1;
//! - `U(j) = PRF(password, U(j - 1))`, for `j` from 2 to `c`;
//! - `T(i) = U(1) ^ U(2) ^ ... ^ U(c)`.
//!
//! The salt makes the key depend on more than the password, so that two users
//! with the same password get different keys, and an attacker cannot use one
//! table of precomputed keys against all of them. The iterations are the work
//! factor: each guess takes `c` times as long as one call of the function, and
//! the chain cannot be computed in parallel, because each output is the input
//! of the next. The blocks, on the other hand, are independent of each other.
//!
//! # Using it
//!
//! [`derive()`] fills a buffer of the caller's with the key, of any length from
//! one byte up to `2^32 - 1` blocks of HashLen bytes. An empty buffer, or a
//! longer one, is [`Error::InvalidLength`], and so is a count of zero iterations
//! ([`Error::InvalidIterations`]); either way the buffer is left as it was.
//!
//! - **Use a random salt, a new one for each password.** It need not be secret,
//!   but it must be stored with the key, and it must never repeat. RFC 8018
//!   (section 4.1) asks for at least 64 bits, and NIST SP 800-132 for at least
//!   128 bits; 16 random bytes are enough.
//! - **Set the iteration count as high as you can afford.** RFC 8018 (section
//!   4.2) gives 1,000 as a minimum, which today is far too few: OWASP's
//!   password storage guidance, at the time of writing, asks for 600,000
//!   iterations of HMAC-SHA-256 and 210,000 of HMAC-SHA-512. Choose the number
//!   from the time it takes on the slowest machine that must derive the key,
//!   store it with the salt, and raise it as hardware gets faster.
//! - **Ask for one block unless you need more.** Each block costs `c`
//!   iterations of its own, but an attacker who wants to test a guess needs
//!   only the first one. A key longer than HashLen costs the owner more work
//!   than the attacker's, which is the opposite of the point. To get more key
//!   material from a password, derive one key of HashLen bytes and expand it
//!   with [HKDF](crate::hkdf).
//! - **PBKDF2 needs almost no memory.** It runs at full speed on a GPU or an
//!   ASIC, where a memory-hard function such as scrypt (RFC 7914) or Argon2
//!   (RFC 9106) does not. This crate has neither; where there is a choice, take
//!   one of those. PBKDF2 is the one that standards (FIPS 140, PKCS #5, WPA2,
//!   LUKS1, 1Password and many file formats) ask for.
//! - **A long password is shortened.** HMAC hashes a key longer than the block
//!   of the hash, so a password of more than 64 bytes (128 for SHA-384 and
//!   SHA-512) has the same key as its own hash, and any two passwords with the
//!   same hash have the same key.
//! - **Nothing is checked or stretched but what you pass.** An empty password
//!   or an empty salt is allowed. To check a password, derive the key again
//!   with the stored salt and iteration count and compare it with the stored
//!   key, with a comparison that does not stop at the first difference.
//! - **MD5 and SHA-1 are there for older formats.** Their collisions do not
//!   break HMAC, which does not need collision resistance, but neither should
//!   be chosen for a new design; SHA-256 or SHA-512 should.
//!
//! The password keys an [`Hmac`](crate::hmac::Hmac) inside [`derive()`], whose
//! states, worth as much as the password, are overwritten with zeros when it
//! returns. That is best effort: the hash functions' working values on the
//! stack are not overwritten, nor are the digests they return (each `U(j)`,
//! which generic code over `Digest` can read but not overwrite). The password
//! and the key are the caller's buffers, and wiping them is the caller's job.
//!
//! # Implementation
//!
//! PBKDF2 has no backend of its own. It is a loop of HMAC calls, the work is in
//! the hash, and the hash picks its backend at run time as it always does
//! (FEAT_SHA256 for SHA-256 on an Apple M1, say). [`derive()`] keys one `Hmac`
//! with the password, which hashes the two padded keys once and keeps the state
//! of the hash after each, so an iteration costs what the definition needs and
//! no more: the inner hash of `U(j - 1)` from one state, and the outer hash of
//! that digest from the other. For all eight hashes, an output and the padding
//! after it fit in one block, so that is two calls of the compression function
//! per iteration. `U(1)` takes more only if the salt is long: its message is
//! the salt and the four bytes of the block number, fed to the hash in those
//! two parts, from where they are. Each `T(i)` is built in the caller's buffer
//! by XORing every `U(j)` into it, so nothing is allocated, and a derivation
//! keeps no copy of the key in progress.
//!
//! The module is safe Rust. The `unsafe` it relies on is in the wiping of
//! HMAC's states when they are dropped: volatile writes, which the compiler
//! would otherwise delete as stores nobody reads.
//!
//! ## Trust
//!
//! The tests check this implementation against sources that share nothing with
//! it: the vectors of RFC 6070 (HMAC-SHA-1) and RFC 7914 (HMAC-SHA-256), those
//! of Project Wycheproof for SHA-1, SHA-224, SHA-256, SHA-384 and SHA-512, and,
//! for all eight hashes, vectors made with Python's `hashlib` that a
//! second library and OpenSSL 3.6 reproduce. Those cover passwords of one block
//! and one byte more, where HMAC starts hashing its key; salts on both sides of
//! the point where the first message spills into a second block; every length
//! of key around a multiple of the hash's output, and a key long enough for the
//! block number to use three of its four bytes; and from one to a thousand
//! iterations.
//!
//! ## Side channels
//!
//! Nothing that depends on the password is used as a memory address or as a
//! branch condition. What PBKDF2 and HMAC do, and every address they touch,
//! depends only on the lengths of the password, the salt and the key, and on
//! the iteration count, and never on the contents of the password; nothing
//! compares a secret byte with anything. The SHA-2 functions underneath have
//! the same property (see [`sha2`](crate::sha2)). Unlike for ECDH, the compiled
//! code has not been inspected for it, and no timing measurement backs it up.
//! The lengths and the count are not hidden, and nothing here is protected
//! against attacks that read power consumption or inject faults.
//!
//! # Example
//!
//! ```
//! use cryptors::{pbkdf2::{self, Error}, sha2::Sha256};
//!
//! // RFC 7914, section 11: 1 iteration of HMAC-SHA-256, 64 bytes of key.
//! let mut key = [0; 64];
//! pbkdf2::derive::<Sha256>(b"passwd", b"salt", 1, &mut key)?;
//! assert_eq!(
//!     key[..16],
//!     [
//!         0x55, 0xac, 0x04, 0x6e, 0x56, 0xe3, 0x08, 0x9f, 0xec, 0x16, 0x91, 0xc2, 0x25, 0x44,
//!         0xb6, 0x05,
//!     ]
//! );
//!
//! // A password hash: a random salt, stored with the key, and many iterations
//! // (a real one uses far more, 600,000 for HMAC-SHA-256 today; this keeps the test fast).
//! # let salt = [0x42; 16];
//! let mut stored = [0; 32];
//! pbkdf2::derive::<Sha256>(b"correct horse", &salt, 10_000, &mut stored)?;
//!
//! // A shorter key is the start of a longer one, so ask for what you need.
//! let mut short = [0; 16];
//! pbkdf2::derive::<Sha256>(b"correct horse", &salt, 10_000, &mut short)?;
//! assert_eq!(short, stored[..16]);
//!
//! // No iterations and no key are errors, not panics.
//! assert_eq!(
//!     pbkdf2::derive::<Sha256>(b"correct horse", &salt, 0, &mut short),
//!     Err(Error::InvalidIterations)
//! );
//! assert_eq!(
//!     pbkdf2::derive::<Sha256>(b"correct horse", &salt, 1, &mut []),
//!     Err(Error::InvalidLength)
//! );
//! # Ok::<(), Error>(())
//! ```

mod kdf;

pub use kdf::{Error, derive};
