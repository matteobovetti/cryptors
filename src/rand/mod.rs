//! A cryptographically secure random number generator: the operating system's,
//! which is what every key, nonce, salt and token should come from. The module
//! adds nothing between the program and the system's generator, so what it
//! returns is as strong as that is.
//!
//! | Platform | Source |
//! |----------|--------|
//! | Linux, FreeBSD, DragonFly BSD | `getrandom(2)`; on a Linux older than 3.17, which has no such call, `/dev/urandom` |
//! | macOS, iOS, tvOS, watchOS, visionOS, OpenBSD | `arc4random_buf(3)` |
//! | Any other Unix (NetBSD, Android, illumos, Solaris, ...) | `/dev/urandom` |
//! | Windows and every other platform | none: every call fails with [`Unsupported`](std::io::ErrorKind::Unsupported) |
//!
//! There are four items. [`Reader`] is the generator as an [`io::Read`](std::io::Read),
//! which is what the `generate`, `sign` and `encapsulate` functions of the other
//! modules take; [`fill()`] writes random bytes into a buffer; [`text()`] returns a
//! random string for a token or a password; and [`below()`] returns a uniform number
//! below a bound from any reader.
//!
//! # How it works
//!
//! Each call asks the operating system for the bytes it needs, and nothing
//! is kept in the process between calls: no buffer of bytes to read ahead, no
//! key to expand, no counter. The system's generator is seeded from the
//! hardware's entropy sources and the timing of events, and reseeded as it
//! runs; it is meant to be called for every key. A second generator in the
//! process, seeded from the first, would add a state that a forked child
//! shares with its parent and that a restored snapshot of a virtual machine
//! repeats, which the system's generator is built to avoid; so there is none.
//!
//! That also means this module is not a DRBG in the sense of NIST SP 800-90A and
//! has not been validated under FIPS 140: what it gives is as strong as the
//! system's generator, and no more certified.
//!
//! The calls differ in what can go wrong:
//!
//! - `getrandom(2)` is asked for the whole buffer, in requests of at most
//!   2^31 − 1 bytes. It can return fewer bytes than asked for, when a signal
//!   interrupts it or when the request is large, and fewer is not a failure:
//!   the call is repeated for what is left. A call made before the kernel has
//!   gathered enough entropy to start (a few seconds into boot, in practice
//!   only on small machines) waits, rather than return bytes that are not yet
//!   unpredictable; once it has, a call never waits again.
//! - `arc4random_buf(3)` takes a buffer of any size and cannot fail.
//! - `/dev/urandom` is opened on first use and kept, so a program that has since
//!   used up its file descriptors can still draw bytes. It is where a system
//!   with no better call lands, and the way back on a Linux that has no
//!   `getrandom` (the call fails with `ENOSYS`).
//!
//! # Using it
//!
//! - **Take keys, nonces and salts from here.** [`fill()`] for a buffer,
//!   `Reader` for anything that takes a reader. The `generate` of every key
//!   in the crate does this with `&mut Reader`.
//! - **A failure is not something to recover from.** If the system cannot give
//!   random bytes, nothing that follows is safe: not a key, and not a retry
//!   with a weaker source. [`fill()`] and [`text()`] panic on it, and `Reader`
//!   and [`below()`] return the error for a program that must clean up first.
//!   On every platform in the table above, short of a sandbox that forbids the
//!   call, this does not happen.
//! - **Never fall back to anything predictable.** The time, the process
//!   number, an address, and the output of a hash of those are all guessable.
//! - **A number below a bound is not `value % bound`.** If `bound` is not a
//!   power of two, some numbers are then more likely than others (a byte modulo
//!   6 gives 0 to 3 in 43 cases of 256 and 4 and 5 in 42). [`below()`] discards
//!   what does not fit and draws again, so all are equally likely.
//! - **A text is a secret; it is not a password people remember.** [`text()`]
//!   is 26 characters of the base32 alphabet of RFC 4648 (130 bits). That is
//!   right for an API token, a reset link or an identifier that must not be
//!   guessed, and wrong for something a person has to type or say aloud.
//! - **Randomness is not a key.** A password a person chooses has little
//!   entropy: derive a key from it with [PBKDF2](crate::pbkdf2). A shared secret
//!   from a key agreement is not uniform bytes either: pass it through
//!   [HKDF](crate::hkdf).
//!
//! There is no public big integer in the crate, so there is no function for a random
//! integer of any size, nor for a random prime (the primes of an [RSA](crate::rsa)
//! key are drawn from a reader by that module, which keeps its numbers to itself).
//! [`below()`] covers numbers up to `2^64 - 1`.
//!
//! # Implementation
//!
//! The only code that is different on each platform is `sys.rs`, which wraps
//! the call in a function that writes some bytes at the start of a buffer and
//! says how many; the loop that makes this fill a buffer, handling a short
//! write and an interruption and refusing an answer of zero bytes, is shared
//! and is tested with calls that misbehave on purpose. That is also the only
//! `unsafe` in the module: the declaration of the C library's call and one
//! call to it, with the buffer's pointer and length. The standard library has no
//! stable interface to the system's generator, and so no safe way to the same
//! bytes (`/dev/urandom` is one only on a Unix, and costs a file descriptor).
//!
//! `text()` and `below()` overwrite the bytes they drew, which are secret until
//! they have been turned into a character or a number, before they return. The
//! bytes that `fill()` writes are the caller's, and wiping them is the caller's
//! job.
//!
//! ## Trust
//!
//! There are no test vectors for a generator that is meant to be unpredictable,
//! so the tests check what can be checked. The loop that fills a buffer is
//! checked against calls that return one byte at a time, are interrupted, return
//! nothing, claim to have written too much, or fail. Every length from empty to
//! four megabytes is filled to the last byte and not past it (guards on both
//! sides). A megabyte of output has every byte value about equally often and as
//! many one bits as zeros, within six standard deviations; a thousand draws of
//! 32 bytes are all different, and so are eight threads' draws; a stuck or
//! constant generator fails these. `text()` maps each of the 256 byte values to
//! the character RFC 4648's table gives for its low five bits. `below()`
//! agrees with another implementation's answers on a table of 22 inputs (bounds
//! from 1 to `2^64 - 1`, draws refused and bytes left unread), and it is
//! uniform on a bound that a modulo would bias. The `/dev/urandom` route is run
//! on every Unix, and on Linux the fall back to it was run under a filter that
//! makes `getrandom` fail with `ENOSYS`.
//!
//! These checks run on the Linux machines of the project's continuous
//! integration (x86-64, Arm and RISC-V under emulation) and on macOS. The
//! calls for FreeBSD, DragonFly BSD and OpenBSD are written from their
//! manuals and have not been run; neither has Windows, which is not supported.
//!
//! ## Side channels
//!
//! Nothing here branches on, or uses as an address, a random byte that is
//! secret, except that `below()` draws again when a number is out of range. How
//! many times it draws is visible in the time it takes; it tells nothing about
//! the number it returns, because a draw that is refused is thrown away and the
//! next is independent of it. The system's generator is outside this module.
//!
//! # Example
//!
//! ```
//! use cryptors::rand::{self, Reader};
//! use cryptors::ecdh::{PrivateKey, X25519};
//!
//! // A 256-bit key, for AES-256 or HMAC.
//! let mut key = [0u8; 32];
//! rand::fill(&mut key);
//!
//! // A token to put in a link: 26 characters, 130 bits.
//! let token = rand::text();
//! assert_eq!(token.len(), 26);
//!
//! // `Reader` is what the keys of the crate take as their source of randomness.
//! let alice = PrivateKey::<X25519>::generate(&mut Reader)?;
//! let bob = PrivateKey::<X25519>::generate(&mut Reader)?;
//! assert_eq!(
//!     alice.diffie_hellman(bob.public_key())?.as_bytes(),
//!     bob.diffie_hellman(alice.public_key())?.as_bytes()
//! );
//!
//! // A uniform number below a bound: a die, the index of an item to draw.
//! let die = rand::below(&mut Reader, 6)? + 1;
//! assert!((1..=6).contains(&die));
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

mod random;
mod sys;

pub use random::{Reader, below, fill, text};
