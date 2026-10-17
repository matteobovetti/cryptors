# Rand

Rand is the operating system's cryptographically secure random number generator, the source for every key, nonce, salt
and token. It adds nothing between the program and the system's generator, so it is exactly as strong as that. Each
call asks the system for the bytes it needs and nothing is kept between calls, so a forked child never shares state with
its parent and a restored virtual machine never repeats bytes it gave out. It is not a NIST SP 800-90A DRBG and has not
been validated under FIPS 140.

| Platform | Source |
|----------|--------|
| Linux, FreeBSD, DragonFly BSD | `getrandom(2)`; on a Linux older than 3.17, which has no such call, `/dev/urandom` |
| macOS, iOS, tvOS, watchOS, visionOS, OpenBSD | `arc4random_buf(3)` |
| Any other Unix (NetBSD, Android, illumos, Solaris, ...) | `/dev/urandom` |
| Windows and every other platform | none: every call fails with `ErrorKind::Unsupported` |

Four items, none generic: `Reader` (the generator as an `io::Read`), `fill(&mut buf)`, `text()` and
`below(&mut reader, max)`. The standard library has no stable interface to the system's generator (`std::random` is
unstable) and the crate has no dependencies, so the module declares the C library call itself. That is its only
`unsafe`: one call with a buffer's pointer and length.

## Usage

```rust
use cryptors::ecdh::{PrivateKey, X25519};
use cryptors::rand::{self, Reader};

// A 256-bit key, for AES-256 or HMAC. `fill` has no error to handle: if the system cannot give random bytes, nothing
// after it can be secure, and it panics.
let mut key = [0u8; 32];
rand::fill(&mut key);

// A token for a link or an API key: 26 characters of the RFC 4648 base32 alphabet (A-Z, 2-7), 130 bits.
let token = rand::text();
assert_eq!(token.len(), 26);

// `Reader` is what the keys of the crate take as their source of randomness. It returns an error rather than panic.
let alice = PrivateKey::<X25519>::generate(&mut Reader).unwrap();
let bob = PrivateKey::<X25519>::generate(&mut Reader).unwrap();
assert_eq!(
    alice.diffie_hellman(bob.public_key()).unwrap().as_bytes(),
    bob.diffie_hellman(alice.public_key()).unwrap().as_bytes()
);

// A uniform number in 0..max, with no bias: a die, the index of an item to draw. Any reader will do, so a test can give
// it fixed bytes: 0xff is masked to 7, which is not below 6, so it is drawn again, and 0x04 is.
assert!((1..=6).contains(&(rand::below(&mut Reader, 6).unwrap() + 1)));
assert_eq!(rand::below(&mut &[0xff, 0x04][..], 6).unwrap(), 4);
```

`below(rng, max)` reads the fewest bytes that hold `max - 1`, clears the first byte's bits above the highest one bit of
`max - 1`, and draws again if the result is not below `max`. A draw is refused with probability under a half, so fewer
than two draws are needed on average, and every number is equally likely. `value % max` is not uniform: a byte modulo 6
gives each of 0 to 3 in 43 cases of 256, and 4 and 5 in 42. `below` fails with `InvalidData` after 128 refused draws in
a row (a stuck reader), panics on a `max` of zero, and reads nothing for a `max` of 1.

With no public big integer in the crate, there is no random integer of any size and no random prime; `below` covers
numbers up to `2^64 - 1`. ([RSA](rsa.md) draws its primes from a reader internally.)

`examples/rand.rs` fills a key, prints tokens, rolls a die 60,000 times and checks the faces, shuffles a deck with
`below`, and agrees on an X25519 secret between keys from `Reader`: `cargo run --release --example rand`.

## Security

- **Take every key, nonce and salt from here; never fall back to anything predictable.** The time, a process number,
  an address, or a hash of them can be guessed. If the system cannot answer, stop: `fill` and `text` panic; `Reader`
  and `below` return the error, for a program that must clean up first.
- **It fails only where the system does.** `getrandom` does not fail a valid request; with no flags it waits only while
  the kernel gathers its initial entropy, once, at boot. A sandbox that forbids the call (`EPERM`) is an error for the
  caller, not a reason to read a file; only `ENOSYS` (a Linux before 3.17) falls back to `/dev/urandom`.
- **A text is a secret, not a password a person types.** 130 bits suits a token, not something read aloud. A password
  chosen by a person goes through [PBKDF2](pbkdf2.md), a key-agreement secret through [HKDF](hkdf.md); neither is uniform.
- **Zeroization.** `text` and `below` overwrite the bytes they drew (secret until they become a character or a number)
  before returning; `fill` writes the caller's buffer, which the caller must wipe.

No secret random byte is a branch condition or a memory address, except that `below` redraws an out-of-range number.
The number of draws shows in the timing but says nothing about the result: a refused draw is thrown away, and the next
is independent of it. The system's generator, and its quality, are outside the crate.

## Testing

```sh
cargo test rand::   # the fill loop, the output's statistics, the text, `below` and its known answers, the /dev/urandom route
```

A generator meant to be unpredictable has no test vectors, so the tests check what can be checked:

- **The fill loop**: calls that return one byte at a time or are interrupted are retried for what is left; calls that
  return nothing, claim to have written too much, or fail give an error, not a loop or a panic.
- **Every length from empty to four megabytes** is filled to the last byte and not past it (guard bytes on both sides),
  and each page of a four-megabyte buffer is written.
- **The output**: a megabyte has every byte value about equally often (chi-square) and as many one bits as zero bits,
  within six standard deviations; a thousand 32-byte draws are all different, as are those of eight threads. A stuck,
  constant or short generator fails these.
- **`text`** maps each of the 256 byte values to the character of its low five bits in RFC 4648's table; 4000 tokens
  have 26 characters, all in the alphabet, each about equally often.
- **`below`** matches another implementation of the algorithm on 22 inputs (bounds from 1 to `2^64 - 1`, refused
  draws, bytes left unread), reading the same bytes. It is uniform for a bound a modulo would bias, and fails with the
  reader's error, with `UnexpectedEof`, and after exactly 128 refused draws.
- **`/dev/urandom`** is tested on every Unix, whichever route the machine takes. On Linux the fallback was run under a
  seccomp filter making `getrandom` fail with `ENOSYS`; with `EPERM` instead, the tests fail, as they should.
- **Mutation check**: each of 19 deliberate breaks of `src/rand/` (the mask, the comparison, the length, the character
  mapping, the number of draws, the short-write loop, the retry, the fallback) is caught by at least one test, except
  one that changes nothing observable (a byte of a buffer overwritten before it is read).

The tests run on the project's Linux machines (x86-64, Arm, and RISC-V under emulation) and on macOS. The FreeBSD,
DragonFly BSD and OpenBSD calls are written from their manuals and have not been run; Windows is not supported.

## Benchmarking

```sh
# cryptors: one test thread, so the benchmarks don't compete with each other for the CPU.
cargo test --release rand:: -- --ignored --nocapture --test-threads=1
cd bench/randcmp && go test -v                  # Go's crypto/rand.Read
```

Five buffer sizes, filled in place, the same on both sides: 16, 32 and 256 bytes (200,000 calls per pass, per-call cost
in operations per second), 4 KiB (20,000 calls) and 1 MiB (100 calls) (per-byte cost in MiB/s). One warm-up pass, best
of five timed passes. Random output cannot be compared, so the Go side checks that the buffers are filled and look
random, and replays the Rust tests' `below` table against `rand.Int`.

Apple M1 Pro, Go 1.27.1, medians of three interleaved runs, higher is better. Both sides call `arc4random_buf` on macOS:

| Buffer | cryptors | Go stdlib |
|--------|----------|-----------|
| 16 bytes | **4.44 M/s** | 3.79 M/s |
| 32 bytes | **4.34 M/s** | 3.71 M/s |
| 256 bytes | **3.70 M/s** (904 MiB/s) | 3.23 M/s (790 MiB/s) |
| 4 KiB | **3,099 MiB/s** | 3,041 MiB/s |
| 1 MiB | 3,041 MiB/s | 3,046 MiB/s |

Run-to-run spread was within 4%, with the machine not idle (load average 5).

- **Small buffers:** 1.15 to 1.17 times Go's rate. The system call is the same; only the code around it differs, and
  nothing was profiled.
- **Large buffers:** 1.02 times at 4 KiB and no gain at 1 MiB: the time is the generator's.

On Linux both sides call `getrandom(2)`, so the figures there are the kernel's; no x86 or Linux figures have been
measured. The manual `Benchmarks` workflow (`.github/workflows/bench.yml`) runs both sides on GitHub's x86-64 and Arm
runners.
