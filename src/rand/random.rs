use std::io;

use super::sys;
use crate::wipe::wipe;

/// The operating system's random number generator, as an [`io::Read`]: every
/// type of the crate that takes a source of random bytes (a `generate` or a
/// `sign` that wants a `&mut impl io::Read`) can be given this one.
///
/// It is a handle with no state, free to copy and to share between threads,
/// and a read from it asks the operating system each time; nothing is buffered
/// or kept in the process. [`read`](io::Read::read) fills the whole buffer
/// and returns its length, never fewer, so [`read_exact`](io::Read::read_exact)
/// needs no second call.
///
/// # Errors
///
/// A read fails only if the operating system does not answer: a Linux kernel
/// older than 3.17 on which `/dev/urandom` cannot be opened, a program in a
/// sandbox that forbids the call, or a platform with no source known to this
/// crate ([`Unsupported`](io::ErrorKind::Unsupported)). On the platforms
/// that matter this does not happen, and a program with no way to go on
/// without randomness can use [`fill`], which panics instead.
///
/// ```
/// use cryptors::rand::Reader;
/// use std::io::Read;
///
/// let mut nonce = [0u8; 12];
/// Reader.read_exact(&mut nonce)?;
/// # Ok::<(), std::io::Error>(())
/// ```
#[derive(Clone, Copy, Debug, Default)]
pub struct Reader;

impl io::Read for Reader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        sys::read(buf)?;
        Ok(buf.len())
    }
}

/// Fills `buf` with random bytes from the operating system.
///
/// There is no error to handle: if the operating system cannot give random
/// bytes, nothing that follows can be secure, and this panics rather than
/// return a buffer that was not filled. A program that would rather handle it
/// reads from [`Reader`], which returns the error instead.
///
/// ```
/// let mut key = [0u8; 32];
/// cryptors::rand::fill(&mut key);
/// # assert!(key.iter().any(|&b| b != 0));
/// ```
///
/// # Panics
///
/// If the operating system fails to answer; see [`Reader`] for when that is.
pub fn fill(buf: &mut [u8]) {
    if let Err(error) = sys::read(buf) {
        panic!("cryptors::rand: failed to read random data from the operating system: {error}");
    }
}

/// The alphabet of RFC 4648 (section 6, table 3): 32 characters, so that five
/// bits choose one.
const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// The characters in a [`text`]: 26 of 5 bits make 130, the least number of
/// characters that holds the 128 bits that the text promises.
const TEXT_LEN: usize = 26;

/// Returns a random string for use where a secret one is needed: a token, a
/// password, an identifier that must not be guessed.
///
/// It is 26 characters of the base32 alphabet of RFC 4648 (`A` to `Z` and `2` to
/// `7`), all of them random and chosen without bias: 130 bits of randomness,
/// enough to make a guess hopeless and a collision between two of them
/// vanishingly unlikely. A future version may return a longer text if that
/// stops being enough, so do not rely on the length.
///
/// ```
/// let token = cryptors::rand::text();
/// assert_eq!(token.len(), 26);
/// assert!(token.bytes().all(|b| b.is_ascii_uppercase() || (b'2'..=b'7').contains(&b)));
/// ```
///
/// # Panics
///
/// If the operating system fails to answer, as [`fill`] does.
#[must_use]
pub fn text() -> String {
    let mut bytes = [0u8; TEXT_LEN];
    fill(&mut bytes);
    let text = encode(&bytes);
    wipe(&mut bytes);
    text
}

/// Maps each byte to the character its low five bits choose. A byte holds
/// eight bits and 256 is a multiple of 32, so each character is equally likely.
fn encode(bytes: &[u8; TEXT_LEN]) -> String {
    bytes
        .iter()
        .map(|&byte| char::from(ALPHABET[usize::from(byte % 32)]))
        .collect()
}

/// Returns a uniform random number in `0..max` (including `0`, excluding `max`)
/// from the bytes of `rng`, without the bias that `value % max` has.
///
/// It reads the fewest bytes that can hold `max - 1`, clears the bits of the
/// first one above the highest bit of `max - 1`, and draws again if the result
/// is not below `max`. That happens with a probability under a half, so it
/// takes fewer than two draws on average, and every number below `max` is
/// equally likely whatever `max` is. A `max` of 1 reads nothing.
///
/// Pass [`Reader`] for the operating system's generator. Any other reader works
/// too, and gives the same number for the same bytes, which is what a test of
/// code that rolls dice needs.
///
/// ```
/// use cryptors::rand::{self, Reader};
///
/// let die = rand::below(&mut Reader, 6)? + 1;
/// assert!((1..=6).contains(&die));
/// # Ok::<(), std::io::Error>(())
/// ```
///
/// # Errors
///
/// Whatever `rng` fails with, and that includes running out of bytes
/// ([`UnexpectedEof`](io::ErrorKind::UnexpectedEof)). It also gives up, with
/// [`InvalidData`](io::ErrorKind::InvalidData), after 128 draws in a row that
/// are not below `max`: a good source gets one wrong with a probability of
/// under a half, so 128 in a row has a probability under `2^-128`, and means
/// the source is stuck (a reader that only returns `0xff`, say); looping on it
/// would never end.
///
/// # Panics
///
/// If `max` is zero: there is no number in `0..0`.
pub fn below<R: io::Read + ?Sized>(rng: &mut R, max: u64) -> io::Result<u64> {
    const ATTEMPTS: usize = 128;

    assert!(max > 0, "cryptors::rand: the bound of `below` is zero");
    let largest = max - 1;
    if largest == 0 {
        return Ok(0);
    }
    // The bytes that hold `largest`, and the bits of the first that are in use.
    let bits = u64::BITS - largest.leading_zeros();
    let len = bits.div_ceil(8) as usize;
    let top_bits = match bits % 8 {
        0 => 8,
        top => top,
    };
    let mask = u8::MAX >> (8 - top_bits);

    let mut buffer = [0u8; 8];
    let mut result = Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "cryptors::rand: the random source did not produce a number below the bound",
    ));
    for _ in 0..ATTEMPTS {
        let bytes = &mut buffer[..len];
        if let Err(error) = rng.read_exact(bytes) {
            result = Err(error);
            break;
        }
        bytes[0] &= mask;
        let candidate = bytes
            .iter()
            .fold(0u64, |acc, &byte| (acc << 8) | u64::from(byte));
        if candidate < max {
            result = Ok(candidate);
            break;
        }
    }
    wipe(&mut buffer);
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use io::Read;
    use std::collections::HashSet;

    /// A reader that returns the bytes it was given, in order, then fails.
    struct Script<'a>(&'a [u8]);

    impl io::Read for Script<'_> {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let n = buf.len().min(self.0.len());
            buf[..n].copy_from_slice(&self.0[..n]);
            self.0 = &self.0[n..];
            Ok(n)
        }
    }

    /// A reader that returns the same byte for ever, and counts what it gave.
    struct Stuck {
        byte: u8,
        bytes: usize,
    }

    impl io::Read for Stuck {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.bytes += buf.len();
            buf.fill(self.byte);
            Ok(buf.len())
        }
    }

    /// A reader that fails, as a source that is gone does.
    struct Broken;

    impl io::Read for Broken {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::from(io::ErrorKind::BrokenPipe))
        }
    }

    fn unhex(hex: &str) -> Vec<u8> {
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn fill_writes_every_byte_and_only_those() {
        // Lengths around the small sizes a nonce or a key has, around the 256
        // bytes up to which a system call never comes back short, and well past
        // one page.
        for len in [
            0, 1, 2, 7, 8, 15, 16, 17, 31, 32, 33, 255, 256, 257, 1000, 4096, 65_537,
        ] {
            const GUARD: usize = 16;
            let mut buf = vec![0xa5; GUARD + len + GUARD];
            fill(&mut buf[GUARD..GUARD + len]);
            assert!(buf[..GUARD].iter().all(|&b| b == 0xa5), "{len}: before");
            assert!(
                buf[GUARD + len..].iter().all(|&b| b == 0xa5),
                "{len}: after"
            );
            // A buffer of 16 bytes or more that is still all zeros, or still all
            // the byte it started with, has not been filled: the chance that
            // random bytes do that is 2^-128.
            if len >= 16 {
                let body = &buf[GUARD..GUARD + len];
                assert!(body.iter().any(|&b| b != 0), "{len}: all zeros");
                assert!(body.iter().any(|&b| b != 0xa5), "{len}: untouched");
            }
        }
    }

    #[test]
    fn the_whole_of_a_large_buffer_is_filled() {
        // Past the size of one request to the system on a platform that limits
        // it, and with a pattern in every page, not just the first.
        let mut buf = vec![0u8; 4 << 20];
        fill(&mut buf);
        for page in buf.chunks(4096) {
            assert!(page.iter().any(|&b| b != 0));
        }
    }

    #[test]
    fn what_comes_out_looks_random() {
        // Not a proof of anything, but it fails for a generator that is stuck,
        // short of entropy or biased, which no other test here would notice:
        // every byte value about equally often (chi-square, 255 degrees of
        // freedom: mean 255, standard deviation 22.6, bounds at about 6 and
        // 6.4 of them), and as many ones as zeros in the bits (standard
        // deviation 1448 in 8,388,608, bound at 6).
        let mut buf = vec![0u8; 1 << 20];
        fill(&mut buf);

        let mut counts = [0u32; 256];
        for &byte in &buf {
            counts[usize::from(byte)] += 1;
        }
        let expected = buf.len() as f64 / 256.0;
        let chi_square: f64 = counts
            .iter()
            .map(|&c| (f64::from(c) - expected).powi(2) / expected)
            .sum();
        assert!(
            (120.0..400.0).contains(&chi_square),
            "chi-square {chi_square}"
        );

        let ones: u64 = buf.iter().map(|b| u64::from(b.count_ones())).sum();
        let half = buf.len() as u64 * 4;
        assert!(ones.abs_diff(half) < 8_688, "{ones} ones of {}", half * 2);
    }

    #[test]
    fn no_two_draws_are_alike() {
        // 32 bytes are 256 bits: two equal draws mean a generator that repeats
        // itself, or one that gives the same bytes to every caller.
        let mut seen = HashSet::new();
        for _ in 0..1000 {
            let mut draw = [0u8; 32];
            fill(&mut draw);
            assert!(seen.insert(draw));
        }
    }

    #[test]
    fn threads_do_not_share_their_bytes() {
        let draws: Vec<[u8; 32]> = std::thread::scope(|scope| {
            let threads: Vec<_> = (0..8)
                .map(|_| {
                    scope.spawn(|| {
                        (0..100)
                            .map(|_| {
                                let mut draw = [0u8; 32];
                                fill(&mut draw);
                                draw
                            })
                            .collect::<Vec<_>>()
                    })
                })
                .collect();
            threads
                .into_iter()
                .flat_map(|thread| thread.join().unwrap())
                .collect()
        });
        assert_eq!(draws.len(), 800);
        assert_eq!(draws.iter().collect::<HashSet<_>>().len(), 800);
    }

    #[test]
    fn the_reader_fills_what_it_is_given() {
        let mut reader = Reader;
        assert_eq!(reader.read(&mut []).unwrap(), 0);
        for len in [1, 16, 255, 256, 257, 10_000] {
            let mut buf = vec![0u8; len];
            assert_eq!(reader.read(&mut buf).unwrap(), len);
            if len >= 16 {
                assert!(buf.iter().any(|&b| b != 0));
            }
        }
        // As the trait object that a function taking `&mut dyn Read` gets.
        let dynamic: &mut dyn io::Read = &mut reader;
        let mut buf = [0u8; 40];
        dynamic.read_exact(&mut buf).unwrap();
        assert!(buf.iter().any(|&b| b != 0));
        // It is `Copy`, so that handing it on does not use it up.
        let copy = reader;
        let (mut a, mut b) = ([0u8; 32], [0u8; 32]);
        { copy }.read_exact(&mut a).unwrap();
        reader.read_exact(&mut b).unwrap();
        assert_ne!(a, b);
        assert_eq!(format!("{reader:?}"), "Reader");
    }

    #[test]
    fn the_reader_feeds_the_keys_of_the_crate() {
        use crate::ecdh::{P256, PrivateKey, X25519};

        let a = PrivateKey::<P256>::generate(&mut Reader).unwrap();
        let b = PrivateKey::<P256>::generate(&mut Reader).unwrap();
        assert_ne!(a.as_bytes(), b.as_bytes());
        let a = PrivateKey::<X25519>::generate(&mut Reader).unwrap();
        let b = PrivateKey::<X25519>::generate(&mut Reader).unwrap();
        assert_ne!(a.as_bytes(), b.as_bytes());
        assert_ne!(a.public_key().as_bytes(), b.public_key().as_bytes());
    }

    #[test]
    fn encode_maps_a_byte_to_the_character_of_its_low_five_bits() {
        // The characters of RFC 4648's table 3, in order: A to Z for 0 to 25,
        // then 2 to 7 for 26 to 31; and every byte value, so that the bits
        // above the fifth are known to be dropped.
        let table: Vec<char> = ('A'..='Z').chain('2'..='7').collect();
        assert_eq!(table.len(), 32);
        for byte in 0..=255u8 {
            let text = encode(&[byte; TEXT_LEN]);
            let want: String =
                std::iter::repeat_n(table[usize::from(byte & 31)], TEXT_LEN).collect();
            assert_eq!(text, want, "byte {byte}");
        }
        // Each position is mapped on its own, in order.
        let mut bytes = [0u8; TEXT_LEN];
        for (i, byte) in bytes.iter_mut().enumerate() {
            *byte = (i * 9) as u8;
        }
        assert_eq!(encode(&bytes), "AJS3ENW7IR2DMV6HQZCLU5GPYB");
    }

    #[test]
    fn text_is_26_characters_of_the_alphabet() {
        let mut seen = HashSet::new();
        let mut counts = [0u32; 32];
        for _ in 0..4000 {
            let token = text();
            assert_eq!(token.len(), TEXT_LEN);
            for byte in token.bytes() {
                let index = ALPHABET.iter().position(|&c| c == byte);
                counts[index.expect("a character outside the alphabet")] += 1;
            }
            assert!(seen.insert(token));
        }
        // 104,000 characters over 32 symbols: 3250 of each, standard deviation
        // 56; a symbol more than 6 of them away means the text is biased.
        for (symbol, &count) in counts.iter().enumerate() {
            assert!(count.abs_diff(3250) < 340, "{symbol}: {count}");
        }
    }

    /// What another implementation of the same algorithm (a mask on the first
    /// byte, and a new draw if the number is not below the bound) returns, given
    /// these bytes by a reader: the number, and how many bytes it read. Made
    /// with a program kept outside the repository; `bench/randcmp` replays the
    /// same table against the standard library of the other side.
    const BELOW: &[(u64, &str, u64, usize)] = &[
        (1, "", 0, 0),
        (2, "fe01", 0, 1),
        (2, "020300", 0, 1),
        (5, "fffefdfc", 4, 4),
        (5, "07060503", 3, 4),
        (6, "0705", 5, 2),
        (10, "ff0a0b0f09", 9, 5),
        (255, "fffe", 254, 2),
        (256, "abcd", 171, 1),
        (257, "ffff0101010002", 256, 6),
        (257, "03000101", 256, 2),
        (1000, "ffff03e803e7", 999, 6),
        (65536, "1234", 4660, 2),
        (65537, "ffffff010001010000", 65536, 9),
        (1 << 32, "deadbeef", 3_735_928_559, 4),
        ((1 << 32) + 1, "ffffffffff0100000000", 4_294_967_296, 10),
        (1 << 56, "ff123456789abcde", 71_796_135_059_561_148, 7),
        (
            (1 << 56) + 1,
            "ff123456789abcde00123456789abcde",
            5_124_095_576_030_430,
            16,
        ),
        (1 << 63, "ffffffffffffffff", (1 << 63) - 1, 8),
        (
            (1 << 63) + 1,
            "ffffffffffffffff80000000000000018000000000000000",
            1 << 63,
            24,
        ),
        (u64::MAX, "fffffffffffffffe", u64::MAX - 1, 8),
        (
            u64::MAX,
            "fffffffffffffffffffffffffffffffe",
            u64::MAX - 1,
            16,
        ),
    ];

    #[test]
    fn below_agrees_with_the_known_answers() {
        for &(max, input, want, consumed) in BELOW {
            let input = unhex(input);
            let mut reader = Script(&input);
            assert_eq!(below(&mut reader, max).unwrap(), want, "max {max}");
            assert_eq!(
                input.len() - reader.0.len(),
                consumed,
                "max {max}: bytes read"
            );
        }
    }

    #[test]
    fn below_a_bound_of_one_reads_nothing() {
        assert_eq!(below(&mut Broken, 1).unwrap(), 0);
    }

    #[test]
    fn below_fails_when_the_source_does() {
        assert_eq!(
            below(&mut Broken, 6).unwrap_err().kind(),
            io::ErrorKind::BrokenPipe
        );
        // Out of bytes, in the middle of a number and in the middle of a retry.
        for (max, input) in [
            (6u64, &[][..]),
            (65_537, &[0xff, 0xff][..]),
            (5, &[0xff][..]),
        ] {
            let error = below(&mut Script(input), max).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof, "max {max}");
        }
    }

    #[test]
    fn below_gives_up_on_a_source_that_never_gives_a_number() {
        // A source of 0xff bytes: masked down to 7, it is never below 5, so the
        // draws are refused one after the other, 128 of them of one byte each,
        // and then an error, not a loop.
        let mut ones = Stuck {
            byte: 0xff,
            bytes: 0,
        };
        let error = below(&mut ones, 5).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(ones.bytes, 128);

        // The same for a bound that takes eight bytes a draw.
        let mut ones = Stuck {
            byte: 0xff,
            bytes: 0,
        };
        assert!(below(&mut ones, (1 << 63) + 1).is_err());
        assert_eq!(ones.bytes, 128 * 8);

        // The last draw that is allowed counts: 127 refusals, then a number.
        let mut input = vec![0xff; 127];
        input.push(0x03);
        assert_eq!(below(&mut Script(&input), 5).unwrap(), 3);
        // And one more refusal is not.
        let mut input = vec![0xff; 128];
        input.push(0x03);
        assert!(below(&mut Script(&input), 5).is_err());
    }

    #[test]
    fn a_zero_bound_is_a_mistake() {
        let panic = std::panic::catch_unwind(|| below(&mut Script(&[0; 8]), 0));
        assert!(panic.is_err());
    }

    #[test]
    fn below_is_uniform() {
        // A bound that is not a power of two, so that a mask without the retry,
        // or `value % max`, would show: 6 of 8 values of 3 bits are used, and
        // `% 6` would give 0 and 1 twice the weight.
        const DRAWS: u32 = 60_000;
        let mut counts = [0u32; 6];
        for _ in 0..DRAWS {
            counts[below(&mut Reader, 6).unwrap() as usize] += 1;
        }
        // 10,000 each, standard deviation 91; the bound is 6 of them.
        for (value, &count) in counts.iter().enumerate() {
            assert!(count.abs_diff(10_000) < 550, "{value}: {count}");
        }

        // The widest bound uses all 64 bits, in both halves of the range.
        let draws: Vec<u64> = (0..200)
            .map(|_| below(&mut Reader, u64::MAX).unwrap())
            .collect();
        assert!(draws.iter().any(|&d| d >> 63 == 1));
        assert!(draws.iter().any(|&d| d >> 63 == 0));
        assert!(draws.iter().all(|&d| d != u64::MAX));
        assert!(draws.iter().any(|&d| d & 0xff != 0));
    }

    #[test]
    #[ignore = "manual throughput check: cargo test --release rand:: -- --ignored --nocapture --test-threads=1"]
    fn throughput() {
        use std::hint::black_box;
        use std::time::Instant;

        /// Runs `pass` once to warm up, then five times, and returns the best
        /// of the five in passes per second.
        fn best_rate(mut pass: impl FnMut()) -> f64 {
            // The first pass is slowed down by page faults and CPU clock
            // ramp-up, not just the generator itself, so it is not timed.
            pass();
            let mut best = 0.0f64;
            for _ in 0..5 {
                let start = Instant::now();
                pass();
                best = best.max(1.0 / start.elapsed().as_secs_f64());
            }
            best
        }

        // Small buffers, as a nonce, a salt or a key is: the cost of a call.
        for len in [16usize, 32, 256] {
            const CALLS: usize = 200_000;
            let mut buf = vec![0u8; len];
            let rate = best_rate(|| {
                for _ in 0..CALLS {
                    fill(black_box(&mut buf));
                }
            });
            println!(
                "rand fill {len} bytes [cryptors]: {CALLS} per pass, best {:.0} ops/s ({:.1} MiB/s)",
                rate * CALLS as f64,
                rate * (CALLS * len) as f64 / (1 << 20) as f64
            );
        }

        // Large buffers, as a block of key material or a test input is: the
        // cost of a byte.
        for (len, calls) in [(4096usize, 20_000usize), (1 << 20, 100)] {
            let mut buf = vec![0u8; len];
            let rate = best_rate(|| {
                for _ in 0..calls {
                    fill(black_box(&mut buf));
                }
            });
            println!(
                "rand fill {len} bytes [cryptors]: {calls} per pass, best {:.1} MiB/s",
                rate * (calls * len) as f64 / (1 << 20) as f64
            );
        }
    }
}
