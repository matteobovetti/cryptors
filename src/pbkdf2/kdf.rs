use core::fmt;

use crate::Digest;
use crate::hmac::Hmac;

/// Whether a derived key of `len` bytes is one PBKDF2 can make from a hash with
/// outputs of `hash_len` bytes: at least one byte, and at most `2^32 - 1`
/// blocks, because the block number is a 32-bit integer (RFC 8018 section 5.2,
/// step 1). Takes `u64`s so that the limit can be tested on any target.
fn is_valid_output_len(len: u64, hash_len: u64) -> bool {
    len > 0 && len.div_ceil(hash_len) <= u64::from(u32::MAX)
}

/// PBKDF2 (RFC 8018 section 5.2) with HMAC over the hash `D` as the
/// pseudorandom function: fills `dk` with a key derived from `password` and
/// `salt` by `iterations` rounds of the function.
///
/// `password` and `salt` may be of any length, empty included. `dk` is filled
/// with the derived key, of any length from one byte up to `2^32 - 1` times the
/// hash's output length. Anything else is an error, and `dk` is left as it was:
/// no `iterations` ([`Error::InvalidIterations`]), no `dk` or one too long
/// ([`Error::InvalidLength`]).
///
/// The same inputs always give the same key, and a shorter `dk` is the start of
/// a longer one. The work is `iterations` times `dk.len()` divided by the
/// hash's output length (rounded up), two calls of the hash's compression
/// function each; nothing is allocated.
///
/// ```
/// use cryptors::{pbkdf2, sha1::Sha1};
///
/// // RFC 6070, test case 3: 4096 iterations of HMAC-SHA-1.
/// let mut dk = [0; 20];
/// pbkdf2::derive::<Sha1>(b"password", b"salt", 4096, &mut dk)?;
/// assert_eq!(dk[..8], [0x4b, 0x00, 0x79, 0x01, 0xb7, 0x65, 0x48, 0x9a]);
/// # Ok::<(), pbkdf2::Error>(())
/// ```
pub fn derive<D: Digest>(
    password: &[u8],
    salt: &[u8],
    iterations: u32,
    dk: &mut [u8],
) -> Result<(), Error> {
    // `chunks_mut` needs blocks of at least one byte. Every hash in the crate
    // has them, and one that did not would be stopped here at compile time.
    const { assert!(D::OUTPUT_LEN > 0, "PBKDF2 needs a hash with an output") };
    if iterations == 0 {
        return Err(Error::InvalidIterations);
    }
    if !is_valid_output_len(dk.len() as u64, D::OUTPUT_LEN as u64) {
        return Err(Error::InvalidLength);
    }

    // The password keys HMAC once, and every call of the function starts from
    // the two states that holds, so the key costs nothing after this.
    let prf = Hmac::<D>::new(password);

    // Each block of the key is independent of the others: T_i is the XOR of
    // U_1 to U_c, where U_1 = PRF(password, salt | INT(i)) and
    // U_j = PRF(password, U_(j-1)). T_i is built in place in `dk`, and the
    // last block may be cut short, which only drops bytes of the XOR that
    // nothing reads (U_j itself is always whole). The count of blocks was
    // checked to fit the counter, so the `zip` never cuts a block off.
    for (block, index) in dk.chunks_mut(D::OUTPUT_LEN).zip(1..=u32::MAX) {
        let mut u = prf.mac_parts(&[salt, &index.to_be_bytes()]);
        block.copy_from_slice(&u.as_ref()[..block.len()]);
        for _ in 1..iterations {
            u = prf.mac(u.as_ref());
            for (t, u) in block.iter_mut().zip(u.as_ref()) {
                *t ^= u;
            }
        }
    }
    Ok(())
}

/// An input that PBKDF2 does not allow.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Error {
    /// The iteration count is zero; it must be a positive integer (RFC 8018
    /// section 5.2).
    InvalidIterations,
    /// The buffer for the derived key is empty, or longer than `2^32 - 1`
    /// outputs of the hash, which is as many as the 32-bit block number
    /// counts (RFC 8018 section 5.2).
    InvalidLength,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Error::InvalidIterations => "PBKDF2 iteration count is zero",
            Error::InvalidLength => {
                "PBKDF2 derived key is empty or longer than (2^32 - 1) times the hash length"
            }
        })
    }
}

impl std::error::Error for Error {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::digest::hex;
    use crate::md5::Md5;
    use crate::sha1::Sha1;
    use crate::sha2::{Sha224, Sha256, Sha384, Sha512, Sha512_224, Sha512_256};

    /// The test data, one vector per line: see the header of the file.
    const VECTORS: &str = include_str!("testdata/vectors.txt");

    fn unhex(s: &str) -> Vec<u8> {
        if s == "-" {
            return Vec::new();
        }
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn derived<D: Digest>(password: &[u8], salt: &[u8], iterations: u32, len: usize) -> String {
        let mut dk = vec![0; len];
        derive::<D>(password, salt, iterations, &mut dk).unwrap();
        hex(&dk)
    }

    /// Runs the lines of one set of `testdata/vectors.txt` through `derive`
    /// and returns how many there were.
    fn check_set(set: &str) -> usize {
        let mut count = 0;
        for line in VECTORS.lines().filter(|l| !l.starts_with('#')) {
            let [line_set, hash, iterations, password, salt, dk] =
                line.split(' ').collect::<Vec<_>>()[..]
            else {
                panic!("malformed line: {line}");
            };
            if line_set != set {
                continue;
            }
            let (password, salt, iterations) =
                (unhex(password), unhex(salt), iterations.parse().unwrap());
            let len = dk.len() / 2;
            let got = match hash {
                "md5" => derived::<Md5>(&password, &salt, iterations, len),
                "sha1" => derived::<Sha1>(&password, &salt, iterations, len),
                "sha224" => derived::<Sha224>(&password, &salt, iterations, len),
                "sha256" => derived::<Sha256>(&password, &salt, iterations, len),
                "sha384" => derived::<Sha384>(&password, &salt, iterations, len),
                "sha512" => derived::<Sha512>(&password, &salt, iterations, len),
                "sha512-224" => derived::<Sha512_224>(&password, &salt, iterations, len),
                "sha512-256" => derived::<Sha512_256>(&password, &salt, iterations, len),
                _ => panic!("unknown hash in: {line}"),
            };
            assert_eq!(got, dk, "{set} {hash}, {iterations} iterations: {line}");
            count += 1;
        }
        count
    }

    /// The vectors printed in the RFCs: RFC 6070 for HMAC-SHA-1 (without its
    /// last, 16,777,216 iterations) and RFC 7914 section 11 for HMAC-SHA-256.
    #[test]
    fn known_answers() {
        // RFC 6070 section 2.
        let sha1 = [
            (
                &b"password"[..],
                &b"salt"[..],
                1,
                20,
                "0c60c80f961f0e71f3a9b524af6012062fe037a6",
            ),
            (
                b"password",
                b"salt",
                2,
                20,
                "ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957",
            ),
            (
                b"password",
                b"salt",
                4096,
                20,
                "4b007901b765489abead49d926f721d065a429c1",
            ),
            (
                b"passwordPASSWORDpassword",
                b"saltSALTsaltSALTsaltSALTsaltSALTsalt",
                4096,
                25,
                "3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038",
            ),
            (
                b"pass\0word",
                b"sa\0lt",
                4096,
                16,
                "56fa6aa75548099dcc37d7f03425e0c3",
            ),
        ];
        for (password, salt, iterations, len, expected) in sha1 {
            let got = derived::<Sha1>(password, salt, iterations, len);
            assert_eq!(got, expected, "RFC 6070, {iterations} iterations");
        }

        // RFC 7914 section 11.
        let sha256 = [
            (
                &b"passwd"[..],
                &b"salt"[..],
                1,
                "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc\
                 49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783",
            ),
            (
                b"Password",
                b"NaCl",
                80000,
                "4ddcd8f60b98be21830cee5ef22701f9641a4418d04c0414aeff08876b34ab56\
                 a1d425a1225833549adb841b51c9b3176a272bdebba1d078478f62b397f33c8d",
            ),
        ];
        for (password, salt, iterations, expected) in sha256 {
            let got = derived::<Sha256>(password, salt, iterations, 64);
            assert_eq!(got, expected, "RFC 7914, {iterations} iterations");
        }
    }

    /// Project Wycheproof's PBKDF2 vectors for SHA-1, SHA-224, SHA-256, SHA-384
    /// and SHA-512 (the selection in `testdata/vectors.txt`).
    #[test]
    fn wycheproof() {
        assert_eq!(check_set("wycheproof"), 59);
    }

    /// All eight hashes at the lengths where an implementation can go wrong.
    // The vectors come from Python's hashlib, Go's crypto/pbkdf2 and OpenSSL
    // 3.6, which agree.
    #[test]
    fn all_hashes_at_the_boundaries() {
        assert_eq!(check_set("cross"), 8 * (6 + 9 + 7 + 5));
    }

    /// The block number is a 32-bit big-endian integer (RFC 8018 section 5.2):
    /// 65,538 blocks make the counter use all of its bytes but the first, which
    /// a one-byte, 16-bit or little-endian counter does not survive. Digests of
    /// the whole output, from the same three implementations.
    #[test]
    fn block_counter() {
        fn digest_of_output<D: Digest>(blocks: usize) -> String {
            let mut dk = vec![0; blocks * D::OUTPUT_LEN];
            derive::<D>(b"password", b"salt", 1, &mut dk).unwrap();
            Sha256::hex_digest(&dk)
        }
        assert_eq!(
            digest_of_output::<Sha256>(65538),
            "f299c79e19a2629baf5677e04ae5e5b0c597d6a7d3f9be93b2845a1da13a7bd3"
        );
        assert_eq!(
            digest_of_output::<Sha1>(65538),
            "f8abbc832f8c7b489e3f946430da31581a71ca2ad44c1e1cccfc06e7f4b9c290"
        );
    }

    /// The first step of each chain that the throughput test (and `bench/pbkdf2cmp`)
    /// times: the password is the hash's output length counting up from zero,
    /// the salt 16 bytes counting up from zero, and the key one output of the
    /// hash. From Python's hashlib and OpenSSL 3.6, which agree.
    #[test]
    fn benchmark_inputs_have_the_known_answers() {
        fn check<D: Digest>(name: &str, expected: [&str; 2]) {
            let password: Vec<u8> = (0..D::OUTPUT_LEN as u8).collect();
            let salt: Vec<u8> = (0..16).collect();
            for (iterations, expected) in [1, 100_000].into_iter().zip(expected) {
                let got = derived::<D>(&password, &salt, iterations, D::OUTPUT_LEN);
                assert_eq!(got, expected, "{name}, {iterations} iterations");
            }
        }
        check::<Sha1>(
            "SHA-1",
            [
                "d3c2bc6bba9ac36b41d4481e3d8ca7e5fc11c4e0",
                "a284998ce9e51d7f74a3723d0fd561ddbc9e8f89",
            ],
        );
        check::<Sha256>(
            "SHA-256",
            [
                "2daef9c73f5ce29c2a48a1cd2554c459fa9410539bdda2983e53090683e8182b",
                "69c3e3ff3a7669afd1a0cb1986cec67e9ad23ef6110cc4da74f9d366e690bd1c",
            ],
        );
        check::<Sha512>(
            "SHA-512",
            [
                "884e89d142973182656d441fb521b3b1f527c408c06cb2671899bf71889288974e936b1bb277\
                 632dcfe70e5b6374119d0f1a68987d46eea9b24e77dd6fe211eb",
                "e8d825502a21b2fd43fb3afef897277df37630cff78defabe8cd0807d612da730f318d97ab40\
                 e4d55669d0c79152b85d01d31dd8fb2113fc66ab56c0949a0862",
            ],
        );
    }

    /// No iterations and no key are refused, and the buffer is left as it was.
    #[test]
    fn invalid_inputs_are_refused() {
        let mut dk = [0xa5; 32];
        assert_eq!(
            derive::<Sha256>(b"password", b"salt", 0, &mut dk),
            Err(Error::InvalidIterations)
        );
        assert_eq!(dk, [0xa5; 32]);
        assert_eq!(
            derive::<Sha256>(b"password", b"salt", 1, &mut []),
            Err(Error::InvalidLength)
        );
        // Zero iterations are reported first, whatever the buffer is.
        assert_eq!(
            derive::<Sha256>(b"password", b"salt", 0, &mut []),
            Err(Error::InvalidIterations)
        );
    }

    /// The longest key is `2^32 - 1` blocks, which no test can allocate; the
    /// rule that decides it is checked on the numbers.
    #[test]
    fn the_longest_key_is_two_to_the_32_minus_one_blocks() {
        let max = u64::from(u32::MAX);
        for hash_len in [16, 20, 28, 32, 48, 64] {
            assert!(!is_valid_output_len(0, hash_len));
            assert!(is_valid_output_len(1, hash_len));
            assert!(is_valid_output_len(hash_len, hash_len));
            assert!(is_valid_output_len(hash_len + 1, hash_len));
            assert!(is_valid_output_len(max * hash_len, hash_len), "{hash_len}");
            assert!(
                !is_valid_output_len(max * hash_len + 1, hash_len),
                "{hash_len}"
            );
        }
    }

    #[test]
    fn errors_say_what_went_wrong() {
        assert_eq!(
            Error::InvalidIterations.to_string(),
            "PBKDF2 iteration count is zero"
        );
        assert_eq!(
            Error::InvalidLength.to_string(),
            "PBKDF2 derived key is empty or longer than (2^32 - 1) times the hash length"
        );
    }

    #[test]
    #[ignore = "manual throughput check: cargo test --release pbkdf2:: -- --ignored --nocapture --test-threads=1"]
    fn throughput() {
        use std::hint::black_box;
        use std::time::Instant;

        /// Iterations of each long derivation, as a password hash would use.
        const ITERATIONS: u32 = 100_000;
        /// Long derivations per pass.
        const DERIVES: usize = 10;
        /// One-iteration derivations per pass.
        const SHORT_DERIVES: usize = 200_000;

        /// Runs `pass` once to warm up, then five times, and returns the best
        /// of the five in passes per second.
        fn best_rate(mut pass: impl FnMut()) -> f64 {
            // The first pass is slowed down by page faults and CPU clock
            // ramp-up, not just PBKDF2 itself, so it is not timed.
            pass();
            let mut best = 0.0f64;
            for _ in 0..5 {
                let start = Instant::now();
                pass();
                best = best.max(1.0 / start.elapsed().as_secs_f64());
            }
            best
        }

        fn run<D: Digest>(name: &str) {
            let salt: Vec<u8> = (0..16).collect();

            // A key of one output of the hash from a password of the same
            // length, many iterations. Each key is the password of the next
            // derivation, so the calls form one chain, and the last key
            // identifies the whole run.
            let mut key: Vec<u8> = (0..D::OUTPUT_LEN as u8).collect();
            let rate = best_rate(|| {
                for _ in 0..DERIVES {
                    let password = key.clone();
                    derive::<D>(black_box(&password), black_box(&salt), ITERATIONS, &mut key)
                        .unwrap();
                }
            });
            println!(
                "pbkdf2-{name} {ITERATIONS} iterations [cryptors]: {DERIVES} per pass, best \
                 {:.2} M iterations/s (last key {}...)",
                rate * (DERIVES as f64 * f64::from(ITERATIONS)) / 1e6,
                hex(&key[..8])
            );

            // One iteration, as when PBKDF2 only stretches a key a little: the
            // cost is the keying of HMAC and two of its calls.
            let mut key: Vec<u8> = (0..D::OUTPUT_LEN as u8).collect();
            let rate = best_rate(|| {
                for _ in 0..SHORT_DERIVES {
                    let password = key.clone();
                    derive::<D>(black_box(&password), black_box(&salt), 1, &mut key).unwrap();
                }
            });
            println!(
                "pbkdf2-{name} 1 iteration [cryptors]: {SHORT_DERIVES} per pass, best {:.0} ops/s \
                 (last key {}...)",
                rate * SHORT_DERIVES as f64,
                hex(&key[..8])
            );
        }

        run::<Sha1>("sha1");
        run::<Sha256>("sha256");
        run::<Sha512>("sha512");
    }
}
