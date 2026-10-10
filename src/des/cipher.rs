use core::fmt;

use super::scalar;
use super::schedule::{Schedule, key_schedule};
use crate::BlockCipher;

/// DES, the Data Encryption Algorithm of FIPS 46-3: a 64-bit block under a
/// 64-bit key, of which 56 bits count.
///
/// Holds the sixteen round keys, which are overwritten with zeros when the
/// value is dropped.
///
/// DES is broken for any use that matters, because its key is too short: see
/// the [module documentation](crate::des).
///
/// ```
/// use cryptors::{BlockCipher, des::Des};
///
/// // FIPS 81, the ECB example: the key 0123456789abcdef and the text "Now is t".
/// let key = [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];
/// let cipher = Des::new(&key);
///
/// let ciphertext = cipher.encrypt_block(b"Now is t");
/// assert_eq!(ciphertext, [0x3f, 0xa4, 0x0e, 0x8a, 0x98, 0x4d, 0x48, 0x15]);
/// assert_eq!(cipher.decrypt_block(&ciphertext), *b"Now is t");
/// ```
#[derive(Clone)]
pub struct Des {
    schedule: Schedule,
}

impl BlockCipher for Des {
    const BLOCK_LEN: usize = 8;
    const KEY_LEN: usize = 8;
    type Key = [u8; 8];
    type Block = [u8; 8];

    /// Builds the cipher, expanding `key` into the sixteen round keys.
    ///
    /// The last bit of every byte of the key is a parity bit, which the
    /// algorithm does not use: keys that differ only in those bits are the same
    /// key. Every other key is accepted, including the weak ones.
    fn new(key: &[u8; 8]) -> Self {
        Self {
            schedule: key_schedule(key),
        }
    }

    /// Encrypts one 8-byte block (`E_K` in FIPS 46-3).
    fn encrypt_block(&self, block: &[u8; 8]) -> [u8; 8] {
        scalar::encrypt(&self.schedule, block)
    }

    /// Decrypts one 8-byte block (`D_K`).
    fn decrypt_block(&self, block: &[u8; 8]) -> [u8; 8] {
        scalar::decrypt(&self.schedule, block)
    }
}

/// Shows the type and nothing else: the round keys are secret.
impl fmt::Debug for Des {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Des").finish_non_exhaustive()
    }
}

/// TDEA, the Triple Data Encryption Algorithm of FIPS 46-3 (also called Triple
/// DES or 3DES): three DES operations in a row, encrypt under `K1`, decrypt
/// under `K2`, encrypt under `K3`.
///
/// The key is the bundle `K1 || K2 || K3`, 24 bytes. The three keying options
/// of the standard are three kinds of bundle, and all are accepted:
///
/// | Keying option | Bundle | Effect |
/// |---------------|--------|--------|
/// | 1 | `K1`, `K2` and `K3` independent | the intended use |
/// | 2 | `K3 = K1` | "two-key" TDEA |
/// | 3 | `K1 = K2 = K3` | the same as single DES |
///
/// Option 3 is not Triple DES in any sense that matters, and option 2 is
/// weaker than option 1 (see the [module documentation](crate::des)); NIST no
/// longer allows either for protecting data.
///
/// Holds the three key schedules, which are overwritten with zeros when the
/// value is dropped.
///
/// ```
/// use cryptors::{BlockCipher, des::{Des, TripleDes}};
///
/// // K1 || K2 || K3.
/// let key = [
///     0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
///     0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01,
///     0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23,
/// ];
/// let cipher = TripleDes::new(&key);
///
/// let ciphertext = cipher.encrypt_block(b"The quic");
/// assert_eq!(ciphertext, [0x1c, 0xcf, 0x23, 0x86, 0x9d, 0x09, 0x33, 0x3e]);
/// assert_eq!(cipher.decrypt_block(&ciphertext), *b"The quic");
///
/// // It is the three DES operations of the standard, one after the other.
/// let [k1, k2, k3]: [[u8; 8]; 3] = [
///     key[..8].try_into().unwrap(),
///     key[8..16].try_into().unwrap(),
///     key[16..].try_into().unwrap(),
/// ];
/// let stage1 = Des::new(&k1).encrypt_block(b"The quic");
/// let stage2 = Des::new(&k2).decrypt_block(&stage1);
/// assert_eq!(Des::new(&k3).encrypt_block(&stage2), ciphertext);
/// ```
#[derive(Clone)]
pub struct TripleDes {
    schedules: [Schedule; 3],
}

impl BlockCipher for TripleDes {
    const BLOCK_LEN: usize = 8;
    const KEY_LEN: usize = 24;
    type Key = [u8; 24];
    type Block = [u8; 8];

    /// Builds the cipher from the key bundle `K1 || K2 || K3`, expanding each
    /// of the three keys.
    ///
    /// As in DES, the last bit of every byte of the key is a parity bit that is
    /// not used. Every bundle is accepted, whatever the relation between its
    /// keys.
    fn new(key: &[u8; 24]) -> Self {
        let (keys, _) = key.as_chunks::<8>();
        Self {
            schedules: core::array::from_fn(|i| key_schedule(&keys[i])),
        }
    }

    /// Encrypts one 8-byte block: the TDEA encryption operation,
    /// `E_K3(D_K2(E_K1(block)))`.
    fn encrypt_block(&self, block: &[u8; 8]) -> [u8; 8] {
        scalar::encrypt3(&self.schedules, block)
    }

    /// Decrypts one 8-byte block: the TDEA decryption operation,
    /// `D_K1(E_K2(D_K3(block)))`.
    fn decrypt_block(&self, block: &[u8; 8]) -> [u8; 8] {
        scalar::decrypt3(&self.schedules, block)
    }
}

/// Shows the type and nothing else: the round keys are secret.
impl fmt::Debug for TripleDes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TripleDes").finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Digest;
    use crate::des::reference;
    use crate::digest::hex;
    use crate::sha2::Sha256;

    /// Either cipher, picked by the length of the key: eight bytes are DES,
    /// twenty-four are the bundle of TDEA.
    enum Cipher {
        Des(Des),
        TripleDes(Box<TripleDes>),
    }

    impl Cipher {
        fn new(key: &[u8]) -> Self {
            match key.len() {
                8 => Cipher::Des(Des::new(key.try_into().unwrap())),
                24 => Cipher::TripleDes(Box::new(TripleDes::new(key.try_into().unwrap()))),
                n => panic!("no DES or TDEA key has {n} bytes"),
            }
        }

        fn encrypt(&self, block: &[u8; 8]) -> [u8; 8] {
            match self {
                Cipher::Des(cipher) => cipher.encrypt_block(block),
                Cipher::TripleDes(cipher) => cipher.encrypt_block(block),
            }
        }

        fn decrypt(&self, block: &[u8; 8]) -> [u8; 8] {
            match self {
                Cipher::Des(cipher) => cipher.decrypt_block(block),
                Cipher::TripleDes(cipher) => cipher.decrypt_block(block),
            }
        }
    }

    /// `len` bytes derived from `label` and `i`: the start of
    /// SHA-256(`label` || `i` as four big-endian bytes). Simple enough to
    /// reproduce in any language, which is how the expected values below were
    /// made.
    fn derive(label: &[u8], i: u32, len: usize) -> Vec<u8> {
        let mut input = label.to_vec();
        input.extend_from_slice(&i.to_be_bytes());
        Sha256::digest(&input)[..len].to_vec()
    }

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn block(s: &str) -> [u8; 8] {
        unhex(s).try_into().unwrap()
    }

    /// Known answers: (key, plaintext, ciphertext). A key of eight bytes is
    /// for DES, one of twenty-four for TDEA.
    ///
    /// The first five are published: FIPS 81 prints the ECB example of the
    /// first three (the text "Now is the time for all " under the key
    /// 0123456789abcdef), and the next two are the first entries of the
    /// variable-plaintext and variable-key tests that NIST's validation program
    /// uses (the files `TECBvartext` and `TECBvarkey`). The rest, and all the TDEA
    /// ones, come from two independent implementations, which agree.
    const KNOWN_ANSWERS: [(&str, &str, &str); 13] = [
        ("0123456789abcdef", "4e6f772069732074", "3fa40e8a984d4815"),
        ("0123456789abcdef", "68652074696d6520", "6a271787ab8883f9"),
        ("0123456789abcdef", "666f7220616c6c20", "893d51ec4b563b53"),
        ("0101010101010101", "8000000000000000", "95f8a5e5dd31d900"),
        ("8001010101010101", "0000000000000000", "95a8d72813daa94d"),
        ("133457799bbcdff1", "0123456789abcdef", "85e813540f0ab405"),
        ("0000000000000000", "0000000000000000", "8ca64de9c1b123a7"),
        ("ffffffffffffffff", "ffffffffffffffff", "7359b2163e4edc58"),
        ("fedcba9876543210", "0123456789abcdef", "ed39d950fa74bcc4"),
        // Three independent keys.
        (
            "0123456789abcdef23456789abcdef01456789abcdef0123",
            "5468652071756963",
            "1ccf23869d09333e",
        ),
        (
            "0123456789abcdeffedcba98765432100011223344556677",
            "ffffffffffffffff",
            "8107de90011c63b2",
        ),
        // Keying option 2 (K3 = K1).
        (
            "0123456789abcdef23456789abcdef010123456789abcdef",
            "6b2062726f776e20",
            "9077d0909fa91b88",
        ),
        // Keying option 3 (K1 = K2 = K3): the same as the DES row for this key.
        (
            "133457799bbcdff1133457799bbcdff1133457799bbcdff1",
            "0123456789abcdef",
            "85e813540f0ab405",
        ),
    ];

    /// Encrypting `0011223344556677` a thousand times in a row, each time on
    /// the previous ciphertext, under the key `00 01 02 ...`: (key length,
    /// ciphertext), from two independent implementations, which agree.
    const CHAINED: [(usize, &str); 2] = [(8, "12535cb0f77ee77c"), (24, "e3598176850e736f")];

    /// SHA-256 of the 1000 ciphertexts of `block(i)` under `key(i)`, for
    /// `key(i) = derive("key", i)` and `block(i) = derive("block", i)`: (key
    /// length, digest), from the same two implementations.
    const MANY_KEYS: [(usize, &str); 2] = [
        (
            8,
            "1e7fff38e474c9af2f3c3415bfbce7db2fdb640b8218d42e609aca7c4b6b3932",
        ),
        (
            24,
            "c80a9099f02324a2a4441157b6d302dc14588ab300ec6f5c44f29296c4eb200a",
        ),
    ];

    #[test]
    fn known_answers() {
        for (key, plaintext, ciphertext) in KNOWN_ANSWERS {
            let cipher = Cipher::new(&unhex(key));
            let (plaintext, ciphertext) = (block(plaintext), block(ciphertext));
            let what = format!("key {key}, block {plaintext:02x?}");
            assert_eq!(cipher.encrypt(&plaintext), ciphertext, "{what}");
            assert_eq!(cipher.decrypt(&ciphertext), plaintext, "{what}");
        }
    }

    #[test]
    fn chained() {
        // 1000 encryptions, each on the previous one's output: a mistake in
        // one table entry that a single block happens to dodge does not
        // survive this.
        let start = block("0011223344556677");
        for (key_len, expected) in CHAINED {
            let cipher = Cipher::new(&(0..key_len as u8).collect::<Vec<_>>());

            let mut state = start;
            for _ in 0..1000 {
                state = cipher.encrypt(&state);
            }
            assert_eq!(hex(&state), expected, "{key_len}-byte key");

            for _ in 0..1000 {
                state = cipher.decrypt(&state);
            }
            assert_eq!(state, start, "{key_len}-byte key, decrypting back");
        }
    }

    #[test]
    fn many_keys() {
        // A thousand different keys per size, which is what exercises the key
        // schedule: the published vectors only have a handful.
        for (key_len, expected) in MANY_KEYS {
            let mut ciphertexts = Vec::new();
            for i in 0..1000 {
                let cipher = Cipher::new(&derive(b"key", i, key_len));
                let plaintext: [u8; 8] = derive(b"block", i, 8).try_into().unwrap();
                let ciphertext = cipher.encrypt(&plaintext);
                assert_eq!(
                    cipher.decrypt(&ciphertext),
                    plaintext,
                    "{key_len}-byte key, i = {i}, decrypting back"
                );
                ciphertexts.extend_from_slice(&ciphertext);
            }
            assert_eq!(
                hex(&Sha256::digest(&ciphertexts)),
                expected,
                "{key_len}-byte keys"
            );
        }
    }

    /// Checks DES against `reference`, the naive implementation written from
    /// the text of the standard: the round keys and the blocks, in both
    /// directions.
    ///
    /// The real one never forms the permutations `IP`, `IP^-1` and `E`, which
    /// is why it needs an independent check on keys and blocks no list of known
    /// answers covers.
    #[test]
    fn matches_reference() {
        let mut keys: Vec<[u8; 8]> = (0..256)
            .map(|i| derive(b"differential key", i, 8).try_into().unwrap())
            .collect();
        keys.push([0; 8]);
        keys.push([0xff; 8]);

        for (i, key) in keys.iter().enumerate() {
            let cipher = Des::new(key);
            let expected = reference::subkeys(key);
            for (n, round_key) in cipher.schedule.keys.iter().enumerate() {
                assert_eq!(
                    reference::unpack(round_key),
                    expected[n],
                    "round key {}, key {key:02x?}",
                    n + 1
                );
            }

            let input: [u8; 8] = derive(b"differential block", i as u32, 8)
                .try_into()
                .unwrap();
            for input in [input, [0; 8], [0xff; 8]] {
                assert_eq!(
                    cipher.encrypt_block(&input),
                    reference::crypt(&input, &expected, false),
                    "encrypting {input:02x?} under {key:02x?}"
                );
                assert_eq!(
                    cipher.decrypt_block(&input),
                    reference::crypt(&input, &expected, true),
                    "decrypting {input:02x?} under {key:02x?}"
                );
            }
        }
    }

    /// Checks that TDEA is what the standard defines it to be -- three DES
    /// operations in a row -- for every kind of key bundle. The single-block
    /// path skips the permutations between the stages, and this is what checks
    /// that it may.
    #[test]
    fn triple_des_is_three_des() {
        fn key(i: u32, label: &[u8]) -> [u8; 8] {
            derive(label, i, 8).try_into().unwrap()
        }

        for i in 0..256 {
            let (k1, k2, k3) = (key(i, b"k1"), key(i, b"k2"), key(i, b"k3"));
            let input: [u8; 8] = derive(b"triple block", i, 8).try_into().unwrap();

            // The three keying options.
            for (k1, k2, k3) in [(k1, k2, k3), (k1, k2, k1), (k1, k1, k1)] {
                let bundle = [k1, k2, k3].concat();
                let cipher = TripleDes::new(bundle.as_slice().try_into().unwrap());
                let (d1, d2, d3) = (Des::new(&k1), Des::new(&k2), Des::new(&k3));

                let encrypted = d3.encrypt_block(&d2.decrypt_block(&d1.encrypt_block(&input)));
                assert_eq!(
                    cipher.encrypt_block(&input),
                    encrypted,
                    "encrypting, i = {i}"
                );

                let decrypted = d1.decrypt_block(&d2.encrypt_block(&d3.decrypt_block(&input)));
                assert_eq!(
                    cipher.decrypt_block(&input),
                    decrypted,
                    "decrypting, i = {i}"
                );
            }

            // Keying option 3 is single DES.
            let triple = TripleDes::new(&[k1, k1, k1].concat().try_into().unwrap());
            assert_eq!(
                triple.encrypt_block(&input),
                Des::new(&k1).encrypt_block(&input),
                "option 3, i = {i}"
            );
        }
    }

    /// The last bit of every byte of a key is not used by the algorithm
    /// (FIPS 46-3): changing it must not change anything.
    #[test]
    fn parity_bits_are_ignored() {
        for (key_len, label) in [(8, &b"parity des"[..]), (24, &b"parity tdea"[..])] {
            let key = derive(label, 0, key_len);
            let input: [u8; 8] = derive(b"parity block", 0, 8).try_into().unwrap();
            let expected = Cipher::new(&key).encrypt(&input);

            // Every byte in turn, and then all of them at once.
            let mut variants: Vec<Vec<u8>> = (0..key_len)
                .map(|i| {
                    let mut other = key.clone();
                    other[i] ^= 1;
                    other
                })
                .collect();
            variants.push(key.iter().map(|byte| byte ^ 1).collect());

            for other in variants {
                assert_ne!(other, key);
                assert_eq!(Cipher::new(&other).encrypt(&input), expected);
            }
        }
    }

    /// Dropping a schedule must leave no round key behind.
    #[test]
    fn dropping_wipes_the_round_keys() {
        use core::mem::{MaybeUninit, size_of};

        let mut slot = MaybeUninit::new(key_schedule(&[0x42; 8]));
        // One raw pointer does the dropping and the reading, so that the drop
        // does not invalidate the pointer the reads go through.
        let schedule = slot.as_mut_ptr();
        let bytes = schedule.cast::<u8>();
        // A schedule is nothing but words, so reading it as `size_of` bytes
        // reads every one of them.
        let read = || -> Vec<u8> {
            (0..size_of::<Schedule>())
                // SAFETY: the slot is alive and every byte of it was written,
                // first by `key_schedule` and then, if the drop works, by `wipe`.
                .map(|i| unsafe { bytes.add(i).read() })
                .collect()
        };
        assert!(read().iter().any(|&b| b != 0), "no round keys to wipe");

        // SAFETY: the slot holds an initialised schedule, dropped only here.
        unsafe { schedule.drop_in_place() };
        assert!(
            read().iter().all(|&b| b == 0),
            "round keys survive the drop"
        );
    }

    /// The Debug output must not show the round keys.
    #[test]
    fn debug_hides_the_key() {
        assert_eq!(format!("{:?}", Des::new(&[0xab; 8])), "Des { .. }");
        assert_eq!(
            format!("{:?}", TripleDes::new(&[0xab; 24])),
            "TripleDes { .. }"
        );
    }

    #[test]
    #[ignore = "manual throughput check: cargo test --release des:: -- --ignored --nocapture --test-threads=1"]
    fn throughput() {
        use std::time::Instant;

        const LEN: usize = 32 * 1024 * 1024;
        let mib = LEN as f64 / (1024.0 * 1024.0);

        // A fixed input: block `i` starts the byte pattern at `8 * i`. The
        // data is transformed in place and the passes are not undone, so what
        // is printed at the end identifies the whole run. It is the same for
        // any other correct implementation run the same way.
        let pattern: Vec<u8> = (0..LEN).map(|i| (i % 251) as u8).collect();

        /// Runs `pass` over a fresh copy of the pattern: once to warm up, then
        /// five times, keeping the best rate.
        fn time(label: &str, pattern: &[u8], mib: f64, mut pass: impl FnMut(&mut [[u8; 8]])) {
            // The first pass over a fresh buffer is slowed down by page faults
            // and CPU clock ramp-up, not just the cipher itself, so it is not
            // timed.
            let mut data = pattern.to_vec();
            let blocks = data.as_chunks_mut::<8>().0;
            pass(blocks);

            let mut best = 0.0f64;
            for _ in 0..5 {
                let start = Instant::now();
                pass(blocks);
                best = best.max(mib / start.elapsed().as_secs_f64());
            }
            println!(
                "{label}: {mib:.0} MiB, best {best:.1} MiB/s (first block {}...)",
                hex(&blocks[0])
            );
        }

        /// Times both directions of `C` under the key `00 01 02 ...`, through
        /// exactly the public API's path: one call per block.
        fn run<C: BlockCipher<Block = [u8; 8]>>(
            name: &str,
            key: &C::Key,
            pattern: &[u8],
            mib: f64,
        ) {
            let cipher = C::new(key);
            time(&format!("{name} encrypt"), pattern, mib, |blocks| {
                for block in blocks {
                    *block = cipher.encrypt_block(block);
                }
            });
            time(&format!("{name} decrypt"), pattern, mib, |blocks| {
                for block in blocks {
                    *block = cipher.decrypt_block(block);
                }
            });
        }

        run::<Des>("des", &core::array::from_fn(|i| i as u8), &pattern, mib);
        run::<TripleDes>("tdea", &core::array::from_fn(|i| i as u8), &pattern, mib);
    }
}
