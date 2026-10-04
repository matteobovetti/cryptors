/// Initial hash state for SHA-224: the second 32 bits of the fractional parts
/// of the square roots of the 9th through 16th primes (FIPS 180-4 section 5.3.2).
const INIT_224: [u32; 8] = [
    0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939, 0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4,
];

/// Initial hash state for SHA-256: the first 32 bits of the fractional parts
/// of the square roots of the first eight primes (FIPS 180-4 section 5.3.3).
const INIT_256: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

/// Round constants: the first 32 bits of the fractional parts of the cube
/// roots of the first 64 primes (FIPS 180-4 section 4.2.2).
pub(super) const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

#[cfg(target_arch = "aarch64")]
#[inline]
fn has_hw_sha256() -> bool {
    // On targets where `sha2` is part of the baseline the first half is
    // true at compile time, so the runtime check is skipped entirely.
    cfg!(target_feature = "sha2") || std::arch::is_aarch64_feature_detected!("sha2")
}

#[cfg(target_arch = "x86_64")]
#[inline]
fn has_hw_sha256() -> bool {
    std::arch::is_x86_feature_detected!("sha")
        && std::arch::is_x86_feature_detected!("ssse3")
        && std::arch::is_x86_feature_detected!("sse4.1")
}

#[cfg(target_arch = "x86_64")]
#[inline]
fn has_avx2_bmi() -> bool {
    std::arch::is_x86_feature_detected!("avx2") && has_bmi()
}

#[cfg(target_arch = "x86_64")]
#[inline]
fn has_bmi() -> bool {
    // On a target that already has both in its baseline (`-C target-cpu=x86-64-v3`,
    // for instance) this folds away at compile time.
    (cfg!(target_feature = "bmi1") && cfg!(target_feature = "bmi2"))
        || (std::arch::is_x86_feature_detected!("bmi1")
            && std::arch::is_x86_feature_detected!("bmi2"))
}

/// Hashes every full 64-byte block in `blocks` into `state`, picking the
/// fastest backend the CPU supports.
///
/// We check which backend to use once per call, not once per block, so the
/// hardware backends only need to set up once per message instead of once
/// per block.
#[inline]
fn compress(state: &mut [u32; 8], blocks: &[u8]) {
    #[cfg(target_arch = "aarch64")]
    if has_hw_sha256() {
        // SAFETY: has_hw_sha256() just confirmed the `sha2` feature is available.
        unsafe { super::aarch64::compress(state, blocks) };
        return;
    }

    #[cfg(target_arch = "x86_64")]
    if has_hw_sha256() {
        // SAFETY: has_hw_sha256() just confirmed `sha`, `ssse3` and `sse4.1` are available.
        unsafe { super::x86::compress(state, blocks) };
        return;
    }

    #[cfg(target_arch = "x86_64")]
    if has_avx2_bmi() {
        // SAFETY: has_avx2_bmi() just confirmed `avx2`, `bmi1` and `bmi2` are available.
        unsafe { super::x86_avx2::compress(state, blocks) };
        return;
    }

    #[cfg(target_arch = "x86_64")]
    if has_bmi() {
        // SAFETY: has_bmi() just confirmed the `bmi1` and `bmi2` features.
        unsafe { super::scalar::compress_bmi(state, blocks) };
        return;
    }

    super::scalar::compress(state, blocks);
}

/// Computes the 224-bit SHA-224 digest of `input`.
///
/// Full blocks are hashed straight out of `input` without copying; only the
/// last partial block (plus padding) is copied onto the stack.
pub fn sha224(input: &[u8]) -> [u8; 28] {
    to_bytes(&hash_with(compress, INIT_224, input))
}

/// Computes the 256-bit SHA-256 digest of `input`.
///
/// Full blocks are hashed straight out of `input` without copying; only the
/// last partial block (plus padding) is copied onto the stack.
pub fn sha256(input: &[u8]) -> [u8; 32] {
    to_bytes(&hash_with(compress, INIT_256, input))
}

/// Pads `input`, runs every block through `compress_fn` starting from the
/// initial state `init`, and returns the final state. SHA-224 and SHA-256
/// differ only in `init` and in how much of this state they output.
///
/// Takes the backend as a parameter so tests can force a specific one; the
/// public functions always call this with the auto-selected `compress`, so it
/// costs nothing in the normal case.
#[inline]
fn hash_with<F: FnMut(&mut [u32; 8], &[u8])>(
    mut compress_fn: F,
    init: [u32; 8],
    input: &[u8],
) -> [u32; 8] {
    let mut state = init;

    let aligned = input.len() & !63;
    compress_fn(&mut state, &input[..aligned]);
    let remainder = &input[aligned..];

    // The leftover bytes plus the required padding (a 0x80 marker byte and
    // an 8-byte length) never need more than one extra 64-byte block.
    let mut tail = [0u8; 128];
    tail[..remainder.len()].copy_from_slice(remainder);
    tail[remainder.len()] = 0x80;

    let bit_len = (input.len() as u64).wrapping_mul(8);
    let total_len = if remainder.len() < 56 { 64 } else { 128 };
    tail[total_len - 8..total_len].copy_from_slice(&bit_len.to_be_bytes());

    compress_fn(&mut state, &tail[..total_len]);
    state
}

/// Writes the leading `N / 4` words of `state` out big-endian: all eight for
/// SHA-256 (`N` = 32), the first seven for SHA-224 (`N` = 28).
fn to_bytes<const N: usize>(state: &[u32; 8]) -> [u8; N] {
    const { assert!(N.is_multiple_of(4) && N <= 32) };

    let mut out = [0u8; N];
    for (word, chunk) in state.iter().zip(out.chunks_exact_mut(4)) {
        chunk.copy_from_slice(&word.to_be_bytes());
    }
    out
}

const HEX: &[u8; 16] = b"0123456789abcdef";

/// Renders `bytes` as lowercase hex.
fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(char::from(HEX[(b >> 4) as usize]));
        out.push(char::from(HEX[(b & 0xf) as usize]));
    }
    out
}

/// Computes the SHA-224 digest of `input` and renders it as lowercase hex.
pub fn sha224_hex(input: &[u8]) -> String {
    hex(&sha224(input))
}

/// Computes the SHA-256 digest of `input` and renders it as lowercase hex.
pub fn sha256_hex(input: &[u8]) -> String {
    hex(&sha256(input))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sha256::scalar;

    /// A backend's compression function, callable like `scalar::compress`.
    type Backend = fn(&mut [u32; 8], &[u8]);

    /// Every backend this CPU can run, named, in the order `compress` prefers
    /// them: the first entry is the one the public functions use, and the
    /// last is always `scalar`.
    ///
    /// The hardware backends are `unsafe` to call because they need a CPU
    /// feature. Each is wrapped in a safe function pointer here, and only
    /// added to the list after that feature has been confirmed, so every
    /// entry is safe to call on this machine.
    fn backends() -> Vec<(&'static str, Backend)> {
        let mut list: Vec<(&'static str, Backend)> = Vec::new();

        #[cfg(target_arch = "aarch64")]
        if has_hw_sha256() {
            // SAFETY: has_hw_sha256() just confirmed the `sha2` feature is available.
            list.push(("aarch64 (FEAT_SHA256)", |s, b| unsafe {
                crate::sha256::aarch64::compress(s, b)
            }));
        }

        #[cfg(target_arch = "x86_64")]
        if has_hw_sha256() {
            // SAFETY: has_hw_sha256() just confirmed `sha`, `ssse3` and `sse4.1` are available.
            list.push(("x86_64 (SHA-NI)", |s, b| unsafe {
                crate::sha256::x86::compress(s, b)
            }));
        }

        #[cfg(target_arch = "x86_64")]
        if has_avx2_bmi() {
            // SAFETY: has_avx2_bmi() just confirmed `avx2`, `bmi1` and `bmi2` are available.
            list.push(("x86_64 (AVX2+BMI2)", |s, b| unsafe {
                crate::sha256::x86_avx2::compress(s, b)
            }));
        }

        #[cfg(target_arch = "x86_64")]
        if has_bmi() {
            // SAFETY: has_bmi() just confirmed the `bmi1` and `bmi2` features.
            list.push(("scalar (BMI1+BMI2)", |s, b| unsafe {
                scalar::compress_bmi(s, b)
            }));
        }

        list.push(("scalar", scalar::compress));
        list
    }

    /// Which backend `compress` picks on this machine.
    fn active_backend() -> &'static str {
        backends()[0].0
    }

    /// Message lengths around every point where the padding layout changes
    /// (a partial block of 55 bytes is the last that leaves room for the
    /// marker and length; 56 forces a second block) plus a few larger sizes
    /// that run the main loop of a backend for many blocks.
    const LENGTHS: [usize; 32] = [
        0, 1, 55, 56, 57, 63, 64, 65, 119, 120, 121, 127, 128, 129, 191, 192, 193, 200, 255, 256,
        257, 511, 512, 513, 1023, 1024, 1025, 4096, 4097, 65536, 65537, 100_000,
    ];

    /// A deterministic input that does not repeat within a block, so a
    /// backend that confuses two words of the message cannot go unnoticed.
    fn pattern(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i % 251) as u8).collect()
    }

    /// Known-answer vectors: (message, SHA-224, SHA-256).
    ///
    /// The empty message, "abc" (one block) and the 448-bit message (whose
    /// padding spills into a second block) are the example messages NIST
    /// publishes for FIPS 180-4; the third example, a million repetitions of
    /// "a", is `MILLION_A_*` below. The last two are common extra checks.
    const VECTORS: [(&[u8], &str, &str); 5] = [
        (
            b"",
            "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f",
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        ),
        (
            b"abc",
            "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7",
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        ),
        (
            b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
            "75388b16512776cc5dba5da1fd890150b0c6455cb4f58b1952522525",
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
        ),
        (
            b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
            "c97ca9a559850ce97a04a96def6d99a9e0e0e2ab14e6b8df265fc0b3",
            "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1",
        ),
        (
            b"The quick brown fox jumps over the lazy dog",
            "730e109bd7a8a32b1cb9d9a09aa2325d2430587ddbc0c38bad911525",
            "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592",
        ),
    ];

    const MILLION_A_224: &str = "20794655980c91d8bbb4c1ea97618a4bf03f42581948b2ee4ee7ad67";
    const MILLION_A_256: &str = "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0";

    /// Digests of `pattern(len)` for lengths at the padding boundaries, as
    /// computed by an independent SHA-2 implementation (OpenSSL): (length,
    /// SHA-224, SHA-256).
    const PATTERN_DIGESTS: [(usize, &str, &str); 16] = [
        (
            1,
            "fff9292b4201617bdc4d3053fce02734166a683d7d858a7f5f59b073",
            "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
        ),
        (
            55,
            "8991dfba74284e04dc7581c7c3e4068ff6cb7a63733361429834bb56",
            "463eb28e72f82e0a96c0a4cc53690c571281131f672aa229e0d45ae59b598b59",
        ),
        (
            56,
            "2b2cd637c16ad7290bb067ad7d8fd04e204fa43a84366afc7130f4ef",
            "da2ae4d6b36748f2a318f23e7ab1dfdf45acdc9d049bd80e59de82a60895f562",
        ),
        (
            57,
            "e87f5bc938c3b981c197d4b163c635a5049fac81c4c6467e1251be48",
            "2fe741af801cc238602ac0ec6a7b0c3a8a87c7fc7d7f02a3fe03d1c12eac4d8f",
        ),
        (
            63,
            "049e8dd7eab3378ce9f823bfb569e5b270235d4b7f9623606971998f",
            "29af2686fd53374a36b0846694cc342177e428d1647515f078784d69cdb9e488",
        ),
        (
            64,
            "c37b88a3522dbf7ac30d1c68ea397ac11d4773571aed01ddab73531e",
            "fdeab9acf3710362bd2658cdc9a29e8f9c757fcf9811603a8c447cd1d9151108",
        ),
        (
            65,
            "114b5fd665736a96585c5d5837d35250aed73c725252cbf7f8b121f6",
            "4bfd2c8b6f1eec7a2afeb48b934ee4b2694182027e6d0fc075074f2fabb31781",
        ),
        (
            119,
            "762f18c0df65c3d0ea64126c8a6e51db4425e76d4d969ed0f83899be",
            "da18797ed7c3a777f0847f429724a2d8cd5138e6ed2895c3fa1a6d39d18f7ec6",
        ),
        (
            120,
            "d022deb78772a77e8b91d68f90ca1f636e8fe047ae219434ced18eef",
            "f52b23db1fbb6ded89ef42a23ce0c8922c45f25c50b568a93bf1c075420bbb7c",
        ),
        (
            121,
            "a802d8b618a503352cdbcc1fbef04ea36499ea72d0e32d314caf83e5",
            "335a461692b30bba1d647cc71604e88e676c90e4c22455d0b8c83f4bd7c8ac9b",
        ),
        (
            127,
            "554c9c3f7e92b80f4121e00cc147535d377eaeb4fb1fa8e25c7f81c1",
            "92ca0fa6651ee2f97b884b7246a562fa71250fedefe5ebf270d31c546bfea976",
        ),
        (
            128,
            "67d88da33fd632d8742424791dface672ff59d597fe38b3f2a998386",
            "471fb943aa23c511f6f72f8d1652d9c880cfa392ad80503120547703e56a2be5",
        ),
        (
            129,
            "a80cb91e08a62f062bd17db00d0e1979d041edeb52b497b205266b9c",
            "5099c6a56203f9687f7d33f4bfdf576d31dc91f6b695ecea38b2770c87631135",
        ),
        (
            191,
            "738dc8e738d4d1e866e30a7946d2e241ce2fe5d2c9bbe82ee8a6a543",
            "d280f473c251cb75c91880ea0eca2a2f1cda3152bef54a38c4a3aedad615c819",
        ),
        (
            192,
            "f36432272b487ddfa019fa20b82cf8b69c9d6ed07b93ce5f55e99a1c",
            "8b4a544837a1a0280fa8a7c82865c27a1064b3cc6281fda0753566b9bb104a87",
        ),
        (
            193,
            "6e010c13db7a0ea4b87845d8d03eb9e3af891f0890451809938b7d57",
            "7daafa7aed7d63d06a98b7b6f785eab5427d084f30d5c9ee6dd0d2f3ada329e6",
        ),
    ];

    #[test]
    fn sha256_known_answers() {
        for (input, _, expected) in VECTORS {
            assert_eq!(sha256_hex(input), expected, "input = {input:?}");
        }
    }

    #[test]
    fn sha224_known_answers() {
        for (input, expected, _) in VECTORS {
            assert_eq!(sha224_hex(input), expected, "input = {input:?}");
        }
    }

    #[test]
    fn million_a() {
        // The third NIST example message: 1,000,000 repetitions of 'a'. It is
        // the only known-answer input big enough (15,625 blocks) to make a
        // backend's main loop run for long.
        let input = vec![b'a'; 1_000_000];
        assert_eq!(sha256_hex(&input), MILLION_A_256);
        assert_eq!(sha224_hex(&input), MILLION_A_224);
    }

    #[test]
    fn padding_boundaries() {
        for (len, sha224_expected, sha256_expected) in PATTERN_DIGESTS {
            let input = pattern(len);
            assert_eq!(sha224_hex(&input), sha224_expected, "SHA-224, len = {len}");
            assert_eq!(sha256_hex(&input), sha256_expected, "SHA-256, len = {len}");
        }
    }

    #[test]
    fn output_shape() {
        let input = b"abc";
        assert_eq!(sha224(input).len(), 28);
        assert_eq!(sha256(input).len(), 32);
        assert_eq!(sha224_hex(input).len(), 56);
        assert_eq!(sha256_hex(input).len(), 64);
        assert!(
            sha256_hex(input)
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
            "hex output must be lowercase"
        );
    }

    #[test]
    fn sha224_is_not_truncated_sha256() {
        // SHA-224 has its own initial state, so its digest is not simply the
        // first 28 bytes of the SHA-256 digest.
        let input = b"abc";
        assert_ne!(sha224(input)[..], sha256(input)[..28]);
    }

    /// Checks that every other backend this CPU can run produces exactly the
    /// same digest as the scalar backend.
    ///
    /// This calls each backend directly instead of going through `compress`,
    /// so the test can't accidentally end up comparing the scalar backend
    /// against itself. Backends the CPU doesn't support are not in
    /// `backends()`, so their part of the test is just skipped.
    #[test]
    fn matches_scalar_backend() {
        let others: Vec<_> = backends()
            .into_iter()
            .filter(|&(name, _)| name != "scalar")
            .collect();

        for (name, backend) in &others {
            for init in [INIT_224, INIT_256] {
                for len in LENGTHS {
                    let input = pattern(len);
                    assert_eq!(
                        hash_with(backend, init, &input),
                        hash_with(scalar::compress, init, &input),
                        "{name} backend disagrees with scalar at len = {len}"
                    );
                }
            }
            println!("{name} backend matches scalar");
        }

        if others.is_empty() {
            println!("no hardware SHA-256 backend on this CPU; only the scalar path is in use");
        }
    }

    /// Checks that the digest does not depend on where in memory the message
    /// starts. The hardware backends read it with unaligned vector loads, and
    /// that is only correct if they never assume an alignment.
    #[test]
    fn unaligned_input() {
        // Five full blocks and a partial one, starting at every offset in
        // the first 64 bytes of the buffer.
        let len = 64 * 5 + 7;
        let backing = pattern(64 + len);
        for offset in 0..64 {
            let input = &backing[offset..offset + len];
            assert_eq!(
                sha256(input),
                to_bytes::<32>(&hash_with(scalar::compress, INIT_256, input)),
                "SHA-256, offset = {offset}"
            );
            assert_eq!(
                sha224(input),
                to_bytes::<28>(&hash_with(scalar::compress, INIT_224, input)),
                "SHA-224, offset = {offset}"
            );
        }
    }

    /// Checks the known-answer vectors against the scalar backend specifically.
    ///
    /// Every other test above goes through the public functions, which skip
    /// `scalar` on a machine with hardware SHA-256. Without this test, the
    /// scalar backend would never actually get checked on such a machine.
    #[test]
    fn scalar_known_answers() {
        for (input, sha224_expected, sha256_expected) in VECTORS {
            let sha224 = hex(&to_bytes::<28>(&hash_with(
                scalar::compress,
                INIT_224,
                input,
            )));
            let sha256 = hex(&to_bytes::<32>(&hash_with(
                scalar::compress,
                INIT_256,
                input,
            )));
            assert_eq!(sha224, sha224_expected, "SHA-224, input = {input:?}");
            assert_eq!(sha256, sha256_expected, "SHA-256, input = {input:?}");
        }

        let million = vec![b'a'; 1_000_000];
        let sha224 = hex(&to_bytes::<28>(&hash_with(
            scalar::compress,
            INIT_224,
            &million,
        )));
        let sha256 = hex(&to_bytes::<32>(&hash_with(
            scalar::compress,
            INIT_256,
            &million,
        )));
        assert_eq!(sha224, MILLION_A_224);
        assert_eq!(sha256, MILLION_A_256);

        for (len, sha224_expected, sha256_expected) in PATTERN_DIGESTS {
            let input = pattern(len);
            let sha224 = hex(&to_bytes::<28>(&hash_with(
                scalar::compress,
                INIT_224,
                &input,
            )));
            let sha256 = hex(&to_bytes::<32>(&hash_with(
                scalar::compress,
                INIT_256,
                &input,
            )));
            assert_eq!(sha224, sha224_expected, "SHA-224, len = {len}");
            assert_eq!(sha256, sha256_expected, "SHA-256, len = {len}");
        }
    }

    /// Checks the scalar backend against a second, independently-written
    /// padding implementation, so a padding bug can't hide just because both
    /// paths share the same (buggy) helper.
    #[test]
    fn scalar_matches_independent_reference() {
        for len in [
            0usize, 1, 55, 56, 57, 63, 64, 65, 119, 120, 121, 128, 200, 1024,
        ] {
            let input = pattern(len);
            assert_eq!(
                hash_with(scalar::compress, INIT_256, &input),
                reference_hash(INIT_256, &input),
                "len = {len}"
            );
        }
    }

    /// Reference implementation for `scalar_matches_independent_reference`.
    /// Builds the whole padded message as one `Vec` -- the simple, unoptimized
    /// way -- instead of only staging the tail on the stack.
    fn reference_hash(init: [u32; 8], input: &[u8]) -> [u32; 8] {
        let mut state = init;

        let mut padded = input.to_vec();
        padded.push(0x80);
        while padded.len() % 64 != 56 {
            padded.push(0);
        }
        let bit_len = (input.len() as u64).wrapping_mul(8);
        padded.extend_from_slice(&bit_len.to_be_bytes());

        scalar::compress(&mut state, &padded);
        state
    }

    /// Checks that the public functions, through whichever backend they pick,
    /// still match the scalar reference.
    #[test]
    fn public_api_matches_scalar() {
        for len in [0usize, 63, 64, 65, 1024, 100_000] {
            let input = pattern(len);
            assert_eq!(
                sha256(&input),
                to_bytes::<32>(&hash_with(scalar::compress, INIT_256, &input)),
                "SHA-256, len = {len}"
            );
            assert_eq!(
                sha224(&input),
                to_bytes::<28>(&hash_with(scalar::compress, INIT_224, &input)),
                "SHA-224, len = {len}"
            );
        }
    }

    #[test]
    #[ignore = "manual throughput check: cargo test --release -- --ignored --nocapture --test-threads=1"]
    fn throughput() {
        use std::time::Instant;

        let data = vec![0x61u8; 64 * 1024 * 1024];
        let mib = data.len() as f64 / (1024.0 * 1024.0);

        // The first pass over a fresh buffer is slowed down by page faults and
        // CPU clock ramp-up, not just SHA-256 itself. So we warm up once, then
        // time several runs and keep the best.
        std::hint::black_box(sha256(&data));

        /// Runs `hash` over `data` five times and prints the best rate.
        fn time(name: &str, backend: &str, data: &[u8], mib: f64, hash: impl Fn(&[u8]) -> Vec<u8>) {
            let mut best = 0.0f64;
            let mut digest = Vec::new();
            for _ in 0..5 {
                let start = Instant::now();
                digest = hash(data);
                best = best.max(mib / start.elapsed().as_secs_f64());
            }
            println!(
                "{name} [{backend}]: {mib:.0} MiB, best {best:.1} MiB/s (digest {}...)",
                super::hex(&digest[..8])
            );
        }

        // Exactly the public API's path: the dispatcher picks the backend.
        time("sha224", active_backend(), &data, mib, |d| {
            sha224(d).to_vec()
        });
        time("sha256", active_backend(), &data, mib, |d| {
            sha256(d).to_vec()
        });

        // Then every backend the dispatcher passed over, down to scalar, so
        // that one run on a machine with the fastest instructions also
        // measures the paths other CPUs would take.
        for (name, backend) in backends().into_iter().skip(1) {
            time("sha224", name, &data, mib, |d| {
                to_bytes::<28>(&hash_with(backend, INIT_224, d)).to_vec()
            });
            time("sha256", name, &data, mib, |d| {
                to_bytes::<32>(&hash_with(backend, INIT_256, d)).to_vec()
            });
        }
    }
}
