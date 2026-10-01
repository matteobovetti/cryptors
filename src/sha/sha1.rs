/// Initial state, RFC 3174 section 6.1.
const INIT: [u32; 5] = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0];

/// Round constants, RFC 3174 section 5.
pub(super) const K: [u32; 4] = [0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xca62c1d6];

#[cfg(target_arch = "aarch64")]
#[inline]
fn has_hw_sha1() -> bool {
    // On targets where `sha2` is baseline (notably aarch64-apple-darwin) this
    // folds to a constant and no runtime probe is emitted at all.
    cfg!(target_feature = "sha2") || std::arch::is_aarch64_feature_detected!("sha2")
}

#[cfg(target_arch = "x86_64")]
#[inline]
fn has_hw_sha1() -> bool {
    std::arch::is_x86_feature_detected!("sha")
        && std::arch::is_x86_feature_detected!("ssse3")
        && std::arch::is_x86_feature_detected!("sse4.1")
}

/// Compresses every complete 64-byte block in `blocks` into `state`, using the
/// fastest backend this CPU supports.
///
/// Dispatch happens once per call rather than once per block, so the hardware
/// backends can hoist constant setup and the state load/store out of their
/// block loop.
#[inline]
fn compress(state: &mut [u32; 5], blocks: &[u8]) {
    #[cfg(target_arch = "aarch64")]
    if has_hw_sha1() {
        // SAFETY: `has_hw_sha1` just confirmed the `sha2` target feature.
        unsafe { super::aarch64::compress(state, blocks) };
        return;
    }

    #[cfg(target_arch = "x86_64")]
    if has_hw_sha1() {
        // SAFETY: `has_hw_sha1` just confirmed `sha`, `ssse3` and `sse4.1`.
        unsafe { super::x86::compress(state, blocks) };
        return;
    }

    super::scalar::compress(state, blocks);
}

/// Computes the 160-bit SHA-1 digest of `input`.
///
/// Full 64-byte blocks are hashed directly out of `input` (no copy); only the
/// final 1-2 blocks (message tail + padding + length) are staged on the stack.
pub fn digest(input: &[u8]) -> [u8; 20] {
    digest_with(compress, input)
}

/// Padding and finalization, parameterized over the compression backend so the
/// tests can drive a specific one. Monomorphizes, so `digest` pays nothing.
#[inline]
fn digest_with<F: FnMut(&mut [u32; 5], &[u8])>(mut compress_fn: F, input: &[u8]) -> [u8; 20] {
    let mut state = INIT;

    let aligned = input.len() & !63;
    compress_fn(&mut state, &input[..aligned]);
    let remainder = &input[aligned..];

    // At most one extra block is needed beyond the remainder: 1 byte for the
    // 0x80 marker + 8 bytes for the length always fit within 64 more bytes.
    let mut tail = [0u8; 128];
    tail[..remainder.len()].copy_from_slice(remainder);
    tail[remainder.len()] = 0x80;

    let bit_len = (input.len() as u64).wrapping_mul(8);
    let total_len = if remainder.len() < 56 { 64 } else { 128 };
    tail[total_len - 8..total_len].copy_from_slice(&bit_len.to_be_bytes());

    compress_fn(&mut state, &tail[..total_len]);

    let mut out = [0u8; 20];
    for (word, chunk) in state.iter().zip(out.chunks_exact_mut(4)) {
        chunk.copy_from_slice(&word.to_be_bytes());
    }
    out
}

const HEX: &[u8; 16] = b"0123456789abcdef";

/// Computes the SHA-1 digest of `input` and renders it as lowercase hex.
pub fn hex_digest(input: &[u8]) -> String {
    let bytes = digest(input);
    let mut out = Vec::with_capacity(40);
    for b in bytes {
        out.push(HEX[(b >> 4) as usize]);
        out.push(HEX[(b & 0xf) as usize]);
    }
    // SAFETY: `out` only ever contains bytes from the `HEX` table, which is ASCII.
    unsafe { String::from_utf8_unchecked(out) }
}

#[cfg(test)]
mod tests {
    use super::{digest, digest_with, hex_digest};
    use crate::sha::scalar;

    /// Which backend `compress` will actually select here.
    fn active_backend() -> &'static str {
        #[cfg(target_arch = "aarch64")]
        if super::has_hw_sha1() {
            return "aarch64 (FEAT_SHA1)";
        }
        #[cfg(target_arch = "x86_64")]
        if super::has_hw_sha1() {
            return "x86_64 (SHA-NI)";
        }
        "scalar"
    }

    #[test]
    fn empty_string() {
        assert_eq!(hex_digest(b""), "da39a3ee5e6b4b0d3255bfef95601890afd80709");
    }

    #[test]
    fn abc() {
        // RFC 3174 section 7.3, test 1.
        assert_eq!(
            hex_digest(b"abc"),
            "a9993e364706816aba3e25717850c26c9cd0d89d"
        );
    }

    #[test]
    fn two_block_message() {
        // RFC 3174 section 7.3, test 2.
        assert_eq!(
            hex_digest(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
            "84983e441c3bd26ebaae4aa1f95129e5e54670f1"
        );
    }

    #[test]
    fn million_a() {
        // RFC 3174 section 7.3, test 3: 1,000,000 repetitions of 'a'.
        // The only vector here long enough to exercise a hardware backend's
        // steady-state block loop (15,625 blocks).
        let input = vec![b'a'; 1_000_000];
        assert_eq!(
            hex_digest(&input),
            "34aa973cd4c4daa4f61eeb2bdbad27316534016f"
        );
    }

    #[test]
    fn repeated_pattern() {
        // RFC 3174 section 7.3, test 4: 10 repetitions of a 64-char string.
        let input = "0123456701234567012345670123456701234567012345670123456701234567".repeat(10);
        assert_eq!(
            hex_digest(input.as_bytes()),
            "dea356a2cddd90c7a7ecedc5ebb563934f460452"
        );
    }

    #[test]
    fn quick_brown_fox() {
        assert_eq!(
            hex_digest(b"The quick brown fox jumps over the lazy dog"),
            "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12"
        );
    }

    #[test]
    fn message_digest() {
        assert_eq!(
            hex_digest(b"message digest"),
            "c12252ceda8be8994d5fa0290a47231c1d16aae3"
        );
    }

    #[test]
    fn crosses_multiple_blocks() {
        let input = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        assert_eq!(
            hex_digest(input),
            "f43b04e4a98aebe3c874514f11a73dbd7d6c150b"
        );
    }

    /// The hardware backends must agree with the scalar reference bit-for-bit.
    ///
    /// This calls the hardware backend *directly* rather than through
    /// `super::compress`, so it cannot silently degenerate into comparing the
    /// scalar backend against itself. On a CPU without hardware SHA-1 the
    /// relevant arm is skipped and the test reports that.
    #[test]
    fn matches_scalar_backend() {
        // Lengths chosen around every boundary that changes block/padding
        // layout, plus sizes large enough to cover a backend's steady state.
        let lengths = [
            0usize, 1, 55, 56, 57, 63, 64, 65, 119, 120, 121, 127, 128, 129, 191, 192, 200, 255,
            256, 257, 1023, 1024, 1025, 4096, 4097, 65536, 100_000,
        ];

        let mut exercised = false;

        #[cfg(target_arch = "aarch64")]
        if super::has_hw_sha1() {
            for len in lengths {
                let input: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
                // SAFETY: `has_hw_sha1` confirmed the `sha2` target feature.
                let hw = digest_with(
                    |s: &mut [u32; 5], b: &[u8]| unsafe { crate::sha::aarch64::compress(s, b) },
                    &input,
                );
                assert_eq!(
                    hw,
                    digest_with(scalar::compress, &input),
                    "aarch64 backend disagrees with scalar at len = {len}"
                );
            }
            exercised = true;
        }

        #[cfg(target_arch = "x86_64")]
        if super::has_hw_sha1() {
            for len in lengths {
                let input: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
                // SAFETY: `has_hw_sha1` confirmed `sha`, `ssse3` and `sse4.1`.
                let hw = digest_with(
                    |s: &mut [u32; 5], b: &[u8]| unsafe { crate::sha::x86::compress(s, b) },
                    &input,
                );
                assert_eq!(
                    hw,
                    digest_with(scalar::compress, &input),
                    "x86_64 backend disagrees with scalar at len = {len}"
                );
            }
            exercised = true;
        }

        if !exercised {
            println!("no hardware SHA-1 backend on this CPU; only the scalar path is in use");
        }
    }

    /// Known-answer vectors driven through the scalar backend explicitly.
    ///
    /// Everything else above goes through `digest`, which on a machine with
    /// hardware SHA-1 never touches `scalar`. Without this, the fallback would
    /// only ever be checked against itself on such a machine.
    #[test]
    fn scalar_rfc_vectors() {
        let cases: [(&[u8], &str); 4] = [
            (b"", "da39a3ee5e6b4b0d3255bfef95601890afd80709"),
            (b"abc", "a9993e364706816aba3e25717850c26c9cd0d89d"),
            (
                b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
                "84983e441c3bd26ebaae4aa1f95129e5e54670f1",
            ),
            (
                b"The quick brown fox jumps over the lazy dog",
                "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12",
            ),
        ];

        for (input, expected) in cases {
            let hex: String = digest_with(scalar::compress, input)
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect();
            assert_eq!(hex, expected, "input = {input:?}");
        }

        let million = vec![b'a'; 1_000_000];
        let hex: String = digest_with(scalar::compress, &million)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert_eq!(hex, "34aa973cd4c4daa4f61eeb2bdbad27316534016f");
    }

    /// The scalar backend itself, checked against an independently padded
    /// reference so a padding bug cannot hide behind a shared helper.
    #[test]
    fn scalar_matches_independent_reference() {
        for len in [
            0usize, 1, 55, 56, 57, 63, 64, 65, 119, 120, 121, 128, 200, 1024,
        ] {
            let input: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
            assert_eq!(
                digest_with(scalar::compress, &input),
                reference_digest(&input),
                "len = {len}"
            );
        }
    }

    /// Ground truth for `scalar_matches_independent_reference`: pads by fully
    /// materializing the message (the straightforward, non-optimized approach)
    /// rather than staging only the tail on the stack.
    fn reference_digest(input: &[u8]) -> [u8; 20] {
        let mut state = super::INIT;

        let mut padded = input.to_vec();
        padded.push(0x80);
        while padded.len() % 64 != 56 {
            padded.push(0);
        }
        let bit_len = (input.len() as u64).wrapping_mul(8);
        padded.extend_from_slice(&bit_len.to_be_bytes());

        scalar::compress(&mut state, &padded);

        let mut out = [0u8; 20];
        for (word, chunk) in state.iter().zip(out.chunks_exact_mut(4)) {
            chunk.copy_from_slice(&word.to_be_bytes());
        }
        out
    }

    /// The public API must route through whichever backend is active and still
    /// produce the reference answer.
    #[test]
    fn public_api_matches_scalar() {
        for len in [0usize, 63, 64, 65, 1024, 100_000] {
            let input: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
            assert_eq!(
                digest(&input),
                digest_with(scalar::compress, &input),
                "len = {len}"
            );
        }
    }

    #[test]
    #[ignore = "manual throughput check: cargo test --release -- --ignored --nocapture"]
    fn throughput() {
        use std::time::Instant;

        let data = vec![0x61u8; 64 * 1024 * 1024];
        let mib = data.len() as f64 / (1024.0 * 1024.0);

        // A single cold pass over a fresh 64 MiB buffer measures page faults and
        // clock ramp as much as SHA-1, so warm up and report the best of several.
        std::hint::black_box(digest(&data));

        let mut best = 0.0f64;
        let mut d = [0u8; 20];
        for _ in 0..5 {
            let start = Instant::now();
            d = digest(&data);
            let elapsed = start.elapsed();
            best = best.max(mib / elapsed.as_secs_f64());
        }

        println!(
            "sha1 [{}]: {mib:.0} MiB, best {best:.1} MiB/s (digest {:02x?})",
            active_backend(),
            d
        );
    }
}
