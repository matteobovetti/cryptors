use crate::Digest;

/// Initial hash state (RFC 3174 section 6.1).
const INIT: [u32; 5] = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0];

/// Round constants (RFC 3174 section 5).
pub(super) const K: [u32; 4] = [0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xca62c1d6];

#[cfg(target_arch = "aarch64")]
#[inline]
fn has_hw_sha1() -> bool {
    // On some targets (e.g. aarch64-apple-darwin) `sha2` is always present,
    // so this check is skipped entirely at compile time.
    cfg!(target_feature = "sha2") || std::arch::is_aarch64_feature_detected!("sha2")
}

#[cfg(target_arch = "x86_64")]
#[inline]
fn has_hw_sha1() -> bool {
    std::arch::is_x86_feature_detected!("sha")
        && std::arch::is_x86_feature_detected!("ssse3")
        && std::arch::is_x86_feature_detected!("sse4.1")
}

/// Hashes every full 64-byte block in `blocks` into `state`, picking the
/// fastest backend the CPU supports.
///
/// We check which backend to use once per call, not once per block, so the
/// hardware backends only need to set up once per message instead of once
/// per block.
#[inline]
fn compress(state: &mut [u32; 5], blocks: &[u8]) {
    #[cfg(target_arch = "aarch64")]
    if has_hw_sha1() {
        // SAFETY: has_hw_sha1() just confirmed the `sha2` feature is available.
        unsafe { super::aarch64::compress(state, blocks) };
        return;
    }

    #[cfg(target_arch = "x86_64")]
    if has_hw_sha1() {
        // SAFETY: has_hw_sha1() just confirmed `sha`, `ssse3` and `sse4.1` are available.
        unsafe { super::x86::compress(state, blocks) };
        return;
    }

    super::scalar::compress(state, blocks);
}

/// SHA-1 (RFC 3174): a 160-bit digest.
///
/// A zero-sized namespace for the hashing functions; it holds no state.
///
/// ```
/// use cryptors::{Digest, sha1::Sha1};
///
/// assert_eq!(Sha1::digest(b"abc")[0], 0xa9);
/// ```
#[derive(Clone, Copy, Debug)]
#[non_exhaustive]
pub struct Sha1;

impl Digest for Sha1 {
    const BLOCK_LEN: usize = 64;
    const OUTPUT_LEN: usize = 20;
    type Output = [u8; 20];

    /// Computes the 160-bit SHA-1 digest of `input`.
    ///
    /// Full blocks are hashed straight out of `input` without copying; only
    /// the last partial block (plus padding) is copied onto the stack.
    fn digest(input: &[u8]) -> [u8; 20] {
        digest_with(compress, input)
    }
}

/// Does the padding and final hashing step. Takes the backend as a parameter
/// so tests can force a specific one; `digest` always calls this with the
/// auto-selected `compress`, so it costs nothing in the normal case.
#[inline]
fn digest_with<F: FnMut(&mut [u32; 5], &[u8])>(mut compress_fn: F, input: &[u8]) -> [u8; 20] {
    let mut state = INIT;

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

    let mut out = [0u8; 20];
    for (word, chunk) in state.iter().zip(out.chunks_exact_mut(4)) {
        chunk.copy_from_slice(&word.to_be_bytes());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::{Sha1, digest_with};
    use crate::Digest;
    use crate::sha1::scalar;

    /// Which backend `compress` picks on this machine.
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
        assert_eq!(
            Sha1::hex_digest(b""),
            "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        );
    }

    #[test]
    fn abc() {
        // RFC 3174 section 7.3, test 1.
        assert_eq!(
            Sha1::hex_digest(b"abc"),
            "a9993e364706816aba3e25717850c26c9cd0d89d"
        );
    }

    #[test]
    fn two_block_message() {
        // RFC 3174 section 7.3, test 2.
        assert_eq!(
            Sha1::hex_digest(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
            "84983e441c3bd26ebaae4aa1f95129e5e54670f1"
        );
    }

    #[test]
    fn million_a() {
        // RFC 3174 section 7.3, test 3: 1,000,000 repetitions of 'a'.
        // This is the only test input big enough (15,625 blocks) to actually
        // exercise a hardware backend's main loop.
        let input = vec![b'a'; 1_000_000];
        assert_eq!(
            Sha1::hex_digest(&input),
            "34aa973cd4c4daa4f61eeb2bdbad27316534016f"
        );
    }

    #[test]
    fn repeated_pattern() {
        // RFC 3174 section 7.3, test 4: 10 repetitions of a 64-char string.
        let input = "0123456701234567012345670123456701234567012345670123456701234567".repeat(10);
        assert_eq!(
            Sha1::hex_digest(input.as_bytes()),
            "dea356a2cddd90c7a7ecedc5ebb563934f460452"
        );
    }

    #[test]
    fn quick_brown_fox() {
        assert_eq!(
            Sha1::hex_digest(b"The quick brown fox jumps over the lazy dog"),
            "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12"
        );
    }

    #[test]
    fn message_digest() {
        assert_eq!(
            Sha1::hex_digest(b"message digest"),
            "c12252ceda8be8994d5fa0290a47231c1d16aae3"
        );
    }

    #[test]
    fn crosses_multiple_blocks() {
        let input = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        assert_eq!(
            Sha1::hex_digest(input),
            "f43b04e4a98aebe3c874514f11a73dbd7d6c150b"
        );
    }

    /// Checks that each hardware backend produces exactly the same digest as
    /// the scalar backend.
    ///
    /// This calls the hardware backend directly instead of going through
    /// `super::compress`, so the test can't accidentally end up comparing the
    /// scalar backend against itself. If the CPU doesn't support that
    /// backend, its part of the test is just skipped.
    #[test]
    #[cfg_attr(
        not(any(target_arch = "aarch64", target_arch = "x86_64")),
        allow(unused_variables, unused_mut)
    )]
    fn matches_scalar_backend() {
        // These lengths cover every point where the padding/block layout
        // changes, plus a few large sizes to exercise the main loop.
        let lengths = [
            0usize, 1, 55, 56, 57, 63, 64, 65, 119, 120, 121, 127, 128, 129, 191, 192, 200, 255,
            256, 257, 1023, 1024, 1025, 4096, 4097, 65536, 100_000,
        ];

        let mut exercised = false;

        #[cfg(target_arch = "aarch64")]
        if super::has_hw_sha1() {
            for len in lengths {
                let input: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
                // SAFETY: has_hw_sha1() just confirmed the `sha2` feature is available.
                let hw = digest_with(
                    |s: &mut [u32; 5], b: &[u8]| unsafe { crate::sha1::aarch64::compress(s, b) },
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
                // SAFETY: has_hw_sha1() just confirmed `sha`, `ssse3` and `sse4.1` are available.
                let hw = digest_with(
                    |s: &mut [u32; 5], b: &[u8]| unsafe { crate::sha1::x86::compress(s, b) },
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

    /// Checks the known-answer vectors against the scalar backend specifically.
    ///
    /// Every other test above goes through `digest`, which skips `scalar` on
    /// a machine with hardware SHA-1. Without this test, the scalar backend
    /// would never actually get checked on such a machine.
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

    /// Checks the scalar backend against a second, independently-written
    /// padding implementation, so a padding bug can't hide just because both
    /// paths share the same (buggy) helper.
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

    /// Reference implementation for `scalar_matches_independent_reference`.
    /// Builds the whole padded message as one `Vec` -- the simple, unoptimized
    /// way -- instead of only staging the tail on the stack.
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

    #[test]
    #[ignore = "manual throughput check: cargo test --release sha1 -- --ignored --nocapture --test-threads=1"]
    fn throughput() {
        use std::time::Instant;

        let data = vec![0x61u8; 64 * 1024 * 1024];
        let mib = data.len() as f64 / (1024.0 * 1024.0);

        // The first pass over a fresh buffer is slowed down by page faults and
        // CPU clock ramp-up, not just SHA-1 itself. So we warm up once, then
        // time several runs and keep the best.
        std::hint::black_box(Sha1::digest(&data));

        let mut best = 0.0f64;
        let mut d = [0u8; 20];
        for _ in 0..5 {
            let start = Instant::now();
            d = Sha1::digest(&data);
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
