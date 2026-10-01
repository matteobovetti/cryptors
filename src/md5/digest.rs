/// Initial state, RFC 1321 section 3.3.
const INIT: [u32; 4] = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476];

/// Per-step additive constants, RFC 1321 section 3.4: `T[i] = floor(2^32 *
/// abs(sin(i + 1)))`, consumed in order by `md5_schedule!`.
pub(super) const T: [u32; 64] = [
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
];

/// Computes the 128-bit MD5 digest of `input`.
///
/// Always runs the scalar backend: a single MD5 digest is one serial
/// dependency chain and has no lane-parallelism for SIMD to exploit. Use
/// [`digest_many`] when several independent messages are needed at once.
///
/// Full 64-byte blocks are hashed directly out of `input` (no copy); only the
/// final 1-2 blocks (message tail + padding + length) are staged on the stack.
pub fn digest(input: &[u8]) -> [u8; 16] {
    digest_with(super::scalar::compress, input)
}

/// Padding and finalization, parameterized over the compression backend so the
/// tests can drive a specific one. Monomorphizes, so `digest` pays nothing.
#[inline]
fn digest_with<F: FnMut(&mut [u32; 4], &[u8])>(mut compress_fn: F, input: &[u8]) -> [u8; 16] {
    let mut state = INIT;

    let aligned = input.len() & !63;
    compress_fn(&mut state, &input[..aligned]);
    let remainder = &input[aligned..];

    let mut tail = [0u8; 128];
    let total_len = pad_tail(&mut tail, remainder, input.len());
    compress_fn(&mut state, &tail[..total_len]);

    encode(&state)
}

/// Writes `remainder` plus MD5 padding (the `0x80` marker, zeros, and
/// `msg_len` in bits as a 64-bit little-endian integer) into `tail`, and
/// returns how many bytes of `tail` are now a padded message.
///
/// At most one extra block is needed beyond the remainder: 1 byte for the
/// marker + 8 bytes for the length always fit within 64 more bytes.
#[inline]
fn pad_tail(tail: &mut [u8; 128], remainder: &[u8], msg_len: usize) -> usize {
    debug_assert!(remainder.len() < 64);

    tail[..remainder.len()].copy_from_slice(remainder);
    tail[remainder.len()] = 0x80;

    let bit_len = (msg_len as u64).wrapping_mul(8);
    let total_len = if remainder.len() < 56 { 64 } else { 128 };
    tail[total_len - 8..total_len].copy_from_slice(&bit_len.to_le_bytes());
    total_len
}

/// Serializes the four state words little-endian, RFC 1321 section 3.5.
#[inline]
fn encode(state: &[u32; 4]) -> [u8; 16] {
    let mut out = [0u8; 16];
    for (word, chunk) in state.iter().zip(out.chunks_exact_mut(4)) {
        chunk.copy_from_slice(&word.to_le_bytes());
    }
    out
}

/// Computes the MD5 digest of every message in `inputs`, in order.
///
/// On a CPU with SIMD this is substantially faster than calling [`digest`] in a
/// loop: messages are hashed in groups of up to 16 (NEON) or 8 (AVX2), one per
/// vector lane, so a whole group costs little more than one digest. Messages
/// within a group need not be the same length -- lanes that run out of blocks
/// early are finished on the scalar backend.
///
/// The widest backend is applied first and then narrower ones to what is left
/// over, so a batch size that is not a multiple of the widest lane count still
/// gets most of the benefit. Only a final remainder narrower than the narrowest
/// backend -- and every message on a CPU without any SIMD backend -- goes
/// through [`digest`] one at a time.
pub fn digest_many(inputs: &[&[u8]]) -> Vec<[u8; 16]> {
    let mut out = Vec::with_capacity(inputs.len());
    #[cfg_attr(
        not(any(target_arch = "aarch64", target_arch = "x86_64")),
        allow(unused_mut)
    )]
    let mut rest = inputs;

    #[cfg(target_arch = "x86_64")]
    {
        if std::arch::is_x86_feature_detected!("avx2") {
            // SAFETY: `is_x86_feature_detected` just confirmed `avx2`.
            rest = many_into::<8, _>(
                |s, m| unsafe { super::x86::compress8(s, m) },
                rest,
                &mut out,
            );
        }
        // `sse2` is part of the x86-64 baseline, so this is unconditional.
        // SAFETY: `sse2` is guaranteed by the x86-64 target baseline.
        rest = many_into::<4, _>(
            |s, m| unsafe { super::x86::compress4(s, m) },
            rest,
            &mut out,
        );
    }

    #[cfg(target_arch = "aarch64")]
    {
        // `neon` is part of the aarch64 baseline, so these are unconditional.
        // SAFETY: `neon` is guaranteed by the aarch64 target baseline.
        rest = many_into::<16, _>(
            |s, m| unsafe { super::aarch64::compress16(s, m) },
            rest,
            &mut out,
        );
        // SAFETY: as above.
        rest = many_into::<8, _>(
            |s, m| unsafe { super::aarch64::compress8(s, m) },
            rest,
            &mut out,
        );
        // SAFETY: as above.
        rest = many_into::<4, _>(
            |s, m| unsafe { super::aarch64::compress4(s, m) },
            rest,
            &mut out,
        );
    }

    out.extend(rest.iter().map(|input| digest(input)));
    out
}

/// Hashes every complete group of `W` messages at the front of `inputs` with
/// `compress` -- a backend that compresses one block in each of `W` lanes --
/// appending their digests to `out`, and returns the fewer-than-`W` messages
/// left over for a narrower backend to pick up.
#[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
fn many_into<'a, const W: usize, F>(
    mut compress: F,
    inputs: &'a [&'a [u8]],
    out: &mut Vec<[u8; 16]>,
) -> &'a [&'a [u8]]
where
    F: FnMut(&mut [[u32; W]; 4], &[[u32; W]; 16]),
{
    let mut groups = inputs.chunks_exact(W);
    for group in &mut groups {
        out.extend_from_slice(&group_digest(&mut compress, group));
    }
    groups.remainder()
}

/// Hashes exactly `W` messages simultaneously, one per lane.
///
/// `state` and `m` are held lane-transposed (`state[word][lane]`,
/// `m[word][lane]`) because that is the layout a vector register wants: one
/// load yields word `word` of all `W` messages.
#[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
fn group_digest<const W: usize, F>(compress: &mut F, group: &[&[u8]]) -> [[u8; 16]; W]
where
    F: FnMut(&mut [[u32; W]; 4], &[[u32; W]; 16]),
{
    debug_assert_eq!(group.len(), W);

    // Stage each lane's padded tail once up front, so the block loops below can
    // treat a lane as a flat sequence of `blocks[lane]` complete blocks.
    let mut tails = [[0u8; 128]; W];
    // Blocks taken straight out of the input; later ones come from `tails`.
    let mut aligned = [0usize; W];
    let mut blocks = [0usize; W];

    for (lane, input) in group.iter().enumerate() {
        let full = input.len() & !63;
        let total = pad_tail(&mut tails[lane], &input[full..], input.len());
        aligned[lane] = full / 64;
        blocks[lane] = full / 64 + total / 64;
    }

    let mut state = [[0u32; W]; 4];
    for (slot, &init) in state.iter_mut().zip(INIT.iter()) {
        *slot = [init; W];
    }

    // Lane-parallel phase: while every lane still has a block, all `W` advance
    // together on the backend.
    let common = blocks.iter().copied().min().unwrap_or(0);
    let mut m = [[0u32; W]; 16];
    for b in 0..common {
        for lane in 0..W {
            let block = block_at(group[lane], &tails[lane], aligned[lane], b);
            for (word, src) in block.chunks_exact(4).enumerate() {
                m[word][lane] = u32::from_le_bytes([src[0], src[1], src[2], src[3]]);
            }
        }
        compress(&mut state, &m);
    }

    // Tail phase: lanes with blocks left over (longer messages) finish alone.
    let mut out = [[0u8; 16]; W];
    for lane in 0..W {
        let mut s = [
            state[0][lane],
            state[1][lane],
            state[2][lane],
            state[3][lane],
        ];
        for b in common..blocks[lane] {
            let block = block_at(group[lane], &tails[lane], aligned[lane], b);
            // `block_at` always returns exactly 64 bytes.
            super::scalar::process_block(&mut s, block.try_into().unwrap());
        }
        out[lane] = encode(&s);
    }

    out
}

/// Returns block `b` of a padded message: the first `aligned` blocks come
/// straight out of `input`, the remaining one or two out of the staged `tail`.
#[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
#[inline]
fn block_at<'a>(input: &'a [u8], tail: &'a [u8; 128], aligned: usize, b: usize) -> &'a [u8] {
    let (buf, i) = if b < aligned {
        (input, b * 64)
    } else {
        (&tail[..], (b - aligned) * 64)
    };
    &buf[i..i + 64]
}

const HEX: &[u8; 16] = b"0123456789abcdef";

/// Computes the MD5 digest of `input` and renders it as lowercase hex.
pub fn hex_digest(input: &[u8]) -> String {
    let bytes = digest(input);
    let mut out = Vec::with_capacity(32);
    for b in bytes {
        out.push(HEX[(b >> 4) as usize]);
        out.push(HEX[(b & 0xf) as usize]);
    }
    // SAFETY: `out` only ever contains bytes from the `HEX` table, which is ASCII.
    unsafe { String::from_utf8_unchecked(out) }
}

#[cfg(test)]
mod tests {
    use super::{digest, digest_many, hex_digest};
    use crate::md5::scalar;

    /// Which backend `digest_many` will actually select here, and its width.
    fn active_backend() -> (&'static str, usize) {
        #[cfg(target_arch = "x86_64")]
        {
            if std::arch::is_x86_feature_detected!("avx2") {
                ("x86_64 (AVX2)", 8)
            } else {
                ("x86_64 (SSE2)", 4)
            }
        }
        #[cfg(target_arch = "aarch64")]
        {
            ("aarch64 (NEON)", 16)
        }
        #[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
        {
            ("scalar", 1)
        }
    }

    /// RFC 1321 appendix A.5, the full test suite.
    #[test]
    fn rfc_test_suite() {
        let cases: [(&[u8], &str); 7] = [
            (b"", "d41d8cd98f00b204e9800998ecf8427e"),
            (b"a", "0cc175b9c0f1b6a831c399e269772661"),
            (b"abc", "900150983cd24fb0d6963f7d28e17f72"),
            (b"message digest", "f96b697d7cb7938d525a2f31aaf161d0"),
            (
                b"abcdefghijklmnopqrstuvwxyz",
                "c3fcd3d76192e4007dfb496cca67e13b",
            ),
            (
                b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
                "d174ab98d277d9f5a5611c2c9f419d9f",
            ),
            (
                b"12345678901234567890123456789012345678901234567890123456789012345678901234567890",
                "57edf4a22be3c955ac49da2e2107b67a",
            ),
        ];

        for (input, expected) in cases {
            assert_eq!(hex_digest(input), expected, "input = {input:?}");
        }
    }

    #[test]
    fn quick_brown_fox() {
        assert_eq!(
            hex_digest(b"The quick brown fox jumps over the lazy dog"),
            "9e107d9d372bb6826bd81d3542a419d6"
        );
    }

    #[test]
    fn crosses_multiple_blocks() {
        let input = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        assert_eq!(hex_digest(input), "76658de2ac7d406f93dfbe8bb6d9f549");
    }

    #[test]
    fn million_a() {
        // Long enough to exercise a backend's steady-state block loop
        // (15,625 blocks) rather than just its padding path.
        let input = vec![b'a'; 1_000_000];
        assert_eq!(hex_digest(&input), "7707d6ae4e027c70eea2a935c2296f21");
    }

    #[test]
    fn block_boundary_lengths() {
        // Cross-check the stack-buffer tail path in `digest` against an
        // independently padded (heap-allocated) reference, across every
        // length that changes how many blocks the tail occupies.
        for len in [0usize, 1, 55, 56, 57, 63, 64, 65, 119, 120, 121, 128, 200] {
            let input = pattern(len);
            assert_eq!(digest(&input), reference_digest(&input), "len = {len}");
        }
    }

    /// Ground truth for `block_boundary_lengths`: pads by fully materializing
    /// the message (the straightforward, non-optimized approach) rather than
    /// staging only the tail on the stack.
    fn reference_digest(input: &[u8]) -> [u8; 16] {
        let mut state = super::INIT;

        let mut padded = input.to_vec();
        padded.push(0x80);
        while padded.len() % 64 != 56 {
            padded.push(0);
        }
        let bit_len = (input.len() as u64).wrapping_mul(8);
        padded.extend_from_slice(&bit_len.to_le_bytes());

        scalar::compress(&mut state, &padded);
        super::encode(&state)
    }

    /// Deterministic pseudo-random message of length `len`.
    fn pattern(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i % 251) as u8).collect()
    }

    /// Lengths chosen around every boundary that changes block/padding layout,
    /// plus sizes large enough to cover a backend's steady state.
    const LENGTHS: [usize; 27] = [
        0, 1, 55, 56, 57, 63, 64, 65, 119, 120, 121, 127, 128, 129, 191, 192, 200, 255, 256, 257,
        1023, 1024, 1025, 4096, 4097, 65536, 100_000,
    ];

    /// The lane-parallel backends must agree with the scalar reference
    /// bit-for-bit, for every message in a group and for every mix of lengths.
    ///
    /// This calls the hardware backend *directly* rather than through
    /// `digest_many`, so it cannot silently degenerate into comparing the
    /// scalar backend against itself. On a target without a SIMD backend
    /// nothing is checked and the test reports that.
    #[test]
    fn matches_scalar_backend() {
        #[cfg(target_arch = "aarch64")]
        {
            // Every width `digest_many` can step down through. SAFETY: `neon`
            // is guaranteed by the aarch64 target baseline.
            check_backend::<4, _>(
                |s, m| unsafe { crate::md5::aarch64::compress4(s, m) },
                "neon",
            );
            check_backend::<8, _>(
                |s, m| unsafe { crate::md5::aarch64::compress8(s, m) },
                "neon",
            );
            check_backend::<16, _>(
                |s, m| unsafe { crate::md5::aarch64::compress16(s, m) },
                "neon",
            );
        }

        #[cfg(target_arch = "x86_64")]
        {
            // SAFETY: `sse2` is guaranteed by the x86-64 target baseline.
            check_backend::<4, _>(|s, m| unsafe { crate::md5::x86::compress4(s, m) }, "sse2");

            if std::arch::is_x86_feature_detected!("avx2") {
                // SAFETY: `is_x86_feature_detected` just confirmed `avx2`.
                check_backend::<8, _>(|s, m| unsafe { crate::md5::x86::compress8(s, m) }, "avx2");
            } else {
                println!("no AVX2 on this CPU; the 8-lane backend was not exercised");
            }
        }

        #[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
        println!("no SIMD MD5 backend on this target; only the scalar path is in use");
    }

    /// Drives one backend through `super::many_into` over several
    /// message-length mixes and compares every digest against `digest`.
    #[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
    fn check_backend<const W: usize, F>(mut compress: F, name: &str)
    where
        F: FnMut(&mut [[u32; W]; 4], &[[u32; W]; 16]) + Copy,
    {
        /// Hashes one group through the backend alone, with no width cascade
        /// and no scalar fallback for a short group, so a disagreement cannot
        /// be masked by another path picking up the work.
        fn only<const W: usize, F>(compress: &mut F, group: &[&[u8]]) -> Vec<[u8; 16]>
        where
            F: FnMut(&mut [[u32; W]; 4], &[[u32; W]; 16]),
        {
            let mut out = Vec::new();
            let rest = super::many_into::<W, _>(compress, group, &mut out);
            // Callers only ever pass exact multiples of `W`.
            assert!(rest.is_empty());
            out
        }

        // Recorded so that a CI log (run with `--nocapture`) shows which
        // backends the machine actually had the features to execute, rather
        // than leaving it to be inferred from the target triple.
        println!("exercising the {name} backend at {W} lanes against scalar");

        // Uniform lengths: every lane finishes on the same block, so the
        // lane-parallel phase covers the whole message.
        for len in LENGTHS {
            let input = pattern(len);
            let group: Vec<&[u8]> = vec![&input; W];
            assert_eq!(
                only::<W, _>(&mut compress, &group),
                vec![digest(&input); W],
                "{name}/{W}: uniform group disagrees with scalar at len = {len}"
            );
        }

        // Ragged lengths: lanes run out of blocks at different times, so the
        // scalar tail phase takes over for some lanes and not others. Every
        // rotation is tried so each length lands in each lane.
        let inputs: Vec<Vec<u8>> = LENGTHS.iter().map(|&len| pattern(len)).collect();
        for offset in 0..inputs.len() {
            let group: Vec<&[u8]> = (0..W)
                .map(|lane| inputs[(offset + lane * 7) % inputs.len()].as_slice())
                .collect();
            let expected: Vec<[u8; 16]> = group.iter().map(|input| digest(input)).collect();
            assert_eq!(
                only::<W, _>(&mut compress, &group),
                expected,
                "{name}/{W}: ragged group disagrees with scalar at offset = {offset}"
            );
        }

        // Several groups in one call, so the state really is reinitialized per
        // group rather than carried over.
        let group: Vec<&[u8]> = (0..3 * W)
            .map(|i| inputs[i % inputs.len()].as_slice())
            .collect();
        let expected: Vec<[u8; 16]> = group.iter().map(|input| digest(input)).collect();
        assert_eq!(
            only::<W, _>(&mut compress, &group),
            expected,
            "{name}/{W}: disagrees with scalar across three consecutive groups"
        );
    }

    /// The public API must route through whichever backend is active and still
    /// produce the same digests as hashing each message on its own.
    #[test]
    fn digest_many_matches_digest() {
        assert!(digest_many(&[]).is_empty());

        let inputs: Vec<Vec<u8>> = LENGTHS.iter().map(|&len| pattern(len)).collect();

        // Every prefix: covers all remainder sizes for any lane width, with a
        // different length mix in each group.
        for count in 0..=inputs.len() {
            let group: Vec<&[u8]> = inputs[..count].iter().map(Vec::as_slice).collect();
            let expected: Vec<[u8; 16]> = group.iter().map(|input| digest(input)).collect();
            assert_eq!(digest_many(&group), expected, "count = {count}");
        }

        // Many identical messages: the common case, and the one where every
        // lane stays in the lane-parallel phase to the very last block.
        let input = pattern(10_000);
        let group: Vec<&[u8]> = vec![&input; 33];
        assert_eq!(digest_many(&group), vec![digest(&input); 33]);
    }

    #[test]
    #[ignore = "manual throughput check: cargo test --release -- --ignored --nocapture"]
    fn throughput() {
        use std::time::Instant;

        const TOTAL: usize = 64 * 1024 * 1024;
        let mib = TOTAL as f64 / (1024.0 * 1024.0);
        let (backend, lanes) = active_backend();

        // Single message: no lane-parallelism to exploit, so this measures the
        // scalar backend and is the baseline the batch figure is compared to.
        let data = vec![0x61u8; TOTAL];
        // A single cold pass over a fresh 64 MiB buffer measures page faults and
        // clock ramp as much as MD5, so warm up and report the best of several.
        std::hint::black_box(digest(&data));
        let mut single = 0.0f64;
        let mut d = [0u8; 16];
        for _ in 0..5 {
            let start = Instant::now();
            d = digest(&data);
            single = single.max(mib / start.elapsed().as_secs_f64());
        }
        println!("md5 single [scalar]: {mib:.0} MiB, best {single:.1} MiB/s (digest {d:02x?})");

        // Batch: the same 64 MiB split into independent messages, which is what
        // `digest_many` can put one-per-lane. 64 KiB each is large enough that
        // per-message setup is negligible and small enough to stay cache-warm.
        const MSG: usize = 64 * 1024;
        let messages: Vec<&[u8]> = data.chunks_exact(MSG).collect();
        std::hint::black_box(digest_many(&messages));
        let mut batch = 0.0f64;
        let mut n = 0;
        for _ in 0..5 {
            let start = Instant::now();
            let out = digest_many(&messages);
            batch = batch.max(mib / start.elapsed().as_secs_f64());
            n = out.len();
        }
        println!(
            "md5 batch [{backend}, {lanes} lanes]: {n} x {} KiB = {mib:.0} MiB, \
             best {batch:.1} MiB/s ({:.2}x single)",
            MSG / 1024,
            batch / single
        );
    }
}
