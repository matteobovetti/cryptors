//! SHA-1 compression using the x86 SHA extensions (SHA-NI).
//!
//! `SHA1RNDS4` performs four SHA-1 rounds, `SHA1NEXTE` folds the running E term
//! into the next group, and `SHA1MSG1`/`SHA1MSG2` expand the message schedule,
//! so a block costs 20 round instructions instead of 80 scalar steps.
//!
//! Only reachable through `super::compress`, which verifies the `sha`, `ssse3`
//! and `sse4.1` target features first.
//!
//! NOTE: this backend is compile-verified and differential-tested against
//! `super::scalar` on any CPU that reports SHA-NI, but it was developed on an
//! aarch64 host and has not been executed on SHA-NI hardware by its author.
//! The `matches_scalar_backend` test in the parent module is what establishes
//! its correctness; run the test suite on a SHA-NI machine to exercise it.

use core::arch::x86_64::*;

/// Compresses every complete 64-byte block in `blocks` into `state`.
///
/// Any trailing bytes that do not form a full block are ignored; callers are
/// responsible for padding (see `super::digest`).
///
/// # Safety
///
/// The caller must ensure the `sha`, `ssse3` and `sse4.1` target features are
/// available on this CPU. `super::compress` is the only caller and checks
/// this. No other invariants are required: the loop walks `chunks_exact(64)`,
/// so every vector load below is in bounds for any `blocks` length, and
/// `state` is a fixed-size array.
#[target_feature(enable = "sha,ssse3,sse4.1")]
pub(super) unsafe fn compress(state: &mut [u32; 5], blocks: &[u8]) {
    // Reverses all 16 bytes: this both byte-swaps each word (SHA-1 reads the
    // message big-endian) and flips word order to match the reversed ABCD
    // layout the SHA-NI instructions expect.
    let mask = _mm_set_epi64x(0x0001_0203_0405_0607, 0x0809_0a0b_0c0d_0e0f);

    // SHA-NI keeps ABCD in reverse word order, and E alone in the top lane.
    // SAFETY: `state` holds 5 words, so the 4-word load is in bounds.
    let loaded = unsafe { _mm_loadu_si128(state.as_ptr().cast()) };
    let mut abcd = _mm_shuffle_epi32(loaded, 0x1b);
    let mut e0 = _mm_set_epi32(state[4] as i32, 0, 0, 0);

    for block in blocks.chunks_exact(64) {
        let abcd_saved = abcd;
        let e0_saved = e0;

        // SAFETY: `chunks_exact(64)` guarantees `block` is exactly 64 bytes, so
        // all four 16-byte loads are in bounds.
        let (mut m0, mut m1, mut m2, mut m3) = unsafe {
            let p = block.as_ptr();
            (
                _mm_shuffle_epi8(_mm_loadu_si128(p.cast()), mask),
                _mm_shuffle_epi8(_mm_loadu_si128(p.add(16).cast()), mask),
                _mm_shuffle_epi8(_mm_loadu_si128(p.add(32).cast()), mask),
                _mm_shuffle_epi8(_mm_loadu_si128(p.add(48).cast()), mask),
            )
        };

        let mut e1;

        // Rounds 0-3. The round constants are folded in by SHA1RNDS4 itself,
        // selected by the const immediate (0 => K[0] .. 3 => K[3]).
        e0 = _mm_add_epi32(e0, m0);
        e1 = abcd;
        abcd = _mm_sha1rnds4_epu32::<0>(abcd, e0);

        // Rounds 4-7
        e1 = _mm_sha1nexte_epu32(e1, m1);
        e0 = abcd;
        abcd = _mm_sha1rnds4_epu32::<0>(abcd, e1);
        m0 = _mm_sha1msg1_epu32(m0, m1);

        // Rounds 8-11
        e0 = _mm_sha1nexte_epu32(e0, m2);
        e1 = abcd;
        abcd = _mm_sha1rnds4_epu32::<0>(abcd, e0);
        m1 = _mm_sha1msg1_epu32(m1, m2);
        m0 = _mm_xor_si128(m0, m2);

        // Rounds 12-15
        e1 = _mm_sha1nexte_epu32(e1, m3);
        e0 = abcd;
        m0 = _mm_sha1msg2_epu32(m0, m3);
        abcd = _mm_sha1rnds4_epu32::<0>(abcd, e1);
        m2 = _mm_sha1msg1_epu32(m2, m3);
        m1 = _mm_xor_si128(m1, m3);

        // Rounds 16-19
        e0 = _mm_sha1nexte_epu32(e0, m0);
        e1 = abcd;
        m1 = _mm_sha1msg2_epu32(m1, m0);
        abcd = _mm_sha1rnds4_epu32::<0>(abcd, e0);
        m3 = _mm_sha1msg1_epu32(m3, m0);
        m2 = _mm_xor_si128(m2, m0);

        // Rounds 20-23
        e1 = _mm_sha1nexte_epu32(e1, m1);
        e0 = abcd;
        m2 = _mm_sha1msg2_epu32(m2, m1);
        abcd = _mm_sha1rnds4_epu32::<1>(abcd, e1);
        m0 = _mm_sha1msg1_epu32(m0, m1);
        m3 = _mm_xor_si128(m3, m1);

        // Rounds 24-27
        e0 = _mm_sha1nexte_epu32(e0, m2);
        e1 = abcd;
        m3 = _mm_sha1msg2_epu32(m3, m2);
        abcd = _mm_sha1rnds4_epu32::<1>(abcd, e0);
        m1 = _mm_sha1msg1_epu32(m1, m2);
        m0 = _mm_xor_si128(m0, m2);

        // Rounds 28-31
        e1 = _mm_sha1nexte_epu32(e1, m3);
        e0 = abcd;
        m0 = _mm_sha1msg2_epu32(m0, m3);
        abcd = _mm_sha1rnds4_epu32::<1>(abcd, e1);
        m2 = _mm_sha1msg1_epu32(m2, m3);
        m1 = _mm_xor_si128(m1, m3);

        // Rounds 32-35
        e0 = _mm_sha1nexte_epu32(e0, m0);
        e1 = abcd;
        m1 = _mm_sha1msg2_epu32(m1, m0);
        abcd = _mm_sha1rnds4_epu32::<1>(abcd, e0);
        m3 = _mm_sha1msg1_epu32(m3, m0);
        m2 = _mm_xor_si128(m2, m0);

        // Rounds 36-39
        e1 = _mm_sha1nexte_epu32(e1, m1);
        e0 = abcd;
        m2 = _mm_sha1msg2_epu32(m2, m1);
        abcd = _mm_sha1rnds4_epu32::<1>(abcd, e1);
        m0 = _mm_sha1msg1_epu32(m0, m1);
        m3 = _mm_xor_si128(m3, m1);

        // Rounds 40-43
        e0 = _mm_sha1nexte_epu32(e0, m2);
        e1 = abcd;
        m3 = _mm_sha1msg2_epu32(m3, m2);
        abcd = _mm_sha1rnds4_epu32::<2>(abcd, e0);
        m1 = _mm_sha1msg1_epu32(m1, m2);
        m0 = _mm_xor_si128(m0, m2);

        // Rounds 44-47
        e1 = _mm_sha1nexte_epu32(e1, m3);
        e0 = abcd;
        m0 = _mm_sha1msg2_epu32(m0, m3);
        abcd = _mm_sha1rnds4_epu32::<2>(abcd, e1);
        m2 = _mm_sha1msg1_epu32(m2, m3);
        m1 = _mm_xor_si128(m1, m3);

        // Rounds 48-51
        e0 = _mm_sha1nexte_epu32(e0, m0);
        e1 = abcd;
        m1 = _mm_sha1msg2_epu32(m1, m0);
        abcd = _mm_sha1rnds4_epu32::<2>(abcd, e0);
        m3 = _mm_sha1msg1_epu32(m3, m0);
        m2 = _mm_xor_si128(m2, m0);

        // Rounds 52-55
        e1 = _mm_sha1nexte_epu32(e1, m1);
        e0 = abcd;
        m2 = _mm_sha1msg2_epu32(m2, m1);
        abcd = _mm_sha1rnds4_epu32::<2>(abcd, e1);
        m0 = _mm_sha1msg1_epu32(m0, m1);
        m3 = _mm_xor_si128(m3, m1);

        // Rounds 56-59
        e0 = _mm_sha1nexte_epu32(e0, m2);
        e1 = abcd;
        m3 = _mm_sha1msg2_epu32(m3, m2);
        abcd = _mm_sha1rnds4_epu32::<2>(abcd, e0);
        m1 = _mm_sha1msg1_epu32(m1, m2);
        m0 = _mm_xor_si128(m0, m2);

        // Rounds 60-63
        e1 = _mm_sha1nexte_epu32(e1, m3);
        e0 = abcd;
        m0 = _mm_sha1msg2_epu32(m0, m3);
        abcd = _mm_sha1rnds4_epu32::<3>(abcd, e1);
        m2 = _mm_sha1msg1_epu32(m2, m3);
        m1 = _mm_xor_si128(m1, m3);

        // Rounds 64-67
        e0 = _mm_sha1nexte_epu32(e0, m0);
        e1 = abcd;
        m1 = _mm_sha1msg2_epu32(m1, m0);
        abcd = _mm_sha1rnds4_epu32::<3>(abcd, e0);
        m3 = _mm_sha1msg1_epu32(m3, m0);
        m2 = _mm_xor_si128(m2, m0);

        // Rounds 68-71
        e1 = _mm_sha1nexte_epu32(e1, m1);
        e0 = abcd;
        m2 = _mm_sha1msg2_epu32(m2, m1);
        abcd = _mm_sha1rnds4_epu32::<3>(abcd, e1);
        m3 = _mm_xor_si128(m3, m1);

        // Rounds 72-75
        e0 = _mm_sha1nexte_epu32(e0, m2);
        e1 = abcd;
        m3 = _mm_sha1msg2_epu32(m3, m2);
        abcd = _mm_sha1rnds4_epu32::<3>(abcd, e0);

        // Rounds 76-79
        e1 = _mm_sha1nexte_epu32(e1, m3);
        e0 = abcd;
        abcd = _mm_sha1rnds4_epu32::<3>(abcd, e1);

        // Feed-forward: add this block's starting state back in. SHA1NEXTE
        // supplies the rotate-left-30 that the E term needs.
        e0 = _mm_sha1nexte_epu32(e0, e0_saved);
        abcd = _mm_add_epi32(abcd, abcd_saved);
    }

    // SAFETY: `state` holds 5 words, so the 4-word store is in bounds.
    unsafe { _mm_storeu_si128(state.as_mut_ptr().cast(), _mm_shuffle_epi32(abcd, 0x1b)) };
    state[4] = _mm_extract_epi32(e0, 3) as u32;
}
