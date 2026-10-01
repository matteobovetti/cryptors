//! SHA-1 compression using the ARMv8 cryptographic extensions (FEAT_SHA1).
//!
//! `SHA1C`/`SHA1P`/`SHA1M` each perform four SHA-1 rounds, and `SHA1SU0`/`SHA1SU1`
//! expand four message-schedule words, so a block costs 20 round instructions
//! instead of 80 scalar steps. Measured ~2.8x the scalar backend on an M1 Pro.
//!
//! Only reachable through `super::compress`, which verifies the `sha2` target
//! feature first.

use core::arch::aarch64::*;

use super::K;

/// Compresses every complete 64-byte block in `blocks` into `state`.
///
/// Any trailing bytes that do not form a full block are ignored; callers are
/// responsible for padding (see `super::digest`).
///
/// # Safety
///
/// The caller must ensure the `sha2` target feature is available on this CPU.
/// `super::compress` is the only caller and checks this. No other invariants
/// are required: the loop walks `chunks_exact(64)`, so every vector load below
/// is in bounds for any `blocks` length, and `state` is a fixed-size array.
#[target_feature(enable = "sha2")]
pub(super) unsafe fn compress(state: &mut [u32; 5], blocks: &[u8]) {
    let k0 = vdupq_n_u32(K[0]);
    let k1 = vdupq_n_u32(K[1]);
    let k2 = vdupq_n_u32(K[2]);
    let k3 = vdupq_n_u32(K[3]);

    // ABCD travels in a vector register; E is scalar, as the instructions expect.
    // SAFETY: `state` holds 5 words, so the 4-word load is in bounds.
    let mut abcd = unsafe { vld1q_u32(state.as_ptr()) };
    let mut e0 = state[4];

    for block in blocks.chunks_exact(64) {
        let abcd_saved = abcd;
        let e0_saved = e0;

        // SHA-1 reads the message big-endian; `rev32` byte-swaps four words at once.
        // SAFETY: `chunks_exact(64)` guarantees `block` is exactly 64 bytes, so
        // all four 16-byte loads are in bounds.
        let (mut m0, mut m1, mut m2, mut m3) = unsafe {
            let p = block.as_ptr();
            (
                vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(p))),
                vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(p.add(16)))),
                vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(p.add(32)))),
                vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(p.add(48)))),
            )
        };

        // Each group below runs four rounds, and meanwhile computes the `w + k`
        // for the group after next and advances the schedule, so the SHA units
        // never wait on their inputs. `e1`/`e0` alternate as the rotating E.
        let mut t0 = vaddq_u32(m0, k0);
        let mut t1 = vaddq_u32(m1, k0);
        let mut e1;

        // Rounds 0-19 use SHA1C (the "choose" function).
        e1 = vsha1h_u32(vgetq_lane_u32(abcd, 0));
        abcd = vsha1cq_u32(abcd, e0, t0);
        t0 = vaddq_u32(m2, k0);
        m0 = vsha1su0q_u32(m0, m1, m2);

        e0 = vsha1h_u32(vgetq_lane_u32(abcd, 0));
        abcd = vsha1cq_u32(abcd, e1, t1);
        t1 = vaddq_u32(m3, k0);
        m0 = vsha1su1q_u32(m0, m3);
        m1 = vsha1su0q_u32(m1, m2, m3);

        e1 = vsha1h_u32(vgetq_lane_u32(abcd, 0));
        abcd = vsha1cq_u32(abcd, e0, t0);
        t0 = vaddq_u32(m0, k0);
        m1 = vsha1su1q_u32(m1, m0);
        m2 = vsha1su0q_u32(m2, m3, m0);

        e0 = vsha1h_u32(vgetq_lane_u32(abcd, 0));
        abcd = vsha1cq_u32(abcd, e1, t1);
        t1 = vaddq_u32(m1, k1);
        m2 = vsha1su1q_u32(m2, m1);
        m3 = vsha1su0q_u32(m3, m0, m1);

        e1 = vsha1h_u32(vgetq_lane_u32(abcd, 0));
        abcd = vsha1cq_u32(abcd, e0, t0);
        t0 = vaddq_u32(m2, k1);
        m3 = vsha1su1q_u32(m3, m2);
        m0 = vsha1su0q_u32(m0, m1, m2);

        // Rounds 20-39 use SHA1P (the "parity" function).
        e0 = vsha1h_u32(vgetq_lane_u32(abcd, 0));
        abcd = vsha1pq_u32(abcd, e1, t1);
        t1 = vaddq_u32(m3, k1);
        m0 = vsha1su1q_u32(m0, m3);
        m1 = vsha1su0q_u32(m1, m2, m3);

        e1 = vsha1h_u32(vgetq_lane_u32(abcd, 0));
        abcd = vsha1pq_u32(abcd, e0, t0);
        t0 = vaddq_u32(m0, k1);
        m1 = vsha1su1q_u32(m1, m0);
        m2 = vsha1su0q_u32(m2, m3, m0);

        e0 = vsha1h_u32(vgetq_lane_u32(abcd, 0));
        abcd = vsha1pq_u32(abcd, e1, t1);
        t1 = vaddq_u32(m1, k1);
        m2 = vsha1su1q_u32(m2, m1);
        m3 = vsha1su0q_u32(m3, m0, m1);

        e1 = vsha1h_u32(vgetq_lane_u32(abcd, 0));
        abcd = vsha1pq_u32(abcd, e0, t0);
        t0 = vaddq_u32(m2, k2);
        m3 = vsha1su1q_u32(m3, m2);
        m0 = vsha1su0q_u32(m0, m1, m2);

        e0 = vsha1h_u32(vgetq_lane_u32(abcd, 0));
        abcd = vsha1pq_u32(abcd, e1, t1);
        t1 = vaddq_u32(m3, k2);
        m0 = vsha1su1q_u32(m0, m3);
        m1 = vsha1su0q_u32(m1, m2, m3);

        // Rounds 40-59 use SHA1M (the "majority" function).
        e1 = vsha1h_u32(vgetq_lane_u32(abcd, 0));
        abcd = vsha1mq_u32(abcd, e0, t0);
        t0 = vaddq_u32(m0, k2);
        m1 = vsha1su1q_u32(m1, m0);
        m2 = vsha1su0q_u32(m2, m3, m0);

        e0 = vsha1h_u32(vgetq_lane_u32(abcd, 0));
        abcd = vsha1mq_u32(abcd, e1, t1);
        t1 = vaddq_u32(m1, k2);
        m2 = vsha1su1q_u32(m2, m1);
        m3 = vsha1su0q_u32(m3, m0, m1);

        e1 = vsha1h_u32(vgetq_lane_u32(abcd, 0));
        abcd = vsha1mq_u32(abcd, e0, t0);
        t0 = vaddq_u32(m2, k2);
        m3 = vsha1su1q_u32(m3, m2);
        m0 = vsha1su0q_u32(m0, m1, m2);

        e0 = vsha1h_u32(vgetq_lane_u32(abcd, 0));
        abcd = vsha1mq_u32(abcd, e1, t1);
        t1 = vaddq_u32(m3, k3);
        m0 = vsha1su1q_u32(m0, m3);
        m1 = vsha1su0q_u32(m1, m2, m3);

        e1 = vsha1h_u32(vgetq_lane_u32(abcd, 0));
        abcd = vsha1mq_u32(abcd, e0, t0);
        t0 = vaddq_u32(m0, k3);
        m1 = vsha1su1q_u32(m1, m0);
        m2 = vsha1su0q_u32(m2, m3, m0);

        // Rounds 60-79 return to SHA1P.
        e0 = vsha1h_u32(vgetq_lane_u32(abcd, 0));
        abcd = vsha1pq_u32(abcd, e1, t1);
        t1 = vaddq_u32(m1, k3);
        m2 = vsha1su1q_u32(m2, m1);
        m3 = vsha1su0q_u32(m3, m0, m1);

        e1 = vsha1h_u32(vgetq_lane_u32(abcd, 0));
        abcd = vsha1pq_u32(abcd, e0, t0);
        t0 = vaddq_u32(m2, k3);
        m3 = vsha1su1q_u32(m3, m2);

        e0 = vsha1h_u32(vgetq_lane_u32(abcd, 0));
        abcd = vsha1pq_u32(abcd, e1, t1);
        t1 = vaddq_u32(m3, k3);

        e1 = vsha1h_u32(vgetq_lane_u32(abcd, 0));
        abcd = vsha1pq_u32(abcd, e0, t0);

        e0 = vsha1h_u32(vgetq_lane_u32(abcd, 0));
        abcd = vsha1pq_u32(abcd, e1, t1);

        // Feed-forward: add this block's starting state back in.
        e0 = e0.wrapping_add(e0_saved);
        abcd = vaddq_u32(abcd_saved, abcd);
    }

    // SAFETY: `state` holds 5 words, so the 4-word store is in bounds.
    unsafe { vst1q_u32(state.as_mut_ptr(), abcd) };
    state[4] = e0;
}
