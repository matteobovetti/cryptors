//! From-scratch MD5 implementation (RFC 1321). Broken for security use; study/legacy-checksum only.
//!
//! # Why there is no single-message hardware backend
//!
//! Unlike SHA-1 (see [`crate::sha`]), **no mainstream CPU has an MD5
//! instruction**. The ARMv8 cryptographic extensions cover AES, PMULL, SHA-1,
//! SHA-2, SHA-3 and SM3/SM4; x86 offers AES-NI and SHA-NI (SHA-1/SHA-256).
//! Neither includes MD5, and none is likely to: MD5 has been broken since 2004.
//!
//! Plain SIMD cannot rescue a single digest either. SHA-1 is accelerable partly
//! because its 80-word message schedule is independent of the round state, so
//! schedule expansion and rounds overlap. MD5 has no schedule at all -- it
//! reuses the 16 message words directly -- and all 64 steps form one serial
//! dependency chain through `a`, `b`, `c`, `d`. There is nothing to put in
//! lanes 1..N of a vector register.
//!
//! # What is accelerated: multi-buffer hashing
//!
//! What *is* independent is two different messages. [`digest_many`] exploits
//! exactly that, placing one message per vector lane and running N digests in
//! lockstep for the price of one dependency chain:
//!
//! | Backend | Requires | Lanes |
//! |---------|----------|-------|
//! | [`x86`] (AVX2) | `avx2` | 8 messages at a time |
//! | [`x86`] (SSE2) | `sse2` -- x86-64 baseline | 4 messages at a time |
//! | [`aarch64`] (NEON) | `neon` -- aarch64 baseline | 4 messages at a time |
//! | [`scalar`] | nothing -- always available | 1 (reference) |
//!
//! [`digest`] therefore always runs the scalar backend, which is already at the
//! serial-dependency limit; [`digest_many`] is where the hardware wins. The
//! scalar backend is the correctness reference, and every lane-parallel backend
//! is differential-tested against it by `matches_scalar_backend`.

/// The MD5 round schedule, RFC 1321 section 3.4: for each of the 64 steps, the
/// nonlinear function, the four state variables in round order, the message
/// word consumed, the left-rotation amount, and the index into [`digest::T`].
///
/// Every backend drives this one table, invoking the `$step` macro it supplies
/// 64 times. The table is thus written -- and auditable against the RFC -- in
/// exactly one place, and a backend can only differ from the reference in *how*
/// a step is computed, never in *which* steps run.
macro_rules! md5_schedule {
    ($step:ident, $a:ident, $b:ident, $c:ident, $d:ident, $m:ident) => {
        // Round 1: F, shifts 7/12/17/22, message word i.
        $step!(F, $a, $b, $c, $d, $m[0], 7, 0);
        $step!(F, $d, $a, $b, $c, $m[1], 12, 1);
        $step!(F, $c, $d, $a, $b, $m[2], 17, 2);
        $step!(F, $b, $c, $d, $a, $m[3], 22, 3);
        $step!(F, $a, $b, $c, $d, $m[4], 7, 4);
        $step!(F, $d, $a, $b, $c, $m[5], 12, 5);
        $step!(F, $c, $d, $a, $b, $m[6], 17, 6);
        $step!(F, $b, $c, $d, $a, $m[7], 22, 7);
        $step!(F, $a, $b, $c, $d, $m[8], 7, 8);
        $step!(F, $d, $a, $b, $c, $m[9], 12, 9);
        $step!(F, $c, $d, $a, $b, $m[10], 17, 10);
        $step!(F, $b, $c, $d, $a, $m[11], 22, 11);
        $step!(F, $a, $b, $c, $d, $m[12], 7, 12);
        $step!(F, $d, $a, $b, $c, $m[13], 12, 13);
        $step!(F, $c, $d, $a, $b, $m[14], 17, 14);
        $step!(F, $b, $c, $d, $a, $m[15], 22, 15);

        // Round 2: G, shifts 5/9/14/20, message word (1 + 5i) mod 16.
        $step!(G, $a, $b, $c, $d, $m[1], 5, 16);
        $step!(G, $d, $a, $b, $c, $m[6], 9, 17);
        $step!(G, $c, $d, $a, $b, $m[11], 14, 18);
        $step!(G, $b, $c, $d, $a, $m[0], 20, 19);
        $step!(G, $a, $b, $c, $d, $m[5], 5, 20);
        $step!(G, $d, $a, $b, $c, $m[10], 9, 21);
        $step!(G, $c, $d, $a, $b, $m[15], 14, 22);
        $step!(G, $b, $c, $d, $a, $m[4], 20, 23);
        $step!(G, $a, $b, $c, $d, $m[9], 5, 24);
        $step!(G, $d, $a, $b, $c, $m[14], 9, 25);
        $step!(G, $c, $d, $a, $b, $m[3], 14, 26);
        $step!(G, $b, $c, $d, $a, $m[8], 20, 27);
        $step!(G, $a, $b, $c, $d, $m[13], 5, 28);
        $step!(G, $d, $a, $b, $c, $m[2], 9, 29);
        $step!(G, $c, $d, $a, $b, $m[7], 14, 30);
        $step!(G, $b, $c, $d, $a, $m[12], 20, 31);

        // Round 3: H, shifts 4/11/16/23, message word (5 + 3i) mod 16.
        $step!(H, $a, $b, $c, $d, $m[5], 4, 32);
        $step!(H, $d, $a, $b, $c, $m[8], 11, 33);
        $step!(H, $c, $d, $a, $b, $m[11], 16, 34);
        $step!(H, $b, $c, $d, $a, $m[14], 23, 35);
        $step!(H, $a, $b, $c, $d, $m[1], 4, 36);
        $step!(H, $d, $a, $b, $c, $m[4], 11, 37);
        $step!(H, $c, $d, $a, $b, $m[7], 16, 38);
        $step!(H, $b, $c, $d, $a, $m[10], 23, 39);
        $step!(H, $a, $b, $c, $d, $m[13], 4, 40);
        $step!(H, $d, $a, $b, $c, $m[0], 11, 41);
        $step!(H, $c, $d, $a, $b, $m[3], 16, 42);
        $step!(H, $b, $c, $d, $a, $m[6], 23, 43);
        $step!(H, $a, $b, $c, $d, $m[9], 4, 44);
        $step!(H, $d, $a, $b, $c, $m[12], 11, 45);
        $step!(H, $c, $d, $a, $b, $m[15], 16, 46);
        $step!(H, $b, $c, $d, $a, $m[2], 23, 47);

        // Round 4: I, shifts 6/10/15/21, message word 7i mod 16.
        $step!(I, $a, $b, $c, $d, $m[0], 6, 48);
        $step!(I, $d, $a, $b, $c, $m[7], 10, 49);
        $step!(I, $c, $d, $a, $b, $m[14], 15, 50);
        $step!(I, $b, $c, $d, $a, $m[5], 21, 51);
        $step!(I, $a, $b, $c, $d, $m[12], 6, 52);
        $step!(I, $d, $a, $b, $c, $m[3], 10, 53);
        $step!(I, $c, $d, $a, $b, $m[10], 15, 54);
        $step!(I, $b, $c, $d, $a, $m[1], 21, 55);
        $step!(I, $a, $b, $c, $d, $m[8], 6, 56);
        $step!(I, $d, $a, $b, $c, $m[15], 10, 57);
        $step!(I, $c, $d, $a, $b, $m[6], 15, 58);
        $step!(I, $b, $c, $d, $a, $m[13], 21, 59);
        $step!(I, $a, $b, $c, $d, $m[4], 6, 60);
        $step!(I, $d, $a, $b, $c, $m[11], 10, 61);
        $step!(I, $c, $d, $a, $b, $m[2], 15, 62);
        $step!(I, $b, $c, $d, $a, $m[9], 21, 63);
    };
}

#[cfg(target_arch = "aarch64")]
mod aarch64;
mod digest;
mod scalar;
#[cfg(target_arch = "x86_64")]
mod x86;

use digest::T;

pub use digest::{digest, digest_many, hex_digest};
