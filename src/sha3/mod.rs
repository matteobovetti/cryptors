//! From-scratch SHA-3 and SHAKE implementation (FIPS 202).
//!
//! Every function here is built on one permutation, Keccak-f\[1600\], applied
//! through the "sponge" construction: the input is XORed into a 1600-bit
//! state `rate` bits at a time (absorbing) with the permutation run between
//! blocks, and once the whole input is absorbed the state is read back out
//! `rate` bits at a time (squeezing), permuting again between reads if more
//! output is wanted than one block holds.
//!
//! Unlike MD5 and SHA-1, SHA-3 is not broken: it has no practical collision
//! or preimage attack, and the sponge is structurally immune to the
//! length-extension weakness of Merkle-Damgard designs.
//!
//! # What is accelerated
//!
//! Hashing *one* message is inherently serial -- block `n + 1` cannot be
//! absorbed until block `n` has been permuted -- so a single digest can only
//! be sped up by making the permutation itself cheaper. ARMv8.2's SHA-3
//! extension does exactly that, fusing Keccak's XOR/rotate/and-not patterns
//! into single instructions:
//!
//! | Backend | Architecture | Requires | Messages at once |
//! |---------|--------------|----------|------------------|
//! | [`aarch64`] (FEAT_SHA3) | AArch64 | `sha3` | 1 |
//! | [`scalar`], BMI1/BMI2 build | x86-64 | `bmi1` and `bmi2` | 1 |
//! | [`scalar`] | any | nothing -- always available | 1 |
//!
//! **No x86 CPU implements Keccak.** SHA-NI covers SHA-1 and SHA-256 only, so
//! a single message on x86 runs on [`scalar`]. Where the CPU has BMI1 and
//! BMI2, it runs a second build of the same code that uses their `andn` and
//! `rorx`, which cuts about a quarter of the instructions in every round.
//! Plain SIMD does not help a single message: Keccak's 25-lane state and
//! 5-wide rows map badly onto 4-lane registers, and the shuffling needed
//! costs more than it saves -- which is why the Keccak team's own reference
//! code ships no single-message AVX2 variant.
//!
//! What *is* parallel is hashing several independent messages, exactly as for
//! [`crate::md5`]. The `*_many` functions put one message per vector lane and
//! run several sponges side by side:
//!
//! | Backend | Architecture | Requires | Messages at once |
//! |---------|--------------|----------|------------------|
//! | [`x86`] (AVX2) | x86-64 | `avx2` | 4 |
//! | [`x86`] (SSE2) | x86-64 | `sse2` -- always on x86-64 | 2 |
//! | [`aarch64`] (FEAT_SHA3) | AArch64 | `sha3` | 2 |
//! | [`scalar`] | any | nothing -- always available | 1 |
//!
//! The manual `Benchmarks` workflow (`.github/workflows/bench.yml`) measures
//! the backends on real x86-64 and AArch64 runners.
//!
//! Keccak's rho step rotates each of the 25 state lanes by a fixed amount
//! that depends only on *which* lane it is, never on the message. So in a
//! batch every vector lane wants the same rotation, and on aarch64 the
//! multi-buffer backend gets the SHA-3 extension's fused instructions *and*
//! two messages per register from the same code.
//!
//! [`scalar`] is the backend we trust to be correct; every other backend is
//! checked against it byte-for-byte by the `matches_scalar_backend` test, and
//! [`scalar`] itself is checked against FIPS 202's own vectors and against a
//! second, independently written permutation.

/// One round of Keccak-f\[1600\], written once and shared by every vector
/// backend.
///
/// [`scalar::permute`] runs an in-place variant instead: the same round, with
/// chi done row by row and lanes stored in a rotating layout. That saves
/// general-purpose registers. Doing chi row by row was found to make the
/// FEAT_SHA3 backend slower, so the vector backends keep this form.
///
/// The five step mappings of FIPS 202 Section 3.2 are expressed in terms of
/// five operations, supplied by the caller as macros so each backend can say
/// *how* it computes them while the sequence of steps stays identical:
///
/// | Operation | Must compute | Fused instruction |
/// |-----------|--------------|-------------------|
/// | `$xor5!(a, b, c, d, e)` | `a ^ b ^ c ^ d ^ e` | 2x `EOR3` |
/// | `$rax1!(a, b)` | `a ^ rotl(b, 1)` | `RAX1` |
/// | `$xar!(a, b, N)` | `rotl(a ^ b, N)` | `XAR` |
/// | `$xor!(a, b)` | `a ^ b` | `EOR` |
/// | `$bcax!(a, b, c)` | `a ^ (!b & c)` | `BCAX` |
///
/// Note the operand order of `$bcax!`: ARM's `BCAX` instruction computes
/// `a ^ (b & !c)`, so the aarch64 backend passes its last two arguments the
/// other way round to satisfy the contract above.
///
/// `$a` is the 25-lane state, indexed flat as `$a[x + 5y]`. `$rc` is this
/// round's iota constant, already widened to the backend's value type.
///
/// theta's final XOR is folded into rho's rotation and pi's relocation, so
/// the three become one `$xar!` per lane: lane `$a[src]` is XORed with its
/// column's `d`, rotated by its own rho offset, and lands at its pi
/// destination. The source, destination and rotation of all 25 are derived
/// from FIPS 202 Algorithm 2 (`(x, y) -> (y, 2x + 3y)`, rotating by the
/// triangular numbers mod 64); lane 0 is the one fixed point, and rotates by
/// zero, so it uses a plain `$xor!`.
macro_rules! keccak_round {
    (
        $xor5:ident, $rax1:ident, $xar:ident, $xor:ident, $bcax:ident,
        $a:ident, $rc:expr
    ) => {{
        // Theta, part 1: the parity of each of the five columns.
        let c0 = $xor5!($a[0], $a[5], $a[10], $a[15], $a[20]);
        let c1 = $xor5!($a[1], $a[6], $a[11], $a[16], $a[21]);
        let c2 = $xor5!($a[2], $a[7], $a[12], $a[17], $a[22]);
        let c3 = $xor5!($a[3], $a[8], $a[13], $a[18], $a[23]);
        let c4 = $xor5!($a[4], $a[9], $a[14], $a[19], $a[24]);

        // Theta, part 2: d[x] = c[x - 1] ^ rotl(c[x + 1], 1).
        let d0 = $rax1!(c4, c1);
        let d1 = $rax1!(c0, c2);
        let d2 = $rax1!(c1, c3);
        let d3 = $rax1!(c2, c4);
        let d4 = $rax1!(c3, c0);

        // Theta part 3 + rho + pi, fused.
        let b0 = $xor!($a[0], d0);
        let b1 = $xar!($a[6], d1, 44);
        let b2 = $xar!($a[12], d2, 43);
        let b3 = $xar!($a[18], d3, 21);
        let b4 = $xar!($a[24], d4, 14);
        let b5 = $xar!($a[3], d3, 28);
        let b6 = $xar!($a[9], d4, 20);
        let b7 = $xar!($a[10], d0, 3);
        let b8 = $xar!($a[16], d1, 45);
        let b9 = $xar!($a[22], d2, 61);
        let b10 = $xar!($a[1], d1, 1);
        let b11 = $xar!($a[7], d2, 6);
        let b12 = $xar!($a[13], d3, 25);
        let b13 = $xar!($a[19], d4, 8);
        let b14 = $xar!($a[20], d0, 18);
        let b15 = $xar!($a[4], d4, 27);
        let b16 = $xar!($a[5], d0, 36);
        let b17 = $xar!($a[11], d1, 10);
        let b18 = $xar!($a[17], d2, 15);
        let b19 = $xar!($a[23], d3, 56);
        let b20 = $xar!($a[2], d2, 62);
        let b21 = $xar!($a[8], d3, 55);
        let b22 = $xar!($a[14], d4, 39);
        let b23 = $xar!($a[15], d0, 41);
        let b24 = $xar!($a[21], d1, 2);

        // Chi: each lane XORed with a nonlinear function of its own row.
        $a[0] = $bcax!(b0, b1, b2);
        $a[1] = $bcax!(b1, b2, b3);
        $a[2] = $bcax!(b2, b3, b4);
        $a[3] = $bcax!(b3, b4, b0);
        $a[4] = $bcax!(b4, b0, b1);

        $a[5] = $bcax!(b5, b6, b7);
        $a[6] = $bcax!(b6, b7, b8);
        $a[7] = $bcax!(b7, b8, b9);
        $a[8] = $bcax!(b8, b9, b5);
        $a[9] = $bcax!(b9, b5, b6);

        $a[10] = $bcax!(b10, b11, b12);
        $a[11] = $bcax!(b11, b12, b13);
        $a[12] = $bcax!(b12, b13, b14);
        $a[13] = $bcax!(b13, b14, b10);
        $a[14] = $bcax!(b14, b10, b11);

        $a[15] = $bcax!(b15, b16, b17);
        $a[16] = $bcax!(b16, b17, b18);
        $a[17] = $bcax!(b17, b18, b19);
        $a[18] = $bcax!(b18, b19, b15);
        $a[19] = $bcax!(b19, b15, b16);

        $a[20] = $bcax!(b20, b21, b22);
        $a[21] = $bcax!(b21, b22, b23);
        $a[22] = $bcax!(b22, b23, b24);
        $a[23] = $bcax!(b23, b24, b20);
        $a[24] = $bcax!(b24, b20, b21);

        // Iota: break the round's symmetry.
        $a[0] = $xor!($a[0], $rc);
    }};
}

/// Runs all 24 rounds by invoking [`keccak_round`] once per round constant.
///
/// `$rc` is a macro that widens [`digest::RC`]`[i]` to the backend's value
/// type, so a vector backend broadcasts the constant across its lanes.
macro_rules! keccak_rounds {
    (
        $xor5:ident, $rax1:ident, $xar:ident, $xor:ident, $bcax:ident,
        $a:ident, $rc:ident
    ) => {
        for round in 0..24 {
            let rc = $rc!(super::digest::RC[round]);
            keccak_round!($xor5, $rax1, $xar, $xor, $bcax, $a, rc);
        }
    };
}

#[cfg(target_arch = "aarch64")]
mod aarch64;
mod digest;
mod scalar;
#[cfg(target_arch = "x86_64")]
mod x86;

pub use digest::{
    sha3_224, sha3_224_hex, sha3_224_many, sha3_256, sha3_256_hex, sha3_256_many, sha3_384,
    sha3_384_hex, sha3_384_many, sha3_512, sha3_512_hex, sha3_512_many, shake128, shake128_hex,
    shake128_many, shake256, shake256_hex, shake256_many,
};
