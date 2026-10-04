//! SHA-256 compression for x86-64 CPUs with AVX2 and BMI2 but without the SHA
//! extensions (Intel's cores from Haswell until SHA-NI arrived with Ice Lake).
//!
//! Nothing here speeds up the rounds themselves: they are as serial as ever,
//! and run in general-purpose registers just like in `super::scalar`, using
//! the same helper functions, compiled with BMI2's `rorx` and BMI1's `andn`.
//! What AVX2 takes over is the message schedule, the other half of the work.
//! It is computed for *two* blocks at once, one in each 128-bit half of a
//! 256-bit register, four words per block per step, and each word is stored
//! with its round constant already added. The first block's rounds then run
//! interleaved with that vector work, which uses different execution units
//! and fills the cycles the rounds spend waiting on each other; the second
//! block's rounds find all of their words ready and do no schedule work at
//! all.
//!
//! This is the design of Intel's white paper "Fast SHA-256 Implementations on
//! Intel Architecture Processors" (Guilford, Yap and Gopal, 2012).
//!
//! This code only runs via `super::compress`, which checks the `avx2`,
//! `bmi1` and `bmi2` CPU features are present before calling it.

use core::arch::x86_64::*;

use super::K;
use super::scalar::{big_sigma0, big_sigma1, ch, maj};

/// The schedule of two blocks, with the round constants already added: for
/// group `g` (rounds `4g` to `4g + 3`), `words[8g..8g + 4]` belong to the first
/// block and `words[8g + 4..8g + 8]` to the second, the layout of the 256-bit
/// register they were computed in.
#[repr(C, align(32))]
struct Schedule {
    words: [u32; 128],
}

/// Runs one round, as `super::scalar` does on targets other than aarch64,
/// except that `$wk` is `K[t] + W[t]`, read from the precomputed schedule.
/// The new `e` is written into whichever variable is passed as `$d`, and the
/// new `a` into whichever is passed as `$h`.
macro_rules! round {
    ($a:ident, $b:ident, $c:ident, $d:ident, $e:ident, $f:ident, $g:ident, $h:ident, $bc:ident, $wk:expr) => {
        let t1 = $h
            .wrapping_add(big_sigma1($e))
            .wrapping_add(ch($e, $f, $g))
            .wrapping_add($wk);
        $d = $d.wrapping_add(t1);
        $h = t1
            .wrapping_add(big_sigma0($a))
            .wrapping_add(maj($a, $b, &mut $bc));
    };
}

/// Runs the four rounds of one group, reading their words from
/// `$schedule.words[$i..$i + 4]`. Afterwards `a`-`d` and `e`-`h` have traded
/// places, so consecutive calls alternate between passing the variables as
/// `a, b, c, d, e, f, g, h` and as `e, f, g, h, a, b, c, d`.
macro_rules! four_rounds {
    ($a:ident, $b:ident, $c:ident, $d:ident, $e:ident, $f:ident, $g:ident, $h:ident, $bc:ident, $schedule:ident, $i:expr) => {
        round!($a, $b, $c, $d, $e, $f, $g, $h, $bc, $schedule.words[$i]);
        round!($h, $a, $b, $c, $d, $e, $f, $g, $bc, $schedule.words[$i + 1]);
        round!($g, $h, $a, $b, $c, $d, $e, $f, $bc, $schedule.words[$i + 2]);
        round!($f, $g, $h, $a, $b, $c, $d, $e, $bc, $schedule.words[$i + 3]);
    };
}

/// Rotates every 32-bit word of `x` right by `N` bits. AVX2 has no vector
/// rotate, so this is two shifts and an OR; `M` must be `32 - N`.
#[target_feature(enable = "avx2")]
#[inline]
fn rotr<const N: i32, const M: i32>(x: __m256i) -> __m256i {
    _mm256_or_si256(_mm256_srli_epi32::<N>(x), _mm256_slli_epi32::<M>(x))
}

/// FIPS 180-4 section 4.1.2: the lowercase sigma used by the message
/// schedule, on eight words at once.
#[target_feature(enable = "avx2")]
#[inline]
fn small_sigma0(x: __m256i) -> __m256i {
    _mm256_xor_si256(
        _mm256_xor_si256(rotr::<7, 25>(x), rotr::<18, 14>(x)),
        _mm256_srli_epi32::<3>(x),
    )
}

/// FIPS 180-4 section 4.1.2: the other lowercase sigma of the message
/// schedule, on eight words at once.
#[target_feature(enable = "avx2")]
#[inline]
fn small_sigma1(x: __m256i) -> __m256i {
    _mm256_xor_si256(
        _mm256_xor_si256(rotr::<17, 15>(x), rotr::<19, 13>(x)),
        _mm256_srli_epi32::<10>(x),
    )
}

/// Computes the next group of four schedule words of both blocks.
///
/// `x0`..`x3` hold the four previous groups, oldest first: words `t - 16` to
/// `t - 1`, four per register, in each 128-bit half. Each new word is
/// `small_sigma1(w[t-2]) + w[t-7] + small_sigma0(w[t-15]) + w[t-16]`. The
/// `w[t-7]` and `w[t-15]` terms straddle two groups and are picked out by
/// four-byte shifts across them (which AVX2 does within each half, so the two
/// blocks never mix). The `w[t-2]` term is the catch: for the last two of the
/// four new words it is one of the *first two new words*, so those are
/// finished first and then fed back.
#[target_feature(enable = "avx2")]
#[inline]
fn next_words(x0: __m256i, x1: __m256i, x2: __m256i, x3: __m256i) -> __m256i {
    let w15 = _mm256_alignr_epi8::<4>(x1, x0); // w[t-15..t-12]
    let w7 = _mm256_alignr_epi8::<4>(x3, x2); // w[t-7..t-4]
    let partial = _mm256_add_epi32(_mm256_add_epi32(x0, w7), small_sigma0(w15));

    // Words t and t + 1: their w[t-2] terms are words 2 and 3 of `x3`. The
    // blend keeps only the two results that belong in these positions.
    let s1 = small_sigma1(_mm256_shuffle_epi32::<0b11_10_11_10>(x3));
    let low = _mm256_add_epi32(
        partial,
        _mm256_blend_epi32::<0b1100_1100>(s1, _mm256_setzero_si256()),
    );

    // Words t + 2 and t + 3: their w[t-2] terms are the words just finished.
    let s1 = small_sigma1(_mm256_shuffle_epi32::<0b01_00_01_00>(low));
    _mm256_add_epi32(
        low,
        _mm256_blend_epi32::<0b0011_0011>(s1, _mm256_setzero_si256()),
    )
}

/// Adds the round constants of group `group` to `words` (the same four in
/// both halves) and stores the result at its place in `schedule`.
#[target_feature(enable = "avx2")]
#[inline]
fn store(schedule: &mut Schedule, group: usize, words: __m256i) {
    assert!(group < 16);
    // SAFETY: `group` is at most 15, so the four words read from `K` at
    // `4 * group` end at or before `K[63]`.
    let k =
        _mm256_broadcastsi128_si256(unsafe { _mm_loadu_si128(K.as_ptr().add(4 * group).cast()) });
    // SAFETY: `group` is at most 15, so the eight words written at
    // `8 * group` end at or before `words[127]`. That offset is a multiple of
    // 32 bytes and `Schedule` is 32-byte aligned, as the aligned store needs.
    unsafe {
        _mm256_store_si256(
            schedule.words.as_mut_ptr().add(8 * group).cast(),
            _mm256_add_epi32(words, k),
        );
    }
}

/// Hashes every full 64-byte block in `blocks` into `state`, two at a time.
///
/// Any leftover bytes that don't fill a whole block are ignored; it's up to
/// the caller to pad the message first (see `super::digest`).
///
/// # Safety
///
/// The caller must make sure the `avx2`, `bmi1` and `bmi2` CPU features are
/// available. `super::compress` is the only caller, and it checks this
/// already. Nothing else needs checking: the input is split into whole
/// 64-byte blocks with `as_chunks`, so every load below is safely in bounds,
/// and `state` is a fixed-size array.
#[target_feature(enable = "avx2,bmi1,bmi2")]
pub(super) unsafe fn compress(state: &mut [u32; 8], blocks: &[u8]) {
    let (blocks, _) = blocks.as_chunks::<64>();
    let (pairs, odd) = blocks.as_chunks::<2>();
    for [first, second] in pairs {
        hash_blocks(state, first, Some(second));
    }
    // An odd block out goes through the same code alone.
    if let [last] = odd {
        hash_blocks(state, last, None);
    }
}

/// Hashes `first` and then, if there is one, `second` into `state`.
///
/// Without a second block, the first is loaded into both halves of the
/// schedule registers, so the vector work is the same; only the second set of
/// rounds is skipped.
#[target_feature(enable = "avx2,bmi1,bmi2")]
fn hash_blocks(state: &mut [u32; 8], first: &[u8; 64], second: Option<&[u8; 64]>) {
    // Reverses the bytes of each 32-bit word, because SHA-256 reads the
    // message big-endian; the same 128-bit mask in both halves.
    let mask =
        _mm256_broadcastsi128_si256(_mm_set_epi64x(0x0c0d_0e0f_0809_0a0b, 0x0405_0607_0001_0203));

    // Group `i` of both blocks: the first in the low half, the second in the
    // high half.
    let upper = second.unwrap_or(first);
    let load = |i: usize| {
        // SAFETY: both blocks are 64 bytes and `i` is at most 3, so each
        // 16-byte load at `16 * i` is in bounds.
        let (lo, hi) = unsafe {
            (
                _mm_loadu_si128(first.as_ptr().add(16 * i).cast()),
                _mm_loadu_si128(upper.as_ptr().add(16 * i).cast()),
            )
        };
        _mm256_shuffle_epi8(_mm256_set_m128i(hi, lo), mask)
    };
    let (mut x0, mut x1, mut x2, mut x3) = (load(0), load(1), load(2), load(3));

    let mut schedule = Schedule { words: [0; 128] };
    store(&mut schedule, 0, x0);
    store(&mut schedule, 1, x1);
    store(&mut schedule, 2, x2);
    store(&mut schedule, 3, x3);

    // The first block. While each group of four rounds runs, the group four
    // ahead is computed and stored; `x0`..`x3` take turns holding the oldest
    // group, which is the one being replaced.
    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;
    let mut bc = b ^ c;
    four_rounds!(a, b, c, d, e, f, g, h, bc, schedule, 0);
    x0 = next_words(x0, x1, x2, x3);
    store(&mut schedule, 4, x0);
    four_rounds!(e, f, g, h, a, b, c, d, bc, schedule, 8);
    x1 = next_words(x1, x2, x3, x0);
    store(&mut schedule, 5, x1);
    four_rounds!(a, b, c, d, e, f, g, h, bc, schedule, 16);
    x2 = next_words(x2, x3, x0, x1);
    store(&mut schedule, 6, x2);
    four_rounds!(e, f, g, h, a, b, c, d, bc, schedule, 24);
    x3 = next_words(x3, x0, x1, x2);
    store(&mut schedule, 7, x3);
    four_rounds!(a, b, c, d, e, f, g, h, bc, schedule, 32);
    x0 = next_words(x0, x1, x2, x3);
    store(&mut schedule, 8, x0);
    four_rounds!(e, f, g, h, a, b, c, d, bc, schedule, 40);
    x1 = next_words(x1, x2, x3, x0);
    store(&mut schedule, 9, x1);
    four_rounds!(a, b, c, d, e, f, g, h, bc, schedule, 48);
    x2 = next_words(x2, x3, x0, x1);
    store(&mut schedule, 10, x2);
    four_rounds!(e, f, g, h, a, b, c, d, bc, schedule, 56);
    x3 = next_words(x3, x0, x1, x2);
    store(&mut schedule, 11, x3);
    four_rounds!(a, b, c, d, e, f, g, h, bc, schedule, 64);
    x0 = next_words(x0, x1, x2, x3);
    store(&mut schedule, 12, x0);
    four_rounds!(e, f, g, h, a, b, c, d, bc, schedule, 72);
    x1 = next_words(x1, x2, x3, x0);
    store(&mut schedule, 13, x1);
    four_rounds!(a, b, c, d, e, f, g, h, bc, schedule, 80);
    x2 = next_words(x2, x3, x0, x1);
    store(&mut schedule, 14, x2);
    four_rounds!(e, f, g, h, a, b, c, d, bc, schedule, 88);
    x3 = next_words(x3, x0, x1, x2);
    store(&mut schedule, 15, x3);
    // Groups 12 to 15: the whole schedule has been produced by now.
    four_rounds!(a, b, c, d, e, f, g, h, bc, schedule, 96);
    four_rounds!(e, f, g, h, a, b, c, d, bc, schedule, 104);
    four_rounds!(a, b, c, d, e, f, g, h, bc, schedule, 112);
    four_rounds!(e, f, g, h, a, b, c, d, bc, schedule, 120);
    add_into(state, [a, b, c, d, e, f, g, h]);

    if second.is_none() {
        return;
    }

    // The second block: the same rounds, reading the high half of each group.
    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;
    let mut bc = b ^ c;
    four_rounds!(a, b, c, d, e, f, g, h, bc, schedule, 4);
    four_rounds!(e, f, g, h, a, b, c, d, bc, schedule, 12);
    four_rounds!(a, b, c, d, e, f, g, h, bc, schedule, 20);
    four_rounds!(e, f, g, h, a, b, c, d, bc, schedule, 28);
    four_rounds!(a, b, c, d, e, f, g, h, bc, schedule, 36);
    four_rounds!(e, f, g, h, a, b, c, d, bc, schedule, 44);
    four_rounds!(a, b, c, d, e, f, g, h, bc, schedule, 52);
    four_rounds!(e, f, g, h, a, b, c, d, bc, schedule, 60);
    four_rounds!(a, b, c, d, e, f, g, h, bc, schedule, 68);
    four_rounds!(e, f, g, h, a, b, c, d, bc, schedule, 76);
    four_rounds!(a, b, c, d, e, f, g, h, bc, schedule, 84);
    four_rounds!(e, f, g, h, a, b, c, d, bc, schedule, 92);
    four_rounds!(a, b, c, d, e, f, g, h, bc, schedule, 100);
    four_rounds!(e, f, g, h, a, b, c, d, bc, schedule, 108);
    four_rounds!(a, b, c, d, e, f, g, h, bc, schedule, 116);
    four_rounds!(e, f, g, h, a, b, c, d, bc, schedule, 124);
    add_into(state, [a, b, c, d, e, f, g, h]);
}

/// Adds one block's final working variables back into the running state.
#[inline]
fn add_into(state: &mut [u32; 8], vars: [u32; 8]) {
    for (s, v) in state.iter_mut().zip(vars) {
        *s = s.wrapping_add(v);
    }
}
