//! GHASH (SP 800-38D section 6.4), the parts every backend shares, and the
//! choice between the backends.
//!
//! A 16-byte block is two 64-bit big-endian words, `[hi, lo]`, the first byte
//! of the block starting `hi`. In GCM's bit order that makes the most
//! significant bit of `hi` the coefficient of `x^0`: the polynomial is stored
//! bit-reflected. The backends differ only in how they multiply; they hand back
//! an unreduced 256-bit product, and [`reduce`] finishes it the same way for
//! all of them.

use super::scalar;
use crate::wipe::wipe;

/// How many blocks the hardware backends multiply before they reduce: they
/// hash `Y = (Y ^ X1) H^16 ^ X2 H^15 ^ ... ^ X16 H` as sixteen independent
/// products and one reduction, with the powers of `H` computed once per key.
/// Fewer leave the multipliers waiting on the reduction between groups: with
/// eight, GHASH measured 30% slower on an Apple M1 Pro. Thirty-two, tried with
/// an earlier Karatsuba version of the backends, was no faster than sixteen.
pub(super) const AGGREGATE: usize = 16;

/// A block as `[hi, lo]`.
pub(super) fn words(block: &[u8; 16]) -> (u64, u64) {
    let (hi, lo) = block.split_at(8);
    (
        u64::from_be_bytes(hi.try_into().expect("8 bytes")),
        u64::from_be_bytes(lo.try_into().expect("8 bytes")),
    )
}

/// Reduces a 256-bit carry-less product of two bit-reflected values, `[v0, v1,
/// v2, v3]` with `v3` the most significant word, to the element of GF(2^128)
/// it stands for, as `[hi, lo]`. GCM's polynomial is `x^128 + x^7 + x^2 + x +
/// 1`.
///
/// A sum of such products reduces to the sum of their reductions, which is what
/// lets the hardware backends add sixteen products before calling this once.
pub(super) fn reduce(v: [u64; 4]) -> [u64; 2] {
    let [v0, v1, v2, v3] = v;

    // The product of two bit-reflected 128-bit values is the reflection of the
    // true product shifted right by one, so shift it back.
    let v3 = (v3 << 1) | (v2 >> 63);
    let v2 = (v2 << 1) | (v1 >> 63);
    let v1 = (v1 << 1) | (v0 >> 63);
    let v0 = v0 << 1;

    // The coefficients of x^128 to x^255 are in `v1` and `v0`, and x^128 = x^7
    // + x^2 + x + 1, which in the reflected layout is a shift right by 0, 1, 2
    // and 7 into the low half. `v0` goes first: the bits its shifts push below
    // the low half are still of degree 128 or more, and join `v1`.
    let v2 = v2 ^ v0 ^ (v0 >> 1) ^ (v0 >> 2) ^ (v0 >> 7);
    let v1 = v1 ^ (v0 << 63) ^ (v0 << 62) ^ (v0 << 57);
    let v3 = v3 ^ v1 ^ (v1 >> 1) ^ (v1 >> 2) ^ (v1 >> 7);
    let v2 = v2 ^ (v1 << 63) ^ (v1 << 62) ^ (v1 << 57);
    [v3, v2]
}

#[cfg(target_arch = "aarch64")]
#[inline]
fn has_pmull() -> bool {
    // Rust reports `aes` only where FEAT_PMULL is present as well. On targets
    // where it is part of the baseline (aarch64-apple-darwin) the check folds
    // away at compile time.
    cfg!(target_feature = "aes") || std::arch::is_aarch64_feature_detected!("aes")
}

#[cfg(target_arch = "x86_64")]
#[inline]
fn has_pclmulqdq() -> bool {
    // SSSE3 for the byte shuffle that reverses a block.
    std::arch::is_x86_feature_detected!("pclmulqdq") && std::arch::is_x86_feature_detected!("ssse3")
}

/// A GHASH backend.
///
/// A hardware variant only says which backend to prefer: [`Ghash`] checks the
/// CPU feature again before every call into it, and falls back to `Scalar`
/// without it, so no value of this type can make the code run an instruction
/// the CPU lacks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Backend {
    Scalar,
    #[cfg(target_arch = "aarch64")]
    Aarch64,
    #[cfg(target_arch = "x86_64")]
    X86,
}

impl Backend {
    /// The fastest backend this CPU supports.
    pub(super) fn detect() -> Self {
        #[cfg(target_arch = "aarch64")]
        if has_pmull() {
            return Backend::Aarch64;
        }
        #[cfg(target_arch = "x86_64")]
        if has_pclmulqdq() {
            return Backend::X86;
        }
        Backend::Scalar
    }

    /// Every backend this CPU supports, the one [`detect`](Self::detect)
    /// picks first and `Scalar` last.
    #[cfg(test)]
    pub(super) fn available() -> Vec<Self> {
        let mut list = Vec::new();
        #[cfg(target_arch = "aarch64")]
        if has_pmull() {
            list.push(Backend::Aarch64);
        }
        #[cfg(target_arch = "x86_64")]
        if has_pclmulqdq() {
            list.push(Backend::X86);
        }
        list.push(Backend::Scalar);
        list
    }

    #[cfg(test)]
    pub(super) fn name(self) -> &'static str {
        match self {
            Backend::Scalar => "scalar (ctmul64)",
            #[cfg(target_arch = "aarch64")]
            Backend::Aarch64 => "aarch64 (PMULL)",
            #[cfg(target_arch = "x86_64")]
            Backend::X86 => "x86_64 (PCLMULQDQ)",
        }
    }
}

/// `H^1` to `H^16`, which the hardware backends multiply by, each as `[lo,
/// hi]`: the order of the two 64-bit lanes of a vector register, so that the
/// backends load them as they are. Wiped when dropped.
pub(super) struct Powers(pub(super) [[u64; 2]; AGGREGATE]);

impl Drop for Powers {
    fn drop(&mut self) {
        wipe(&mut self.0);
    }
}

/// The hash key `H = E_K(0^128)`, in the forms the backends use, and the
/// backend to use it with. Both forms wipe themselves when dropped.
pub(super) struct HashKey {
    backend: Backend,
    scalar: scalar::Key,
    /// Only the hardware backends read this, and a target without one (RISC-V,
    /// say) computes it for nothing.
    #[cfg_attr(
        not(any(target_arch = "aarch64", target_arch = "x86_64")),
        allow(dead_code)
    )]
    powers: Powers,
}

impl HashKey {
    pub(super) fn new(h: &[u8; 16], backend: Backend) -> Self {
        let (hi, lo) = words(h);
        let scalar = scalar::Key::new([hi, lo]);
        let mut powers = Powers([[0; 2]; AGGREGATE]);
        let mut power = [hi, lo];
        for slot in &mut powers.0 {
            *slot = [power[1], power[0]];
            power = scalar::mul(power, &scalar);
        }
        wipe(&mut power);
        Self {
            backend,
            scalar,
            powers,
        }
    }
}

/// GHASH over a sequence of inputs, each padded with zeros to a whole number
/// of blocks.
pub(super) struct Ghash<'k> {
    key: &'k HashKey,
    /// The running value, `[hi, lo]`.
    y: [u64; 2],
}

impl<'k> Ghash<'k> {
    pub(super) fn new(key: &'k HashKey) -> Self {
        Self { key, y: [0; 2] }
    }

    /// Absorbs `data`, and zeros up to the end of its last block.
    pub(super) fn update(&mut self, data: &[u8]) {
        let (blocks, rest) = data.as_chunks::<16>();
        self.blocks(blocks);
        if !rest.is_empty() {
            let mut last = [0u8; 16];
            last[..rest.len()].copy_from_slice(rest);
            self.blocks(&[last]);
        }
    }

    /// Absorbs whole blocks, on the backend of the key.
    fn blocks(&mut self, blocks: &[[u8; 16]]) {
        match self.key.backend {
            #[cfg(target_arch = "aarch64")]
            Backend::Aarch64 if has_pmull() => {
                // SAFETY: has_pmull() just confirmed the `aes` feature, which
                // includes FEAT_PMULL.
                unsafe { super::aarch64::update(&self.key.powers, &mut self.y, blocks) }
            }
            #[cfg(target_arch = "x86_64")]
            Backend::X86 if has_pclmulqdq() => {
                // SAFETY: has_pclmulqdq() just confirmed `pclmulqdq` and
                // `ssse3`.
                unsafe { super::x86::update(&self.key.powers, &mut self.y, blocks) }
            }
            _ => scalar::update(&self.key.scalar, &mut self.y, blocks),
        }
    }

    /// Absorbs the length block `[len(A)]_64 || [len(C)]_64`, in bits, and
    /// returns the hash.
    pub(super) fn finish(mut self, aad_len: usize, text_len: usize) -> [u8; 16] {
        // The caller has kept both below 2^61 bytes, so the bit counts fit.
        let bits = |len: usize| ((len as u64) * 8).to_be_bytes();
        let mut lengths = [0u8; 16];
        lengths[..8].copy_from_slice(&bits(aad_len));
        lengths[8..].copy_from_slice(&bits(text_len));
        self.blocks(&[lengths]);
        let mut out = [0u8; 16];
        out[..8].copy_from_slice(&self.y[0].to_be_bytes());
        out[8..].copy_from_slice(&self.y[1].to_be_bytes());
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gcm::tests::stream;

    /// GHASH of `data` under `h` on `backend`, starting from `y`.
    fn hash(backend: Backend, h: &[u8; 16], y: [u64; 2], data: &[u8]) -> [u8; 16] {
        let key = HashKey::new(h, backend);
        let mut ghash = Ghash::new(&key);
        ghash.y = y;
        ghash.update(data);
        ghash.finish(0, data.len())
    }

    /// Checks that every other backend this CPU can run hashes exactly as the
    /// scalar one does, over lengths that straddle the groups of sixteen blocks
    /// the hardware backends reduce at a time, and with a running value that is
    /// not zero, which the first block of each call takes in.
    #[test]
    fn matches_scalar_backend() {
        let others: Vec<Backend> = Backend::available()
            .into_iter()
            .filter(|&backend| backend != Backend::Scalar)
            .collect();
        for &backend in &others {
            for i in 0..64u32 {
                let h: [u8; 16] = stream(b"ghash key", i, 16).try_into().unwrap();
                let y = [
                    u64::from(i).wrapping_mul(0x9e37_79b9_7f4a_7c15),
                    !u64::from(i),
                ];
                for len in [
                    0, 1, 15, 16, 17, 112, 127, 128, 129, 143, 144, 255, 256, 257, 1000,
                ] {
                    let data = stream(b"ghash data", i, len);
                    assert_eq!(
                        hash(backend, &h, y, &data),
                        hash(Backend::Scalar, &h, y, &data),
                        "{}, i = {i}, {len} bytes",
                        backend.name()
                    );
                }
            }
            println!("{} backend matches scalar", backend.name());
        }
        if others.is_empty() {
            println!("no carry-less multiply on this CPU; only the scalar GHASH is in use");
        }
    }

    /// Checks that the result does not depend on where in memory the blocks
    /// sit: the hardware backends load them with unaligned vector loads. Every
    /// backend is checked, not just the one the dispatcher picks.
    #[test]
    fn unaligned_input() {
        let h: [u8; 16] = stream(b"unaligned key", 0, 16).try_into().unwrap();
        let data = stream(b"unaligned data", 0, 300);
        let want = hash(Backend::Scalar, &h, [0; 2], &data);
        for backend in Backend::available() {
            for offset in 0..16 {
                let mut buffer = vec![0u8; offset + data.len()];
                buffer[offset..].copy_from_slice(&data);
                assert_eq!(
                    hash(backend, &h, [0; 2], &buffer[offset..]),
                    want,
                    "{}, offset = {offset}",
                    backend.name()
                );
            }
        }
    }

    /// Dropping the powers of `H` must leave none of them behind. (The scalar
    /// form of the key has a test of its own.)
    #[test]
    fn dropping_wipes_the_powers() {
        let key = HashKey::new(&[0x77; 16], Backend::Scalar);
        let powers = Powers(key.powers.0);
        // SAFETY: the powers are 32 `u64`s, with no padding.
        let (before, after) = unsafe { crate::wipe::bytes_around_drop(powers) };
        assert!(before.iter().any(|&b| b != 0), "no powers to wipe");
        assert!(after.iter().all(|&b| b == 0), "the powers survive the drop");
    }
}
