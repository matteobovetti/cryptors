//! Helpers for the tests of this module.

use super::algorithm::{expand_key, hash_g};
use super::keypair::DecapsulationKey;
use super::params::{Parameters, SEED_LEN};

/// A reproducible stream of numbers (xorshift64*).
pub(super) struct Prng(pub u64);

impl Prng {
    pub(super) fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    /// A number in `0..bound`.
    pub(super) fn below(&mut self, bound: u64) -> u64 {
        self.next() % bound
    }

    pub(super) fn bytes(&mut self, len: usize) -> Vec<u8> {
        (0..len).map(|_| (self.next() >> 56) as u8).collect()
    }
}

pub(super) fn unhex(s: &str) -> Vec<u8> {
    assert!(s.len().is_multiple_of(2), "odd number of hex digits");
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
        .collect()
}

pub(super) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The key of the draft of FIPS 203, whose `K-PKE.KeyGen` hashes `d` alone,
/// without the `k` of the final standard: the key that C2SP's vectors are for.
/// Everything after the hash is the same.
pub(super) fn draft_key<P: Parameters>(seed: &[u8; SEED_LEN]) -> DecapsulationKey<P> {
    let (rho, sigma) = hash_g(seed[..32].try_into().unwrap(), &[]);
    DecapsulationKey::from_generated(seed, expand_key::<P>(&rho, sigma))
}
