//! Helpers for the tests of this module.

/// A reproducible stream of numbers (xorshift64*).
pub(super) struct Prng(pub u64);

impl Prng {
    pub(super) fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    /// A number in `[-bound, bound]`.
    pub(super) fn signed(&mut self, bound: i32) -> i32 {
        (self.next() % (2 * bound as u64 + 1)) as i32 - bound
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
