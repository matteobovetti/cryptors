//! Helpers of the tests: hex, the text form of the data files, a reader that
//! returns bytes it was given, the random source of c2sp.org/det-keygen, and keys
//! built from the numbers of a data file.

use super::keypair::PrivateKey;
use crate::hmac::Hmac;
use crate::sha2::Sha256;
use std::io;

pub(super) fn hex(bytes: &[u8]) -> String {
    crate::digest::hex(bytes)
}

/// The bytes of a hex string, which may be empty or `-` (the files' way to write
/// an empty string). An odd number of digits is taken as a number with its
/// leading zero left out.
pub(super) fn unhex(s: &str) -> Vec<u8> {
    if s == "-" {
        return Vec::new();
    }
    let s = if s.len() % 2 == 1 {
        format!("0{s}")
    } else {
        s.to_string()
    };
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).expect("hex"))
        .collect()
}

/// One `[kind]` block of a data file: lines of `key = value`.
pub(super) struct Record<'a> {
    pub(super) kind: &'a str,
    fields: Vec<(&'a str, &'a str)>,
}

impl<'a> Record<'a> {
    pub(super) fn get(&self, key: &str) -> Option<&'a str> {
        self.fields.iter().find(|(k, _)| *k == key).map(|(_, v)| *v)
    }

    pub(super) fn text(&self, key: &str) -> &'a str {
        self.get(key)
            .unwrap_or_else(|| panic!("{} has no {key}", self.kind))
    }

    pub(super) fn bytes(&self, key: &str) -> Vec<u8> {
        unhex(self.text(key))
    }

    pub(super) fn int(&self, key: &str) -> usize {
        self.text(key).parse().expect("a decimal number")
    }

    /// The `e` of a record, which is a hex number that fits 64 bits.
    pub(super) fn exponent(&self) -> u64 {
        u64::from_str_radix(self.text("e"), 16).expect("a hex number")
    }
}

/// The records of a data file, in order.
pub(super) fn records(text: &str) -> Vec<Record<'_>> {
    let mut out: Vec<Record<'_>> = Vec::new();
    for line in text.lines() {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(kind) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            out.push(Record {
                kind,
                fields: Vec::new(),
            });
        } else {
            let (key, value) = line.split_once(" = ").expect("key = value");
            out.last_mut()
                .expect("a field before any record")
                .fields
                .push((key, value));
        }
    }
    out
}

/// The private key that the numbers `n`, `e`, `d`, `p` and `q` of a record make,
/// of any size (the tests run vectors of keys that the public constructor
/// refuses), or `None` if they are refused.
pub(super) fn private_key(r: &Record<'_>) -> Option<PrivateKey> {
    let exponent = u32::try_from(r.exponent()).ok()?;
    PrivateKey::build(
        &r.bytes("n"),
        exponent,
        &r.bytes("d"),
        &r.bytes("p"),
        &r.bytes("q"),
        0,
    )
    .ok()
}

/// A reader that returns the bytes it is given, in order, and `UnexpectedEof`
/// when they are used up.
pub(super) struct Script(pub(super) Vec<u8>);

impl io::Read for Script {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = buf.len().min(self.0.len());
        buf[..n].copy_from_slice(&self.0[..n]);
        self.0.drain(..n);
        Ok(n)
    }
}

/// The random source of c2sp.org/det-keygen: an HMAC_DRBG (NIST SP 800-90A
/// Rev. 1, section 10.1.2) on SHA-256, instantiated with the seed as entropy
/// input, no nonce and a personalization string, and generating as many bytes as
/// each read asks for, with the update that follows each request.
pub(super) struct Drbg {
    key: [u8; 32],
    value: [u8; 32],
}

impl Drbg {
    pub(super) fn new(seed: &[u8], personalization: &[u8]) -> Self {
        let mut drbg = Drbg {
            key: [0; 32],
            value: [1; 32],
        };
        drbg.update(&[seed, personalization].concat());
        drbg
    }

    fn mac(&self, parts: &[&[u8]]) -> [u8; 32] {
        let digest = Hmac::<Sha256>::new(&self.key).mac_parts(parts);
        let mut out = [0; 32];
        out.copy_from_slice(digest.as_ref());
        out
    }

    /// HMAC_DRBG_Update, with the provided data (which is empty after a request).
    fn update(&mut self, data: &[u8]) {
        self.key = self.mac(&[&self.value, &[0], data]);
        self.value = self.mac(&[&self.value]);
        if !data.is_empty() {
            self.key = self.mac(&[&self.value, &[1], data]);
            self.value = self.mac(&[&self.value]);
        }
    }
}

impl io::Read for Drbg {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        for chunk in buf.chunks_mut(32) {
            self.value = self.mac(&[&self.value]);
            chunk.copy_from_slice(&self.value[..chunk.len()]);
        }
        self.update(&[]);
        Ok(buf.len())
    }
}

/// Finds out whether numbers that were meant to be wiped are still in memory
/// that was freed.
///
/// A key of this module keeps its numbers in memory on the heap, so there is no
/// way to look at them after the key is dropped without reading freed memory.
/// The allocator of the test binary reads them instead: when a block is freed
/// and a probe is armed, it counts the 8-byte words of the block that equal one
/// of the "needles", words taken from the numbers being watched. A number that
/// was overwritten with zeros before the block went back has none left.
pub(super) mod probe {
    use std::alloc::{GlobalAlloc, Layout, System};
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

    const MAX_NEEDLES: usize = 512;
    static NEEDLES: [AtomicU64; MAX_NEEDLES] = [const { AtomicU64::new(0) }; MAX_NEEDLES];
    static ARMED: AtomicUsize = AtomicUsize::new(0);
    static HITS: AtomicUsize = AtomicUsize::new(0);
    static ONE_AT_A_TIME: Mutex<()> = Mutex::new(());

    struct Probe;

    // SAFETY: every method does what `System` does, after looking at the block.
    unsafe impl GlobalAlloc for Probe {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            // SAFETY: the caller upholds the contract of `alloc`.
            unsafe { System.alloc(layout) }
        }

        unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
            let armed = ARMED.load(Ordering::Relaxed);
            if armed != 0 {
                for i in 0..layout.size() / 8 {
                    // SAFETY: the block is `layout.size()` bytes and still allocated:
                    // it is freed below. A block of bytes need not be aligned to 8
                    // as far as its layout says.
                    let word = unsafe { ptr.add(8 * i).cast::<u64>().read_unaligned() };
                    if NEEDLES[..armed]
                        .iter()
                        .any(|needle| needle.load(Ordering::Relaxed) == word)
                    {
                        HITS.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
            // SAFETY: the caller upholds the contract of `dealloc`.
            unsafe { System.dealloc(ptr, layout) }
        }
    }

    #[global_allocator]
    static PROBE: Probe = Probe;

    /// Runs `body` and returns how many words that equal one of `needles` were in
    /// blocks it freed, or that any other thread freed while it ran (nothing else
    /// holds a number like these, which are random). Runs of this function do not
    /// overlap.
    pub(in crate::rsa) fn leaks(needles: &[u64], body: impl FnOnce()) -> usize {
        assert!(needles.len() <= MAX_NEEDLES);
        let _turn = ONE_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner());
        for (slot, &needle) in NEEDLES.iter().zip(needles) {
            slot.store(needle, Ordering::Relaxed);
        }
        HITS.store(0, Ordering::Relaxed);
        ARMED.store(needles.len(), Ordering::SeqCst);
        body();
        ARMED.store(0, Ordering::SeqCst);
        HITS.load(Ordering::Relaxed)
    }

    /// The words of `numbers` (little-endian limbs, or big-endian bytes as the
    /// words of memory they are read as), to watch for. Only the words that are
    /// not common values are kept.
    pub(in crate::rsa) fn needles_of_limbs(limbs: &[u64]) -> Vec<u64> {
        limbs.iter().copied().filter(|&w| w > 1 << 32).collect()
    }

    pub(in crate::rsa) fn needles_of_bytes(bytes: &[u8]) -> Vec<u64> {
        bytes
            .chunks_exact(8)
            .map(|c| u64::from_ne_bytes(c.try_into().unwrap()))
            .filter(|&w| w > 1 << 32)
            .collect()
    }
}
