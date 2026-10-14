use core::fmt;

use crate::wipe::wipe;

/// RC4: the stream cipher that Ron Rivest designed in 1987, as Bruce
/// Schneier's *Applied Cryptography* describes it.
///
/// A cipher is built from a key and then turns data into data: it holds the
/// permutation of the 256 byte values that the key set up, and the two indices
/// that walk through it, so every call carries on where the last one stopped.
/// The permutation and the indices are overwritten with zeros when the value is
/// dropped.
///
/// RC4 is broken: see the [module documentation](crate::rc4).
///
/// ```
/// use cryptors::rc4::Rc4;
///
/// let mut cipher = Rc4::new(b"Key").unwrap();
/// let mut data = *b"Plaintext";
/// cipher.apply_keystream(&mut data);
/// assert_eq!(data, [0xbb, 0xf3, 0x16, 0xe8, 0xd9, 0x40, 0xaf, 0x0a, 0xd3]);
///
/// // Decrypting is the same operation, from the same starting point.
/// Rc4::new(b"Key").unwrap().apply_keystream(&mut data);
/// assert_eq!(&data, b"Plaintext");
/// ```
pub struct Rc4 {
    /// The state: a permutation of 0 to 255, as the key schedule left it and
    /// the generator has since shuffled it.
    s: [u8; 256],
    i: u8,
    j: u8,
}

impl Rc4 {
    /// The shortest key RC4 takes, in bytes.
    pub const MIN_KEY_LEN: usize = 1;

    /// The longest key RC4 takes, in bytes: the size of the state.
    pub const MAX_KEY_LEN: usize = 256;

    /// Builds the cipher, running the key schedule: the state starts as the
    /// identity permutation and is shuffled with the bytes of `key`, repeated
    /// as often as it takes to visit the 256 positions once.
    ///
    /// The key must be 1 to 256 bytes, or [`Error::InvalidKeyLen`] is returned.
    /// Keys of 5 to 16 bytes (40 to 128 bits) are the usual. The schedule
    /// repeats the key to cover 256 steps, so a key whose length divides 256 is
    /// the same as itself repeated.
    pub fn new(key: &[u8]) -> Result<Self, Error> {
        if !(Self::MIN_KEY_LEN..=Self::MAX_KEY_LEN).contains(&key.len()) {
            return Err(Error::InvalidKeyLen);
        }
        let mut s: [u8; 256] = core::array::from_fn(|i| i as u8);
        let mut j = 0u8;
        for i in 0..256 {
            j = j.wrapping_add(s[i]).wrapping_add(key[i % key.len()]);
            s.swap(i, usize::from(j));
        }
        Ok(Self { s, i: 0, j: 0 })
    }

    /// XORs `data` with the next bytes of the keystream, in place. Encrypting
    /// and decrypting are the same operation.
    ///
    /// The keystream does not restart: the second of two calls continues where
    /// the first one stopped, so a message can be processed in pieces of any
    /// size, and gives the same result as it would in one call.
    pub fn apply_keystream(&mut self, data: &mut [u8]) {
        let (mut i, mut j) = (self.i, self.j);
        for byte in data {
            i = i.wrapping_add(1);
            let x = self.s[usize::from(i)];
            j = j.wrapping_add(x);
            let y = self.s[usize::from(j)];
            self.s[usize::from(i)] = y;
            self.s[usize::from(j)] = x;
            *byte ^= self.s[usize::from(x.wrapping_add(y))];
        }
        self.i = i;
        self.j = j;
    }

    /// Sets `dst` to `src` XORed with the next bytes of the keystream, leaving
    /// `src` as it was.
    ///
    /// # Panics
    ///
    /// If `dst` and `src` differ in length.
    pub fn xor_keystream(&mut self, dst: &mut [u8], src: &[u8]) {
        dst.copy_from_slice(src);
        self.apply_keystream(dst);
    }
}

/// Shows the type and nothing else: the state is secret.
impl fmt::Debug for Rc4 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Rc4").finish_non_exhaustive()
    }
}

impl Drop for Rc4 {
    fn drop(&mut self) {
        wipe(&mut self.s);
        wipe(core::slice::from_mut(&mut self.i));
        wipe(core::slice::from_mut(&mut self.j));
    }
}

/// An input that RC4 does not allow.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Error {
    /// The key is empty or longer than 256 bytes, the size of the state.
    InvalidKeyLen,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Error::InvalidKeyLen => "RC4 key is empty or longer than 256 bytes",
        })
    }
}

impl std::error::Error for Error {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Digest;
    use crate::digest::hex;
    use crate::sha2::Sha256;
    use crate::wipe::bytes_around_drop;

    /// RFC 6229's vectors, one per line: see the header of the file.
    const RFC_6229: &str = include_str!("testdata/rfc6229.txt");

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// The first `len` bytes of the keystream under `key`.
    fn keystream(key: &[u8], len: usize) -> Vec<u8> {
        let mut bytes = vec![0; len];
        Rc4::new(key).unwrap().apply_keystream(&mut bytes);
        bytes
    }

    /// The vectors of the cypherpunks' posting of 1994, which first published
    /// the algorithm, and of Wikipedia: the keystream under a key, and the
    /// ciphertexts of the three examples that the article gives.
    #[test]
    fn known_answers() {
        let keystreams: [(&str, &str); 5] = [
            ("0123456789abcdef", "7494c2e7104b0879"),
            ("0000000000000000", "de188941a3375d3a"),
            ("ef012345", "d6a141a7ec3c38dfbd61"),
            ("4b6579", "eb9f7781b734ca72a719"),
            ("57696b69", "6044db6d41b7"),
        ];
        for (key, expected) in keystreams {
            let expected = unhex(expected);
            assert_eq!(keystream(&unhex(key), expected.len()), expected, "{key}");
        }

        let messages: [(&[u8], &[u8], &str); 3] = [
            (b"Key", b"Plaintext", "bbf316e8d940af0ad3"),
            (b"Wiki", b"pedia", "1021bf0420"),
            (b"Secret", b"Attack at dawn", "45a01f645fc35b383552544b9bf5"),
        ];
        for (key, plaintext, expected) in messages {
            let mut data = plaintext.to_vec();
            Rc4::new(key).unwrap().apply_keystream(&mut data);
            assert_eq!(hex(&data), expected, "{}", String::from_utf8_lossy(key));
        }
    }

    /// RFC 6229: 14 keys of 40 to 256 bits, 16 bytes of keystream at each of
    /// 18 offsets up to 4096. Fourteen of the lines are at offset 0 and the
    /// others reach through a few thousand steps of the generator, past a
    /// number of wraps of both indices.
    #[test]
    fn rfc_6229() {
        let mut checked = 0;
        for line in RFC_6229.lines().filter(|l| !l.starts_with('#')) {
            let mut fields = line.split(' ');
            let key = unhex(fields.next().unwrap());
            let offset: usize = fields.next().unwrap().parse().unwrap();
            let expected = unhex(fields.next().unwrap());
            assert_eq!(fields.next(), None);

            let stream = keystream(&key, offset + 16);
            assert_eq!(stream[offset..], expected, "{} at {offset}", hex(&key));
            checked += 1;
        }
        assert_eq!(checked, 14 * 18);
    }

    /// Every length of key, 1 to 256 bytes, the key schedule's repetition of
    /// the key included, and 300 bytes of keystream under each, one more wrap
    /// of the first index than a message of 256 bytes has. Their SHA-256 comes
    /// from Go's `crypto/rc4` and from RC4 written in Python, which agree.
    #[test]
    fn every_key_length() {
        let mut all = Vec::new();
        for len in 1..=256usize {
            let key: Vec<u8> = (0..len).map(|i| (i * 7 + len * 13 + 5) as u8).collect();
            all.extend(keystream(&key, 300));
        }
        assert_eq!(
            Sha256::hex_digest(&all),
            "a8bb54507f36397bf013fc5cc7538a5ddad0b1f813cd986bd949a7b7e78342b1"
        );
    }

    /// The state is carried from one call to the next: a message in pieces,
    /// split at every point and into runs of every length, gives what the
    /// whole message gives.
    #[test]
    fn pieces_match_the_whole() {
        let key = b"a key for the pieces";
        let plaintext: Vec<u8> = (0..700).map(|i| (i % 251) as u8).collect();
        let mut whole = plaintext.clone();
        Rc4::new(key).unwrap().apply_keystream(&mut whole);

        for split in 0..=plaintext.len() {
            let mut data = plaintext.clone();
            let mut cipher = Rc4::new(key).unwrap();
            let (head, tail) = data.split_at_mut(split);
            cipher.apply_keystream(head);
            cipher.apply_keystream(&mut []);
            cipher.apply_keystream(tail);
            assert_eq!(data, whole, "split at {split}");
        }
        for run in [1, 2, 3, 255, 256, 257, 300] {
            let mut data = plaintext.clone();
            let mut cipher = Rc4::new(key).unwrap();
            for chunk in data.chunks_mut(run) {
                cipher.apply_keystream(chunk);
            }
            assert_eq!(data, whole, "runs of {run}");
        }
    }

    /// `xor_keystream` is `apply_keystream` from another buffer, and also
    /// carries on from where the cipher stopped.
    #[test]
    fn xor_keystream_leaves_the_source_alone() {
        let key = b"Secret";
        let src = *b"Attack at dawn";
        let mut dst = [0; 14];
        let mut cipher = Rc4::new(key).unwrap();
        cipher.xor_keystream(&mut dst[..5], &src[..5]);
        cipher.xor_keystream(&mut dst[5..], &src[5..]);
        assert_eq!(hex(&dst), "45a01f645fc35b383552544b9bf5");
        assert_eq!(&src, b"Attack at dawn");
    }

    #[test]
    #[should_panic(expected = "source slice length")]
    fn xor_keystream_needs_equal_lengths() {
        Rc4::new(b"Key")
            .unwrap()
            .xor_keystream(&mut [0; 4], &[0; 5]);
    }

    #[test]
    fn key_length_limits() {
        assert_eq!(Rc4::new(&[]).unwrap_err(), Error::InvalidKeyLen);
        assert_eq!(Rc4::new(&[0; 257]).unwrap_err(), Error::InvalidKeyLen);
        assert_eq!(Rc4::new(&[0; 1 << 20]).unwrap_err(), Error::InvalidKeyLen);
        assert!(Rc4::new(&[0]).is_ok());
        assert!(Rc4::new(&[0; 256]).is_ok());
        assert_eq!(Rc4::MIN_KEY_LEN, 1);
        assert_eq!(Rc4::MAX_KEY_LEN, 256);

        assert_eq!(
            Error::InvalidKeyLen.to_string(),
            "RC4 key is empty or longer than 256 bytes"
        );
    }

    /// Dropping a cipher must leave no byte of its state behind.
    #[test]
    fn dropping_wipes_the_state() {
        let mut cipher = Rc4::new(&[0x42; 16]).unwrap();
        cipher.apply_keystream(&mut [0; 100]);
        // SAFETY: `Rc4` is 258 bytes of `u8`, with no padding.
        let (before, after) = unsafe { bytes_around_drop(cipher) };
        assert_eq!(before.len(), 258);
        assert!(before.iter().any(|&b| b != 0), "no state to wipe");
        assert!(after.iter().all(|&b| b == 0), "state survives the drop");
    }

    #[test]
    fn debug_hides_the_state() {
        assert_eq!(
            format!("{:?}", Rc4::new(&[0xab; 16]).unwrap()),
            "Rc4 { .. }"
        );
    }

    #[test]
    #[ignore = "manual throughput check: cargo test --release rc4:: -- --ignored --nocapture --test-threads=1"]
    fn throughput() {
        use std::time::Instant;

        const LEN: usize = 32 * 1024 * 1024;
        let mib = LEN as f64 / (1024.0 * 1024.0);

        // A fixed input, transformed in place with the keystream running on:
        // the passes are not undone, so what is printed at the end identifies
        // the whole run. It is the same for any other correct implementation
        // run the same way.
        let mut data: Vec<u8> = (0..LEN).map(|i| (i % 251) as u8).collect();
        let key: [u8; 16] = core::array::from_fn(|i| i as u8);
        let mut cipher = Rc4::new(&key).unwrap();

        // The first pass over a fresh buffer is slowed down by page faults and
        // CPU clock ramp-up, not just the cipher itself, so it is not timed.
        cipher.apply_keystream(&mut data);

        let mut best = 0.0f64;
        for _ in 0..5 {
            let start = Instant::now();
            cipher.apply_keystream(&mut data);
            best = best.max(mib / start.elapsed().as_secs_f64());
        }
        println!(
            "rc4 [cryptors]: {mib:.0} MiB, best {best:.1} MiB/s (first bytes {}...)",
            hex(&data[..16])
        );
    }
}
