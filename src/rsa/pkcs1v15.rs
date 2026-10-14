//! The PKCS #1 v1.5 paddings (RFC 8017, sections 7.2 and 9.2): `EME-PKCS1-v1_5`
//! for encryption and `EMSA-PKCS1-v1_5` for signatures.

use super::bytes::Wiped;
use super::error::Error;
use super::hash::Pkcs1Hash;
use crate::ec::ct;
use std::io;

/// The shortest padding string of an encryption block, in bytes (RFC 8017,
/// section 7.2.1).
const MIN_PADDING_LEN: usize = 8;

/// The bytes of an encryption block other than the message and the padding
/// string: `0x00 || 0x02 || PS || 0x00`.
const ENCRYPTION_OVERHEAD: usize = 3 + MIN_PADDING_LEN;

/// How many times a byte of padding is drawn again when it comes out zero,
/// before the random source is declared stuck. A good source needs more than
/// one about once in 256 draws; 64 in a row is a chance of 2^-512.
const REDRAWS: usize = 64;

/// `EME-PKCS1-v1_5` encoding of `message` into a block of `k` bytes, the length of
/// the modulus: `0x00 || 0x02 || PS || 0x00 || M`, where `PS` is random
/// bytes, none of them zero, filling what the message leaves.
///
/// # Errors
///
/// Whatever `rng` fails with, and [`InvalidInput`](io::ErrorKind::InvalidInput)
/// (carrying [`Error::MessageTooLong`]) for a message longer than `k - 11`.
pub(super) fn encode_encryption<R: io::Read + ?Sized>(
    k: usize,
    message: &[u8],
    rng: &mut R,
) -> io::Result<Wiped> {
    if k < ENCRYPTION_OVERHEAD || message.len() > k - ENCRYPTION_OVERHEAD {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            Error::MessageTooLong,
        ));
    }
    let mut em = Wiped::zero(k);
    em[1] = 2;
    let message_at = k - message.len();
    let padding = &mut em[2..message_at - 1];
    rng.read_exact(padding)?;
    for byte in padding.iter_mut() {
        let mut redraws = 0;
        while *byte == 0 {
            redraws += 1;
            if redraws > REDRAWS {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "rsa: the random source did not produce a nonzero byte",
                ));
            }
            rng.read_exact(core::slice::from_mut(byte))?;
        }
    }
    em[message_at..].copy_from_slice(message);
    Ok(em)
}

/// Finds the message in the decrypted block `em`, which is at least 2 bytes (it is
/// as long as the modulus, 128 bytes or more): whether
/// `em` is `0x00 || 0x02 || PS || 0x00 || M` with a padding string of at least 8
/// bytes (1 if so, 0 if not), and the offset of `M` in it (0 if it is not).
///
/// There is no branch on the bytes and the whole block is read whatever it
/// holds, so the time does not tell whether, or where, the padding broke: an
/// attacker who can tell has a Bleichenbacher oracle.
pub(super) fn locate_message(em: &[u8]) -> (u64, usize) {
    let first_is_zero = ct::eq(u64::from(em[0]), 0);
    let second_is_two = ct::eq(u64::from(em[1]), 2);

    // The first zero byte after the two header bytes ends the padding.
    let mut looking = 1;
    let mut index = 0;
    for (i, &byte) in em.iter().enumerate().skip(2) {
        let is_zero = ct::eq(u64::from(byte), 0);
        index = ct::select(ct::mask(looking & is_zero), i as u64, index);
        looking &= is_zero ^ 1;
    }

    // The padding string starts at offset 2 and has to be 8 bytes or more, so
    // the zero is at offset 10 or later. `index - 10` wraps to a huge number,
    // with its top bit set, exactly when `index < 10`.
    let long_enough = (index.wrapping_sub(2 + MIN_PADDING_LEN as u64) >> 63) ^ 1;

    let valid = first_is_zero & second_is_two & (looking ^ 1) & long_enough;
    let offset = ct::select(ct::mask(valid), index + 1, 0);
    (valid, offset as usize)
}

/// `EMSA-PKCS1-v1_5` encoding of the digest `digest` of a message into a block of
/// `k` bytes: `0x00 || 0x01 || PS || 0x00 || T`, where `PS` is `0xff` bytes and
/// `T` is the DER encoding of the `DigestInfo` of `D` and the digest.
///
/// # Errors
///
/// [`Error::InvalidDigest`] if `digest` is not as long as the output of `D`, and
/// [`Error::MessageTooLong`] if the key is too short to hold the `DigestInfo`
/// and at least 8 bytes of padding.
pub(super) fn encode_signature<D: Pkcs1Hash>(k: usize, digest: &[u8]) -> Result<Vec<u8>, Error> {
    if digest.len() != D::OUTPUT_LEN {
        return Err(Error::InvalidDigest);
    }
    let prefix = D::DIGEST_INFO_PREFIX;
    let t_len = prefix.len() + digest.len();
    if k < t_len + ENCRYPTION_OVERHEAD {
        return Err(Error::MessageTooLong);
    }
    let mut em = vec![0xff; k];
    em[0] = 0;
    em[1] = 1;
    em[k - t_len - 1] = 0;
    em[k - t_len..k - digest.len()].copy_from_slice(prefix);
    em[k - digest.len()..].copy_from_slice(digest);
    Ok(em)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Digest;
    use crate::sha2::{Sha256, Sha512};

    /// A reader that returns the bytes it is given, in order.
    struct Script(Vec<u8>);

    impl io::Read for Script {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let n = buf.len().min(self.0.len());
            buf[..n].copy_from_slice(&self.0[..n]);
            self.0.drain(..n);
            Ok(n)
        }
    }

    #[test]
    fn encryption_block_layout() {
        let mut rng = Script((1..=255).collect());
        let em = encode_encryption(32, b"hello", &mut rng).unwrap();
        let mut want = vec![0, 2];
        want.extend(1..=24); // 32 - 5 - 3 bytes of padding
        want.push(0);
        want.extend_from_slice(b"hello");
        assert_eq!(&*em, &want[..]);
        // The reader gave exactly the padding's length.
        assert_eq!(rng.0.len(), 255 - 24);
    }

    #[test]
    fn zero_bytes_of_padding_are_drawn_again() {
        // 26 bytes of padding, two of them zero. The first of those is replaced by
        // the second byte read for it, as the first one is zero too.
        let mut script: Vec<u8> = (1..=26).collect();
        script[3] = 0;
        script[7] = 0;
        script.extend_from_slice(&[0, 9, 8]);
        let em = encode_encryption(32, b"abc", &mut Script(script)).unwrap();
        let mut padding: Vec<u8> = (1..=26).collect();
        padding[3] = 9;
        padding[7] = 8;
        assert_eq!(&em[2..28], &padding[..]);
        assert_eq!(em[28], 0);
        assert_eq!(&em[29..], b"abc");
    }

    #[test]
    fn a_stuck_source_is_given_up_on() {
        /// A source of zeros that counts the bytes it is asked for.
        struct Zeros(usize);

        impl io::Read for Zeros {
            fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
                self.0 += buf.len();
                buf.fill(0);
                Ok(buf.len())
            }
        }

        let mut zeros = Zeros(0);
        let error = encode_encryption(32, b"abc", &mut zeros).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        // The 26 bytes of padding, then 64 tries for the first of them that is zero.
        assert_eq!(zeros.0, 26 + REDRAWS);
    }

    #[test]
    fn encryption_message_lengths() {
        let mut rng = io::repeat(7);
        // 11 bytes of overhead.
        assert!(encode_encryption(32, &[1; 21], &mut rng).is_ok());
        let error = encode_encryption(32, &[1; 22], &mut rng).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert_eq!(
            error.get_ref().unwrap().to_string(),
            Error::MessageTooLong.to_string()
        );
        assert!(encode_encryption(10, b"", &mut rng).is_err());
        assert!(encode_encryption(11, b"", &mut rng).is_ok());
    }

    #[test]
    fn locate_finds_the_message_or_nothing() {
        fn block(padding: &[u8], message: &[u8]) -> Vec<u8> {
            let mut em = vec![0, 2];
            em.extend_from_slice(padding);
            em.push(0);
            em.extend_from_slice(message);
            em
        }
        let ok = block(&[0xaa; 8], b"hi");
        assert_eq!(locate_message(&ok), (1, 11));
        // An empty message, and a message with zeros in it.
        assert_eq!(locate_message(&block(&[1; 20], b"")), (1, 23));
        assert_eq!(locate_message(&block(&[1; 20], &[0, 0, 0])), (1, 23));

        // Padding of 7: too short. Of 8: the shortest.
        assert_eq!(locate_message(&block(&[1; 7], b"hi")).0, 0);
        assert_eq!(locate_message(&block(&[1; 8], b"hi")).0, 1);
        // The header: first byte, second byte.
        for (i, change) in [(0, 1), (1, 1), (1, 0), (1, 3)] {
            let mut bad = ok.clone();
            bad[i] = change;
            assert_eq!(locate_message(&bad), (0, 0), "{i} {change}");
        }
        // No zero after the padding at all.
        assert_eq!(
            locate_message(&[0, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1]),
            (0, 0)
        );
        // A zero in the first 8 bytes of padding.
        let mut early = ok.clone();
        early[5] = 0;
        assert_eq!(locate_message(&early), (0, 0));
    }

    #[test]
    fn signature_block_layout() {
        let digest = Sha256::digest(b"abc");
        let em = encode_signature::<Sha256>(128, digest.as_ref()).unwrap();
        assert_eq!(em.len(), 128);
        let t_len = 19 + 32;
        assert_eq!(&em[..2], &[0, 1]);
        assert!(em[2..128 - t_len - 1].iter().all(|&b| b == 0xff));
        assert_eq!(em[128 - t_len - 1], 0);
        assert_eq!(
            &em[128 - t_len..128 - 32],
            <Sha256 as Pkcs1Hash>::DIGEST_INFO_PREFIX
        );
        assert_eq!(&em[128 - 32..], digest.as_ref());
    }

    #[test]
    fn signature_block_sizes() {
        // SHA-512's DigestInfo is 83 bytes, which with the 11 of overhead needs a
        // key of 94 bytes.
        let digest = Sha512::digest(b"abc");
        assert!(encode_signature::<Sha512>(94, digest.as_ref()).is_ok());
        assert_eq!(
            encode_signature::<Sha512>(93, digest.as_ref()),
            Err(Error::MessageTooLong)
        );
        assert_eq!(
            encode_signature::<Sha512>(128, &digest.as_ref()[1..]),
            Err(Error::InvalidDigest)
        );
        assert_eq!(
            encode_signature::<Sha256>(128, digest.as_ref()),
            Err(Error::InvalidDigest)
        );
    }
}
