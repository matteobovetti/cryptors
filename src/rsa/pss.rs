//! The encoding of RSASSA-PSS (RFC 8017, section 9.1): `EMSA-PSS-ENCODE` and
//! `EMSA-PSS-VERIFY`.

use super::error::Error;
use super::mgf1::mgf1_xor;
use crate::Digest;

/// The longest salt that fits in an encoded message of `em_bits` bits, which is
/// `ceil(em_bits / 8) - hLen - 2` bytes, or `None` if even an empty salt does not
/// fit.
pub(super) fn max_salt_len<D: Digest>(em_bits: usize) -> Option<usize> {
    em_bits.div_ceil(8).checked_sub(D::OUTPUT_LEN + 2)
}

/// `H(0x00 * 8 || mHash || salt)`.
fn salted_hash<D: Digest>(m_hash: &[u8], salt: &[u8]) -> D::Output {
    let mut m_prime = vec![0; 8];
    m_prime.extend_from_slice(m_hash);
    m_prime.extend_from_slice(salt);
    D::digest(&m_prime)
}

/// `EMSA-PSS-ENCODE` of the digest `m_hash` with `salt`, into `ceil(em_bits / 8)`
/// bytes:
///
/// ```text
/// EM = maskedDB || H || 0xbc
/// DB = PS || 0x01 || salt                  (PS is zero bytes)
/// H = Hash(0x00 * 8 || mHash || salt)
/// maskedDB = DB xor MGF(H, emLen - hLen - 1), with its top bits cleared
/// ```
///
/// # Errors
///
/// [`Error::InvalidDigest`] if `m_hash` is not as long as the output of `D`, and
/// [`Error::MessageTooLong`] if the encoded message has no room for the salt.
pub(super) fn encode<D: Digest>(
    m_hash: &[u8],
    em_bits: usize,
    salt: &[u8],
) -> Result<Vec<u8>, Error> {
    let h_len = D::OUTPUT_LEN;
    if m_hash.len() != h_len {
        return Err(Error::InvalidDigest);
    }
    let em_len = em_bits.div_ceil(8);
    if em_len < h_len + salt.len() + 2 {
        return Err(Error::MessageTooLong);
    }

    let mut em = vec![0; em_len];
    let ps_len = em_len - salt.len() - h_len - 2;
    let (db, rest) = em.split_at_mut(em_len - h_len - 1);
    let h = salted_hash::<D>(m_hash, salt);
    rest[..h_len].copy_from_slice(h.as_ref());
    rest[h_len] = 0xbc;
    db[ps_len] = 1;
    db[ps_len + 1..].copy_from_slice(salt);
    mgf1_xor::<D>(db, h.as_ref());
    db[0] &= 0xff >> (8 * em_len - em_bits);
    Ok(em)
}

/// `EMSA-PSS-VERIFY` of the encoded message `em` of `ceil(em_bits / 8)` bytes
/// against the digest `m_hash`, where the salt has `salt_len` bytes or, if that
/// is `None`, whatever length the encoded message turns out to have. `em` is
/// overwritten.
///
/// Nothing in it is secret: the message and its signature are public, so the
/// checks stop at the first that fails.
pub(super) fn verify<D: Digest>(
    m_hash: &[u8],
    em: &mut [u8],
    em_bits: usize,
    salt_len: Option<usize>,
) -> Result<(), Error> {
    let h_len = D::OUTPUT_LEN;
    let em_len = em.len();
    assert_eq!(em_len, em_bits.div_ceil(8));
    if m_hash.len() != h_len || em_len < h_len + 2 {
        return Err(Error::VerificationFailed);
    }
    // Step 4: the last byte.
    if em[em_len - 1] != 0xbc {
        return Err(Error::VerificationFailed);
    }
    // Steps 5 and 6: the top bits of the first byte are zero.
    let top_mask = 0xffu8 >> (8 * em_len - em_bits);
    if em[0] & !top_mask != 0 {
        return Err(Error::VerificationFailed);
    }

    // Steps 7 to 9: unmask the data block.
    let (db, rest) = em.split_at_mut(em_len - h_len - 1);
    let h = &rest[..h_len];
    mgf1_xor::<D>(db, h);
    db[0] &= top_mask;

    // The salt is after the first 0x01, or has the length that was asked for.
    let salt_len = match salt_len {
        Some(len) => len,
        None => {
            let ps_len = db
                .iter()
                .position(|&byte| byte == 1)
                .ok_or(Error::VerificationFailed)?;
            db.len() - ps_len - 1
        }
    };

    // Step 10: zeros, then 0x01, then the salt.
    if em_len < h_len + salt_len + 2 {
        return Err(Error::VerificationFailed);
    }
    let ps_len = em_len - h_len - salt_len - 2;
    if db[..ps_len].iter().any(|&byte| byte != 0) || db[ps_len] != 1 {
        return Err(Error::VerificationFailed);
    }

    // Steps 11 to 14: the hash of the digest and the salt is the one stored.
    let salt = &db[db.len() - salt_len..];
    if salted_hash::<D>(m_hash, salt).as_ref() != h {
        return Err(Error::VerificationFailed);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sha2::Sha256;

    #[test]
    fn verify_accepts_what_encode_makes() {
        // Every salt length that fits, for a key of 1,024 bits (em_bits 1,023) and
        // for one whose size is a multiple of 8 plus 1 (em_bits 1,024, where the
        // encoded message is a whole number of bytes).
        for em_bits in [1023, 1024, 1025, 1031] {
            let m_hash = Sha256::digest(b"message");
            let max = max_salt_len::<Sha256>(em_bits).unwrap();
            for salt_len in [0, 1, 20, 32, max - 1, max] {
                let salt: Vec<u8> = (0..salt_len).map(|i| i as u8 ^ 0x5a).collect();
                let em = encode::<Sha256>(m_hash.as_ref(), em_bits, &salt).unwrap();
                assert_eq!(em.len(), em_bits.div_ceil(8));
                assert_eq!(*em.last().unwrap(), 0xbc);
                assert_eq!(em[0] & !(0xff >> (8 * em.len() - em_bits)), 0);
                // With the length, and without.
                for expected in [Some(salt_len), None] {
                    let mut copy = em.clone();
                    verify::<Sha256>(m_hash.as_ref(), &mut copy, em_bits, expected)
                        .unwrap_or_else(|e| panic!("{em_bits} {salt_len} {expected:?}: {e}"));
                }
                // Another length is refused.
                let mut copy = em.clone();
                assert!(
                    verify::<Sha256>(m_hash.as_ref(), &mut copy, em_bits, Some(salt_len + 1))
                        .is_err()
                );
            }
        }
    }

    #[test]
    fn encode_refuses_what_does_not_fit() {
        let m_hash = Sha256::digest(b"message");
        // 1,023 bits: 128 bytes, and 128 - 32 - 2 = 94 bytes of salt at most.
        assert_eq!(max_salt_len::<Sha256>(1023), Some(94));
        assert!(encode::<Sha256>(m_hash.as_ref(), 1023, &[0; 94]).is_ok());
        assert_eq!(
            encode::<Sha256>(m_hash.as_ref(), 1023, &[0; 95]),
            Err(Error::MessageTooLong)
        );
        assert_eq!(max_salt_len::<Sha256>(8 * 33), None);
        assert_eq!(
            encode::<Sha256>(&m_hash.as_ref()[1..], 1023, &[]),
            Err(Error::InvalidDigest)
        );
    }

    #[test]
    fn verify_refuses_every_change() {
        let m_hash = Sha256::digest(b"message");
        let em = encode::<Sha256>(m_hash.as_ref(), 1023, &[0x33; 32]).unwrap();
        // Every bit of the encoded message matters, the cleared one included.
        for i in 0..em.len() {
            for bit in 0..8 {
                let mut bad = em.clone();
                bad[i] ^= 1 << bit;
                assert_eq!(
                    verify::<Sha256>(m_hash.as_ref(), &mut bad, 1023, None),
                    Err(Error::VerificationFailed),
                    "byte {i} bit {bit}"
                );
            }
        }
        // Another digest.
        let other = Sha256::digest(b"messagf");
        assert!(verify::<Sha256>(other.as_ref(), &mut em.clone(), 1023, None).is_err());
        // A digest of the wrong length.
        assert!(verify::<Sha256>(&[0; 31], &mut em.clone(), 1023, None).is_err());
    }
}
