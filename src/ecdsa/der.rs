//! The DER encoding of a signature (RFC 3279, section 2.2.3; SEC 1, annex C.5):
//! `ECDSA-Sig-Value ::= SEQUENCE { r INTEGER, s INTEGER }`.
//!
//! Decoding accepts one encoding of each pair of numbers and no other. A
//! parser that is lenient about lengths, leading zeros or trailing bytes makes
//! the same signature valid in several forms, which breaks anything that
//! identifies a signature by its bytes.

/// The tag of a SEQUENCE.
const SEQUENCE: u8 = 0x30;
/// The tag of an INTEGER.
const INTEGER: u8 = 0x02;

/// Writes `value`, a big-endian number that is not zero, as the content of an
/// INTEGER: no leading zeros, and one zero byte in front if the top bit would
/// make it negative.
fn push_integer(out: &mut Vec<u8>, value: &[u8]) {
    let first = value
        .iter()
        .position(|&byte| byte != 0)
        .unwrap_or(value.len() - 1);
    let digits = &value[first..];
    let pad = usize::from(digits[0] & 0x80 != 0);
    out.push(INTEGER);
    // At most 67 bytes: a length of one byte.
    out.push((digits.len() + pad) as u8);
    if pad == 1 {
        out.push(0);
    }
    out.extend_from_slice(digits);
}

/// The DER encoding of the signature `r || s`, where `r` and `s` are the two
/// halves of `signature`, big-endian numbers from 1 to the order minus 1.
pub(super) fn encode(signature: &[u8]) -> Vec<u8> {
    let (r, s) = signature.split_at(signature.len() / 2);
    let mut content = Vec::with_capacity(2 * (2 + 1 + r.len()));
    push_integer(&mut content, r);
    push_integer(&mut content, s);

    let mut out = Vec::with_capacity(3 + content.len());
    out.push(SEQUENCE);
    // The content is at most 2 * (2 + 67) = 138 bytes (136 for the largest
    // signature of a curve here): one byte of length, or the long form with one
    // length byte.
    if content.len() < 0x80 {
        out.push(content.len() as u8);
    } else {
        out.push(0x81);
        out.push(content.len() as u8);
    }
    out.extend_from_slice(&content);
    out
}

/// Reads one length at the start of `input`: its value and the number of bytes
/// it took. Only the forms DER allows for the sizes here: one byte below 128,
/// or `0x81` and a byte of 128 or more. Anything else is not a length a
/// signature can have.
fn read_length(input: &[u8]) -> Option<(usize, usize)> {
    match *input.first()? {
        short @ 0..=0x7f => Some((usize::from(short), 1)),
        0x81 => {
            let long = *input.get(1)?;
            // Below 128 the short form is the only one DER allows.
            (long >= 0x80).then_some((usize::from(long), 2))
        }
        _ => None,
    }
}

/// Reads one INTEGER from the start of `input`, which must be positive and in
/// the shortest form. Returns its digits (without the leading zero a high top
/// bit needs) and the rest of the input.
fn read_integer(input: &[u8]) -> Option<(&[u8], &[u8])> {
    let (&tag, rest) = input.split_first()?;
    if tag != INTEGER {
        return None;
    }
    let (length, used) = read_length(rest)?;
    let rest = &rest[used..];
    if length == 0 || length > rest.len() {
        return None;
    }
    let (content, rest) = rest.split_at(length);
    // Positive: the top bit is clear.
    if content[0] & 0x80 != 0 {
        return None;
    }
    // Shortest: a zero byte first is only there to clear a top bit that is set.
    if content[0] == 0 && length > 1 {
        if content[1] & 0x80 == 0 {
            return None;
        }
        return Some((&content[1..], rest));
    }
    Some((content, rest))
}

/// Decodes `der` into `r || s`, each half `half` bytes long and zero-padded on
/// the left, or `None` if `der` is not exactly the encoding of two positive
/// integers that fit in `half` bytes. Whether they are below the order is for
/// the caller to check.
pub(super) fn decode(der: &[u8], half: usize, out: &mut [u8]) -> Option<()> {
    assert_eq!(out.len(), 2 * half);

    let (&tag, rest) = der.split_first()?;
    if tag != SEQUENCE {
        return None;
    }
    let (length, used) = read_length(rest)?;
    // The sequence is all there is: no bytes after it, none missing.
    if rest.len() != used + length {
        return None;
    }
    let (r, rest) = read_integer(&rest[used..])?;
    let (s, rest) = read_integer(rest)?;
    if !rest.is_empty() || r.len() > half || s.len() > half {
        return None;
    }

    out.fill(0);
    out[half - r.len()..half].copy_from_slice(r);
    out[2 * half - s.len()..].copy_from_slice(s);
    Some(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `r || s` for numbers `r` and `s` given as short big-endian strings,
    /// zero-padded to `half` bytes.
    fn pair(r: &[u8], s: &[u8], half: usize) -> Vec<u8> {
        let mut out = vec![0; 2 * half];
        out[half - r.len()..half].copy_from_slice(r);
        out[2 * half - s.len()..].copy_from_slice(s);
        out
    }

    #[test]
    fn encodes_the_shortest_form() {
        // Small numbers lose their leading zeros.
        assert_eq!(encode(&pair(&[1], &[2], 32)), [0x30, 6, 2, 1, 1, 2, 1, 2]);
        // A top bit that is set gets a zero byte in front, so that the integer
        // is not negative.
        assert_eq!(
            encode(&pair(&[0x80], &[0xff, 0x01], 32)),
            [0x30, 9, 2, 2, 0, 0x80, 2, 3, 0, 0xff, 0x01]
        );
        // Full-length numbers with the top bit set: 33 bytes each, so the
        // sequence is 70 bytes long.
        let der = encode(&[&[0x80u8; 32][..], &[0xffu8; 32][..]].concat());
        assert_eq!(der.len(), 2 + 2 * 35);
        assert_eq!(&der[..6], [0x30, 70, 2, 33, 0, 0x80]);
        // The largest signature of P-521: its order is below 2^521, so the top
        // byte of a number is at most 0x01 and needs no zero in front. Two numbers
        // of 66 bytes make a content of 136 bytes, which needs the long form of
        // the length: 139 bytes in all.
        let mut largest = [0xffu8; 132];
        (largest[0], largest[66]) = (0x01, 0x01);
        let der = encode(&largest);
        assert_eq!(&der[..5], [0x30, 0x81, 136, 2, 66]);
        assert_eq!(der.len(), 3 + 136);
        // The encoder does not know the order, and a number of 66 bytes with its
        // top bit set (which no P-521 signature has) takes a zero byte: 138.
        let der = encode(&[0xffu8; 132]);
        assert_eq!(&der[..4], [0x30, 0x81, 138, 2]);
        assert_eq!(der.len(), 3 + 138);
    }

    /// The sequence of a signature has a content of up to 138 bytes, and DER writes
    /// a length below 128 in one byte and a longer one after `0x81`. The boundary
    /// is the place to get wrong.
    #[test]
    fn the_length_form_changes_at_128() {
        // Numbers of 61 and 62 significant bytes (top bit clear): a content of
        // 2 + 61 + 2 + 62 = 127 bytes, the longest the short form can hold; and
        // 62 and 62, which make 128 and need the long form.
        let number = |len: usize| -> Vec<u8> {
            let mut bytes = vec![0x11u8; len];
            bytes[0] = 0x01;
            bytes
        };
        let signature = |r: usize, s: usize| [pad(&number(r), 66), pad(&number(s), 66)].concat();
        fn pad(bytes: &[u8], len: usize) -> Vec<u8> {
            [vec![0; len - bytes.len()], bytes.to_vec()].concat()
        }

        let der = encode(&signature(61, 62));
        assert_eq!(&der[..3], [0x30, 127, 2]);
        assert_eq!(der.len(), 2 + 127);
        let der = encode(&signature(62, 62));
        assert_eq!(&der[..4], [0x30, 0x81, 128, 2]);
        assert_eq!(der.len(), 3 + 128);

        // Both read back, and the same content with the length written in the
        // long form when the short one would do is refused: DER has one way to
        // write a length.
        let mut out = vec![0u8; 132];
        for (r, s) in [(61, 62), (62, 62)] {
            let der = encode(&signature(r, s));
            assert!(decode(&der, 66, &mut out).is_some(), "{r} and {s} bytes");
            assert_eq!(out, signature(r, s));
        }
        let short = encode(&signature(61, 62));
        let mut long_form = vec![0x30, 0x81, 127];
        long_form.extend_from_slice(&short[2..]);
        assert!(decode(&short, 66, &mut out).is_some());
        assert!(decode(&long_form, 66, &mut out).is_none());
        // A length of 128 in the short form would be the byte 0x80, which is
        // the indefinite length of BER.
        let mut indefinite = vec![0x30, 0x80];
        indefinite.extend_from_slice(&encode(&signature(62, 62))[3..]);
        assert!(decode(&indefinite, 66, &mut out).is_none());
    }

    #[test]
    fn decodes_what_it_encodes() {
        for (r, s, half) in [
            (&[1u8][..], &[2u8][..], 32),
            (&[0x80], &[0xff, 0x01], 32),
            (&[0x7f; 28], &[0x80; 28], 28),
            (&[0xff; 66], &[0xff; 66], 66),
            (&[0x01, 0xff], &[0x01], 66),
        ] {
            let signature = pair(r, s, half);
            let mut back = vec![0; 2 * half];
            decode(&encode(&signature), half, &mut back).expect("decodes");
            assert_eq!(back, signature);
        }
    }

    #[test]
    fn refuses_every_other_form() {
        let ok: &[u8] = &[0x30, 6, 2, 1, 1, 2, 1, 2];
        let mut out = [0u8; 64];
        assert!(decode(ok, 32, &mut out).is_some());

        let bad: &[&[u8]] = &[
            // Not a sequence, or not integers.
            &[0x31, 6, 2, 1, 1, 2, 1, 2],
            &[0x30, 6, 3, 1, 1, 2, 1, 2],
            &[0x30, 6, 2, 1, 1, 3, 1, 2],
            // Lengths that lie: the sequence is longer or shorter than its
            // content, or an integer runs past the end.
            &[0x30, 7, 2, 1, 1, 2, 1, 2],
            &[0x30, 5, 2, 1, 1, 2, 1, 2],
            &[0x30, 6, 2, 2, 1, 2, 1, 2],
            // Bytes after the sequence.
            &[0x30, 6, 2, 1, 1, 2, 1, 2, 0],
            // Long form of a length that fits in the short form, indefinite
            // length, and lengths of two bytes.
            &[0x30, 0x81, 6, 2, 1, 1, 2, 1, 2],
            &[0x30, 0x80, 2, 1, 1, 2, 1, 2, 0, 0],
            &[0x30, 0x82, 0, 6, 2, 1, 1, 2, 1, 2],
            &[0x30, 7, 2, 0x81, 1, 1, 2, 1, 2],
            // Empty, zero, negative and padded integers.
            &[0x30, 5, 2, 0, 2, 1, 2][..],
            &[0x30, 6, 2, 1, 0x80, 2, 1, 2][..],
            &[0x30, 7, 2, 2, 0, 1, 2, 1, 2][..],
            &[0x30, 8, 2, 3, 0, 0, 0x80, 2, 1, 2][..],
            // Only one integer, or three.
            &[0x30, 3, 2, 1, 1],
            &[0x30, 9, 2, 1, 1, 2, 1, 2, 2, 1, 3],
            // Nothing, and a bare tag.
            &[],
            &[0x30],
            &[0x30, 6],
        ];
        for der in bad {
            assert!(decode(der, 32, &mut out).is_none(), "{der:02x?}");
        }

        // An integer wider than the half is refused, one that just fits is not.
        let mut wide = vec![0x30, 70, 2, 33, 0];
        wide.extend_from_slice(&[0x80; 32]);
        wide.extend_from_slice(&[2, 33, 0]);
        wide.extend_from_slice(&[0x80; 32]);
        assert!(decode(&wide, 32, &mut out).is_some());
        let mut over = vec![0x30, 71, 2, 34, 0, 0x80];
        over.extend_from_slice(&[0x80; 32]);
        over.extend_from_slice(&[2, 33, 0]);
        over.extend_from_slice(&[0x80; 32]);
        assert!(decode(&over, 32, &mut out).is_none());
        // And the same for s.
        let mut over = vec![0x30, 71, 2, 33, 0];
        over.extend_from_slice(&[0x80; 32]);
        over.extend_from_slice(&[2, 34, 0, 0x80]);
        over.extend_from_slice(&[0x80; 32]);
        assert!(decode(&over, 32, &mut out).is_none());
    }
}
