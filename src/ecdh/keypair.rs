//! Private keys, public keys and shared secrets.

use super::ct;
use super::curve::{Curve, Error, MAX_PRIVATE_KEY_LEN, MAX_PUBLIC_KEY_LEN, MAX_SHARED_SECRET_LEN};
use crate::digest::hex;
use crate::wipe::wipe;
use core::fmt;
use core::marker::PhantomData;
use std::io;

/// A private key of the curve `C`: the secret that one side of an exchange
/// keeps.
///
/// It holds the public key that goes with it, so [`public_key`] is free. The
/// bytes of the key are overwritten with zeros when it is dropped, and `Debug`
/// does not show them. That is best effort: the working values of the
/// arithmetic (numbers that depend on the key, on the stack and in registers
/// while it is in use) are not overwritten, and neither is the copy that moving
/// the key (into a `Box` or a `Vec`, say) can leave behind where it was.
///
/// [`public_key`]: PrivateKey::public_key
pub struct PrivateKey<C: Curve> {
    bytes: [u8; MAX_PRIVATE_KEY_LEN],
    public: PublicKey<C>,
}

/// A public key of the curve `C`: what one side of an exchange sends to the
/// other.
///
/// Holding one means the bytes passed the checks of the curve, so it can be
/// used in [`PrivateKey::diffie_hellman`] without further ones.
pub struct PublicKey<C: Curve> {
    bytes: [u8; MAX_PUBLIC_KEY_LEN],
    curve: PhantomData<C>,
}

/// The result of an exchange: the bytes that both sides compute and nobody else
/// can. It is the input of a key derivation function, not a key.
///
/// The bytes are overwritten with zeros when it is dropped, and `Debug` does
/// not show them.
pub struct SharedSecret<C: Curve> {
    bytes: [u8; MAX_SHARED_SECRET_LEN],
    curve: PhantomData<C>,
}

impl<C: Curve> PrivateKey<C> {
    /// Generates a key from `rng`, which has to be a source of cryptographically
    /// secure random bytes: the secrecy of everything that follows depends on
    /// it. The standard library has none that is stable, so this takes any
    /// reader; on Unix, `File::open("/dev/urandom")` is one.
    ///
    /// For the NIST curves it draws as many bytes as the key has, and tries
    /// again for the (very rare) ones that are not below the order of the
    /// curve, as NIST SP 800-56A (section 5.6.1.2.2) describes. X25519 takes
    /// the first 32 bytes.
    ///
    /// # Errors
    ///
    /// Whatever `rng` fails with. It also gives up, with
    /// [`InvalidData`](io::ErrorKind::InvalidData), after 64 candidates in a
    /// row that are not keys: a good source gets one wrong with a probability
    /// of about 2^-32 for P-256 and much less for the others, so 64 in a row
    /// means the source is stuck (a reader that only returns zeros, say), and
    /// looping on it would never end.
    pub fn generate<R: io::Read + ?Sized>(rng: &mut R) -> io::Result<Self> {
        const ATTEMPTS: usize = 64;

        let mut buffer = [0u8; MAX_PRIVATE_KEY_LEN];
        let mut result = Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "ecdh: the random source did not produce a private key",
        ));
        for _ in 0..ATTEMPTS {
            if let Err(error) = rng.read_exact(&mut buffer[..C::PRIVATE_KEY_LEN]) {
                result = Err(error);
                break;
            }
            buffer[0] &= C::FIRST_BYTE_MASK;
            if C::check_private(&buffer[..C::PRIVATE_KEY_LEN]) {
                result = Ok(Self::new(&buffer[..C::PRIVATE_KEY_LEN]));
                break;
            }
        }
        wipe(&mut buffer);
        result
    }

    /// Builds a key from its encoding: [`Curve::PRIVATE_KEY_LEN`] bytes.
    ///
    /// For a NIST curve that is the scalar as a big-endian number (SEC 1,
    /// section 2.3.8), which has to be at least 1 and below the order of the
    /// curve (section 3.2.1); zero is refused because the matching public key
    /// would be the point at infinity. For X25519 it is 32 bytes of any value: the clamping of RFC
    /// 7748 is applied when the key is used and the bytes are kept as they are.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if !C::check_private(bytes) {
            return Err(Error::InvalidPrivateKey);
        }
        Ok(Self::new(bytes))
    }

    /// `bytes` must have passed `C::check_private`.
    fn new(bytes: &[u8]) -> Self {
        let mut key = Self {
            bytes: [0; MAX_PRIVATE_KEY_LEN],
            public: PublicKey {
                bytes: [0; MAX_PUBLIC_KEY_LEN],
                curve: PhantomData,
            },
        };
        key.bytes[..C::PRIVATE_KEY_LEN].copy_from_slice(bytes);
        C::public_key(bytes, &mut key.public.bytes[..C::PUBLIC_KEY_LEN]);
        key
    }

    /// The encoding of the key, in the form [`from_bytes`] takes.
    ///
    /// [`from_bytes`]: PrivateKey::from_bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..C::PRIVATE_KEY_LEN]
    }

    /// The public key to send to the other side.
    pub fn public_key(&self) -> &PublicKey<C> {
        &self.public
    }

    /// Computes the shared secret of this key and the other side's public key.
    ///
    /// For a NIST curve this is ECDH as in SEC 1 (section 3.3.1), and the
    /// secret is the x-coordinate of the shared point, a big-endian number of
    /// [`Curve::SHARED_SECRET_LEN`] bytes. It is also the Shared Secret
    /// Computation of the Ephemeral Unified Model of NIST SP 800-56A Rev. 3
    /// (section 6.1.2.2). For X25519 it is the function of RFC 7748 (section
    /// 6.1).
    ///
    /// Both sides get the same bytes, and they are not uniformly random: run
    /// them through a key derivation function before using them as a key.
    ///
    /// # Errors
    ///
    /// [`Error::LowOrderPoint`] if the secret would be the point at infinity,
    /// which only an X25519 public key of small order can cause.
    pub fn diffie_hellman(&self, peer: &PublicKey<C>) -> Result<SharedSecret<C>, Error> {
        let mut secret = SharedSecret {
            bytes: [0; MAX_SHARED_SECRET_LEN],
            curve: PhantomData,
        };
        C::diffie_hellman(
            self.as_bytes(),
            peer.as_bytes(),
            &mut secret.bytes[..C::SHARED_SECRET_LEN],
        )?;
        Ok(secret)
    }
}

impl<C: Curve> PublicKey<C> {
    /// Builds a key from its encoding: [`Curve::PUBLIC_KEY_LEN`] bytes.
    ///
    /// For a NIST curve that is an uncompressed point (SEC 1, section 2.3.3):
    /// the byte `0x04` and the two coordinates as big-endian numbers of equal
    /// length. Compressed points and the point at infinity are refused, and so
    /// are coordinates that are not below the prime of the field (a second
    /// encoding of the same point) and points that are not on the curve.
    /// Those are the checks of NIST SP 800-56A Rev. 3, sections 5.6.2.3.3 and
    /// 5.6.2.3.4. The full routine adds that the point has order `n`, which on
    /// a curve of prime order every point but infinity does. For X25519 it is the
    /// u-coordinate as 32 little-endian bytes, of any value; its top bit is
    /// ignored and a value not below 2^255 - 19 is reduced, as RFC 7748
    /// requires.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if !C::check_public(bytes) {
            return Err(Error::InvalidPublicKey);
        }
        let mut key = Self {
            bytes: [0; MAX_PUBLIC_KEY_LEN],
            curve: PhantomData,
        };
        key.bytes[..C::PUBLIC_KEY_LEN].copy_from_slice(bytes);
        Ok(key)
    }

    /// The encoding of the key, in the form [`from_bytes`] takes.
    ///
    /// [`from_bytes`]: PublicKey::from_bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..C::PUBLIC_KEY_LEN]
    }
}

impl<C: Curve> SharedSecret<C> {
    /// The secret: [`Curve::SHARED_SECRET_LEN`] bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..C::SHARED_SECRET_LEN]
    }
}

impl<C: Curve> AsRef<[u8]> for SharedSecret<C> {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl<C: Curve> Drop for PrivateKey<C> {
    fn drop(&mut self) {
        wipe(&mut self.bytes);
    }
}

impl<C: Curve> Drop for SharedSecret<C> {
    fn drop(&mut self) {
        wipe(&mut self.bytes);
    }
}

impl<C: Curve> Clone for PrivateKey<C> {
    fn clone(&self) -> Self {
        Self {
            bytes: self.bytes,
            public: self.public.clone(),
        }
    }
}

impl<C: Curve> Clone for PublicKey<C> {
    fn clone(&self) -> Self {
        Self {
            bytes: self.bytes,
            curve: PhantomData,
        }
    }
}

/// Compares in constant time: two private keys are equal if their encodings
/// are, and the time it takes does not say where they differ. For X25519 that
/// is the 32 bytes as given, not the clamped scalar, so two keys that clamp to
/// the same scalar compare unequal.
impl<C: Curve> PartialEq for PrivateKey<C> {
    fn eq(&self, other: &Self) -> bool {
        ct::bytes_eq(self.as_bytes(), other.as_bytes())
    }
}

impl<C: Curve> Eq for PrivateKey<C> {}

/// Two public keys are equal if their encodings are. For X25519, 32 bytes that
/// stand for the same `u` coordinate (one with its top bit set, or one that is
/// not below the prime) are different encodings of the same key, and compare
/// unequal; they give the same secret.
impl<C: Curve> PartialEq for PublicKey<C> {
    fn eq(&self, other: &Self) -> bool {
        self.as_bytes() == other.as_bytes()
    }
}

impl<C: Curve> Eq for PublicKey<C> {}

/// Compares in constant time.
impl<C: Curve> PartialEq for SharedSecret<C> {
    fn eq(&self, other: &Self) -> bool {
        ct::bytes_eq(self.as_bytes(), other.as_bytes())
    }
}

impl<C: Curve> Eq for SharedSecret<C> {}

impl<C: Curve> fmt::Debug for PrivateKey<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PrivateKey<{}> {{ .. }}", C::NAME)
    }
}

impl<C: Curve> fmt::Debug for PublicKey<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PublicKey<{}>({})", C::NAME, hex(self.as_bytes()))
    }
}

impl<C: Curve> fmt::Debug for SharedSecret<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SharedSecret<{}> {{ .. }}", C::NAME)
    }
}

#[cfg(test)]
mod tests {
    use super::super::vectors::*;
    use super::super::{P256, P384, P521, X25519};
    use super::*;
    use crate::{Digest, sha2::Sha512};

    /// A reader that returns the bytes it was given, in order, then fails.
    struct Script<'a>(&'a [u8]);

    impl io::Read for Script<'_> {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let n = buf.len().min(self.0.len());
            buf[..n].copy_from_slice(&self.0[..n]);
            self.0 = &self.0[n..];
            Ok(n)
        }
    }

    fn check_known_answer<C: Curve>(kat: &Kat) {
        let private = PrivateKey::<C>::from_bytes(&unhex(kat.private)).unwrap();
        assert_eq!(private.as_bytes(), unhex(kat.private));
        assert_eq!(private.public_key().as_bytes(), unhex(kat.public));

        let public = PublicKey::<C>::from_bytes(&unhex(kat.public)).unwrap();
        assert_eq!(&public, private.public_key());

        let peer = PublicKey::<C>::from_bytes(&unhex(kat.peer)).unwrap();
        let secret = private.diffie_hellman(&peer).unwrap();
        assert_eq!(secret.as_bytes(), unhex(kat.secret));
    }

    #[test]
    fn known_answers() {
        check_known_answer::<P256>(&P256_KAT);
        check_known_answer::<P384>(&P384_KAT);
        check_known_answer::<P521>(&P521_KAT);
        check_known_answer::<X25519>(&X25519_KAT);
    }

    #[test]
    fn encoding_lengths() {
        fn check<C: Curve>(private: usize, public: usize, secret: usize) {
            assert_eq!(C::PRIVATE_KEY_LEN, private, "{}", C::NAME);
            assert_eq!(C::PUBLIC_KEY_LEN, public, "{}", C::NAME);
            assert_eq!(C::SHARED_SECRET_LEN, secret, "{}", C::NAME);
            assert!(private <= MAX_PRIVATE_KEY_LEN);
            assert!(public <= MAX_PUBLIC_KEY_LEN);
            assert!(secret <= MAX_SHARED_SECRET_LEN);
        }
        check::<P256>(32, 65, 32);
        check::<P384>(48, 97, 48);
        check::<P521>(66, 133, 66);
        check::<X25519>(32, 32, 32);
    }

    /// Project Wycheproof's cases, a selection of them. For the NIST curves,
    /// every case that is invalid or merely acceptable, which is where an
    /// implementation goes wrong. For X25519, every case with a public key of
    /// small order, not reduced, of a special form or small. For both, the
    /// known-answer cases and a sample of the valid edge cases (doublings,
    /// ephemeral keys, shared secrets, addition chains), among them the one
    /// whose shared secret is all zeros.
    fn check_wycheproof<C: Curve>(cases: &[Wycheproof]) {
        for case in cases {
            let what = format!("{} test {} ({})", C::NAME, case.id, case.flags);
            let private = PrivateKey::<C>::from_bytes(&unhex(case.private))
                .unwrap_or_else(|e| panic!("{what}: private key refused: {e}"));
            let public = match PublicKey::<C>::from_bytes(&unhex(case.public)) {
                Ok(public) => public,
                Err(e) => {
                    assert_eq!(e, Error::InvalidPublicKey, "{what}");
                    assert_ne!(case.result, "valid", "{what}: valid public key refused");
                    continue;
                }
            };
            assert_ne!(
                case.result, "invalid",
                "{what}: invalid public key accepted"
            );

            let result = private.diffie_hellman(&public);
            if C::NAME == "X25519" && case.shared.bytes().all(|b| b == b'0') {
                // A point of small order: an all-zero secret, which is refused
                // rather than returned. (On a NIST curve a zero x-coordinate is
                // a legitimate secret, as the point with x = 0 is on the curve.)
                assert_eq!(result.unwrap_err(), Error::LowOrderPoint, "{what}");
            } else {
                assert_eq!(result.unwrap().as_bytes(), unhex(case.shared), "{what}");
            }
        }
    }

    #[test]
    fn wycheproof() {
        check_wycheproof::<P256>(WYCHEPROOF_P256);
        check_wycheproof::<P384>(WYCHEPROOF_P384);
        check_wycheproof::<P521>(WYCHEPROOF_P521);
        check_wycheproof::<X25519>(WYCHEPROOF_X25519);
    }

    #[test]
    fn rejects_invalid_private_keys() {
        fn check<C: Curve>(invalid: &[&str]) {
            let len = C::PRIVATE_KEY_LEN;
            // Wrong lengths, whatever the bytes are.
            for bad in [0, 1, len - 1, len + 1, 200] {
                let bytes = vec![0x01; bad];
                assert_eq!(
                    PrivateKey::<C>::from_bytes(&bytes).unwrap_err(),
                    Error::InvalidPrivateKey,
                    "{} bytes for {}",
                    bad,
                    C::NAME
                );
            }
            // Zero, the order, and numbers above it.
            for hex in invalid {
                assert_eq!(
                    PrivateKey::<C>::from_bytes(&unhex(hex)).unwrap_err(),
                    Error::InvalidPrivateKey,
                    "{hex}"
                );
            }
            // All ones is above the order on every curve, and the largest
            // number below it is fine.
            assert!(PrivateKey::<C>::from_bytes(&vec![0xff; len]).is_err() || C::NAME == "X25519");
        }
        check::<P256>(INVALID_PRIVATE_P256);
        check::<P384>(INVALID_PRIVATE_P384);
        check::<P521>(INVALID_PRIVATE_P521);
        // X25519 refuses only the wrong lengths, and takes zero and all ones.
        check::<X25519>(&[]);
        assert!(PrivateKey::<X25519>::from_bytes(&[0; 32]).is_ok());
        assert!(PrivateKey::<X25519>::from_bytes(&[0xff; 32]).is_ok());
    }

    #[test]
    fn rejects_invalid_public_keys() {
        fn check<C: Curve>(invalid: &[&str]) {
            let len = C::PUBLIC_KEY_LEN;
            for bad in [0, 1, len - 1, len + 1, 200] {
                let bytes = vec![0x04; bad];
                assert_eq!(
                    PublicKey::<C>::from_bytes(&bytes).unwrap_err(),
                    Error::InvalidPublicKey,
                    "{} bytes for {}",
                    bad,
                    C::NAME
                );
            }
            for hex in invalid {
                assert_eq!(
                    PublicKey::<C>::from_bytes(&unhex(hex)).unwrap_err(),
                    Error::InvalidPublicKey,
                    "{hex}"
                );
            }
        }
        check::<P256>(INVALID_PUBLIC_P256);
        check::<P384>(INVALID_PUBLIC_P384);
        check::<P521>(INVALID_PUBLIC_P521);

        // A coordinate equal to the prime is a second way to write 0, and so a
        // second encoding of a point that is valid in its reduced form.
        for zero_x in [&ZERO_X_P256, &ZERO_X_P384, &ZERO_X_P521] {
            assert_eq!(
                zero_x.not_reduced.len(),
                zero_x.point.len(),
                "the same size as the point"
            );
        }
        for (hex, len) in [
            (ZERO_X_P256.not_reduced, 65),
            (ZERO_X_P384.not_reduced, 97),
            (ZERO_X_P521.not_reduced, 133),
        ] {
            let bytes = unhex(hex);
            assert_eq!(bytes.len(), len);
            let refused = match len {
                65 => PublicKey::<P256>::from_bytes(&bytes).is_err(),
                97 => PublicKey::<P384>::from_bytes(&bytes).is_err(),
                _ => PublicKey::<P521>::from_bytes(&bytes).is_err(),
            };
            assert!(refused, "x equal to p accepted on a {len}-byte curve");
        }

        // A valid point stops being one when its tag, or a coordinate, changes.
        fn tampered<C: Curve>(kat: &Kat) {
            let valid = unhex(kat.public);
            assert!(PublicKey::<C>::from_bytes(&valid).is_ok());
            for tag in [0, 1, 2, 3, 5, 6, 7] {
                let mut bytes = valid.clone();
                bytes[0] = tag;
                assert!(PublicKey::<C>::from_bytes(&bytes).is_err(), "tag {tag}");
            }
            for position in [
                1,
                C::PUBLIC_KEY_LEN / 2,
                C::PUBLIC_KEY_LEN / 2 + 1,
                C::PUBLIC_KEY_LEN - 1,
            ] {
                let mut bytes = valid.clone();
                bytes[position] ^= 1;
                assert!(
                    PublicKey::<C>::from_bytes(&bytes).is_err(),
                    "byte {position}"
                );
            }
        }
        tampered::<P256>(&P256_KAT);
        tampered::<P384>(&P384_KAT);
        tampered::<P521>(&P521_KAT);

        // X25519 refuses only the wrong lengths.
        for bad in [0, 1, 31, 33, 200] {
            assert_eq!(
                PublicKey::<X25519>::from_bytes(&vec![9; bad]).unwrap_err(),
                Error::InvalidPublicKey
            );
        }
        assert!(PublicKey::<X25519>::from_bytes(&[0; 32]).is_ok());
    }

    /// X25519 with the points of small order, for which the secret is all zeros
    /// whatever the private key is. RFC 7748 (section 6.1) allows an
    /// implementation to check for that, and this one does.
    #[test]
    fn x25519_refuses_points_of_small_order() {
        let private = PrivateKey::<X25519>::from_bytes(&[0x42; 32]).unwrap();
        for u in [
            // The points of order 2 and 4 (u = 0, 1 and p - 1), the two of order
            // 8, and the encodings p and p + 1 of 0 and 1 that are not below
            // the prime, which have to be reduced first.
            "0000000000000000000000000000000000000000000000000000000000000000",
            "0100000000000000000000000000000000000000000000000000000000000000",
            "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
            "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
            "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",
            "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
            "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        ] {
            let mut bytes = unhex(u);
            for top_bit in [0x00, 0x80] {
                // The top bit of the last byte is ignored.
                bytes[31] = (bytes[31] & 0x7f) | top_bit;
                let public = PublicKey::<X25519>::from_bytes(&bytes).unwrap();
                assert_eq!(
                    private.diffie_hellman(&public).unwrap_err(),
                    Error::LowOrderPoint,
                    "{u} with top bit {top_bit:#x}"
                );
            }
        }
    }

    /// The derivation of the chained test: a key from `state`, `which` of the two
    /// of a round, trying again with the next counter for the rare candidate
    /// that is not a valid NIST key.
    fn derive<C: Curve>(state: &[u8], which: u8) -> PrivateKey<C> {
        for counter in 0..=255 {
            let mut material = Vec::new();
            for part in 0..2 {
                let mut input = state.to_vec();
                input.extend([which, counter, part]);
                material.extend(Sha512::digest(&input));
            }
            let mut candidate = material[..C::PRIVATE_KEY_LEN].to_vec();
            candidate[0] &= C::FIRST_BYTE_MASK;
            if let Ok(key) = PrivateKey::<C>::from_bytes(&candidate) {
                return key;
            }
        }
        unreachable!("256 candidates in a row were refused");
    }

    /// Rounds of two derived keys exchanging with each other, each round
    /// seeded by the hash of the last, compared with what OpenSSL gets from
    /// the same keys. A wrong carry in one multiplication among the hundreds of
    /// thousands that these exchanges make changes every value after it.
    fn check_chain<C: Curve>(expected: &[&str; 2]) {
        let mut state =
            Sha512::digest(format!("cryptors ecdh chain {}", C::NAME).as_bytes()).to_vec();
        for round in 0..CHAIN_STEPS {
            let (a, b) = (derive::<C>(&state, 0), derive::<C>(&state, 1));
            let from_a = a.diffie_hellman(b.public_key()).unwrap();
            let from_b = b.diffie_hellman(a.public_key()).unwrap();
            assert_eq!(
                from_a,
                from_b,
                "{}: the two sides disagree in round {round}",
                C::NAME
            );

            let mut input = state.clone();
            input.extend(from_a.as_bytes());
            input.extend(a.public_key().as_bytes());
            input.extend(b.public_key().as_bytes());
            state = Sha512::digest(&input).to_vec();
            if round == 0 {
                assert_eq!(state, unhex(expected[0]), "{} after one round", C::NAME);
            }
        }
        assert_eq!(
            state,
            unhex(expected[1]),
            "{} after {CHAIN_STEPS} rounds",
            C::NAME
        );
    }

    #[test]
    fn chained_exchanges() {
        check_chain::<P256>(&CHAIN_P256);
        check_chain::<P384>(&CHAIN_P384);
        check_chain::<P521>(&CHAIN_P521);
        check_chain::<X25519>(&CHAIN_X25519);
    }

    #[test]
    fn generate_draws_one_key_from_the_reader() {
        let bytes: Vec<u8> = (1..=66).collect();

        // A valid key is used as it comes, and nothing more than its length is read.
        let mut reader = Script(&bytes);
        let key = PrivateKey::<P256>::generate(&mut reader).unwrap();
        assert_eq!(key.as_bytes(), &bytes[..32]);
        assert_eq!(reader.0.len(), 66 - 32);

        let mut reader = Script(&bytes);
        let key = PrivateKey::<P384>::generate(&mut reader).unwrap();
        assert_eq!(key.as_bytes(), &bytes[..48]);
        assert_eq!(reader.0.len(), 66 - 48);

        // Only P-521 masks the first byte: for the other curves every bit of it
        // is part of the key, the high one too.
        let mut high = bytes.clone();
        high[0] = 0xfe;
        let key = PrivateKey::<P256>::generate(&mut Script(&high)).unwrap();
        assert_eq!(key.as_bytes(), &high[..32]);
        let key = PrivateKey::<P384>::generate(&mut Script(&high)).unwrap();
        assert_eq!(key.as_bytes(), &high[..48]);

        // P-521 keeps one bit of the first byte, and 1 is already that.
        let mut reader = Script(&bytes);
        let key = PrivateKey::<P521>::generate(&mut reader).unwrap();
        assert_eq!(key.as_bytes(), &bytes[..66]);
        assert!(reader.0.is_empty());

        // X25519 takes any 32 bytes as they are: the key keeps them unclamped.
        let key = PrivateKey::<X25519>::generate(&mut Script(&[0xff; 32])).unwrap();
        assert_eq!(key.as_bytes(), [0xff; 32]);
    }

    #[test]
    fn generate_skips_candidates_that_are_not_keys() {
        let good: Vec<u8> = (1..=66).collect();

        // Zero, then the order itself, then a valid key.
        let order = |hex: &str| unhex(hex);
        let p256_order = order("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551");
        let mut input = vec![0; 32];
        input.extend(&p256_order);
        input.extend(&good[..32]);
        let mut reader = Script(&input);
        let key = PrivateKey::<P256>::generate(&mut reader).unwrap();
        assert_eq!(key.as_bytes(), &good[..32]);
        assert!(reader.0.is_empty(), "all three candidates were drawn");

        // For P-521, 0xff.. is masked to 0x01ff..ff, above the order. Without the
        // mask a candidate would be too big about 99% of the time (it is a
        // number of 528 bits and the order has 521); with it, 0xfe becomes 0x00
        // and a small number is a valid key.
        let mut input = vec![0xff; 66];
        let mut small = vec![0; 66];
        small[0] = 0xfe;
        small[65] = 5;
        input.extend(&small);
        let key = PrivateKey::<P521>::generate(&mut Script(&input)).unwrap();
        let mut expected = vec![0; 66];
        expected[65] = 5;
        assert_eq!(key.as_bytes(), expected);
    }

    #[test]
    fn generate_reports_a_reader_that_fails() {
        // Too few bytes for a key.
        let error = PrivateKey::<P384>::generate(&mut Script(&[7; 47])).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
        // A refused candidate and then nothing.
        let error = PrivateKey::<P256>::generate(&mut Script(&[0; 32])).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
        assert!(PrivateKey::<X25519>::generate(&mut Script(&[])).is_err());
    }

    #[test]
    fn equality_and_cloning() {
        let a = PrivateKey::<P256>::from_bytes(&[1; 32]).unwrap();
        let b = PrivateKey::<P256>::from_bytes(&[2; 32]).unwrap();
        assert_eq!(a, a.clone());
        assert_ne!(a, b);
        assert_eq!(a.public_key(), &a.public_key().clone());
        assert_ne!(a.public_key(), b.public_key());

        let (s, t) = (
            a.diffie_hellman(b.public_key()).unwrap(),
            b.diffie_hellman(a.public_key()).unwrap(),
        );
        assert_eq!(s, t);
        assert_ne!(s, a.diffie_hellman(a.public_key()).unwrap());
    }

    /// A private key and a shared secret must leave no byte behind.
    #[test]
    fn dropping_wipes_the_secrets() {
        use core::mem::MaybeUninit;

        // One raw pointer does the dropping and the reading, so that the drop
        // does not invalidate the pointer the reads go through.
        let mut private = MaybeUninit::new(PrivateKey::<P384>::from_bytes(&[0x42; 48]).unwrap());
        let private = private.as_mut_ptr();
        // SAFETY: `private` is a valid pointer to the live key; this takes the
        // address of a field and reads nothing.
        let bytes = unsafe { &raw const (*private).bytes };
        let read = || {
            // SAFETY: the slot stays allocated, and every byte of the array was
            // written by `new` and then, if the drop works, by `wipe`.
            unsafe { bytes.read() }
        };
        assert!(read().iter().any(|&b| b != 0), "nothing to wipe");
        // SAFETY: the key is initialised and dropped only here.
        unsafe { private.drop_in_place() };
        assert!(
            read().iter().all(|&b| b == 0),
            "the private key survives the drop"
        );

        let key = PrivateKey::<X25519>::from_bytes(&[0x42; 32]).unwrap();
        let mut secret = MaybeUninit::new(key.diffie_hellman(key.public_key()).unwrap());
        let secret = secret.as_mut_ptr();
        // SAFETY: as above.
        let bytes = unsafe { &raw const (*secret).bytes };
        let read = || {
            // SAFETY: as above.
            unsafe { bytes.read() }
        };
        assert!(read().iter().any(|&b| b != 0), "nothing to wipe");
        // SAFETY: the secret is initialised and dropped only here.
        unsafe { secret.drop_in_place() };
        assert!(
            read().iter().all(|&b| b == 0),
            "the shared secret survives the drop"
        );
    }

    #[test]
    fn debug_hides_the_secrets() {
        let private = PrivateKey::<P256>::from_bytes(&unhex(P256_KAT.private)).unwrap();
        assert_eq!(format!("{private:?}"), "PrivateKey<P-256> { .. }");

        let peer = PublicKey::<P256>::from_bytes(&unhex(P256_KAT.peer)).unwrap();
        let secret = private.diffie_hellman(&peer).unwrap();
        assert_eq!(format!("{secret:?}"), "SharedSecret<P-256> { .. }");

        // A public key is public, and shows.
        assert_eq!(
            format!("{peer:?}"),
            format!("PublicKey<P-256>({})", P256_KAT.peer)
        );
    }

    /// The smallest and the largest private keys are keys: 1 and 2, and n - 1,
    /// the largest number below the order.
    #[test]
    fn edge_scalars_are_keys() {
        fn check<C: Curve>(vectors: &[[&str; 2]; 3]) {
            for [private, public] in vectors {
                let key = PrivateKey::<C>::from_bytes(&unhex(private))
                    .unwrap_or_else(|e| panic!("{} {private}: {e}", C::NAME));
                assert_eq!(
                    key.public_key().as_bytes(),
                    unhex(public),
                    "{} {private}",
                    C::NAME
                );
            }
        }
        check::<P256>(&EDGE_SCALARS_P256);
        check::<P384>(&EDGE_SCALARS_P384);
        check::<P521>(&EDGE_SCALARS_P521);
    }

    /// The point with x = 0 is on every NIST curve (b is a square), so it is a
    /// valid public key, and a shared secret can legitimately be all zeros.
    /// Nothing about a zero secret is an error here, unlike X25519.
    #[test]
    fn a_zero_x_coordinate_is_not_special_on_the_nist_curves() {
        fn check<C: Curve>(vector: &ZeroX) {
            let peer = PublicKey::<C>::from_bytes(&unhex(vector.point)).unwrap();
            for (d, expected) in [1u8, 2].into_iter().zip(vector.secrets) {
                let mut scalar = vec![0; C::PRIVATE_KEY_LEN];
                *scalar.last_mut().unwrap() = d;
                let secret = PrivateKey::<C>::from_bytes(&scalar)
                    .unwrap()
                    .diffie_hellman(&peer)
                    .unwrap();
                assert_eq!(secret.as_bytes(), unhex(expected), "{} d = {d}", C::NAME);
            }
            // 1 * (0, y) is the point itself: its x is zero.
            assert!(unhex(vector.secrets[0]).iter().all(|&b| b == 0));
        }
        check::<P256>(&ZERO_X_P256);
        check::<P384>(&ZERO_X_P384);
        check::<P521>(&ZERO_X_P521);
    }

    /// A reader that returns the same bytes for ever, and counts what it gave.
    struct Stuck {
        byte: u8,
        reads: usize,
    }

    impl io::Read for Stuck {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.reads += 1;
            buf.fill(self.byte);
            Ok(buf.len())
        }
    }

    #[test]
    fn generate_gives_up_on_a_source_that_never_gives_a_key() {
        // Zero is not a key, on a NIST curve: 64 tries, then an error, not a loop.
        let mut zeros = Stuck { byte: 0, reads: 0 };
        let error = PrivateKey::<P256>::generate(&mut zeros).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(zeros.reads, 64);

        // All ones is masked to 0x01ff..ff for P-521, above the order.
        let mut ones = Stuck {
            byte: 0xff,
            reads: 0,
        };
        assert!(PrivateKey::<P521>::generate(&mut ones).is_err());
        assert_eq!(ones.reads, 64);
        let mut ones = Stuck {
            byte: 0xff,
            reads: 0,
        };
        assert!(PrivateKey::<P384>::generate(&mut ones).is_err());

        // X25519 takes any 32 bytes, zeros too, on the first try.
        let mut zeros = Stuck { byte: 0, reads: 0 };
        let key = PrivateKey::<X25519>::generate(&mut zeros).unwrap();
        assert_eq!(key.as_bytes(), [0; 32]);
        assert_eq!(zeros.reads, 1);
    }

    #[test]
    #[ignore = "manual throughput check: cargo test --release ecdh:: -- --ignored --nocapture --test-threads=1"]
    fn throughput() {
        use std::hint::black_box;
        use std::time::{Duration, Instant};

        /// The best of five batches of `op`, in microseconds per call, after a
        /// warm-up call (which also builds the table of multiples of the
        /// generator, once) and a pass to size the batches to about 100 ms.
        fn time(mut op: impl FnMut()) -> f64 {
            op();
            let start = Instant::now();
            let mut calls = 0u32;
            while start.elapsed() < Duration::from_millis(50) {
                op();
                calls += 1;
            }
            let batch = (2 * calls).max(1);

            let mut best = f64::MAX;
            for _ in 0..5 {
                let start = Instant::now();
                for _ in 0..batch {
                    op();
                }
                best = best.min(start.elapsed().as_secs_f64() / f64::from(batch));
            }
            best * 1e6
        }

        /// A private key of `len` bytes that is valid on every curve here: a
        /// fixed pattern with a top byte below the order of each.
        fn scalar(len: usize, seed: usize) -> Vec<u8> {
            let mut bytes: Vec<u8> = (0..len).map(|i| (seed + i * 37) as u8).collect();
            bytes[0] = if len == 66 { 0x01 } else { 0x7f };
            bytes
        }

        fn run<C: Curve>() {
            let private = scalar(C::PRIVATE_KEY_LEN, 11);
            let peer_private =
                PrivateKey::<C>::from_bytes(&scalar(C::PRIVATE_KEY_LEN, 53)).unwrap();
            let peer = peer_private.public_key().as_bytes().to_vec();

            let key = PrivateKey::<C>::from_bytes(&private).unwrap();
            let peer_key = PublicKey::<C>::from_bytes(&peer).unwrap();
            let secret = key.diffie_hellman(&peer_key).unwrap();

            // Building a private key derives its public key: a multiplication
            // of the generator. Building a public key checks that the point is
            // on the curve. The exchange is a multiplication of the peer's
            // point, and a full side of a handshake is all three.
            let rows = [
                (
                    "new private key",
                    time(|| {
                        drop(black_box(
                            PrivateKey::<C>::from_bytes(black_box(&private)).unwrap(),
                        ))
                    }),
                ),
                (
                    "new public key",
                    time(|| {
                        black_box(PublicKey::<C>::from_bytes(black_box(&peer)).unwrap());
                    }),
                ),
                (
                    "ecdh",
                    time(|| drop(black_box(key.diffie_hellman(black_box(&peer_key)).unwrap()))),
                ),
                (
                    "handshake",
                    time(|| {
                        let key = PrivateKey::<C>::from_bytes(black_box(&private)).unwrap();
                        let peer = PublicKey::<C>::from_bytes(black_box(&peer)).unwrap();
                        drop(black_box(key.diffie_hellman(&peer).unwrap()));
                    }),
                ),
            ];
            for (name, micros) in rows {
                println!(
                    "{} {name} [cryptors]: best {micros:.1} us/op, {:.0} ops/s (secret {}...)",
                    C::NAME,
                    1e6 / micros,
                    hex(&secret.as_bytes()[..8])
                );
            }
        }

        run::<P256>();
        run::<P384>();
        run::<P521>();
        run::<X25519>();
    }
}
