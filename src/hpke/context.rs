//! The modes, the key schedule and the encryption context (RFC 9180 section
//! 5), and the setup and single-shot functions of a suite (sections 5.1 and
//! 6.1).

use core::fmt;

use super::kem::{self, PrivateKey, PublicKey};
use super::secret::Secret;
use super::{Aead, Error, Suite};
use crate::aes::{Aes128, Aes256};
use crate::gcm::{Gcm, NONCE_LEN, NotAuthentic, TooLong};
use crate::wipe::wipe;

/// The shortest pre-shared key accepted: RFC 9180 requires a PSK to have at
/// least 32 bytes of entropy (section 5.1.2), which a shorter one cannot.
const MIN_PSK_LEN: usize = 32;

/// The sequence number at which a context stops: `(1 << (8 * Nn)) - 1` with
/// the 12-byte nonces of both AEADs (RFC 9180 section 5.2).
const SEQ_LIMIT: u128 = (1 << (8 * NONCE_LEN)) - 1;

/// The mode of HPKE (RFC 9180 section 5): what, besides the recipient's key,
/// goes into the shared secret.
///
/// This is the one-byte value of the protocol. The setup functions take a
/// [`SenderMode`] or a [`RecipientMode`] instead, which carry the inputs the
/// mode needs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Mode {
    /// `mode_base`, `0x00`: encryption to a public key, from anyone.
    Base,
    /// `mode_psk`, `0x01`: the sender also proves it holds a pre-shared key.
    Psk,
    /// `mode_auth`, `0x02`: the sender also proves it holds a private key.
    Auth,
    /// `mode_auth_psk`, `0x03`: both.
    AuthPsk,
}

impl Mode {
    /// The mode's value in the key schedule.
    pub const fn id(self) -> u8 {
        match self {
            Mode::Base => 0x00,
            Mode::Psk => 0x01,
            Mode::Auth => 0x02,
            Mode::AuthPsk => 0x03,
        }
    }
}

/// The mode of a sender, with the inputs it needs (RFC 9180 sections 5.1.1 to
/// 5.1.4).
///
/// A pre-shared key and its identifier must both be non-empty, and the key at
/// least 32 bytes long; otherwise setup fails with [`Error::InvalidPsk`]. The
/// key must also have at least 32 bytes of entropy, which cannot be checked:
/// it must not be a password.
#[derive(Clone, Copy)]
pub enum SenderMode<'a> {
    /// `mode_base`.
    Base,
    /// `mode_psk`: the pre-shared key and its identifier.
    Psk {
        /// The pre-shared key.
        psk: &'a [u8],
        /// The identifier of the key, which the recipient uses to find it.
        psk_id: &'a [u8],
    },
    /// `mode_auth`: the sender's private key.
    Auth {
        /// The sender's private key, whose public key the recipient knows.
        sk_s: &'a PrivateKey,
    },
    /// `mode_auth_psk`: both.
    AuthPsk {
        /// The pre-shared key.
        psk: &'a [u8],
        /// The identifier of the key.
        psk_id: &'a [u8],
        /// The sender's private key.
        sk_s: &'a PrivateKey,
    },
}

/// The mode of a recipient, with the inputs it needs: the same pre-shared key
/// as the sender's, and the sender's public key in place of its private key.
#[derive(Clone, Copy)]
pub enum RecipientMode<'a> {
    /// `mode_base`.
    Base,
    /// `mode_psk`: the pre-shared key and its identifier.
    Psk {
        /// The pre-shared key.
        psk: &'a [u8],
        /// The identifier of the key.
        psk_id: &'a [u8],
    },
    /// `mode_auth`: the sender's public key.
    Auth {
        /// The public key of the sender's private key.
        pk_s: &'a PublicKey,
    },
    /// `mode_auth_psk`: both.
    AuthPsk {
        /// The pre-shared key.
        psk: &'a [u8],
        /// The identifier of the key.
        psk_id: &'a [u8],
        /// The public key of the sender's private key.
        pk_s: &'a PublicKey,
    },
}

impl SenderMode<'_> {
    /// The mode's value.
    pub const fn mode(&self) -> Mode {
        match self {
            SenderMode::Base => Mode::Base,
            SenderMode::Psk { .. } => Mode::Psk,
            SenderMode::Auth { .. } => Mode::Auth,
            SenderMode::AuthPsk { .. } => Mode::AuthPsk,
        }
    }

    /// The pre-shared key and its identifier, empty in the modes without.
    fn psk(&self) -> (&[u8], &[u8]) {
        match *self {
            SenderMode::Psk { psk, psk_id } | SenderMode::AuthPsk { psk, psk_id, .. } => {
                (psk, psk_id)
            }
            SenderMode::Base | SenderMode::Auth { .. } => (b"", b""),
        }
    }
}

impl RecipientMode<'_> {
    /// The mode's value.
    pub const fn mode(&self) -> Mode {
        match self {
            RecipientMode::Base => Mode::Base,
            RecipientMode::Psk { .. } => Mode::Psk,
            RecipientMode::Auth { .. } => Mode::Auth,
            RecipientMode::AuthPsk { .. } => Mode::AuthPsk,
        }
    }

    fn psk(&self) -> (&[u8], &[u8]) {
        match *self {
            RecipientMode::Psk { psk, psk_id } | RecipientMode::AuthPsk { psk, psk_id, .. } => {
                (psk, psk_id)
            }
            RecipientMode::Base | RecipientMode::Auth { .. } => (b"", b""),
        }
    }
}

/// Shows the mode and nothing else: the pre-shared key is secret.
impl fmt::Debug for SenderMode<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SenderMode::{:?}", self.mode())
    }
}

/// Shows the mode and nothing else: the pre-shared key is secret.
impl fmt::Debug for RecipientMode<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RecipientMode::{:?}", self.mode())
    }
}

/// `VerifyPSKInputs(mode, psk, psk_id)` (RFC 9180 section 5.1), and the
/// length that the entropy requirement implies.
fn verify_psk_inputs(mode: Mode, psk: &[u8], psk_id: &[u8]) -> Result<(), Error> {
    let (got_psk, got_psk_id) = (!psk.is_empty(), !psk_id.is_empty());
    if got_psk != got_psk_id {
        // "Inconsistent PSK inputs".
        return Err(Error::InvalidPsk);
    }
    let needs_psk = matches!(mode, Mode::Psk | Mode::AuthPsk);
    if got_psk != needs_psk {
        // "PSK input provided when not needed", or "Missing required PSK
        // input".
        return Err(Error::InvalidPsk);
    }
    if got_psk && psk.len() < MIN_PSK_LEN {
        return Err(Error::InvalidPsk);
    }
    Ok(())
}

/// What `KeySchedule()` derives (RFC 9180 section 5.1): the AEAD key, the
/// base nonce and the exporter secret, before they become a context. The
/// key and the nonce are empty for the export-only AEAD.
pub(super) struct Schedule {
    pub(super) key: Secret,
    pub(super) base_nonce: Secret,
    pub(super) exporter_secret: Secret,
}

/// `KeySchedule(mode, shared_secret, info, psk, psk_id)` (RFC 9180 section
/// 5.1).
pub(super) fn key_schedule(
    suite: Suite,
    mode: Mode,
    shared_secret: &[u8],
    info: &[u8],
    psk: &[u8],
    psk_id: &[u8],
) -> Result<Schedule, Error> {
    verify_psk_inputs(mode, psk, psk_id)?;
    let (suite_id, kdf) = (suite.id(), suite.kdf());

    let psk_id_hash = kdf.labeled_extract(&suite_id, b"", b"psk_id_hash", psk_id);
    let info_hash = kdf.labeled_extract(&suite_id, b"", b"info_hash", info);
    let key_schedule_context = [
        &[mode.id()][..],
        psk_id_hash.as_bytes(),
        info_hash.as_bytes(),
    ]
    .concat();

    let secret = kdf.labeled_extract(&suite_id, shared_secret, b"secret", psk);
    let expand = |label: &[u8], len: usize| {
        let mut out = Secret::zeroed(len);
        kdf.labeled_expand(
            &suite_id,
            secret.as_bytes(),
            label,
            &key_schedule_context,
            out.as_mut_bytes(),
        )
        .expect("Nk, Nn and Nh are within every KDF's limit");
        out
    };

    // `Nk` and `Nn` (RFC 9180 section 7.3). The export-only AEAD has neither,
    // and section 5.3 lets their derivation be skipped.
    let (key_len, nonce_len) = match suite.aead() {
        Aead::Aes128Gcm => (16, NONCE_LEN),
        Aead::Aes256Gcm => (32, NONCE_LEN),
        Aead::ExportOnly => (0, 0),
    };
    let (key, base_nonce) = if key_len == 0 {
        (Secret::zeroed(0), Secret::zeroed(0))
    } else {
        (expand(b"key", key_len), expand(b"base_nonce", nonce_len))
    };
    Ok(Schedule {
        key,
        base_nonce,
        exporter_secret: expand(b"exp", kdf.hash_len()),
    })
}

/// A keyed AEAD.
enum Cipher {
    Aes128Gcm(Gcm<Aes128>),
    Aes256Gcm(Gcm<Aes256>),
    ExportOnly,
}

impl Cipher {
    /// The AEAD of `aead`, under `key`, of the AEAD's key length.
    fn new(aead: Aead, key: &[u8]) -> Self {
        /// The key as the array the cipher takes, wiped after use.
        fn keyed<const N: usize, C>(key: &[u8], new: impl Fn(&[u8; N]) -> C) -> C {
            let mut array: [u8; N] = key.try_into().expect("the key schedule made Nk bytes");
            let cipher = new(&array);
            wipe(&mut array);
            cipher
        }
        match aead {
            Aead::Aes128Gcm => Cipher::Aes128Gcm(keyed(key, Gcm::new)),
            Aead::Aes256Gcm => Cipher::Aes256Gcm(keyed(key, Gcm::new)),
            Aead::ExportOnly => Cipher::ExportOnly,
        }
    }
}

/// An encryption context (RFC 9180 section 5.2): the AEAD, its base nonce
/// and sequence number, and the exporter secret. The secrets are wiped when it
/// is dropped: the AEAD's by the cipher and the rest by [`Secret`].
struct Context {
    suite: Suite,
    cipher: Cipher,
    base_nonce: Secret,
    seq: u128,
    exporter_secret: Secret,
}

impl Context {
    fn new(suite: Suite, schedule: Schedule) -> Self {
        Self {
            suite,
            cipher: Cipher::new(suite.aead(), schedule.key.as_bytes()),
            base_nonce: schedule.base_nonce,
            seq: 0,
            exporter_secret: schedule.exporter_secret,
        }
    }

    /// `ComputeNonce(seq)` (RFC 9180 section 5.2): the base nonce XORed with
    /// the sequence number as a 12-byte big-endian integer.
    fn nonce(&self) -> [u8; NONCE_LEN] {
        // The sequence number never reaches 2^96, so its first four bytes as a
        // `u128` are zero and the last twelve are all of it.
        let seq = self.seq.to_be_bytes();
        let base = self.base_nonce.as_bytes();
        core::array::from_fn(|i| base[i] ^ seq[16 - NONCE_LEN + i])
    }

    /// `ContextS.Seal(aad, pt)` (RFC 9180 section 5.2).
    fn seal(&mut self, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, Error> {
        let ciphertext = match &self.cipher {
            Cipher::ExportOnly => return Err(Error::ExportOnly),
            // The check of `IncrementSeq()`, made before the message instead
            // of after it, which fails the same calls.
            _ if self.seq >= SEQ_LIMIT => return Err(Error::MessageLimitReached),
            Cipher::Aes128Gcm(gcm) => gcm.seal(&self.nonce(), aad, plaintext),
            Cipher::Aes256Gcm(gcm) => gcm.seal(&self.nonce(), aad, plaintext),
        }
        .map_err(|TooLong| Error::MessageTooLong)?;
        self.seq += 1;
        Ok(ciphertext)
    }

    /// `ContextR.Open(aad, ct)` (RFC 9180 section 5.2). A ciphertext that does
    /// not open leaves the sequence number where it was.
    fn open(&mut self, aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, Error> {
        let plaintext = match &self.cipher {
            Cipher::ExportOnly => return Err(Error::ExportOnly),
            _ if self.seq >= SEQ_LIMIT => return Err(Error::MessageLimitReached),
            Cipher::Aes128Gcm(gcm) => gcm.open(&self.nonce(), aad, ciphertext),
            Cipher::Aes256Gcm(gcm) => gcm.open(&self.nonce(), aad, ciphertext),
        }
        .map_err(|NotAuthentic| Error::Open)?;
        self.seq += 1;
        Ok(plaintext)
    }

    /// `Context.Export(exporter_context, L)` (RFC 9180 section 5.3).
    fn export(&self, exporter_context: &[u8], len: usize) -> Result<Vec<u8>, Error> {
        // Checked before allocating, so a huge length fails instead of
        // aborting.
        let kdf = self.suite.kdf();
        if len > 255 * kdf.hash_len() {
            return Err(Error::ExportTooLong);
        }
        let mut out = vec![0u8; len];
        kdf.labeled_expand(
            &self.suite.id(),
            self.exporter_secret.as_bytes(),
            b"sec",
            exporter_context,
            &mut out,
        )
        .map_err(|_| Error::ExportTooLong)?;
        Ok(out)
    }
}

/// The sender's side of an HPKE context: it seals a sequence of messages to
/// one recipient, and exports secrets the recipient can export too.
///
/// Made by [`Suite::setup_sender`]. Each [`seal`](Self::seal) uses the next
/// nonce, so the recipient must [`open`](Recipient::open) the ciphertexts in
/// the order they were sealed. The type is deliberately not `Clone`: two
/// copies would seal different messages under the same nonce.
///
/// The keys are overwritten with zeros when the context is dropped, and
/// `Debug` does not show them.
pub struct Sender {
    context: Context,
}

impl Sender {
    /// `ContextS.Seal(aad, pt)` (RFC 9180 section 5.2): encrypts and
    /// authenticates `plaintext`, and authenticates `aad` with it. The
    /// ciphertext is 16 bytes longer than the plaintext, for the tag.
    ///
    /// Fails with [`Error::ExportOnly`] if the suite's AEAD is export-only,
    /// [`Error::MessageLimitReached`] once the context has sealed `2^96 - 1`
    /// messages, and [`Error::MessageTooLong`] for a plaintext over `2^36 - 32`
    /// bytes. A failed call does not use up a nonce.
    pub fn seal(&mut self, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, Error> {
        self.context.seal(aad, plaintext)
    }

    /// `Context.Export(exporter_context, L)` (RFC 9180 section 5.3): `len`
    /// bytes of secret derived from the context and `exporter_context`, which
    /// the recipient's context exports too.
    ///
    /// Fails with [`Error::ExportTooLong`] if `len` is more than 255 hash
    /// lengths of the suite's KDF: 8160 bytes for HKDF-SHA256, 12240 for
    /// HKDF-SHA384 and 16320 for HKDF-SHA512.
    pub fn export(&self, exporter_context: &[u8], len: usize) -> Result<Vec<u8>, Error> {
        self.context.export(exporter_context, len)
    }
}

/// The recipient's side of an HPKE context: it opens the sender's
/// messages, in the order they were sealed, and exports the same secrets.
///
/// Made by [`Suite::setup_recipient`]. Like [`Sender`], it is not `Clone`, and
/// its keys are wiped on drop and hidden from `Debug`.
pub struct Recipient {
    context: Context,
}

impl Recipient {
    /// `ContextR.Open(aad, ct)` (RFC 9180 section 5.2): the plaintext of the
    /// next ciphertext in the sequence.
    ///
    /// Fails with [`Error::Open`] if it does not authenticate, which leaves
    /// the sequence where it was, so the next call still expects the same
    /// message. Fails with [`Error::ExportOnly`] and
    /// [`Error::MessageLimitReached`] as [`Sender::seal`] does.
    pub fn open(&mut self, aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, Error> {
        self.context.open(aad, ciphertext)
    }

    /// `Context.Export(exporter_context, L)` (RFC 9180 section 5.3): the same
    /// as [`Sender::export`] on the sender's side.
    pub fn export(&self, exporter_context: &[u8], len: usize) -> Result<Vec<u8>, Error> {
        self.context.export(exporter_context, len)
    }
}

/// Shows the type and nothing else: the keys are secret.
impl fmt::Debug for Sender {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Sender").finish_non_exhaustive()
    }
}

/// Shows the type and nothing else: the keys are secret.
impl fmt::Debug for Recipient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Recipient").finish_non_exhaustive()
    }
}

#[cfg(test)]
impl Sender {
    /// Moves the sequence number, to test what happens at its limit without
    /// sealing 2^96 messages first.
    pub(super) fn set_sequence(&mut self, seq: u128) {
        self.context.seq = seq;
    }
}

#[cfg(test)]
impl Recipient {
    pub(super) fn set_sequence(&mut self, seq: u128) {
        self.context.seq = seq;
    }
}

impl Suite {
    /// `SetupBaseS`, `SetupPSKS`, `SetupAuthS` or `SetupAuthPSKS` (RFC 9180
    /// section 5.1), as `mode` says: a context that seals messages to the
    /// holder of the private key of `pk_r`, and the encapsulated key `enc`
    /// to send it along with them.
    ///
    /// `info` is public information that binds the context to its use; the
    /// recipient must give the same.
    ///
    /// # Entropy
    ///
    /// **`ikm_e` must be fresh, uniformly random bytes from a cryptographically
    /// secure source, at least [`Kem::private_key_len`](super::Kem::private_key_len)
    /// of them (32 for X25519 and P-256, 48 for P-384, 66 for P-521), never
    /// used for anything else, and never used twice.** The crate has no random
    /// number generator, so the randomness of the encapsulation comes from the
    /// caller: the ephemeral key pair is `DeriveKeyPair(ikm_e)` (RFC 9180
    /// sections 4 and 7.1.3).
    ///
    /// Nothing else is random, so the same `ikm_e` and inputs always give the
    /// same `enc` and the same context. That is what makes the test vectors of
    /// RFC 9180, which publish their `ikmE`, checkable through this function.
    /// It is also why reusing `ikm_e` is fatal: two contexts with the same
    /// key encrypt their first messages under the same key and nonce, which
    /// breaks AES-GCM's confidentiality and integrity both (RFC 9180 section
    /// 9.7.5). Predictable bytes are as bad: whoever can guess `ikm_e` can
    /// decrypt the Base and PSK modes.
    ///
    /// # Errors
    ///
    /// [`Error::KemMismatch`] if `pk_r` (or the sender's key, in the
    /// authenticated modes) belongs to another KEM than the suite's,
    /// [`Error::IkmTooShort`] for an `ikm_e` shorter than a private key,
    /// [`Error::LowOrderPublicKey`] if `pk_r` is an X25519 key of small order,
    /// and [`Error::InvalidPsk`] for a pre-shared key and identifier that do
    /// not go together.
    ///
    /// ```
    /// use cryptors::hpke::{Aead, Kdf, Kem, RecipientMode, SenderMode, Suite};
    ///
    /// let suite = Suite::new(Kem::X25519HkdfSha256, Kdf::HkdfSha256, Aead::Aes128Gcm);
    /// // In real use: 32 or more random bytes for the key, 32 for each setup.
    /// let sk_r = Kem::X25519HkdfSha256.derive_key_pair(&[1; 32])?;
    /// let ikm_e = [2; 32];
    ///
    /// let (enc, mut sender) =
    ///     suite.setup_sender(sk_r.public_key(), b"app v1", SenderMode::Base, &ikm_e)?;
    /// let first = sender.seal(b"header 1", b"first message")?;
    /// let second = sender.seal(b"header 2", b"second message")?;
    ///
    /// let mut recipient = suite.setup_recipient(&enc, &sk_r, b"app v1", RecipientMode::Base)?;
    /// assert_eq!(recipient.open(b"header 1", &first)?, b"first message");
    /// assert_eq!(recipient.open(b"header 2", &second)?, b"second message");
    /// assert_eq!(sender.export(b"exporter", 32)?, recipient.export(b"exporter", 32)?);
    /// # Ok::<(), cryptors::hpke::Error>(())
    /// ```
    pub fn setup_sender(
        &self,
        pk_r: &PublicKey,
        info: &[u8],
        mode: SenderMode<'_>,
        ikm_e: &[u8],
    ) -> Result<(Vec<u8>, Sender), Error> {
        let sk_s = match mode {
            SenderMode::Base | SenderMode::Psk { .. } => None,
            SenderMode::Auth { sk_s } | SenderMode::AuthPsk { sk_s, .. } => Some(sk_s),
        };
        let (shared_secret, enc) = kem::encap(self.kem(), pk_r, sk_s, ikm_e)?;
        let (psk, psk_id) = mode.psk();
        let schedule = key_schedule(
            *self,
            mode.mode(),
            shared_secret.as_bytes(),
            info,
            psk,
            psk_id,
        )?;
        let context = Context::new(*self, schedule);
        Ok((enc, Sender { context }))
    }

    /// `SetupBaseR`, `SetupPSKR`, `SetupAuthR` or `SetupAuthPSKR` (RFC 9180
    /// section 5.1), as `mode` says: the context that opens what the sender's
    /// sealed, from the encapsulated key `enc` it sent, the recipient's
    /// private key and the same `info`.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidPublicKey`] unless `enc` is a public key of the suite's
    /// KEM (for the NIST curves, a valid uncompressed point),
    /// [`Error::KemMismatch`] if `sk_r` (or the sender's public key, in the
    /// authenticated modes) belongs to another KEM, [`Error::LowOrderPublicKey`]
    /// if `enc` (or the sender's public key) is an X25519 key of small order,
    /// and [`Error::InvalidPsk`] as for the sender. A wrong `info`, pre-shared
    /// key or sender key is not detected here, but by the first
    /// [`open`](Recipient::open), with [`Error::Open`].
    pub fn setup_recipient(
        &self,
        enc: &[u8],
        sk_r: &PrivateKey,
        info: &[u8],
        mode: RecipientMode<'_>,
    ) -> Result<Recipient, Error> {
        let pk_s = match mode {
            RecipientMode::Base | RecipientMode::Psk { .. } => None,
            RecipientMode::Auth { pk_s } | RecipientMode::AuthPsk { pk_s, .. } => Some(pk_s),
        };
        let shared_secret = kem::decap(self.kem(), enc, sk_r, pk_s)?;
        let (psk, psk_id) = mode.psk();
        let schedule = key_schedule(
            *self,
            mode.mode(),
            shared_secret.as_bytes(),
            info,
            psk,
            psk_id,
        )?;
        let context = Context::new(*self, schedule);
        Ok(Recipient { context })
    }

    /// The single-shot `Seal<MODE>(pkR, info, aad, pt, ...)` (RFC 9180
    /// section 6.1): one message, from a context that is then thrown away.
    /// Returns the encapsulated key and the ciphertext.
    ///
    /// The same as [`setup_sender`](Self::setup_sender) followed by one
    /// [`Sender::seal`], with the same requirement on `ikm_e`: fresh random
    /// bytes, as many as a private key of the KEM, never reused. Go's
    /// `hpke.Seal` returns `enc || ct` as one string, with no `aad`; the two
    /// are interchangeable with that split.
    ///
    /// ```
    /// use cryptors::hpke::{Aead, Kdf, Kem, RecipientMode, SenderMode, Suite};
    ///
    /// let suite = Suite::new(Kem::X25519HkdfSha256, Kdf::HkdfSha256, Aead::Aes256Gcm);
    /// let sk_r = Kem::X25519HkdfSha256.derive_key_pair(&[3; 32])?;
    ///
    /// let (enc, ct) = suite.seal(sk_r.public_key(), b"info", b"aad", b"hello", SenderMode::Base, &[4; 32])?;
    /// let pt = suite.open(&enc, &sk_r, b"info", b"aad", &ct, RecipientMode::Base)?;
    /// assert_eq!(pt, b"hello");
    /// # Ok::<(), cryptors::hpke::Error>(())
    /// ```
    pub fn seal(
        &self,
        pk_r: &PublicKey,
        info: &[u8],
        aad: &[u8],
        plaintext: &[u8],
        mode: SenderMode<'_>,
        ikm_e: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), Error> {
        let (enc, mut sender) = self.setup_sender(pk_r, info, mode, ikm_e)?;
        let ciphertext = sender.seal(aad, plaintext)?;
        Ok((enc, ciphertext))
    }

    /// The single-shot `Open<MODE>(enc, skR, info, aad, ct, ...)` (RFC 9180
    /// section 6.1): [`setup_recipient`](Self::setup_recipient) followed by
    /// one [`Recipient::open`].
    pub fn open(
        &self,
        enc: &[u8],
        sk_r: &PrivateKey,
        info: &[u8],
        aad: &[u8],
        ciphertext: &[u8],
        mode: RecipientMode<'_>,
    ) -> Result<Vec<u8>, Error> {
        self.setup_recipient(enc, sk_r, info, mode)?
            .open(aad, ciphertext)
    }
}
