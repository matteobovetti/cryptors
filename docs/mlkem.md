# ML-KEM

ML-KEM, the Module-Lattice-Based Key-Encapsulation Mechanism of [FIPS 203](https://csrc.nist.gov/pubs/fips/203/final)
(CRYSTALS-Kyber as NIST standardized it), is a post-quantum way to agree on a secret: a sender uses the receiver's
public key to make a random shared secret and a ciphertext holding it, and only the private key's holder can find the
secret in the ciphertext. Its lattice problem (module LWE) has no known quantum attack, while [ECDH](ecdh.md) falls to
Shor's algorithm. That matters already, because a key exchange recorded today can be opened later; hybrid key exchanges
such as X25519MLKEM768 in TLS run ML-KEM next to X25519. Keys, ciphertexts and secrets are their own types (not `Digest`
or `BlockCipher`), generic over a parameter set: one of three types implementing the sealed trait `Parameters`.

Types: `DecapsulationKey<P>`, `EncapsulationKey<P>`, `Ciphertext<P>`, `SharedSecret<P>`, the parameter sets `MlKem512`,
`MlKem768` and `MlKem1024`, `Error`, `SEED_LEN`, `SHARED_SECRET_LEN`.

| Parameter set | Type | NIST category | Decapsulation key | Encapsulation key | Ciphertext | Shared secret |
|---------------|------|---------------|-------------------|-------------------|------------|---------------|
| ML-KEM-512 | `MlKem512` | 1 (key search on AES-128) | 64 bytes | 800 bytes | 768 bytes | 32 bytes |
| ML-KEM-768 | `MlKem768` | 3 (key search on AES-192) | 64 bytes | 1,184 bytes | 1,088 bytes | 32 bytes |
| ML-KEM-1024 | `MlKem1024` | 5 (key search on AES-256) | 64 bytes | 1,568 bytes | 1,568 bytes | 32 bytes |

- Keys, ciphertexts and secrets of different parameter sets do not compile together. Most protocols use ML-KEM-768.
- The decapsulation key is the 64-byte seed `d || z` of `ML-KEM.KeyGen` (`DecapsulationKey::from_seed`,
  `DecapsulationKey::seed`). FIPS 203's expanded decapsulation key (1,632 to 3,168 bytes) is not accepted: a seed is
  smaller and there is nothing to check in it.
- `EncapsulationKey::from_bytes` does the checks of FIPS 203 section 7.2: the length, and the "modulus check" that every
  coefficient is below `q = 3329`. `Ciphertext::from_bytes` checks the length, the only thing to check.
- **Decapsulation cannot fail.** A ciphertext not made for the key (made for another key, changed on the way, or random)
  still gives a secret, `J(z || c)`, which looks random and which the sender does not have ("implicit rejection"). The
  failure shows at the first use of the wrong secret.
- The standard library has no stable secure random source, so key generation and encapsulation take any `std::io::Read`,
  as in ECDH, ECDSA, Ed25519 and ML-DSA. A reader of fixed bytes gives the same key or secret every time, which is for
  tests. Encapsulation reads FIPS 203's 32-byte message `m` from it and nothing else; no function takes `m` as an
  argument, because FIPS 203 does not let an application choose it (section 6.2).

## Usage

```rust
use cryptors::mlkem::{Ciphertext, DecapsulationKey, EncapsulationKey, Error, MlKem768};

// The receiver's key, from a seed of 64 bytes.
let seed: [u8; 64] = core::array::from_fn(|i| (i * 37 + 11) as u8);
let key = DecapsulationKey::<MlKem768>::from_seed(&seed);
assert_eq!(key.encapsulation_key().as_bytes()[..8], [0xa6, 0xd5, 0x10, 0xac, 0xe0, 0x7b, 0xbc, 0x1a]);

// The sender has the bytes of the encapsulation key (this is where a key of the wrong length, or with a coefficient
// that is not below q, is refused)...
let public = EncapsulationKey::<MlKem768>::from_bytes(key.encapsulation_key().as_bytes())?;

// ... and makes a secret and a ciphertext for it. A real program passes a source of secure random bytes; this is the
// 32 bytes of the message m, fixed, so that the answer is known.
let m: [u8; 32] = core::array::from_fn(|i| (i * 7 + 3) as u8);
let (secret, ciphertext) = public.encapsulate(&mut &m[..])?;
assert_eq!(secret.as_bytes()[..8], [0xc9, 0x48, 0x02, 0xd6, 0xa8, 0x31, 0x78, 0xe9]);

// The receiver reads the ciphertext and finds the same secret.
let received = Ciphertext::<MlKem768>::from_bytes(ciphertext.as_bytes())?;
assert_eq!(key.decapsulate(&received), secret);

// A ciphertext that has been changed is not refused. It gives a secret that is not the sender's, and the same one
// every time.
let mut changed = ciphertext.as_bytes().to_vec();
changed[0] ^= 1;
let rejected = key.decapsulate(&Ciphertext::<MlKem768>::from_bytes(&changed)?);
assert_ne!(rejected, secret);

// A ciphertext of the wrong length is.
assert_eq!(Ciphertext::<MlKem768>::from_bytes(&changed[1..]), Err(Error::InvalidCiphertext));
```

Real keys come from `DecapsulationKey::generate`; the sender's encapsulation also needs random bytes from your own
source:

```rust
use cryptors::mlkem::{DecapsulationKey, EncapsulationKey, MlKem768};
use std::fs::File;

let mut rng = File::open("/dev/urandom")?;                 // on Unix; any io::Read of random bytes will do

// The receiver: store key.seed(), and send the encapsulation key to the sender.
let key = DecapsulationKey::<MlKem768>::generate(&mut rng)?;
let to_send = key.encapsulation_key().as_bytes();

// The sender, which has those bytes: send the ciphertext, and keep the secret.
let public = EncapsulationKey::<MlKem768>::from_bytes(to_send)?;
let (secret, ciphertext) = public.encapsulate(&mut rng)?;
```

`examples/mlkem.rs` runs a complete exchange on each parameter set, with a changed ciphertext, bytes that are not a key
or a ciphertext, and a session key derived from the secret with [HKDF](hkdf.md): `cargo run --release --example mlkem`.

## Security

The best known attacks are lattice reduction, classical or quantum, and the three parameter sets are chosen against them
(the categories are NIST's). FIPS 203 makes the scheme secure against an attacker who can have ciphertexts of their
choice decapsulated (IND-CCA2), with the Fujisaki-Okamoto transform: decapsulation encrypts the message it found again,
and compares.

- **Authenticates nobody.** Both sides get the same secret, but neither learns who the other is: a man in the middle is
  possible unless something binds the keys to identities (signatures such as [ML-DSA](mldsa.md) or [Ed25519](ed25519.md),
  certificates, a pre-shared secret). Prefer a fresh key pair for each exchange.
- **The secret is an input, not a protocol.** Its 32 bytes are uniform for anyone without the decapsulation key. Derive
  the protocol's keys from it with a key derivation function such as [HKDF](hkdf.md), with the encapsulation key and the
  ciphertext in the input to bind them to this exchange.
- **Younger than the curves.** Lattice problems have been studied for less time than discrete logarithms, so many
  deployments pair ML-KEM with X25519 in a hybrid, where an attack on either alone is not enough. This crate has both,
  and no combiner for them.
- **Implicit rejection hides whether a ciphertext was good.** `decapsulate` takes the same steps for every ciphertext
  and picks the secret with a mask, so the time does not tell. A protocol must not reveal it another way, such as an
  error message that depends on the secret being right.
- **The randomness is the caller's.** `generate` and `encapsulate` are only as good as their reader. FIPS 203 asks for a
  generator at least as strong as the set: 128, 192 and 256 bits (section 3.3). A predictable reader makes a key or
  secret that can be guessed.
- **Keys are checked when read**, as described above. Every other string of the right length is a ciphertext, and every
  one with each coefficient below `q` is an encapsulation key.
- **Secret-independent arithmetic, checked one way only.** No branch or memory address derives from `s`, `d`, `z`, the
  message `m` or the noise. The transform, products, reductions, compression and noise sampling use only additions,
  multiplications, shifts and masks; the only tables, the roots of unity, are read in loop order. The ciphertext
  comparison ORs the differences of all bytes, and a mask picks the secret. The one sampler that depends on its bytes,
  `SampleNTT`, takes the public `rho`. In the assembly `rustc` 1.95 produced for `aarch64-apple-darwin` and
  `x86_64-apple-darwin`, the only conditional jumps in ML-KEM-768's key generation, encapsulation and decapsulation are
  fixed-count loops, comparisons with constant buffer sizes, checks of public lengths and of an allocation, and the
  loops that overwrite buffers. That is one compiler on two targets, not a proof; no timing was measured on real
  hardware, and nothing protects against power analysis or fault injection.
- **Keys stay in memory for as long as they exist.** The seed, the secret vector and every shared secret are zeroed when
  dropped; `Debug` shows no secret (an encapsulation key shows the first bytes of its hash). Not wiped: arithmetic
  temporaries in stack and registers, and copies left by moves. A decapsulation key keeps its expanded form (5, 9 and 14
  KiB of heap) so decapsulating does not expand it again; an encapsulation key holds 4, 7 and 12 KiB. Every operation
  uses at most 16 KiB of stack in a release build, 24 KiB in a debug build.

## Testing

```sh
cargo test -- mlkem:: sha3::xof   # known answers, vectors of NIST, Wycheproof and C2SP, and each part against its definition
cargo test --release mlkem::keypair::tests::accumulated_10000 -- --ignored   # 10,000 rounds for each set
MLKEM_VECTORS=/dir cargo test --release mlkem::conformance -- --ignored --nocapture   # every ACVP and Wycheproof vector
```

- **Accumulated known answers** of Go's `crypto/mlkem`: seeds, messages and bad ciphertexts from one SHAKE128, and a
  hash of all resulting keys, ciphertexts and secrets; 100 rounds per set are in the tests. Go and OpenSSL 3.6 agree on
  the ML-KEM-768 and ML-KEM-1024 values; OpenSSL makes the ML-KEM-512 one, which Go has no code for.
- **C2SP's accumulated vectors** (CCTV, `ML-KEM/README.md`): the same kind of stream, 10,000 rounds per set, with the
  expanded decapsulation key in the hash. They are for the FIPS 203 draft, whose key generation hashes `d` without the
  `k` the final standard adds, so the test makes keys that way. Everything after that hash is unchanged, so they cover
  sampling, the transform, compression, encoding, encapsulation and decapsulation for all three sets. All three hashes
  match (the test runs on demand).
- **NIST ACVP** (ACVP-Server `ML-KEM-keyGen-FIPS203` and `ML-KEM-encapDecap-FIPS203`): all 240 were run once with no
  failure; 54 are in the tests. That is 75 key generation, 75 encapsulation, 30 decapsulation (good and modified
  ciphertexts) and 60 key checks (an encapsulation key with a coefficient too large, a decapsulation key with a modified
  hash).
- **Project Wycheproof:** all 1,725 ML-KEM cases, including random, bit-flipped, too long and too short ciphertexts;
  C2SP's `strcmp` vectors (a zero byte must not end the ciphertext comparison); malleable ciphertexts; seeds whose `rho`
  gives unusually large or many rejected matrix entries; encapsulation keys with an unreduced coefficient (100 of them)
  or the wrong length; and expanded decapsulation keys with a corrupted hash or encapsulation key. The 1,665 this API
  can express (60 have a seed of the wrong length, which `from_seed` refuses to compile) were run once with no failure;
  123 are in the tests.
- **C2SP's "unlucky" vectors:** draft seeds for which `SampleNTT` must read more than 575 bytes of SHAKE128 for one
  matrix entry, which a random seed needs once in 2^38.
- **OpenSSL 3.6.4** (once, outside the tests, all three sets, 100 rounds each): the same encapsulation key from the same
  seed, the same ciphertext and secret from the same message, and the same secret from a bad ciphertext.
- **Go:** `bench/mlkemcmp` reproduces with Go's `crypto/mlkem` the encapsulation key of Wycheproof's first
  key-generation case, and the key, ciphertext and secret of its benchmark inputs, which this crate's tests pin too
  (with OpenSSL's values for ML-KEM-512).
- **Each part against its definition:** the transform, its inverse and the `T_q` product against the specification's
  written-out algorithms and its appendix A tables (which the roots of unity computed at compile time must equal), and
  against polynomial multiplication by the definition `X^256 = -1`, at the extremes the bounds on intermediate values
  allow; Barrett's reduction for every 16-bit number; Montgomery's over its whole range; `Compress` and `Decompress`
  against the definitions with a true division for every number modulo `q`; the encodings against the specification's
  bit strings; the modulus check for every number from `q` to 4095; the two samplers against the written-out algorithms.
- **API behaviour:** a full exchange with the encapsulation key and ciphertext as bytes; readers giving exactly 32 and
  64 bytes, failing or running out; the implicit-rejection secret written out for a change to the first and last byte of
  `u`, of `v` and in the middle; every length around the right one for keys and ciphertexts; a coefficient equal to `q`
  in a key's last polynomial; `Debug` showing no secret; a dropped key and a dropped secret leaving nothing behind.
- **Mutation testing:** of 88 small changes (a constant, an operand, a sign, a dropped check, a flipped comparison, a
  dropped wipe) to the reductions, transform, product, encodings, samplers, key generation, encryption, decapsulation
  with its implicit rejection, and the API, each in a scratch copy, 86 fail a test and 2 survive. Both survivors
  overwrite a copy of the random bytes that is never read again (the seed in `generate`, the message in `encapsulate`),
  which cannot be observed. The first run had one more survivor, a gap: key generation without reducing `t` gives the
  same key bytes, so it passes every vector, but breaks the bound the product is sized for; a test now looks at it.
  Tests that only restated another's check were then removed: each remaining test reads a published vector, writes out
  the definition of a part, or is the only one to fail for some change.

## Benchmarking

```sh
# cryptors: one test thread, so the benchmarks don't compete with each other for the CPU.
cargo test --release mlkem:: -- --ignored --nocapture --test-threads=1
cd bench/mlkemcmp && go test -v -run TestThroughput               # Go's crypto/mlkem as shipped, with its assembly Keccak
cd bench/mlkemcmp && go test -tags purego -v -run TestThroughput  # Go with a portable Keccak
```

Each run uses the same key, and times building a decapsulation key from its seed (expanding the matrix and the secret
vector, and the encapsulation key), building an encapsulation key from its bytes (the modulus check, its hash, and
expanding the matrix), encapsulating, and decapsulating a good ciphertext. Key generation is not timed. Both sides keep
the matrix in the key, so encapsulating and decapsulating do not expand it again. Encapsulation reads its 32 bytes from
a cheap generator here and from the system in Go, whose `Encapsulate` takes no reader. Each operation runs about 50 ms
to size a batch of about 100 ms, and the best of five batches is reported. Both sides print the first 8 bytes of the
shared secret of a fixed message, and all three runs print the same. Go has ML-KEM-768 and ML-KEM-1024 only.

Apple M1 Pro, Go 1.27.1, medians of five interleaved runs, µs per operation (lower is better):

| Operation | cryptors | Go stdlib | Go portable (`purego`) |
|-----------|----------|-----------|------------------------|
| ML-KEM-512 new decapsulation key | 7.2 | — | — |
| ML-KEM-512 new encapsulation key | 3.9 | — | — |
| ML-KEM-512 encapsulate | 4.2 | — | — |
| ML-KEM-512 decapsulate | 6.2 | — | — |
| ML-KEM-768 new decapsulation key | **11.8** | 37.9 | 46.3 |
| ML-KEM-768 new encapsulation key | **7.7** | 10.6 | 17.4 |
| ML-KEM-768 encapsulate | **5.4** | 34.8 | 36.3 |
| ML-KEM-768 decapsulate | **8.2** | 50.6 | 54.1 |
| ML-KEM-1024 new decapsulation key | **18.6** | 57.9 | 71.8 |
| ML-KEM-1024 new encapsulation key | **13.2** | 18.3 | 29.8 |
| ML-KEM-1024 encapsulate | **7.0** | 53.6 | 55.5 |
| ML-KEM-1024 decapsulate | **10.6** | 79.5 | 83.7 |

Run-to-run spread was within 3% in every cell, on a desktop that was not idle (load average 3 to 5), so the last digit
means little.

- **Decapsulating takes 6.2 to 7.5 times less here than in Go, encapsulating 6.4 to 7.7 times, building a decapsulation
  key 3.1 to 3.2 times and building an encapsulation key 1.4 times.** Go's ML-KEM is also portable (only its Keccak is
  assembly), so this compares two implementations of one algorithm. Reading both, the difference is in how arithmetic
  and memory are handled (not measured separately). This one keeps coefficients in `i16` without reducing after each
  sum, multiplies with Montgomery's reduction, adds a row's products in 32 bits before one reduction, and keeps working
  vectors in stack arrays. Go reduces every sum with a conditional subtraction, and allocates slices and a SHAKE state
  for each polynomial it samples.
- **The matrix is most of the work of a key.** The "new encapsulation key" row (the matrix, a hash and the modulus
  check) is 65% (ML-KEM-768) and 71% (ML-KEM-1024) of the "new decapsulation key" row, which adds the noise, the
  transforms and the products. The matrix is `k * k` streams of about three SHAKE128 blocks each, on a Keccak both sides
  run on `FEAT_SHA3` here, which is why that gap is the smallest (1.4 times).
- **An encapsulation key is parsed, and its matrix expanded, once**: that is the "new encapsulation key" row.
  Encapsulating again to the same key repeats only the second row.

Possible speedups, not done: explicit NEON and AVX2 for transforms and products (the compiler uses NEON in places); the
two- and four-way Keccak of `sha3::shake128_many` for the matrix, which is many independent streams; batch
decapsulation.

No x86 figures yet: nothing here can time real x86 hardware, and Rosetta 2 translates the instructions, so its timings
say nothing about an x86 CPU. The manual `Benchmarks` workflow (`.github/workflows/bench.yml`) runs both sides on
GitHub's x86-64 and Arm runners.
