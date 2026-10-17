# RSA

RSA encrypts a message to the holder of a private key, and lets the holder sign a message that anyone with the public key
can check. Its public keys are in almost every X.509 certificate, its signatures are TLS 1.2's and the JWT algorithms
`RS256` and `PS256`, and its encryption wraps the keys of CMS, S/MIME and JWE. [RFC 8017](https://www.rfc-editor.org/info/rfc8017)
(PKCS #1 v2.2) turns its one operation, a power modulo the product of two primes, into four schemes:

| Scheme | For | With the public key | With the private key | Defined in |
|--------|-----|---------------------|----------------------|------------|
| RSAES-OAEP | encryption | `encrypt_oaep`, `encrypt_oaep_mgf1` | `decrypt_oaep`, `decrypt_oaep_mgf1` | section 7.1 |
| RSASSA-PSS | signatures | `verify_pss`, `verify_pss_prehash` | `sign_pss`, `sign_pss_prehash` | section 8.1 |
| RSAES-PKCS1-v1_5 | encryption, for old protocols | `encrypt_pkcs1v15` | `decrypt_pkcs1v15`, `decrypt_pkcs1v15_session_key` | section 7.2 |
| RSASSA-PKCS1-v1_5 | signatures, as most certificates have them | `verify_pkcs1v15`, `verify_pkcs1v15_prehash` | `sign_pkcs1v15`, `sign_pkcs1v15_prehash` | section 8.2 |

- It is neither a `Digest` nor a `BlockCipher`. There are two types, `PublicKey` and `PrivateKey`, with a method for each
  scheme, and no type parameter but the hash: any `Digest` for OAEP and PSS, one of the eight of the sealed trait
  `Pkcs1Hash` (MD5, SHA-1 and the six SHA-2 functions) for a PKCS #1 v1.5 signature, which carries the hash's name.
- A key has two primes and a modulus of 1,024 to 16,384 bits, and an odd public exponent from 3 to 2^31 - 1 (65,537 for
  the keys it generates). The sizes and what they hold:

| Modulus | Security (NIST SP 800-57) | Ciphertext and signature | OAEP with SHA-256 holds | PKCS #1 v1.5 holds |
|---------|---------------------------|--------------------------|-------------------------|--------------------|
| 1,024 bits | 80 bits: old data only | 128 bytes | 62 bytes | 117 bytes |
| 2,048 bits | 112 bits | 256 bytes | 190 bytes | 245 bytes |
| 3,072 bits | 128 bits | 384 bytes | 318 bytes | 373 bytes |
| 4,096 bits | about 140 bits | 512 bytes | 446 bytes | 501 bytes |
| 7,680 bits | 192 bits | 960 bytes | 894 bytes | 949 bytes |
| 15,360 bits | 256 bits | 1,920 bytes | 1,854 bytes | 1,909 bytes |

RSA carries a key, not a document: it encrypts a few hundred bytes at most, so a message goes under a symmetric key that
RSA delivers, and a document is signed by signing its hash.

Standards:

- Schemes: RFC 8017 sections 7 and 8, with the encodings of section 9 (`EMSA-PSS`, `EMSA-PKCS1-v1_5`) and MGF1 (appendix
  B.2.1). The private operation uses the second representation of a private key (section 3.2), with the Chinese
  remainder theorem.
- Key generation: [FIPS 186-5](https://csrc.nist.gov/pubs/fips/186-5/final) appendix A.1, drawn from a reader as
  [c2sp.org/det-keygen](https://c2sp.org/det-keygen) specifies, so a deterministic reader gives the same key as any other
  implementation of it.
- Keys are numbers: big-endian bytes for the modulus, the exponent and the private key's components. The encodings that
  carry them (PKCS #1's `RSAPrivateKey`, PKCS #8, SubjectPublicKeyInfo) are ASN.1, which the crate has no parser for yet
  (X.509 is planned).
- Left out: keys of more than two primes, PSS with a hash for MGF1 other than the message's (OAEP has it), and PKCS #1 v1.5
  signatures with SHA-3 (not a `Digest` yet; the `_prehash` forms need a name that `Pkcs1Hash` does not have).

## Usage

```rust
use cryptors::rsa::{Error, PrivateKey, PublicKey, SaltLength};
use cryptors::sha1::Sha1;
use cryptors::sha2::Sha256;

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len() / 2).map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap()).collect()
}

// The first key of RSA Laboratories' PKCS #1 test vectors, 1,024 bits: the modulus, the private exponent and the primes.
let key = PrivateKey::from_components(
    &unhex(concat!(
        "a8b3b284af8eb50b387034a860f146c4919f318763cd6c5598c8ae4811a1e0abc4c7e0b082d693a5e7fced675cf4668512772c0cbc64a742",
        "c6c630f533c8cc72f62ae833c40bf25842e984bb78bdbf97c0107d55bdb662f5c4e0fab9845cb5148ef7392dd3aaff93ae1e6b667bb3d424",
        "7616d4f5ba10d4cfd226de88d39f16fb"
    )),
    65537,
    &unhex(concat!(
        "53339cfdb79fc8466a655c7316aca85c55fd8f6dd898fdaf119517ef4f52e8fd8e258df93fee180fa0e4ab29693cd83b152a553d4ac4d181",
        "2b8b9fa5af0e7f55fe7304df41570926f3311f15c4d65a732c483116ee3d3d2d0af3549ad9bf7cbfb78ad884f84d5beb04724dc7369b31de",
        "f37d0cf539e9cfcdd3de653729ead5d1"
    )),
    &unhex("d32737e7267ffe1341b2d5c0d150a81b586fb3132bed2f8d5262864a9cb9f30af38be448598d413a172efb802c21acf1c11c520c2f26a471dcad212eac7ca39d"),
    &unhex("cc8853d1d54da630fac004f471f281c7b8982d8224a490edbeb33d3e3d5cc93c4765703d1dd791642f1f116a0dd852be2419b2af72bfe9a030e860b0288b5d77"),
).unwrap();

// The sender has only the public key's numbers, and encrypts with OAEP. The "random" seed here is the vector's own, so
// that the ciphertext is the vector's too.
let public = PublicKey::new(&key.public_key().modulus(), key.public_key().exponent()).unwrap();
let message = unhex("6628194e12073db03ba94cda9ef9532397d50dba79b987004afefe34");
let mut seed: &[u8] = &unhex("18b776ea21069d69776a33e96bad48e1dda0a5ef");
let ciphertext = public.encrypt_oaep::<Sha1, _>(&mut seed, &message, b"").unwrap();
assert_eq!(ciphertext[..16], unhex("354fe67b4a126d5d35fe36c777791a3f")[..]);

// The holder decrypts with the same hash and label; anything else is the same error.
assert_eq!(key.decrypt_oaep::<Sha1>(&ciphertext, b""), Ok(message));
assert_eq!(key.decrypt_oaep::<Sha1>(&ciphertext, b"other"), Err(Error::Decryption));

// PSS is randomized (here with a fixed string for the random bytes); PKCS #1 v1.5 is deterministic.
let mut noise: &[u8] = &[7; 32];
let signature = key.sign_pss::<Sha256, _>(&mut noise, b"a message", SaltLength::EqualsHash).unwrap();
assert_eq!(public.verify_pss::<Sha256>(b"a message", &signature, SaltLength::EqualsHash), Ok(()));
assert_eq!(public.verify_pss::<Sha256>(b"another", &signature, SaltLength::EqualsHash), Err(Error::VerificationFailed));
let signature = key.sign_pkcs1v15::<Sha256>(b"a message").unwrap();
assert_eq!(public.verify_pkcs1v15::<Sha256>(b"a message", &signature), Ok(()));
```

Real keys come from `PrivateKey::generate`. The randomness is a reader, as everywhere else in the crate:

```rust
use cryptors::rand::Reader;
use cryptors::rsa::PrivateKey;
use cryptors::sha2::Sha256;

let mut rng = Reader;                                       // the operating system's; any io::Read of random bytes will do
let key = PrivateKey::generate(&mut rng, 2048)?;
let ciphertext = key.public_key().encrypt_oaep::<Sha256, _>(&mut rng, b"a 32-byte session key goes here", b"")?;
assert_eq!(key.decrypt_oaep::<Sha256>(&ciphertext, b"").unwrap(), b"a 32-byte session key goes here");
```

`examples/rsa.rs` checks a known answer, generates a key, sends a secret with OAEP to the holder of its public numbers and
authenticates a message with it, signs with PSS and PKCS #1 v1.5, stores and restores a key, and shows each failure:

```sh
cargo run --release --example rsa
```

## Security

RSA does not resist a large quantum computer (Shor's algorithm factors the modulus); what must stay secret past one needs a
post-quantum scheme such as [ML-KEM](mlkem.md) or [ML-DSA](mldsa.md).

- **Use OAEP and PSS in a new design.** PKCS #1 v1.5 encryption has no integrity check in its padding, and a service that
  says whether a ciphertext decrypts hands out the decryption of any ciphertext (Bleichenbacher, 1998, and the same attack
  on implementations again and again since, for TLS and for XML encryption). It is here to read old data.
  `decrypt_pkcs1v15_session_key` is the protection of RFC 3218 for the protocols that cannot move: it replaces a key you
  already hold, or leaves it, and does not say which.
- **One error for every failed decryption.** `Error::Decryption` does not say whether the ciphertext was short, large,
  had another label or a broken padding, and the checks of the padding take the same time whichever fails. A program
  that tells its peer more, by a message or by a delay, rebuilds the oracle of Manger's attack on OAEP.
- **A PKCS #1 v1.5 signature is rebuilt, not parsed.** The block is made again from the digest and compared, which is
  what keeps out the forgeries of the verifiers that read the `DigestInfo` leniently (Bleichenbacher, 2006; Mozilla's NSS,
  2014). A signature whose number is not below the modulus, or is not as long as it, is refused.
- **The randomness is the caller's.** A key from a predictable reader is guessable, and an OAEP ciphertext or a PSS
  signature made from one is not randomized. `rand::Reader` is the operating system's.
- **Sizes.** Keys under 1,024 bits are refused and 2,048 bits is the floor of NIST's guidance; the cap of 16,384 is so
  that a key from outside cannot make a verification take minutes. A key is for one purpose (FIPS 186-5, SP 800-56B):
  the types do not stop a program from signing and decrypting with one, and it should not.
- **Pick the hash on purpose.** SHA-256 and up. The hash of a v1.5 signature includes MD5 and SHA-1 for the signatures
  that still use them, and is only as strong as they are. For OAEP with another hash for MGF1 than for the label (some
  protocols fix it to SHA-1) there is `encrypt_oaep_mgf1`; use `encrypt_oaep` if you have the choice.
- **A fault does not give the key away.** The result of a private operation is raised to the public exponent and compared
  with its input before it is released, so a bit flipped in one of the two exponentiations of the Chinese remainder
  theorem (which would make a signature that reveals a prime, Boneh, DeMillo and Lipton, 1997) fails instead. There is no
  blinding: the operation takes the same time for every input, so there is nothing to hide.
- **Constant-time where it matters, checked by inspection and a coarse test.** Nothing that depends on a private key is
  used as a branch condition or a memory address in the private operation or the padding checks of a decryption: the
  exponentiation reads every entry of its table, and every choice between two numbers is a selection by a mask.
  `rustc`'s assembly for aarch64 and x86_64 was inspected for the product, the table lookup of the exponentiation and the
  search for the message in a decrypted block, and its conditional jumps there are loops over public lengths and checks of
  public lengths; the masks go through `black_box`, and the selections are conditional moves and bit operations. A coarse test in the manner of dudect (`timing_does_not_depend_on_the_input`, run by hand on a quiet machine) compared 6,000 private
  operations on inputs with little in them with 6,000 on random ones: the means differed by under 0.05% and Welch's t stayed
  under 2.4 in three runs (dudect's threshold is 4.5). That is one
  compiler's output for two targets, and a measurement on one machine; nothing protects against power analysis or fault
  injection that skips the check. Key generation is not constant-time (it is a search: refused candidates, trial division
  and Miller-Rabin rounds are visible, never the key it ends with), and neither is verification, which has no secret.
- **Key wiping is best effort.** A private key's numbers, and the temporaries of the operations and of key generation, are
  overwritten with zeros when they are dropped (checked by an allocator that looks for them in freed memory). Values on
  the stack and in registers are not wiped, nor are copies left by moves; the bytes returned by `d()`, `p()` and the like
  are the caller's.

## Testing

```sh
cargo test rsa::    # known answers, Wycheproof, the arithmetic against Python's integers, and key generation against other implementations
```

| Source | Coverage |
|--------|----------|
| Project Wycheproof | 75 files of OAEP and PKCS #1 v1.5 decryption, PKCS #1 v1.5 signatures (verification and generation) and PSS verification: 8,043 cases that this module can read, all passed once; 759 kept in the tests (every kind of fault in every file that matters) |
| RSA Laboratories' PKCS #1 vectors | OAEP examples: the ciphertext of each message from the vector's own seed, bit for bit. PSS: 60 signatures by keys of 1,024 to 1,031 bits, 1,536 and 2,048, verified and reproduced from their salts; the keys of 1,025 to 1,031 bits are the ones whose encoded message is a byte shorter than the modulus or has bits to clear |
| OpenSSL | 315 ciphertexts and signatures (OAEP with every hash and a label, v1.5 encryption, v1.5 signatures with all eight hashes, PSS with the salt lengths protocols use) under keys of 1,024, 1,025, 1,031, 2,047, 2,048, 3,072 and 4,096 bits; v1.5 signatures are reproduced exactly. `bench/rsacmp` checks Go reads them the same way |
| [c2sp.org/det-keygen](https://c2sp.org/det-keygen) | 21 key-generation seeds of 2,048, 2,064, 3,072, 4,096 and 8,192 bits: the key an HMAC_DRBG makes the process give, to the last bit of `d` |
| [c2sp.org/CCTV/keygen](https://c2sp.org/CCTV/keygen) | the benchmark's 708 candidates of 2,048 bits: the primes are the 354th and the last, and the key has the modulus and private exponent that Python and Go make |
| Arithmetic | products, powers and remainders against Python's integers for moduli of 1 to 32 limbs (all ones, a power of two plus one, a top limb of 1, a top limb with its high bits clear) and remainders modulo even numbers |
| Keys wrong in exactly one way | primes too close, a private exponent too short, a composite `p`, a modulus that is not `p * q`; and streams of candidates that make generation draw again: for a shared factor of 40 bits in `p - 1` and `q - 1`, for a `p - 1` that the public exponent divides, and for the same prime twice |

Wycheproof's files cover paddings of every wrong shape, BER lengths and missing NULLs in a `DigestInfo`, tiny and huge
signature values, ciphertexts of the wrong length, special salt lengths, and keys of odd sizes. 
Mutation testing: 195 mutants of the code (the Montgomery product and its constants, the exponentiations, the reductions, every
check of a key, the private operation, the four paddings and MGF1, the hash prefixes, key generation, and the wiping of each
buffer that holds a secret). 154 fail a test and 27 hang the suite, because key generation never ends on broken arithmetic. The
14 survivors are equivalent to the original: a check made twice in two places (the size of the key in OAEP, the digest's length
in PSS, the block that a v1.5 signature is compared with), a relaxed assertion, an exponent of 2 that the parity check refuses
anyway, a mask that the length check makes redundant (the session key, the search in the padding), the trial division that
Miller-Rabin repeats, the mask of a Miller-Rabin base that its range check repeats, the check of the modulus's size that the
shape of a candidate guarantees, and a modular inverse that takes smaller steps.

Everything this implementation makes was also read by others, once: 1,528 ciphertexts and signatures (every scheme, hash and
key size of the tests, with and without labels and salts) decrypt or verify with OpenSSL (1,304 of them; it has no OAEP with
SHA-512/224 or SHA-512/256) and with Go, which also reproduces the v1.5 signatures byte for byte. The tests run on x86-64
(under Rosetta) as well as Arm.

The tests also check:

- every scheme round-trips on keys of 1,024, 1,025, 1,031, 2,047 and 2,048 bits, at the longest message and with none;
- every error of a decryption is the same error, and so is every error of a verification, for ciphertexts and signatures
  that are too short, too long, equal to or above the modulus, zero, and changed in any byte;
- a private operation whose result fails the check releases nothing, whichever number of the key was damaged;
- the private operation makes the same number of Montgomery products for any input, and the exponentiation for any exponent;
- `Debug` shows no secret, and a dropped key, the temporaries of its use and of its generation leave nothing behind.

## Benchmarking

```sh
# cryptors: one test thread, so the benchmarks don't compete with each other for the CPU.
cargo test --release rsa::keypair -- --ignored --nocapture --test-threads=1
cd bench/rsacmp && go test -v -run TestThroughput               # Go's crypto/rsa as shipped, with its assembly
cd bench/rsacmp && go test -tags purego -v -run TestThroughput  # Go's portable code, with no assembly
```

Method:

- Keys: three of OpenSSL's (`src/rsa/testdata/interop.txt`) of 2,048, 3,072 and 4,096 bits, which both sides read from there.
- Operations, as in Go's own benchmarks of `crypto/rsa`: a new private key (checks its numbers and makes the ones of the
  Chinese remainder theorem), OAEP and PKCS #1 v1.5 decryption and encryption of a message of 13 bytes, signing and
  verifying the SHA-256 digest of "testing" with PKCS #1 v1.5 and with PSS (salt as long as the hash), and, for 2,048 bits,
  generating a key from the 708 candidates of c2sp.org/CCTV/keygen's benchmark, so that both searches are the same.
- Each runs about 50 ms to size a batch of about 100 ms; best of five batches.
- The randomized operations read a cheap generator on both sides (`GODEBUG=cryptocustomrand=1` for Go), so the system RNG's
  cost is excluded.
- All three runs print the same first 8 bytes of the PKCS #1 v1.5 signature.

| Operation | cryptors | Go stdlib | Go portable (`purego`) |
|-----------|----------|-----------|------------------------|
| 2048 new private key | 714.4 | **585.6** | 690.7 |
| 2048 OAEP decrypt | 964.2 | **890.0** | 1105.0 |
| 2048 OAEP encrypt | **27.4** | 29.2 | 39.7 |
| 2048 sign PKCS1v15 | 964.2 | **921.2** | 1131.6 |
| 2048 verify PKCS1v15 | **27.1** | 28.6 | 37.1 |
| 2048 sign PSS | 967.1 | **911.4** | 1125.4 |
| 2048 verify PSS | **27.5** | 29.2 | 39.1 |
| 3072 new private key | 1956.4 | **1582.6** | 1931.2 |
| 3072 OAEP decrypt | 2997.4 | **2567.2** | 3280.6 |
| 3072 OAEP encrypt | **58.6** | 83.0 | 86.1 |
| 3072 sign PKCS1v15 | 3007.0 | **2622.4** | 3334.3 |
| 3072 verify PKCS1v15 | **58.1** | 82.0 | 81.9 |
| 3072 sign PSS | 2996.4 | **2611.8** | 3325.0 |
| 3072 verify PSS | **59.0** | 83.0 | 85.0 |
| 4096 new private key | 4224.5 | **3342.4** | 4179.6 |
| 4096 OAEP decrypt | 6837.8 | **5621.3** | 7310.7 |
| 4096 OAEP encrypt | **107.2** | 142.8 | 147.1 |
| 4096 sign PKCS1v15 | 6852.2 | **5760.5** | 7384.5 |
| 4096 verify PKCS1v15 | **106.6** | 141.9 | 141.7 |
| 4096 sign PSS | 6837.6 | **5723.7** | 7417.7 |
| 4096 verify PSS | **107.2** | 142.9 | 145.5 |
| 2048 generate key (ms) | 56.1 | **52.7** | 64.9 |

Apple M1 Pro, Go 1.27.1, medians of five interleaved runs, µs per operation (lower is better; the last row is in ms):

- PKCS #1 v1.5 decryption and encryption are within 1% of OAEP's at every size, and signing with PKCS #1 v1.5 and with PSS
  differ by under 1% too: the padding is nothing beside the exponentiation.
- The public operations (encrypt, verify) are 6% faster than Go's at 2,048 bits and 25 to 30% faster at 3,072 and 4,096,
  where Go's assembly does not apply (it has it for numbers of 1,024, 1,536 and 2,048 bits only) and its speed is about the
  `purego` column's.
- The private operations (decrypt, sign) are 5 to 8% slower than Go's at 2,048 bits, 15 to 17% at 3,072 and 19 to 22% at
  4,096, against its assembly (the primes of 1,024, 1,536 and 2,048 bits are the sizes it has), and 6 to 15% faster than its
  portable code, which is the like-for-like comparison. The product is Montgomery's with both halves of a round in one
  pass and two carries: about 0.64 ns per multiply-add, 2 cycles, with around ten instructions for each.
- A new private key costs 22 to 26% more than Go's. A new public key, which sets up the constants of the modulus, is 12, 25
  and 45 µs, and is paid once per key; Go pays it in every call that uses one.
- Key generation takes 7% longer than Go's, from the same candidates.

Not done yet, would make it faster:

- A squaring that uses the symmetry of the product: it saves a quarter of the multiplications, but its reduction has one
  carry chain where the product has two, which ran about a fifth slower per multiplication when the product was written that
  way. An estimate that it gains nothing, not a measurement of a squaring.
- Unrolled kernels for the sizes of 1,024 to 2,048 bits, as Go's assembly is, and an x86-64 kernel with `mulx` and `adx`.
- The checks of a new private key: the remainders modulo `p - 1` and `q - 1` are made a bit at a time, which is simple and
  constant-time and could use the Montgomery product.


No x86 figures yet: nothing here can time real x86 hardware, and Rosetta 2 timings say nothing about an x86 CPU. The
manual `Benchmarks` workflow (`.github/workflows/bench.yml`) runs both sides on GitHub's x86-64 and Arm runners.
