# DES

DES ([FIPS 46-3](https://csrc.nist.gov/pubs/fips/46-3/final)) is a 64-bit block cipher: a 16-round Feistel network with
a 56-bit key. FIPS 46-3 also defines TDEA (Triple DES): three DES operations under three keys. Both implement
`BlockCipher`, one block at a time; modes of operation (CBC, CTR, ...) are not provided yet.

**DES is broken and TDEA is obsolete.** Use them only to read existing data or talk to legacy systems. For anything new,
use [AES](aes.md).

| Cipher | Type | Key | Block | Rounds |
|--------|------|-----|-------|--------|
| DES | `Des` | 64 bits (8 bytes), of which 56 are used | 64 bits (8 bytes) | 16 |
| TDEA | `TripleDes` | 3 x 64 bits (24 bytes) | 64 bits (8 bytes) | 3 x 16 |

TDEA encrypts under `K1`, decrypts under `K2`, encrypts under `K3`. `TripleDes` takes `K1 || K2 || K3` as one 24-byte
key, so the FIPS 46-3 keying options are just kinds of key:

| Keying option | Bundle | Remarks |
|---------------|--------|---------|
| 1 | `K1`, `K2` and `K3` independent | the intended use |
| 2 | `K1` and `K2` independent, `K3 = K1` | "two-key" TDEA |
| 3 | `K1 = K2 = K3` | single DES, with a longer key |

## Usage

```rust
use cryptors::{BlockCipher, des::{Des, TripleDes}};

// FIPS 81, the ECB example: the key 0123456789abcdef and the text "Now is t".
let key = [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];
let plaintext = *b"Now is t";

// Building the cipher runs the key schedule once; every block then reuses it.
let cipher = Des::new(&key);
let ciphertext: [u8; 8] = cipher.encrypt_block(&plaintext);
assert_eq!(ciphertext, [0x3f, 0xa4, 0x0e, 0x8a, 0x98, 0x4d, 0x48, 0x15]);
assert_eq!(cipher.decrypt_block(&ciphertext), plaintext);

// TDEA takes the key bundle K1 || K2 || K3. With three equal keys (keying option 3) it is single DES.
let bundle: [u8; 24] = [key, key, key].concat().try_into().unwrap();
let triple = TripleDes::new(&bundle);
assert_eq!(triple.encrypt_block(&plaintext), ciphertext);

// Generic code works with the 8-byte block too.
fn encrypt_zeros<C: BlockCipher>(key: &C::Key) -> C::Block {
    C::new(key).encrypt_block(&C::Block::default())
}
assert_eq!(encrypt_zeros::<TripleDes>(&[0; 24]).len(), TripleDes::BLOCK_LEN);
```

## Security

- **DES: the 56-bit key can be brute-forced.** The EFF DES Cracker took 56 hours (1998), and 22 hours with
  distributed.net (1999); crack.sh advertises the whole key space in about 26 hours.
- **TDEA is weaker than its key size.** Meet-in-the-middle brings three-key TDEA to about 112 bits; NIST rates two-key
  TDEA at no more than 80.
- **TDEA's 64-bit block is too short.** Collisions appear after about 2^32 blocks (32 GiB) under one key and leak
  plaintext XORs (Sweet32, CVE-2016-2183).
- **Status.** NIST withdrew FIPS 46-3 in 2005 and SP 800-67 (TDEA) on 1 January 2024. TDEA is no longer approved for
  encryption; decrypting old data is still allowed.
- **Block cipher, not an encryption scheme.** ECB (each block encrypted on its own) leaks message structure and
  authenticates nothing. With an 8-byte block, the mode and the data volume per key matter even more than for AES.
- **Not constant-time.** No targeted CPU has a DES instruction, so the only backend indexes lookup tables by secret
  state, which can leak through cache timing as in AES's scalar backend (see [AES](aes.md)). The 2 KiB tables give a
  coarser signal, but still one. The key schedule only shifts and masks.
- **Key wiping is best effort.** Round keys are zeroed on drop and hidden from `Debug`. Stack copies and copies left
  behind by moves are not reachable; build the cipher where it will stay.
- **Every key is accepted.** The low (parity) bit of each key byte is unused and not checked. The 4 weak and 12
  semi-weak keys are accepted (a random key hits one with probability near 2^-52).

## Testing

```sh
cargo test des::   # known-answer vectors, and a comparison with a literal implementation of the standard
```

- **Known answers:** the FIPS 81 ECB example, the first entries of NIST's `TECBvartext` and `TECBvarkey` tests, and
  vectors for all three TDEA keying options.
- **OpenSSL / Go sets** (they agree), for DES and TDEA: 1,000 chained encryptions, and 1,000 different keys to exercise
  the key schedule.
- **`matches_reference`:** with one implementation there is no backend to diff against, so round keys and blocks in
  both directions are checked against a slow bit-by-bit DES that follows FIPS 46-3 literally (`src/des/reference.rs`).
  The real code folds `IP`, `IP^-1` and `E` into rotations and tables, which known answers alone would not fully cover.
- **`triple_des_is_three_des`:** the fused TDEA path (no permutations between stages) matches three DES calls, for each
  keying option.

## Benchmarking

```sh
# cryptors: one test thread, so the benchmarks don't compete with each other for the CPU.
cargo test --release des:: -- --ignored --nocapture --test-threads=1
cd bench/descmp && go test -v                        # Go's crypto/des, which has no assembly and so no purego run
```

Both sides encrypt (or decrypt) 32 MiB in place as independent 8-byte blocks, one call per block (ECB, no mode); best
of five passes after a warm-up. Both print the same first block as a cross-check.

Apple M1 Pro, MiB/s (medians of five interleaved runs):

| Workload | cryptors | Go stdlib |
|----------|----------|-----------|
| DES encrypt | **110.3** | 96.6 |
| DES decrypt | **110.3** | 96.3 |
| TDEA encrypt | **36.6** | 33.8 |
| TDEA decrypt | **36.5** | 33.9 |

- Decryption is as fast as encryption. TDEA runs at a third of DES speed (48 rounds against 16).
- Fused TDEA (no permutations between stages) reaches 36.9 MiB/s, against 30.2 MiB/s for three separate DES calls (one
  run of three).
- Key setup: about 0.5 µs for DES and 1.7 µs for TDEA (one run of three).
- Rounds form one dependency chain, so a single block leaves the CPU mostly idle. An out-of-crate experiment running 2,
  3, 4 and 8 independent blocks side by side reached 181, 236, 278 and 332 MiB/s for DES (one run). That needs a
  multi-block API (`BlockCipher` has none) and a mode with independent blocks (ECB, CTR, CBC decryption).
- No x86 figures yet: nothing here can time real x86 hardware. The manual `Benchmarks` workflow
  (`.github/workflows/bench.yml`) runs both sides on GitHub's x86-64 and Arm runners.
