# SHA-512 performance plan

Scope: `src/sha2/sha512/`, the one compression function shared by SHA-384, SHA-512, SHA-512/224 and
SHA-512/256, so every step applies to all four. Targets are aarch64 and x86-64. The Go reference is
go1.27.1, `crypto/internal/fips140/sha512`: `sha512block.go` (generic), `sha512block_arm64.s`, and
`sha512block_amd64.s`, which is generated from `_asm/sha512block_amd64_asm.go`. `crypto/sha512` is a
thin wrapper around it.

Everything below was measured on 2026-10-05 on the Apple M1 Pro, unless a line says otherwise. x86
numbers can only come from the GitHub runners (see §6). Prototypes were throwaway copies of the
tree outside the repo; the code that matters is reproduced here.

## 0. Status

| Step | What | Target | Measured / expected | Gate | Status |
|------|------|--------|---------------------|------|--------|
| B1 | Short-message benchmark, Rust and Go | both | measurement only | — | planned |
| A1 | FEAT_SHA512 dataflow | aarch64 | **at the floor, no change** | — | analysed, closed |
| A2 | Stream K inside the FEAT_SHA512 loop | aarch64 | 1-block digest −11% time, long messages ±0 (prototype) | §3 | planned |
| A3 | Port SHA-256's aarch64 scalar tuning | aarch64 | scalar +16.4% (prototype) | §3 | planned, needs decision Q1 |
| X0 | Baseline x86 run of the Benchmarks workflow | x86-64 | numbers only | — | needs decision Q2 |
| X1 | AVX2 two-block backend (`x86_avx2.rs`) | x86-64 | +20–40% over BMI scalar (prior, see §4) | §4 | planned |
| X2 | Nested-Sigma form in the x86 scalar | x86-64 | −5% / −8% instructions (static only) | §4 | planned, low priority |
| A4 | Two-message FEAT_SHA512 for `digest_many` | aarch64 | 1.75x for batches (microbenchmark) | §5 | optional, decision Q3 |
| X3–X5 | SHA512-NI, AVX-512VL, AVX2 multi-buffer | x86-64 | — | — | deferred, decision Q3/Q4 |

## 1. Where we stand

### Throughput, one 64 MiB message (MiB/s, best of 5, median of 3 runs, machine idle)

| Function | cryptors scalar | Go `purego` | cryptors FEAT_SHA512 | Go stdlib (arm64 asm) |
|----------|-----------------|-------------|----------------------|-----------------------|
| SHA-512 | 542.0 | 445.9 | 1395.6 | 1378.6 |

Our accelerated path and Go's are level, and our scalar is 1.22x Go's portable code. The README's
morning figures (1386 / 540 / 1364 / 438) agree to within 2%.

### Short messages (ns per `Sha512::digest`, best of 7; Go: `sha512.Sum512`)

| Length | blocks | cryptors (FEAT_SHA512) | Go stdlib | Go `purego` |
|--------|--------|------------------------|-----------|-------------|
| 0 | 1 | 89–92 | 123 | 308 |
| 64 | 1 | 72–78 | 126 | 311 |
| 111 | 1 | 73 | 126 | 311 |
| 112 | 2 | 160 | 216 | — |
| 1024 | 9 | 789 | 832 | — |
| 8192 | 65 | 5666 | 5787 | — |

We are already 1.7x faster than Go on one-block messages. Neither benchmark in the repo measures this
today (both only hash 64 MiB), which is what B1 fixes. The empty message is consistently slower than
a 64-byte one (see A2).

### Compiled code (instructions per 128-byte block, hot loop)

| Backend | Build | Instr/block | Notes |
|---------|-------|-------------|-------|
| FEAT_SHA512 | aarch64-apple-darwin | 462 | 40 `SHA512H`, 40 `SHA512H2`, 32+32 `SU0`/`SU1`, 152 `EXT`, 124 `ADD`, 31 loads, no vector copies; same mix as Go's asm |
| scalar | aarch64-unknown-linux-gnu | 2495 | 31/round; **320 instructions just build K** (`mov` + 3 `movk` per constant); 576 `eor` with a folded rotate |
| scalar BMI1/BMI2 | x86_64-unknown-linux-gnu | 3510 | 44/round; 363 stack moves, 351 register copies, 80 `movabs` for K |
| scalar baseline | x86_64-unknown-linux-gnu | 4102 | 51/round; 1050 register copies (`ror` overwrites its input) |

The FEAT_SHA512 function also has 118 instructions **before** its loop. LLVM hoists all 40 K
vectors out of the block loop (40 `adrp`+`ldr` from separate constant-pool entries), spills 27 of them
to the stack and saves `d8`–`d15`, then reloads them inside the loop anyway. Go's asm streams K from
the table inside the loop instead. A one-block message pays the whole setup for 462 instructions of
work.

### M1 latencies of the SHA-512 instructions (cycles; dependent `asm!` chains, calibrated against a 1-cycle `add x` chain)

| Operation | Latency | Throughput |
|-----------|---------|------------|
| `ADD.2D`, `EXT` (`SUB.2D` assumed equal, not timed alone) | 2 | — |
| `SHA512H`/`SHA512H2` → `SHA512H`/`SHA512H2`, through the accumulator (Vd) | 2 | `SHA512H` and `SHA512H2` share one unit: one of either every 2 cycles |
| into `SHA512H`/`SHA512H2` through Vn/Vm (from any producer), or through Vd from a non-SHA instruction | 3 | |
| `SHA512SU0`, `SHA512SU1` | 2 | 1 per cycle; H + H2 + SU0 + SU1 together take 4 cycles, the same as H + H2 alone |
| `EXT → SHA512H → ADD` (the `e` chain of one round pair) | **7.0** | |
| real backend, per round pair (276 cycles / 40) | **6.9** | |

## 2. What Go does, and what we take from it

- **arm64** (`sha512block_arm64.s`, Ard Biesheuvel's Linux kernel design). The same four instructions
  with the same dataflow as our `rounds2!`, with the state rotating through five registers instead of
  being renamed. Two differences: it loads K with post-increment `VLD1.P` *inside* the loop, four
  round pairs ahead into a rotating set of registers, and it issues one `PRFM` on the table. **We take
  the K streaming (A2).** The dataflow is already the same as ours, and §3 A1 shows it is at the floor.
- **amd64** (`sha512block_amd64_asm.go`, Intel's white paper *Fast SHA512 Implementations on Intel
  Architecture Processors*, also in Linux as `sha512-avx2-asm.S`). Gated on AVX + AVX2 + BMI2. The
  message schedule runs four words at a time in YMM. `W + K` is stored to the stack, and the rounds run
  in general-purpose registers with `rorx` (`ADDQ` takes `W + K` as a memory operand). It is one block
  at a time, so for the 4-word schedule it must feed `w[t-2]` back inside each step (`VPERM2F128`, a
  mask `VPAND` and `VPBLENDD` per four words). **We take the AVX2-schedule-plus-BMI2-rounds split
  (X1),** but with the two-block layout our SHA-256 `x86_avx2.rs` and OpenSSL already use. With 64-bit
  words, two words per block per 128-bit half, that layout needs *no* feedback at all, and the second
  block's rounds do no schedule work.
- **generic** (`blockGeneric`): textbook, with an 80-word `w` array. Our scalar is already 1.22x
  faster. Nothing to take.
- Go has no SHA512-NI path on amd64 either.

## 3. aarch64

### A1. FEAT_SHA512 dataflow: closed, no change

The per-pair recurrence is `ef → EXT (2) → SHA512H via Vn/Vm (3) → ADD (2) → ef`, 7 cycles, and the
real loop runs at 6.9. Since `SHA512H`'s `Y[0]` (`d`) is only ever added to the first round's T1, I
tried taking the `ADD` off the chain: pre-add `c, d` into the accumulator, pass `Y = [0, e]`, so
`SHA512H` returns the new `(e, f)` directly, and recover T1 for `SHA512H2` with a `SUB`. The digests
are correct (all tests pass), but it is not faster:

| Variant (isolated round pairs, no schedule) | cycles / pair |
|---------------------------------------------|---------------|
| current | 7.03 |
| folded accumulator + `SUB` | 7.05 |
| folded, T1 from a second `SHA512H` | 6.96 |
| **two independent messages interleaved** | **4.01 per message** |

In the full backend (same session, MiB/s): current 1356–1366, folded 1369–1381, folded with the
add order pinned by `opaque()` (LLVM had regrouped `acc` as `(gh + cd) + K·W`) 1355–1390.

Why: the 2-cycle accumulator latency exists only from H/H2 to H/H2. Fed from an `ADD`/`SUB` it is 3,
so the fold creates a second recurrence, `ADD → SHA512H → SUB → SHA512H2`, measured at 10 cycles per
two pairs, and both 5-cycle chains compete for the single H/H2 unit. A second `SHA512H` makes it 3
unit ops per pair, 6 cycles. The interleaved line shows the true throughput floor, `H + H2` = 4 cycles
per pair, which a single message cannot reach. **Single-message FEAT_SHA512 stays as it is.** The only
lever left is several messages at once (A4).

### A2. Stream K inside the FEAT_SHA512 loop

Hide the table pointer once per block, so LLVM cannot hoist the 40 loads out of the loop:

```rust
for block in blocks {
    let k = core::hint::black_box(K.as_ptr());   // one per block; same pointer value
    ...
    rounds2!(ab, cd, ef, gh, m0, 0, k);          // `$k` threaded through the macros:
                                                 // macro hygiene hides a plain local
}
// in rounds2!:  vld1q_u64($k.add(2 * $i))
```

Prototype: the code before the loop goes from 118 instructions to 9 (no constant-pool loads, spills
or callee-saved saves). The loop goes from 462 to 457, since K now arrives in `ldp` pairs, plus one
stack store and load per block for `black_box`. 1-block digests went from 72.7 to 64.9 ns (−11%),
112 bytes from 160 to 151 ns (−6%), and 8 KiB from 5666 to 5658 ns. One 64 MiB message was unchanged
(1395.8 vs 1397.8 MiB/s, medians of three alternating runs). Tests pass.

While here, look into the 0-byte anomaly (89–92 ns, against 73 for 64 bytes). The guess, unverified,
is a store-to-load-forwarding stall: `hash_with` writes `0x80` into `tail[0]` with a byte store, and
the backend's first 16-byte load reads it straight back, before round 0 can start. For 64 bytes, the
affected load is the fifth one, which round 8 needs only later. If that is it, writing the marker as
part of a wider store fixes it.

- Gate: long-message throughput within ±1%; 1-block digest at least 5% faster; at most about 20
  instructions before the loop. The `SAFETY` comment of the load must now say that `k` is `K.as_ptr()`.
- Docs: none user-visible. README SHA-512 benchmarking gains the short-message row from B1.

### A3. Port SHA-256's aarch64 scalar tuning

This is the same treatment `src/sha2/sha256/scalar.rs` got on aarch64, transplanted to 64-bit words:

1. Standalone Sigma rotates: `ror(x, n) = opaque(x.rotate_right(n))` in `big_sigma0`/`big_sigma1`, so
   LLVM stops folding them into 2-cycle `eor …, ror #n` chains.
2. Pinned add order: SHA-256's `#[cfg(target_arch = "aarch64")]` arm of `round!`, unchanged except
   for the word type (`hkw`, `hkwd`, `t1`, the new `d`, the new `h`, each behind `opaque`).
3. K read from memory: `core::hint::black_box(&K)` on aarch64, so each constant is half of an `ldp`
   instead of four instructions (SHA-256's `round_constants()`).

Prototype ablation (alternating A/B runs, MiB/s; this was at a slightly busier moment than §1's
table, so compare the ratios):

| Variant | scalar SHA-512 | vs now |
|---------|----------------|--------|
| now | 529.7 | — |
| 1 only | 563.8 | +6.4% |
| 1 + 2 | 604.1 | +14.0% |
| 1 + 2 + 3 | 616.5 | **+16.4%** |

All three pay, so all three go in. That takes the scalar from 1.22x to about 1.4x Go's portable code.
On this Mac the scalar is only reached by the tests, since FEAT_SHA512 is in the baseline. The cores
that run it are aarch64 parts without FEAT_SHA512, such as Neoverse N1 (Graviton2, Ampere Altra) and
Cortex-A72/A76, and their ALUs are not Apple's. The pins were chosen for the M1's 2-cycle
shifted-operand ops.

- Gate: M1 at least +10%, and the Arm CI runner (`ubuntu-24.04-arm`, a Neoverse core; its throughput
  test times `scalar` after the hardware backend) must not regress. If it does, keep only the parts
  that are neutral there.
- Docs: README "Rules" paragraph ("the one other use is … SHA-256's two aarch64 backends") and the
  SHA-512 Benchmarking prose; the `scalar.rs` header gains SHA-256's explanation; the memory note
  "no aarch64 scalar tuning" goes. This adds `unsafe` (empty `asm!`), hence decision Q1.

## 4. x86-64

Nothing here can be timed on this machine. Rosetta has no BMI/AVX2, and Docker amd64 has AVX2+BMI but
emulated timing. Correctness runs under Docker; speed comes only from the Benchmarks workflow.

### X0. Baseline run

Push a branch and dispatch `.github/workflows/bench.yml`. It already runs `make bench-throughput` and
`make bench-go`, which include `sha2::sha512` and `bench/sha512cmp`, so no workflow change is needed.
This gives, in one job: cryptors BMI scalar and baseline scalar, Go AVX2 (default) and Go generic
(`purego`). Every x86 gate below compares within that one job.

### X1. AVX2 two-block backend: `src/sha2/sha512/x86_avx2.rs`

This is the mirror image of `src/sha2/sha256/x86_avx2.rs`, the white-paper design adapted to 64-bit
words:

- **Schedule**: eight YMM registers `x0..x7`. Each holds two consecutive words of block 1 in its low
  128 bits and the same two words of block 2 in its high 128 bits. One step makes two new words per
  block: `new = σ1(x7) + alignr::<8>(x5, x4) + σ0(alignr::<8>(x1, x0)) + x0`, with `alignr` working
  within each half, so the blocks never mix. `w[t-2]` and `w[t-1]` are both in `x7`, so there is
  **no feedback inside a step**, unlike SHA-256 (the `blend` dance in `next_words`) and Go's 4-word
  layout.
- **Rotates**: AVX2 has no 64-bit rotate, so `srl | sll`. σ0's `ror 8` is a byte rotation and could be
  one `vpshufb`; measure both, since shuffles compete for one port on Intel.
- **K**: `vbroadcasti128` a K pair, add it, and store `W + K` into a 32-byte-aligned
  `[u64; 160]` (two blocks × 80).
- **Rounds**: `scalar.rs`'s `big_sigma0/1`, `ch` and `maj` (made `pub(super)`, as SHA-256's are),
  compiled with `bmi1,bmi2`, reading `W + K` as one memory operand. That drops the `movabs` and an
  `add` per round, and the whole schedule, from the scalar side. Block 1's rounds interleave with
  the vector steps; block 2's rounds only read the array.
- An odd block out is loaded into both halves and only the first set of rounds runs, as in SHA-256.
- Dispatch: `avx2 && bmi1 && bmi2` → `x86_avx2`, else BMI → `compress_bmi`, else `compress`. Add it
  to `backends()`, and `matches_scalar_backend` and `unaligned_input` then cover it with no new test.

Expectation, as a prior rather than a promise: OpenSSL's `sha512-x86_64.pl` header gives
integer-only against its best vector path for SHA-512 as 7.25 → 5.20 cycles/byte on Skylake (its
table says +40%), 7.66 → 5.40 on Haswell (+42%) and 7.05 → 5.67 on Ryzen (+20%). Its AVX2 path is
this layout: it loads the first block into eight XMM halves and `vinserti128`s the second block into
the upper halves. Statically, our scalar side drops from about 3510 to about 2300 instructions per
block, plus about 400 vector instructions.

- Correctness: the full suite under `docker run --platform linux/amd64 … rust:1-slim cargo test`
  (exposes AVX2/BMI), clippy for `x86_64-unknown-linux-gnu`, and a throwaway mutation pass like the
  one SHA-256's AVX2 got (6/6 caught). The README must not claim that pass, as it is not in the repo.
- Gate (CI x86 job): at least 1.15x the BMI scalar, otherwise drop it, the same rule as SHA-256's
  AVX2 step. Report it against Go's AVX2 too; the target is parity or better.
- Docs: `sha2/mod.rs` backend table and the paragraph saying the 64-bit functions always run
  `scalar` on x86; the README "Dedicated instructions" paragraph ("on x86 SHA-384, SHA-512 and
  SHA-512/t run on the scalar backend") and the SHA-256 AVX2 paragraph, which becomes shared; the
  `bench.yml` matrix comment; the README x86 figures, once they exist.

### X2. Nested-Sigma form in the x86 scalar (low priority)

`Σ1(e) = ror(ror(ror(e, 23) ^ e, 4) ^ e, 14)` and `Σ0(a) = ror(ror(ror(a, 5) ^ a, 6) ^ a, 28)`,
the form OpenSSL's integer code uses (identities checked on 10,000 random words). Static
effect: BMI 3510 → 3339 instructions (stack moves 363 → 227); baseline 4102 → 3774 (copies
1050 → 729). llvm-mca is split: −8% to +4% depending on the CPU model, which is no signal. Do this
after X1, because once AVX2 exists, the BMI build is only reached by CPUs with BMI2 but no AVX2,
which are rare. The baseline build (pre-Haswell, Atom-class, Rosetta) is what would benefit.

- Gate: CI shows at least 3% gain on the build it targets and no regression on the other;
  otherwise drop it.

## 5. Optional: several messages at once (`Digest::digest_many`)

The trait's default `digest_many` hashes one message at a time. MD5 and SHA-3 override it, and the
SHA-2 types don't.

- **A4, aarch64**: two messages interleaved instruction by instruction through the same `rounds2!`
  dataflow. 4.01 against 7.03 cycles per pair per message in isolation, so up to 1.75x for batches of
  long messages, and more for one-block ones, which are pure latency. It needs the README's
  multi-buffer rules: lanes leave at their own last block, and a differential test over batches of
  unequal lengths.
- **X5, x86 AVX2 four lanes** (AVX-512 eight): one message per 64-bit lane, with a transpose on load.
  It could be about 2x the BMI scalar, but that is an unmeasured estimate, and it is the largest item
  here.

Both widen the scope from "faster SHA-512" to "a batch API path", hence decision Q3.

## 6. Order of work and how each step is verified

1. **B1**: add a `#[ignore]` short-message test next to `throughput` (lengths 0, 64, 111, 112, 128,
   256, 1024, 8192; ns per digest, best of 7) and its Go twin in `bench/sha512cmp`. This first, so A2
   is measured on both sides.
2. **A2**, then **A3** (both measurable here). Then **X0 → X1 → X2** on CI.
3. Optional steps per the decisions below.

For every step:

- `make ci`; strict rustdoc with `RUSTDOCFLAGS="-D warnings" cargo doc --no-deps` (plus
  `--document-private-items`, and `--target x86_64-unknown-linux-gnu` for x86 work); clippy on the
  host, `x86_64-unknown-linux-gnu` and `aarch64-unknown-linux-gnu`.
- x86 code: the full suite under Docker amd64.
- Timing: before each run, check `uptime` (load should be near idle; today four orphaned
  mutation-harness test binaries had pushed it to 200 and cut throughput by up to 5x). Pass
  `--test-threads=1`, alternate A/B builds in separate `CARGO_TARGET_DIR`s, take best-of-5 per run
  and the median of three runs.
- Keep the `*.rs` docs free of Go and of this machine's numbers; those go in the README and in
  `bench/`.

## 7. Considered and rejected

- **Folding `c, d` into `SHA512H`'s accumulator**: §3 A1; correct but no faster.
- **More K hoisting on aarch64**: LLVM already hoists, too far; that is A2's problem, not its fix.
- **K through memory on x86** (`black_box(&K)`): statically worse, 3510 → 3541 (BMI) and 4102 → 4255
  (baseline). LLVM loads into registers and spills more. x86 keeps the immediates, as SHA-256 does.
- **Go's one-block, four-word AVX2 layout**: needs the feedback shuffles every step and does
  schedule work for every block; the two-block layout has neither.
- **NEON schedule for the aarch64 scalar**: no 64-bit vector rotate without FEAT_SHA3 (`XAR`), and
  the cores that lack FEAT_SHA512 lack FEAT_SHA3 too.
- **Pins on x86**: SHA-256 showed they raise spills from about 260 to about 400 stack operands per
  block; x86 keeps the textbook order.

## 8. Decisions needed

- **Q1.** A3 makes the SHA-512 scalar the third place with an empty `asm!` barrier (aarch64 only),
  the same trade as SHA-256's option (a). OK?
- **Q2.** X0 means pushing a branch and dispatching the Benchmarks workflow. OK to do that when we
  reach it?
- **Q3.** Are A4/X5 (multi-message `digest_many`) in scope, or a separate plan?
- **Q4.** X3 (x86 `VSHA512RNDS2`/`MSG1`/`MSG2`, Arrow Lake / Lunar Lake): still deferred until some
  machine can execute it? (Recommended: yes. It would need a software model of the three
  instructions as its only test, and the README would have to say no hardware ran it.) X4
  (AVX-512VL rotates/`vpternlogq` in X1's schedule) waits for X1's numbers and for a runner that
  reports `avx512vl`.

## Appendix: reproducing the measurements

- **Codegen**: `cargo rustc --release --lib --target <T> -- --emit asm` in a fresh `CARGO_TARGET_DIR`,
  then count instructions between the loop label and its backward branch. On `aarch64-apple-darwin`
  the scalar is dead in the library (FEAT_SHA512 is in the baseline), so its loop is taken from
  `aarch64-unknown-linux-gnu`.
- **Latencies**: an `asm!` loop of 8 copies of the chain, 5×10⁷ iterations, best of 7, divided by the
  time per cycle measured by an `add x10, x10, x9` chain on the same run (3.11–3.16 GHz). Key bodies:
  `ext v3.16b, v0.16b, v0.16b, #8; sha512h q4, q3, v3.2d; add v0.2d, v4.2d, v5.2d` (7.0),
  the same without the `add`, chaining `ext v3, v4, v4` (5.0),
  `add v0.2d, v0.2d, v9.2d; sha512h q0, q1, v2.2d` (5.0, so 3 via Vd from an `ADD`),
  `sha512h q0, q1, v2.2d` alone (2.0), four independent `sha512h` (2.0 each).
- **Isolated round pairs**: `rounds2!` without schedule or loads, in intrinsics, 8 pairs × 2×10⁷
  iterations, for the variants of §3 A1.
