//go:build !purego

package mlkemcmp

// impl names what crypto/mlkem runs on in this build. The lattice arithmetic
// (the transform, the sampling, the compression) is portable Go on every
// platform; what has assembly is the Keccak permutation under SHA-3 and SHAKE,
// which dominates the rest: crypto/internal/fips140/sha3 has it for amd64, for
// arm64 on darwin (using the SHA-3 instructions, which it finds slower than its
// portable code on other Arm cores, so it does not use them there) and for
// s390x.
const impl = "Go crypto/mlkem"
