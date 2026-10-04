//go:build purego

package sha3cmp

// impl names what crypto/sha3 runs in this build: with the purego tag, its
// portable Keccak on every platform.
const impl = "Go crypto/sha3, purego"
