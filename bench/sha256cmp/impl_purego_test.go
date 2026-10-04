//go:build purego

package sha256cmp

// impl names what crypto/sha256 runs in this build: with the purego tag, its
// portable code on every platform.
const impl = "Go crypto/sha256, purego"
