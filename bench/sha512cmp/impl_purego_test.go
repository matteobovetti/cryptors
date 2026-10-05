//go:build purego

package sha512cmp

// impl names what crypto/sha512 runs in this build: with the purego tag, its
// portable code on every platform.
const impl = "Go crypto/sha512, purego"
