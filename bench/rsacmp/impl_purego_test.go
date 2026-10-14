//go:build purego

package rsacmp

// impl names what crypto/rsa runs in this build: with the purego tag, the
// portable code of bigmod's inner loop for every size, and of the hashes.
const impl = "Go crypto/rsa, purego"
