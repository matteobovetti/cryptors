//go:build purego

package mldsacmp

// impl names what crypto/mldsa runs on in this build: with the purego tag, Go's
// portable Keccak under SHAKE on every platform, and no assembly anywhere.
const impl = "Go crypto/mldsa, purego"
