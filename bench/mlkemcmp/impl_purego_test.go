//go:build purego

package mlkemcmp

// impl names what crypto/mlkem runs on in this build: with the purego tag, Go's
// portable Keccak under SHA-3 and SHAKE on every platform, and no assembly
// anywhere.
const impl = "Go crypto/mlkem, purego"
