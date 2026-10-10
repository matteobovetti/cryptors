//go:build purego

package hpkecmp

// impl names what crypto/hpke runs on in this build: with the purego tag,
// Go's portable AES, GHASH and field arithmetic on every platform.
const impl = "Go crypto/hpke, purego"
