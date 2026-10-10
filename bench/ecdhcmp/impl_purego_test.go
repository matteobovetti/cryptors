//go:build purego

package ecdhcmp

// impl names what crypto/ecdh runs in this build: with the purego tag, its
// portable code on every platform.
const impl = "Go crypto/ecdh, purego"
