//go:build purego

package aescmp

// impl names what crypto/aes runs in this build: with the purego tag, its
// portable code on every platform.
const impl = "Go crypto/aes, purego"
