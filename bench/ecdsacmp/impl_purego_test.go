//go:build purego

package ecdsacmp

// impl names what crypto/ecdsa runs in this build: with the purego tag, its
// portable code on every platform, for the curves and for the hashes of the
// HMAC_DRBG alike, and no KDSA on s390x.
const impl = "Go crypto/ecdsa, purego"
