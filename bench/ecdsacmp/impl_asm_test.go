//go:build !purego

package ecdsacmp

// impl names what crypto/ecdsa runs in this build. Its curve arithmetic
// (crypto/internal/fips140/nistec) is assembly for P-256 on amd64, arm64,
// ppc64le and s390x and portable code elsewhere; P-224, P-384 and P-521 are
// portable code everywhere. The arithmetic modulo the order is portable code
// on every platform: the inversion for P-256 (nistec.P256OrdInverse) is Go, and
// crypto/internal/fips140/bigmod, which does the rest, has assembly only for
// the sizes of RSA. On s390x with the KDSA instruction, that instruction signs
// and verifies on P-256, P-384 and P-521. The SHA-2 of the HMAC_DRBG that makes
// the nonces is assembly where Go has some for the platform.
const impl = "Go crypto/ecdsa"
