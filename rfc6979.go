/*
Paraphrasing RFC6979:

	This package implements a deterministic digital signature generation
	procedure.  Such signatures are compatible with standard Digital
	Signature Algorithm (DSA) and Elliptic Curve Digital Signature
	Algorithm (ECDSA) digital signatures and can be processed with
	unmodified verifiers, which need not be aware of the procedure
	described therein.  Deterministic signatures retain the cryptographic
	security features associated with digital signatures but can be more
	easily implemented in various environments, since they do not need
	access to a source of high-quality randomness.

Provides functions similar to crypto/dsa and crypto/ecdsa.
*/
package rfc6979

import (
	"bytes"
	"crypto/hmac"
	"hash"
	"math/big"
)

// A function which provides a fresh Hash (e.g., sha256.New).
type HashAlgorithm func() hash.Hash

func (alg HashAlgorithm) digest(m []byte) []byte {
	h := alg()
	h.Write(m)
	return h.Sum(nil)
}

func (alg HashAlgorithm) mac(k []byte, m []byte) []byte {
	h := hmac.New(alg, k)
	h.Write(m)
	return h.Sum(nil)
}

// https://tools.ietf.org/html/rfc6979#section-2.3.2
func bits2int(in []byte, qlen int) *big.Int {
	vlen := len(in) * 8
	v := new(big.Int).SetBytes(in)
	if vlen > qlen {
		v = new(big.Int).Rsh(v, uint(vlen-qlen))
	}
	return v
}

// https://tools.ietf.org/html/rfc6979#section-2.3.3
func int2octets(v *big.Int, rolen int) []byte {
	out := v.Bytes()

	// pad with zeros if it's too short
	if len(out) < rolen {
		out2 := make([]byte, rolen)
		copy(out2[rolen-len(out):], out)
		return out2
	}

	// drop most significant bytes if it's too long
	if len(out) > rolen {
		out2 := make([]byte, rolen)
		copy(out2, out[len(out)-rolen:])
		return out2
	}

	return out
}

// https://tools.ietf.org/html/rfc6979#section-2.3.4
func bits2octets(in []byte, q *big.Int, qlen, rolen int) []byte {
	z1 := bits2int(in, qlen)
	z2 := new(big.Int).Sub(z1, q)
	if z2.Sign() < 0 {
		return int2octets(z1, rolen)
	}
	return int2octets(z2, rolen)
}

// https://tools.ietf.org/html/rfc6979#section-3.2
func generateSecret(q, x *big.Int, alg HashAlgorithm, hash []byte, test func(*big.Int) bool) {
	// Step A
	qlen := q.BitLen()
	holen := alg().Size()
	rolen := (qlen + 7) >> 3

	// Step B
	v := bytes.Repeat([]byte{0x01}, holen)

	// Step C
	k := bytes.Repeat([]byte{0x00}, holen)

	// Step D
	b := int2octets(x, rolen)
	bh := bits2octets(hash, q, qlen, rolen)
	bx := append(b, bh...)

	k = alg.mac(k, append(append(v, 0x00), bx...))

	// Step E
	v = alg.mac(k, v)

	// Step F
	k = alg.mac(k, append(append(v, 0x01), bx...))

	// Step G
	v = alg.mac(k, v)

	for {
		// Step H1
		t := make([]byte, 0)

		// Step H2
		for len(t) < qlen/8 {
			v = alg.mac(k, v)
			t = append(t, v...)
		}

		secret := bits2int(t, qlen)
		if secret.Cmp(big.NewInt(1)) >= 0 && secret.Cmp(q) < 0 && test(secret) {
			return
		}
		k = alg.mac(k, append(v, 0x00))
		v = alg.mac(k, v)

	}
}
