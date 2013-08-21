rfc6979
=======

A Go implementation of [RFC 6979](https://tools.ietf.org/html/rfc6979)'s
deterministic DSA/ECDSA signature scheme.

``` go
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha512"
	"fmt"
	"github.com/codahale/rfc6979"
)

func main() {
	// Generate a key pair.
	// You need a high-quality PRNG for this.
	k, _ := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)

	// Hash a message.
	alg := sha512.New()
	alg.Write([]byte("I am a potato."))
	hash := alg.Sum(nil)

	// Sign the message. You don't need a PRNG for this.
	r, s, _ := rfc6979.SignECDSA(k, hash, sha512.New)
	fmt.Printf("Signature: %X%X", r, s)
}

```
