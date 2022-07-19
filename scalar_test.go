package bls

import (
	"crypto/rand"
	"testing"
)

func TestScalarHash(t *testing.T) {
	token := make([]byte, 32)
	rand.Read(token)
	NewKyberScalar().(*Scalar).Hash(suite, token)
}
