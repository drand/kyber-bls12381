package bls

import (
	"testing"
)

func TestScalarHash(t *testing.T) {
	NewKyberScalar().(*Scalar).Hash(suite, []byte("HelloWorld"))
}
