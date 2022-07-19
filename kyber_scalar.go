package bls

import (
	"fmt"
	"math/big"

	"github.com/drand/kyber"
	"github.com/drand/kyber/group/mod"
)

var curveOrder, _ = new(big.Int).SetString("73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001", 16)

type Scalar struct {
	*mod.Int
}

func NewKyberScalar() kyber.Scalar {
	return &Scalar{mod.NewInt64(0, curveOrder)}
}

func (s *Scalar) Hash(h kyber.HashFactory, msg []byte) kyber.Scalar {
	canonicalBitLen := s.Int.MarshalSize() * 8
	actualBitLen := s.Int.V.BitLen()
	toMask := canonicalBitLen - actualBitLen
	var fullMask byte = 0xff
	var mask byte = 0
	for toMask > 0 {
		mask = mask<<1 + 1
		toMask = toMask >> 1
	}
	mask = mask & fullMask

	buff := msg
	for {
		hash := h.Hash()
		_, _ = hash.Write(buff)
		buff = hash.Sum(nil)
		if s.Int.BO == mod.LittleEndian {
			buff[0] = buff[0] & mask
		} else {
			buff[len(buff)-1] = buff[len(buff)-1] & mask
		}
		if err := s.UnmarshalBinary(buff); err == nil {
			return s
		} else {
			fmt.Println("canonicalBitLen: ", canonicalBitLen, " actual bit len:", actualBitLen, " error: ", err)
		}
	}
}
