package bls

import (
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
	actualBitLen := s.Int.M.BitLen()
	toMask := canonicalBitLen - actualBitLen
	buff := msg
	for {
		hash := h.Hash()
		_, _ = hash.Write(buff)
		buff = hash.Sum(nil)
		if s.Int.BO == mod.LittleEndian {
			buff[0] = buff[0] >> toMask
		} else {
			buff[len(buff)-1] = buff[len(buff)-1] >> toMask
		}
		if err := s.UnmarshalBinary(buff); err == nil {
			return s
		}
	}
}
