package bls

import (
	"bytes"
	"crypto/cipher"
	"encoding/hex"
	"io"

	"github.com/drand/kyber"
	"github.com/drand/kyber/group/mod"
	bls12381 "github.com/kilic/bls12-381"
)

// domainG2 is the DST used for hash to curve on G2, this is the default from the RFC.
// This is compatible with the paired library > v18
var domainG2 = []byte("BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_")

func DefaultDomainG2() []byte {
	return domainG2
}

// KyberG2 is a kyber.Point holding a G2 point on BLS12-381 curve
type KyberG2 struct {
	p *bls12381.PointG2
	// domain separation tag. We treat a 0 len dst as the default value as per the RFC "Tags MUST have nonzero length"
	dst []byte
}

func NullKyberG2(dst ...byte) *KyberG2 {
	var p bls12381.PointG2
	return newKyberG2(&p, dst)
}

func newKyberG2(p *bls12381.PointG2, dst []byte) *KyberG2 {
	return &KyberG2{p: p, dst: dst}
}

func (k *KyberG2) Equal(k2 kyber.Point) bool {
	k2g2, ok := k2.(*KyberG2)
	if !ok {
		return false
	}
	return bls12381.NewG2().Equal(k.p, k2g2.p) && bytes.Equal(k.dst, k2g2.dst)
}

func (k *KyberG2) Null() kyber.Point {
	return newKyberG2(bls12381.NewG2().Zero(), k.dst)
}

func (k *KyberG2) Base() kyber.Point {
	return newKyberG2(bls12381.NewG2().One(), k.dst)
}

func (k *KyberG2) Pick(rand cipher.Stream) kyber.Point {
	var dst, src [32]byte
	rand.XORKeyStream(dst[:], src[:])
	return k.Hash(dst[:])
}

func (k *KyberG2) Set(q kyber.Point) kyber.Point {
	k.p.Set(q.(*KyberG2).p)
	return k
}

func (k *KyberG2) Clone() kyber.Point {
	var p bls12381.PointG2
	p.Set(k.p)
	return newKyberG2(&p, k.dst)
}

func (k *KyberG2) EmbedLen() int {
	panic("bls12-381: unsupported operation")
}

func (k *KyberG2) Embed(data []byte, rand cipher.Stream) kyber.Point {
	panic("bls12-381: unsupported operation")
}

func (k *KyberG2) Data() ([]byte, error) {
	panic("bls12-381: unsupported operation")
}

func (k *KyberG2) Add(a, b kyber.Point) kyber.Point {
	aa := a.(*KyberG2)
	bb := b.(*KyberG2)
	bls12381.NewG2().Add(k.p, aa.p, bb.p)
	return k
}

func (k *KyberG2) Sub(a, b kyber.Point) kyber.Point {
	aa := a.(*KyberG2)
	bb := b.(*KyberG2)
	bls12381.NewG2().Sub(k.p, aa.p, bb.p)
	return k
}

func (k *KyberG2) Neg(a kyber.Point) kyber.Point {
	aa := a.(*KyberG2)
	bls12381.NewG2().Neg(k.p, aa.p)
	return k
}

func (k *KyberG2) Mul(s kyber.Scalar, q kyber.Point) kyber.Point {
	if q == nil {
		q = NullKyberG2(k.dst...).Base()
	}
	bls12381.NewG2().MulScalarBig(k.p, q.(*KyberG2).p, &s.(*mod.Int).V)
	return k
}

// MarshalBinary returns a compressed point, without any domain separation tag information
func (k *KyberG2) MarshalBinary() ([]byte, error) {
	// we need to clone the point because of https://github.com/kilic/bls12-381/issues/37
	// in order to avoid risks of race conditions.
	t := new(bls12381.PointG2).Set(k.p)
	return bls12381.NewG2().ToCompressed(t), nil
}

// UnmarshalBinary populates the point from a compressed point representation.
func (k *KyberG2) UnmarshalBinary(buff []byte) error {
	var err error
	k.p, err = bls12381.NewG2().FromCompressed(buff)
	return err
}

// MarshalTo writes a compressed point to the Writer, without any domain separation tag information
func (k *KyberG2) MarshalTo(w io.Writer) (int, error) {
	buf, err := k.MarshalBinary()
	if err != nil {
		return 0, err
	}
	return w.Write(buf)
}

// UnmarshalFrom populates the point from a compressed point representation read from the Reader.
func (k *KyberG2) UnmarshalFrom(r io.Reader) (int, error) {
	buf := make([]byte, k.MarshalSize())
	n, err := io.ReadFull(r, buf)
	if err != nil {
		return n, err
	}
	return n, k.UnmarshalBinary(buf)
}

func (k *KyberG2) MarshalSize() int {
	return 96
}

func (k *KyberG2) String() string {
	b, _ := k.MarshalBinary()
	return "bls12-381.G2: " + hex.EncodeToString(b)
}

func (k *KyberG2) Hash(m []byte) kyber.Point {
	domain := domainG2
	// We treat a 0 len dst as the default value as per the RFC "Tags MUST have nonzero length"
	if len(k.dst) != 0 {
		domain = k.dst
	}
	pg2, _ := bls12381.NewG2().HashToCurve(m, domain)
	k.p = pg2
	return k
}

func (k *KyberG2) IsInCorrectGroup() bool {
	return bls12381.NewG2().InCorrectSubgroup(k.p)
}
