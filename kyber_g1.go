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

// domainG1 is the DST used for hash to curve on G1, this is the default from the RFC.
var domainG1 = []byte("BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_")

func DefaultDomainG1() []byte {
	return domainG1
}

// KyberG1 is a kyber.Point holding a G1 point on BLS12-381 curve
type KyberG1 struct {
	p *bls12381.PointG1
	// domain separation tag. We treat a 0 len dst as the default value as per the RFC "Tags MUST have nonzero length"
	dst []byte

	kyber.Point
	kyber.HashablePoint
}

func NullKyberG1(dst ...byte) *KyberG1 {
	var p bls12381.PointG1
	return newKyberG1(&p, dst)
}
func newKyberG1(p *bls12381.PointG1, dst []byte) *KyberG1 {
	return &KyberG1{p: p, dst: dst}
}

func (k *KyberG1) Equal(k2 kyber.Point) bool {
	k2g1, ok := k2.(*KyberG1)
	if !ok {
		return false
	}
	return bls12381.NewG1().Equal(k.p, k2g1.p) && bytes.Equal(k.dst, k2g1.dst)
}

func (k *KyberG1) Null() kyber.Point {
	return newKyberG1(bls12381.NewG1().Zero(), k.dst)
}

func (k *KyberG1) Base() kyber.Point {
	return newKyberG1(bls12381.NewG1().One(), k.dst)
}

func (k *KyberG1) Pick(rand cipher.Stream) kyber.Point {
	var dst, src [32]byte
	rand.XORKeyStream(dst[:], src[:])
	return k.Hash(dst[:])
}

func (k *KyberG1) Set(q kyber.Point) kyber.Point {
	k.p.Set(q.(*KyberG1).p)
	return k
}

func (k *KyberG1) Clone() kyber.Point {
	var p bls12381.PointG1
	p.Set(k.p)
	return newKyberG1(&p, k.dst)
}

func (k *KyberG1) EmbedLen() int {
	panic("bls12-381: unsupported operation")
}

func (k *KyberG1) Embed(data []byte, rand cipher.Stream) kyber.Point {
	panic("bls12-381: unsupported operation")
}

func (k *KyberG1) Data() ([]byte, error) {
	panic("bls12-381: unsupported operation")
}

func (k *KyberG1) Add(a, b kyber.Point) kyber.Point {
	aa := a.(*KyberG1)
	bb := b.(*KyberG1)
	bls12381.NewG1().Add(k.p, aa.p, bb.p)
	return k
}

func (k *KyberG1) Sub(a, b kyber.Point) kyber.Point {
	aa := a.(*KyberG1)
	bb := b.(*KyberG1)
	bls12381.NewG1().Sub(k.p, aa.p, bb.p)
	return k
}

func (k *KyberG1) Neg(a kyber.Point) kyber.Point {
	aa := a.(*KyberG1)
	bls12381.NewG1().Neg(k.p, aa.p)
	return k
}

func (k *KyberG1) Mul(s kyber.Scalar, q kyber.Point) kyber.Point {
	if q == nil {
		q = NullKyberG1(k.dst...).Base()
	}
	bls12381.NewG1().MulScalarBig(k.p, q.(*KyberG1).p, &s.(*mod.Int).V)
	return k
}

// MarshalBinary returns a compressed point, without any domain separation tag information
func (k *KyberG1) MarshalBinary() ([]byte, error) {
	// we need to clone the point because of https://github.com/kilic/bls12-381/issues/37
	// in order to avoid risks of race conditions.
	t := new(bls12381.PointG1).Set(k.p)
	return bls12381.NewG1().ToCompressed(t), nil
}

// UnmarshalBinary populates the point from a compressed point representation.
func (k *KyberG1) UnmarshalBinary(buff []byte) error {
	var err error
	k.p, err = bls12381.NewG1().FromCompressed(buff)
	return err
}

// MarshalTo writes a compressed point to the Writer, without any domain separation tag information
func (k *KyberG1) MarshalTo(w io.Writer) (int, error) {
	buf, err := k.MarshalBinary()
	if err != nil {
		return 0, err
	}
	return w.Write(buf)
}

// UnmarshalFrom populates the point from a compressed point representation read from the Reader.
func (k *KyberG1) UnmarshalFrom(r io.Reader) (int, error) {
	buf := make([]byte, k.MarshalSize())
	n, err := io.ReadFull(r, buf)
	if err != nil {
		return n, err
	}
	return n, k.UnmarshalBinary(buf)
}

func (k *KyberG1) MarshalSize() int {
	return 48
}

func (k *KyberG1) String() string {
	b, _ := k.MarshalBinary()
	return "bls12-381.G1: " + hex.EncodeToString(b)
}

func (k *KyberG1) Hash(m []byte) kyber.Point {
	domain := domainG1
	// We treat a 0 len dst as the default value as per the RFC "Tags MUST have nonzero length"
	if len(k.dst) != 0 {
		domain = k.dst
	}
	p, _ := bls12381.NewG1().HashToCurve(m, domain)
	k.p = p
	return k
}

func (k *KyberG1) IsInCorrectGroup() bool {
	return bls12381.NewG1().InCorrectSubgroup(k.p)
}
