package bls

import (
	"crypto/cipher"
	"crypto/sha256"
	"hash"
	"io"
	"reflect"

	"github.com/drand/kyber"
	"github.com/drand/kyber/pairing"
	"github.com/drand/kyber/util/random"
	"github.com/drand/kyber/xof/blake2xb"
	bls12381 "github.com/kilic/bls12-381"
)

// GroupChecker allows to verify if a Point is in the correct group or not. For
// curves which don't have a prime order, we need to only consider the points
// lying in the subgroup of prime order. That check returns true if the point is
// correct or not.
type GroupChecker interface {
	kyber.Point
	IsInCorrectGroup() bool
}

type groupBls struct {
	str      string
	newPoint func() kyber.Point
	isPrime  bool
}

func (g *groupBls) String() string {
	return g.str
}

func (g *groupBls) Scalar() kyber.Scalar {
	return NewKyberScalar()
}

func (g *groupBls) ScalarLen() int {
	return g.Scalar().MarshalSize()
}

func (g *groupBls) PointLen() int {
	return g.Point().MarshalSize()
}

func (g *groupBls) Point() kyber.Point {
	return g.newPoint()
}

func (g *groupBls) IsPrimeOrder() bool {
	return g.isPrime
}

func (g *groupBls) Hash() hash.Hash {
	return sha256.New()
}

// XOF returns a newly instantiated blake2xb XOF function.
func (g *groupBls) XOF(seed []byte) kyber.XOF {
	return blake2xb.New(seed)
}

// RandomStream returns a cipher.Stream which corresponds to a key stream from
// crypto/rand.
func (g *groupBls) RandomStream() cipher.Stream {
	return random.New()
}

func NewGroupG1(dst []byte) kyber.Group {
	return &groupBls{
		str:      "bls12-381.G1",
		newPoint: func() kyber.Point { return NullKyberG1(dst) },
		isPrime:  true,
	}
}

func NewGroupG2(dst []byte) kyber.Group {
	return &groupBls{
		str:      "bls12-381.G2",
		newPoint: func() kyber.Point { return NullKyberG2(dst) },
		isPrime:  false,
	}
}

func NewGroupGT() kyber.Group {
	return &groupBls{
		str:      "bls12-381.GT",
		newPoint: func() kyber.Point { return newEmptyGT() },
		isPrime:  false,
	}
}

type Suite struct {
	domainG1 []byte
	domainG2 []byte
}

func NewBLS12381Suite() pairing.Suite {
	return &Suite{}
}

func (s *Suite) SetDomainG1(dst []byte) {
	s.domainG1 = dst
}

func (s *Suite) G1() kyber.Group {
	return NewGroupG1(s.domainG1)
}

func (s *Suite) SetDomainG2(dst []byte) {
	s.domainG2 = dst
}

func (s *Suite) G2() kyber.Group {
	return NewGroupG2(s.domainG2)
}

func (s *Suite) GT() kyber.Group {
	return NewGroupGT()
}

// ValidatePairing implements the `pairing.Suite` interface
func (s *Suite) ValidatePairing(p1, p2, p3, p4 kyber.Point) bool {
	e := bls12381.NewEngine()
	// we need to clone the point because of https://github.com/kilic/bls12-381/issues/37
	// in order to avoid risks of race conditions.
	g1point := new(bls12381.PointG1).Set(p1.(*KyberG1).p)
	g2point := new(bls12381.PointG2).Set(p2.(*KyberG2).p)
	g1point2 := new(bls12381.PointG1).Set(p3.(*KyberG1).p)
	g2point2 := new(bls12381.PointG2).Set(p4.(*KyberG2).p)
	e.AddPair(g1point, g2point)
	e.AddPairInv(g1point2, g2point2)
	return e.Check()
}

func (s *Suite) Pair(p1, p2 kyber.Point) kyber.Point {
	e := bls12381.NewEngine()
	g1point := p1.(*KyberG1).p
	g2point := p2.(*KyberG2).p
	return newKyberGT(e.AddPair(g1point, g2point).Result())
}

// New implements the kyber.Encoding interface.
func (s *Suite) New(t reflect.Type) interface{} {
	panic("Suite.Encoding: deprecated in drand")
}

// Read is the default implementation of kyber.Encoding interface Read.
func (s *Suite) Read(r io.Reader, objs ...interface{}) error {
	panic("Suite.Read(): deprecated in drand")
}

// Write is the default implementation of kyber.Encoding interface Write.
func (s *Suite) Write(w io.Writer, objs ...interface{}) error {
	panic("Suite.Write(): deprecated in drand")
}

// Hash returns a newly instantiated sha256 hash function.
func (s *Suite) Hash() hash.Hash {
	return sha256.New()
}

// XOF returns a newly instantiated blake2xb XOF function.
func (s *Suite) XOF(seed []byte) kyber.XOF {
	return blake2xb.New(seed)
}

// RandomStream returns a cipher.Stream which corresponds to a key stream from
// crypto/rand.
func (s *Suite) RandomStream() cipher.Stream {
	return random.New()
}
