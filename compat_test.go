package bls

import (
	"testing"

	oldBls "github.com/drand/bls12-381"
	"github.com/drand/kyber"
	"github.com/stretchr/testify/require"
)

type Hashable interface {
	Hash([]byte) kyber.Point
}

func TestCompat(t *testing.T) {
	type testVector struct {
		oldGroup kyber.Group
		newGroup kyber.Group
	}
	msg := []byte("Once upon a time, there was compatibility")
	var tvs = []testVector{
		{
			oldGroup: oldBls.NewGroupG1(),
			newGroup: NewGroupG1(),
		},
		{
			oldGroup: oldBls.NewGroupG2(),
			newGroup: NewGroupG2(),
		},
	}

	for _, tv := range tvs {
		og1p := tv.oldGroup.Point().(Hashable).Hash(msg)
		ng1p := tv.newGroup.Point().(Hashable).Hash(msg)
		obuff, err := og1p.MarshalBinary()
		require.NoError(t, err)
		nbuff, err := ng1p.MarshalBinary()
		require.NoError(t, err)
		require.Equal(t, obuff, nbuff)
	}
}
