package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"

	bls "github.com/drand/kyber-bls12381"
	sig "github.com/drand/kyber/sign/bls"
)

type testVector struct {
	Msg          string
	Ciphersuite  string
	G1Compressed []byte
	G2Compressed []byte
	BLSPrivKey   string
	BLSPubKey    []byte
	BLSSigG2     []byte
}

func main() {
	fname := os.Args[1]
	f, err := os.Open(fname)
	if err != nil {
		panic(err)
	}
	defer f.Close()
	var tests []testVector
	if err := json.NewDecoder(f).Decode(&tests); err != nil {
		panic(err)
	}
	for i, tv := range tests {
		bls.Domain = []byte(tv.Ciphersuite)
		g1 := bls.NullKyberG1().Hash([]byte(tv.Msg))
		g1Buff, _ := g1.MarshalBinary()
		exp := tv.G1Compressed
		if !bytes.Equal(g1Buff, exp) {
			fmt.Println("test", i, " fails at G1")
		}
		g2 := bls.NullKyberG2().Hash([]byte(tv.Msg))
		g2Buff, _ := g2.MarshalBinary()
		exp = tv.G2Compressed
		if !bytes.Equal(g2Buff, exp) {
			fmt.Println("test", i, " fails at G2")
		}

		if tv.BLSPrivKey != "" {
			// SIGNATURE is always happening on bls.Domain
			pairing := bls.NewBLS12381Suite()
			scheme := sig.NewSchemeOnG2(pairing)
			pubKey := pairing.G1().Point()
			if err := pubKey.UnmarshalBinary(tv.BLSPubKey); err != nil {
				panic(err)
			}
			err := scheme.Verify(pubKey, []byte(tv.Msg), tv.BLSSigG2)
			if err != nil {
				fmt.Println("test", i, " fails for signature")
			}
		}
	}
}
