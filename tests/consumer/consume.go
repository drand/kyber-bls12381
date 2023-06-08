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
	retCount := 0
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
		g1 := bls.NullKyberG1([]byte(tv.Ciphersuite)).Hash([]byte(tv.Msg))
		g1Buff, _ := g1.MarshalBinary()
		exp := tv.G1Compressed
		if !bytes.Equal(g1Buff, exp) {
			retCount++
			fmt.Println("test", i, " fails at G1")
		}
		g2 := bls.NullKyberG2([]byte(tv.Ciphersuite)).Hash([]byte(tv.Msg))
		g2Buff, _ := g2.MarshalBinary()
		exp = tv.G2Compressed
		if !bytes.Equal(g2Buff, exp) {
			retCount++
			fmt.Println("test", i, " fails at G2")
		}

		if tv.BLSPrivKey != "" {
			// SIGNATURE is always happening on bls.DomainG2
			pairing := bls.NewBLS12381Suite()
			scheme := sig.NewSchemeOnG2(pairing)
			pubKey := pairing.G1().Point()
			if err := pubKey.UnmarshalBinary(tv.BLSPubKey); err != nil {
				panic(err)
			}
			err := scheme.Verify(pubKey, []byte(tv.Msg), tv.BLSSigG2)
			if err != nil {
				retCount++
				fmt.Println("test", i, " fails for signature")
			}
		}
	}
	os.Exit(retCount)
}
