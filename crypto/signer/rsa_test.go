package signer

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
	"testing"
)

func TestRSA(t *testing.T) {
	for i := 0; i < 1; i++ {
		n, d, err := GenRsa4096()
		if err != nil {
			panic(err)
		}
		msg := []byte("test msg")
		hash := sha256.Sum256(msg)
		prikeyBytes := make([]byte, RSA4096LEN*2)
		copy(prikeyBytes, n)
		copy(prikeyBytes[RSA4096LEN:], d)
		sig, err := Rsa4096(hash[:], prikeyBytes)
		if err != nil {
			panic(err)
		}
		fmt.Println(hex.EncodeToString(sig))
		N := new(big.Int).SetBytes(n)
		publikc := rsa.PublicKey{E: E, N: N}
		err = rsa.VerifyPSS(&publikc, crypto.SHA256, hash[:], sig, &rsa.PSSOptions{
			SaltLength: rsa.PSSSaltLengthAuto,
			Hash:       crypto.SHA256,
		})
		if err != nil {
			panic(err)
		}
		fmt.Println("verify passed")
	}

}
