package signer

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"testing"

	"git.liebaopay.com/ksrv/keyserver/crypto/p256"
)

func TestSecp256r1(t *testing.T) {
	prikey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Error(err)
	}

	hash, _ := hex.DecodeString("d7405785618c4f1b3fb6174e1758ab77a0a4df0f32574ad2b0a36010fa7f0e8e")
	signatrue, err := Secp256r1(hash, prikey.D.Bytes())
	if err != nil {
		t.Error(err)
	}

	public := p256.PublicKey{prikey.X, prikey.Y}
	pubKey, _ := public.EncodePoint(true)
	flag := Secp256r1Veify(pubKey, hash, signatrue)

	if !flag {
		t.Error(flag)
	}
}
