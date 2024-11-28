package signer

import (
	"github.com/ethereum/go-ethereum/crypto/secp256k1"
)

// Secp256k1 签名算法
func Secp256k1(hash, privKey []byte) ([]byte, error) {
	return secp256k1.Sign(hash, privKey)
}

// Secp256k1Veify 验签算法
func Secp256k1Veify(pubKey, hash, sig []byte) bool {
	return secp256k1.VerifySignature(pubKey, hash, sig)
}
