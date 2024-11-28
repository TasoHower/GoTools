package signer

import (
	"git.liebaopay.com/ksrv/keyserver/crypto/p256"
	"github.com/sirupsen/logrus"
)

// Secp256r1 签名算法
func Secp256r1(hash, privKey []byte) ([]byte, error) {
	return p256.Sign(privKey, hash)
}

// Secp256r1Veify 验签算法
func Secp256r1Veify(pubKey, hash, sig []byte) bool {
	err := p256.Verify(pubKey, hash, sig)
	if err != nil {
		logrus.Error(err.Error())
		return false
	}
	return true
}
