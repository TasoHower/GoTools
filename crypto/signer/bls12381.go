package signer

import (
	"fmt"

	"git.liebaopay.com/ksrv/keyserver/crypto/bls"
)

// Bls12381 签名算法
func Bls12381(msg, privKey []byte) ([]byte, error) {
	mpl := bls.AugSchemeMPL{}
	sk := bls.KeyFromBytes(privKey)
	signature, err := mpl.Sign(sk, msg)
	if err != nil {
		return nil, fmt.Errorf("sign : %s", err.Error())
	}
	return signature, nil
}

// Bls12381Verify 验签算法
func Bls12381Verify(pubKey, msg, sig []byte) (bool, error) {
	mpl := bls.AugSchemeMPL{}
	pk, err := bls.NewPublicKey(pubKey)
	if err != nil {
		return false, fmt.Errorf("NewPublicKey : %s", err.Error())
	}
	ret := mpl.Verify(pk, msg, sig)
	return ret, nil
}
