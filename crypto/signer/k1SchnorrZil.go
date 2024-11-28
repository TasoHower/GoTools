package signer

import (
	"github.com/Zilliqa/gozilliqa-sdk/keytools"
	go_schnorr "github.com/Zilliqa/gozilliqa-sdk/schnorr"
)

// K1SchnorrZil 签名算法
func K1SchnorrZil(msg, privkey []byte) ([]byte, error) {
	rb, err := keytools.GenerateRandomBytes(keytools.Secp256k1.N.BitLen() / 8)
	if err != nil {
		return nil, err
	}
	publicKey := keytools.GetPublicKeyFromPrivateKey(privkey, true)

	r, s, err := go_schnorr.TrySign(privkey, publicKey, msg, rb)
	if err != nil {
		return nil, err
	}
	var signature [64]byte
	rl := len(r)
	if rl > 32 {
		copy(signature[:32], r[:32])
	} else {
		copy(signature[32-rl:32], r)
	}
	sl := len(s)
	if sl > 32 {
		copy(signature[32:], s[:32])
	} else {
		copy(signature[64-sl:], s)
	}
	return signature[:], nil
}

// K1SchnorrZilVerify 验签算法
func K1SchnorrZilVerify(pubkey, msg, sig []byte) bool {
	return go_schnorr.Verify(pubkey, msg, sig[:32], sig[32:])
}
