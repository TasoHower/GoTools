package bls

import (
	"math/big"

	bls12381 "github.com/kilic/bls12-381"
)

// KeyGen 密钥生成
func KeyGen(seed []byte) PrivateKey {
	L := 48
	okm := extractExpand(L, append(seed, 0), []byte("BLS-SIG-KEYGEN-SALT-"), []byte{0, byte(L)})

	return PrivateKey{new(big.Int).Mod(new(big.Int).SetBytes(okm), bls12381.NewG1().Q())}
}

// KeyFromBytes 反序列化
func KeyFromBytes(keyBytes []byte) PrivateKey {
	return PrivateKey{
		value: new(big.Int).SetBytes(keyBytes),
	}
}
