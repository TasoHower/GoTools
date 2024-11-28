package signer

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"math/big"
)

// RSA4096LEN RSA私钥长度
const RSA4096LEN = 512

// E 固定使用65537
const E = 65537

// Rsa4096 签名算法
func Rsa4096(hash, privKey []byte) ([]byte, error) {
	//privKey 只包含N,D长度各512byte。这里采用非CRT签名，私钥长度比较短
	if len(privKey) != RSA4096LEN*2 {
		return nil, errors.New("invalid private key length")
	}
	n := privKey[:RSA4096LEN]
	d := privKey[RSA4096LEN:]
	bigN := new(big.Int).SetBytes(n)
	bigD := new(big.Int).SetBytes(d)
	priv := rsa.PrivateKey{D: bigD}
	priv.PublicKey.N = bigN
	priv.PublicKey.E = E

	return rsa.SignPSS(rand.Reader, &priv, crypto.SHA256, hash, &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthAuto,
		Hash:       crypto.SHA256,
	})
}

// Rsa4096Verify 验签算法
func Rsa4096Verify(pubkey, hash, sig []byte) error {
	//privKey 只包含N,D长度各512byte。这里采用非CRT签名，私钥长度比较短
	if len(pubkey) != RSA4096LEN {
		return errors.New("invalid private key length")
	}

	bigN := new(big.Int).SetBytes(pubkey)
	pub := rsa.PublicKey{N: bigN, E: E}

	return rsa.VerifyPSS(&pub, crypto.SHA256, hash, sig, &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthAuto,
		Hash:       crypto.SHA256,
	})
}

// GenRsa4096 生成4096密钥对
func GenRsa4096() ([]byte, []byte, error) {
	prikey, err := rsa.GenerateKey(rand.Reader, RSA4096LEN*8)
	if err != nil {
		return nil, nil, err
	}
	n := prikey.N.Bytes()
	d := prikey.D.Bytes()
	if len(d) < RSA4096LEN {
		temp := make([]byte, RSA4096LEN)
		copy(temp[RSA4096LEN-len(d):], d)
		return n, temp, nil
	}
	return n, d, nil
}
