package p256

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
)

var (
	//DefaultCurve 默认曲线
	DefaultCurve = elliptic.P256()
	//DefaultParams 默认曲线参数
	DefaultParams = DefaultCurve.Params()
)

const (
	//SignerLength r、s的长度
	SignerLength = 32
	//SignatureLength 签名结果的长度
	SignatureLength = 64
)

// Sign 签名函数
func Sign(priKey []byte, hash []byte) ([]byte, error) {
	if len(hash) != 32 {
		return nil, errors.New("invalid message length, need 32 bytes")
	}

	privateKey := new(ecdsa.PrivateKey)
	privateKey.Curve = DefaultCurve
	privateKey.D = big.NewInt(0)
	privateKey.D.SetBytes(priKey)

	r, s, err := ecdsa.Sign(rand.Reader, privateKey, hash)
	if err != nil {
		return nil, err
	}

	signature := make([]byte, SignatureLength)

	lenR := len(r.Bytes())
	lenS := len(s.Bytes())
	copy(signature[SignerLength-lenR:], r.Bytes())
	copy(signature[SignatureLength-lenS:], s.Bytes())
	return signature, nil
}

// Verify 验签函数
func Verify(pubkey, hash []byte, signature []byte) error {
	if len(hash) != 32 {
		return errors.New("invalid message length, need 32 bytes")
	}
	len := len(signature)
	if len != SignatureLength {
		fmt.Printf("Unknown signature length %d\n", len)
		return errors.New("Unknown signature length")
	}

	r := new(big.Int).SetBytes(signature[:len/2])
	s := new(big.Int).SetBytes(signature[len/2:])

	publicKey, err := DecodePoint(pubkey, DefaultParams)
	if err != nil {
		return fmt.Errorf("invalid pubkey : %s", err.Error())
	}

	pub := ecdsa.PublicKey{}
	pub.Curve = DefaultCurve
	pub.X = publicKey.X
	pub.Y = publicKey.Y

	if !ecdsa.Verify(&pub, hash, r, s) {
		return errors.New("verify failed")
	}

	return nil
}
