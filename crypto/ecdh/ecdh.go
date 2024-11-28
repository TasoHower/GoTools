package ecdh

import (
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"io"
)

// ErrInvlidPeerPub 非法的对手公钥，公钥不是非压缩格式或者不在曲线之上
var ErrInvlidPeerPub = errors.New("Pubkey of prime256v1 isn't uncompressed or not on curve")

// KeyExchange 迪菲赫尔曼密钥交换
type KeyExchange interface {
	// 生成新的公私钥对，公钥格式非压缩（65字节）
	// 如果 random == nil 则使用 rand.Reader
	GenerateKey(random io.Reader) (priv, pubkey []byte, err error)
	// 使用各自的私钥与对方的公钥生成会话加密密钥，公钥需要非压缩格式（65字节）
	ComputeSecret(selfPriv, otherPublicKey []byte) ([]byte, error)
}

type ecdh struct {
	curve elliptic.Curve
}

// Create 创建椭圆曲线迪菲赫尔曼密钥交换函数
// 默认使用 secp256r1(prime256v1)
func Create(curve elliptic.Curve) KeyExchange {
	if curve == nil {
		curve = elliptic.P256()
	}
	return &ecdh{curve}
}

func (dh *ecdh) GenerateKey(random io.Reader) (priv, pubkey []byte, err error) {
	if random == nil {
		random = rand.Reader
	}
	priv, x, y, err := elliptic.GenerateKey(dh.curve, random)
	pubkey = elliptic.Marshal(dh.curve, x, y)
	return
}

func (dh *ecdh) ComputeSecret(selfPriv, otherPublicKey []byte) ([]byte, error) {
	x, y := elliptic.Unmarshal(dh.curve, otherPublicKey)
	if x == nil || y == nil {
		return nil, ErrInvlidPeerPub
	}
	sX, _ := dh.curve.ScalarMult(x, y, selfPriv)
	return sX.Bytes(), nil
}
