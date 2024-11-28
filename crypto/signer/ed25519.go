package signer

import (
	"crypto/ed25519"
	"crypto/sha512"
	"errors"

	"git.liebaopay.com/ksrv/keyserver/crypto/ed25519/edwards25519"
)

// Error list
var (
	ErrBadKeyLen = errors.New("ed25519: bad private key length")
)

// toPublic generate the public key associated with an extended secret key
func toPublic(privkey []byte) [32]byte {
	var private32 [32]byte
	var pubkey32 [32]byte
	copy(private32[:], privkey[0:32])
	var A edwards25519.ExtendedGroupElement
	edwards25519.GeScalarMultBase(&A, &private32)
	A.ToBytes(&pubkey32)
	return pubkey32
}

// Ed25519 签名算法
func Ed25519(msg, privkey []byte) (signature []byte, err error) {
	if len(privkey) != ed25519.PrivateKeySize {
		return nil, ErrBadKeyLen
	}
	pubkey := toPublic(privkey)

	h := sha512.New()
	h.Write(privkey[32:])
	h.Write(msg)
	var hashOut [64]byte
	h.Sum(hashOut[:0])
	var nonce [32]byte
	edwards25519.ScReduce(&nonce, &hashOut)

	signature = make([]byte, ed25519.SignatureSize)
	var R edwards25519.ExtendedGroupElement
	edwards25519.GeScalarMultBase(&R, &nonce)
	var encodedR [32]byte
	R.ToBytes(&encodedR)
	copy(signature[:32], encodedR[:])
	copy(signature[32:], pubkey[:])

	h.Reset()
	h.Write(signature)
	h.Write(msg)
	h.Sum(hashOut[:0])
	var digest [32]byte
	edwards25519.ScReduce(&digest, &hashOut)

	var s [32]byte
	var private32 [32]byte
	copy(private32[:], privkey[0:32])
	edwards25519.ScMulAdd(&s, &digest, &private32, &nonce)

	copy(signature[:], encodedR[:])
	copy(signature[32:], s[:])

	return signature, nil
}

// Ed25519Verify 验签算法
func Ed25519Verify(pubkey, msg, sig []byte) bool {
	return ed25519.Verify(pubkey, msg, sig)
}
