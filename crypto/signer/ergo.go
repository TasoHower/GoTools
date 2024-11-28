package signer

import (
	"crypto/rand"
	"encoding/hex"
	"math/big"

	"github.com/ethereum/go-ethereum/crypto/secp256k1"
	"golang.org/x/crypto/blake2b"
)

// HLen 签名第一部分h的长度
const HLen = 24

// SigLen 签名总长度
const SigLen = 56

// KLen 随机数K的长度
const KLen = 32

// GenCommitment 生成签名承诺
func GenCommitment(pk []byte, w []byte) []byte {
	prefix, _ := hex.DecodeString("010027100108cd")
	postfix, _ := hex.DecodeString("73000021")
	return append(append(append(prefix, pk...), postfix...), w...)
}

// MakeBlake2bHash 计算hash
func MakeBlake2bHash(source []byte) *big.Int {
	hash := blake2b.Sum256(source)
	i := new(big.Int).SetBytes(hash[:24])
	return i
}

// ErgoSchnorr 签名算法
// 1. 选择一个随机数k, 令 R = kG
// 2. h = H(msg || R || P)
// 3. s = k + h*privKey
// 4. sig = (h,s)
func ErgoSchnorr(msg, privKey []byte) ([]byte, error) {
	curve := secp256k1.S256()

	k := make([]byte, KLen)
	if _, err := rand.Read(k); err != nil {
		return nil, err
	}

	kBig := new(big.Int).SetBytes(k)
	kBig.Mod(kBig, curve.Params().N)

	Rx, Ry := curve.ScalarBaseMult(kBig.Bytes())
	RBytes := secp256k1.CompressPubkey(Rx, Ry)

	Px, Py := curve.ScalarBaseMult(privKey)
	PBytes := secp256k1.CompressPubkey(Px, Py)

	commitment := GenCommitment(PBytes, RBytes)

	//hash = Hash(PBytes, RBytes, msg)
	hash := MakeBlake2bHash(append(commitment, msg...))

	skBigint := new(big.Int).SetBytes(privKey)

	//s = k + sk*hash
	s := new(big.Int)
	s.Mul(skBigint, hash)
	s.Add(s, kBig)
	s.Mod(s, curve.Params().N)

	sig := make([]byte, SigLen)
	hashBytes := hash.Bytes()
	sBytes := s.Bytes()
	copy(sig[HLen-len(hashBytes):], hashBytes)
	copy(sig[SigLen-len(sBytes):], sBytes)

	return sig, nil
}

// ErgoVerify 验签算法
// 1. h = sig[:24] s = sig[24:]
// 2. Q = -h*P S = s*G
// 3. R' = Q + S = s*G - h*priK*G
// 4. h' = H(msg || R' || P)
// 5. 比较h'和h
func ErgoVerify(pubKey, msg, sig []byte) (bool, error) {
	if len(sig) != SigLen {
		return false, nil
	}

	curve := secp256k1.S256()
	h := new(big.Int).SetBytes(sig[:HLen])
	s := new(big.Int).SetBytes(sig[HLen:])
	pkX, pkY := secp256k1.DecompressPubkey(pubKey)
	hNegative := new(big.Int)
	hNegative.Sub(curve.Params().N, h)
	Qx, Qy := curve.ScalarMult(pkX, pkY, hNegative.Bytes())
	Sx, Sy := curve.ScalarBaseMult(s.Bytes())
	Rx, Ry := curve.Add(Qx, Qy, Sx, Sy)
	RBytes := secp256k1.CompressPubkey(Rx, Ry)
	commitment := GenCommitment(pubKey, RBytes)
	h2 := MakeBlake2bHash(append(commitment, msg...))

	return h2.Cmp(h) == 0, nil
}
