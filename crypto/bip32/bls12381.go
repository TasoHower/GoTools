package bip32

import (
	"crypto/hmac"
	"crypto/sha512"
	"encoding/binary"
	"fmt"
	"math/big"

	"git.liebaopay.com/ksrv/keyserver/crypto/bls"
	"git.liebaopay.com/ksrv/keyserver/ksrv"
	"github.com/btcsuite/btcutil"
	bls12381 "github.com/kilic/bls12-381"
)

const (
	blsPubKeySize = 48
	blsPriKeySize = 32
)

// ExtendedKeyBls12381 bls签名算法
type ExtendedKeyBls12381 struct {
	ExtendedKeyEcc
}

func (k *ExtendedKeyBls12381) pubKeyBytes() []byte {
	// Just return the key if it's already an extended public key.
	if !k.IsPrivateL {
		k.PubKey = k.KeyB
		return k.PubKey
	}

	// This is a private extended key, so calculate and memoize the public
	// key if needed.
	if len(k.PubKey) == 0 {
		priK := bls.KeyFromBytes(k.KeyB)
		pubK := priK.GetPublicKey()
		k.PubKey = pubK.Bytes()
	}

	return k.PubKey
}

// Child 生成子密钥
func (k *ExtendedKeyBls12381) Child(i uint32) (ExtendedKey, error) {
	if k.Depth8 == maxUint8 {
		return nil, ErrDeriveBeyondMaxDepth
	}

	// HardenedKeyStart 不能用公钥分散子密钥
	isChildHardened := i >= HardenedKeyStart
	if !k.IsPrivateL && isChildHardened {
		return nil, ErrDeriveHardFromPublic
	}

	var data []byte
	if isChildHardened {
		data = append(k.KeyB)
	} else {
		data = append(k.PubKey)
	}
	var childNum [4]byte
	binary.BigEndian.PutUint32(childNum[:], i)

	data = append(data, childNum[:]...)

	// Take the HMAC-SHA512 of the current key's chain code and the derived
	// data:
	//   I = HMAC-SHA512(Key = chainCode, Data = data)
	hmac512 := hmac.New(sha512.New, k.ChainCodeB)
	hmac512.Write(data)
	ilr := hmac512.Sum(nil)

	il := ilr[:len(ilr)/2]
	childChainCode := ilr[len(ilr)/2:]

	ilNum := new(big.Int).SetBytes(il)

	// For private children:
	//   childKey = parse256(Il) + parentKey
	// For public children:
	//   childKey = serP(point(parse256(Il)) + parentKey)
	var isPrivate bool
	var childKey []byte
	if k.IsPrivateL {
		// childKey = parse256(Il) + parenKey
		keyNum := new(big.Int).SetBytes(k.KeyB)
		ilNum.Add(ilNum, keyNum)
		childKey = big2ByteWithModeNBls(ilNum)
		isPrivate = true
	} else {
		priK := bls.KeyFromBytes(il)
		pubIL := priK.GetPublicKey()

		parentPubKey, err := bls.NewPublicKey(k.KeyB)
		if err != nil {
			return nil, fmt.Errorf("bls.NewPublicKey : %s", err.Error())
		}
		pk := pubIL.Add(parentPubKey)
		childKey = pk.Bytes()
	}

	// The fingerprint of the parent for the derived child is the first 4
	// bytes of the RIPEMD160(SHA256(parentPubKey)).
	parentFP := btcutil.Hash160(k.PubKey)[:4]
	return NewExtendedKeyExt(k.AlgID, k.VersionB, childKey, childChainCode, parentFP, k.Depth8+1, i, isPrivate)
}

// newExtendedKeyBls12381 新建Bls的key
func newExtendedKeyBls12381(version, key, chainCode, parentFP []byte, depth uint8, childNum uint32, isPrivate bool) (*ExtendedKeyBls12381, error) {
	var err error
	if isPrivate {
		key, err = modNBls(key)
		if err != nil {
			return nil, fmt.Errorf("modNBls : %s", err.Error())
		}
	}
	ret := ExtendedKeyBls12381{}

	ret.KeyB = key
	ret.ChainCodeB = chainCode
	ret.Depth8 = depth
	ret.ParentFp = parentFP
	ret.ChildNum = childNum
	ret.VersionB = version
	ret.IsPrivateL = isPrivate
	ret.AlgID = ksrv.NewHDSeedRequest_bls12381
	ret.pubKeyBytes() //强制更新公钥

	ret.PriKeySize = blsPriKeySize
	ret.PubKeySize = blsPubKeySize
	return &ret, nil
}

func modNBls(key []byte) ([]byte, error) {
	if len(key) > blsPriKeySize {
		return nil, ErrInvalidKey
	}
	// 这里对N取模，防止后面出错
	keyNum := new(big.Int).SetBytes(key)
	return big2ByteWithModeNBls(keyNum), nil
}

func big2ByteWithModeNBls(keyNum *big.Int) []byte {
	keyNum = new(big.Int).Mod(keyNum, bls12381.NewG1().Q())

	key1 := keyNum.Bytes()
	ret := make([]byte, blsPriKeySize)

	copy(ret[blsPriKeySize-len(key1):], key1)
	return ret
}
