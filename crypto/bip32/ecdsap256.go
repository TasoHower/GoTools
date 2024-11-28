package bip32

import (
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/sha512"
	"encoding/binary"
	"fmt"
	"math/big"

	"git.liebaopay.com/ksrv/keyserver/crypto/p256"
	"git.liebaopay.com/ksrv/keyserver/ksrv"
	"github.com/btcsuite/btcutil"
)

// ExtendedKeyP256 ecdsa算法r1曲线
type ExtendedKeyP256 struct {
	ExtendedKeyEcc
}

const (
	r1PubKeySize = 33
	r1PriKeySize = 33 //沿用k1的方式
)

var (
	//DefaultCurve 默认P256曲线
	DefaultCurve = elliptic.P256()
	//DefaultParams 默认P256曲线参数
	DefaultParams = DefaultCurve.Params()
)

func (k *ExtendedKeyP256) pubKeyBytes() []byte {
	// Just return the key if it's already an extended public key.
	if !k.IsPrivateL {
		k.PubKey = k.KeyB
		return k.KeyB
	}
	// This is a private extended key, so calculate and memoize the public
	// key if needed.
	if len(k.PubKey) == 0 {
		//k.PubKey
		publicKey := p256.PublicKey{}
		publicKey.X, publicKey.Y = DefaultCurve.ScalarBaseMult(k.KeyB)
		k.PubKey, _ = publicKey.EncodePoint(true)
	}

	return k.PubKey
}

// Child 求子密钥
func (k *ExtendedKeyP256) Child(i uint32) (ExtendedKey, error) {
	// Prevent derivation of children beyond the max allowed depth.
	if k.Depth8 == maxUint8 {
		return nil, ErrDeriveBeyondMaxDepth
	}

	// There are four scenarios that could happen here:
	// 1) Private extended key -> Hardened child private extended key
	// 2) Private extended key -> Non-hardened child private extended key
	// 3) Public extended key -> Non-hardened child public extended key
	// 4) Public extended key -> Hardened child public extended key (INVALID!)

	// Case #4 is invalid, so error out early.
	// A hardened child extended key may not be created from a public
	// extended key.
	isChildHardened := i >= HardenedKeyStart
	if !k.IsPrivateL && isChildHardened {
		return nil, ErrDeriveHardFromPublic
	}

	// The data used to derive the child key depends on whether or not the
	// child is hardened per [BIP32].
	//
	// For hardened children:
	//   0x00 || ser256(parentKey) || ser32(i)
	//
	// For normal children:
	//   serP(parentPubKey) || ser32(i)
	keyLen := 33
	data := make([]byte, keyLen+4)
	if isChildHardened {
		// Case #1.
		// When the child is a hardened child, the key is known to be a
		// private key due to the above early return.  Pad it with a
		// leading zero as required by [BIP32] for deriving the child.
		copy(data[1:], k.KeyB)
	} else {
		// Case #2 or #3.
		// This is either a public or private extended key, but in
		// either case, the data which is used to derive the child key
		// starts with the secp256k1 compressed public key bytes.
		copy(data, k.PubKey)
	}
	binary.BigEndian.PutUint32(data[keyLen:], i)

	// Take the HMAC-SHA512 of the current key's chain code and the derived
	// data:
	//   I = HMAC-SHA512(Key = chainCode, Data = data)
	hmac512 := hmac.New(sha512.New, k.ChainCodeB)
	hmac512.Write(data)
	ilr := hmac512.Sum(nil)

	// Split "I" into two 32-byte sequences Il and Ir where:
	//   Il = intermediate key used to derive the child
	//   Ir = child chain code
	il := ilr[:len(ilr)/2]
	childChainCode := ilr[len(ilr)/2:]

	// Both derived public or private keys rely on treating the left 32-byte
	// sequence calculated above (Il) as a 256-bit integer that must be
	// within the valid range for a secp256k1 private key.  There is a small
	// chance (< 1 in 2^127) this condition will not hold, and in that case,
	// a child extended key can't be created for this index and the caller
	// should simply increment to the next index.

	// The algorithm used to derive the child key depends on whether or not
	// a private or public child is being derived.
	//
	// For private children:
	//   childKey = parse256(Il) + parentKey
	//
	// For public children:
	//   childKey = serP(point(parse256(Il)) + parentKey)
	var isPrivate bool
	var childKey []byte
	if k.IsPrivateL {
		// Case #1 or #2.
		// Add the parent private key to the intermediate private key to
		// derive the final child key.
		//
		// childKey = parse256(Il) + parenKey
		keyNum := new(big.Int).SetBytes(k.KeyB)
		ilNum := new(big.Int).SetBytes(il)
		ilNum.Add(ilNum, keyNum)
		childKey = big2ByteWithModeNP256(ilNum)
		isPrivate = true
	} else {
		// Case #3.
		// Calculate the corresponding intermediate public key for
		// intermediate private key.
		ilx, ily := DefaultCurve.ScalarBaseMult(il)
		if ilx.Sign() == 0 || ily.Sign() == 0 {
			return nil, ErrInvalidChild
		}

		// Convert the serialized compressed parent public key into X
		// and Y coordinates so it can be added to the intermediate
		// public key.
		pubKey, err := p256.DecodePoint(k.KeyB, DefaultParams)
		if err != nil {
			return nil, err
		}

		// Add the intermediate public key to the parent public key to
		// derive the final child key.
		//
		// childKey = serP(point(parse256(Il)) + parentKey)
		childX, childY := DefaultCurve.Add(ilx, ily, pubKey.X, pubKey.Y)
		pk := p256.PublicKey{X: childX, Y: childY}
		childKey, _ = pk.EncodePoint(true)
	}

	// The fingerprint of the parent for the derived child is the first 4
	// bytes of the RIPEMD160(SHA256(parentPubKey)).
	parentFP := btcutil.Hash160(k.PubKey)[:4]
	return NewExtendedKeyExt(k.AlgID, k.VersionB, childKey, childChainCode, parentFP, k.Depth8+1, i, isPrivate)
}

// newExtendedKeyP256 新建r1曲线上的key
func newExtendedKeyP256(version, key, chainCode, parentFP []byte, depth uint8,
	childNum uint32, isPrivate bool) (*ExtendedKeyP256, error) {
	var err error
	if isPrivate {
		key, err = modNP256(key)
		if err != nil {
			return nil, fmt.Errorf("modNP256 : %s", err.Error())
		}
	} else {
		_, err = p256.DecodePoint(key, DefaultParams)
		if err != nil {
			return nil, err
		}
	}

	ret := ExtendedKeyP256{}

	ret.KeyB = key
	ret.ChainCodeB = chainCode
	ret.Depth8 = depth
	ret.ParentFp = parentFP
	ret.ChildNum = childNum
	ret.VersionB = version
	ret.IsPrivateL = isPrivate
	ret.AlgID = ksrv.NewHDSeedRequest_Secp256r1
	ret.pubKeyBytes() //强制更新公钥

	ret.PriKeySize = r1PriKeySize
	ret.PubKeySize = r1PubKeySize

	return &ret, nil
}

func modNP256(key []byte) ([]byte, error) {
	if len(key) > 33 || len(key) == 33 && key[0] != 00 {
		return nil, ErrInvalidKey
	}
	// 这里对N取模，防止后面出错
	keyNum := new(big.Int).SetBytes(key)
	return big2ByteWithModeNP256(keyNum), nil
}

func big2ByteWithModeNP256(keyNum *big.Int) []byte {
	keyNum = new(big.Int).Mod(keyNum, elliptic.P256().Params().N)
	key1 := keyNum.Bytes()
	ret := make([]byte, 32)

	copy(ret[32-len(key1):], key1)
	return ret
}
