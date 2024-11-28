// Copyright (c) 2014-2016 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package bip32

// References:
//   [BIP32]: BIP0032 - Hierarchical Deterministic Wallets
//   https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"

	"git.liebaopay.com/ksrv/keyserver/ksrv"

	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcutil"
	"github.com/btcsuite/btcutil/base58"
)

const (
	eccPubKeySize = 33
	eccPriKeySize = 33
)

// ExtendedKeyEcc houses all the information needed to support a hierarchical
// deterministic extended key.  See the package overview documentation for
// more details on how to use extended keys.
// ExtendedKeyEcc 是普通ecc的bip32规范
type ExtendedKeyEcc struct {
	AlgID      ksrv.NewHDSeedRequest_AlgId
	KeyB       []byte // This will be the pubkey for extended pub keys
	PubKey     []byte // This will only be set for extended priv keys
	ChainCodeB []byte
	Depth8     uint8
	ParentFp   []byte
	ChildNum   uint32
	VersionB   []byte
	IsPrivateL bool
	PubKeySize int //公钥占用长度，序列化反序列化时使用；
	PriKeySize int //私钥占用长度，序列化反序列化时使用；k1私钥32字节，但是占用33字节
}

// pubKeyBytes returns bytes for the serialized compressed public key associated
// with this extended key in an efficient manner including memoization as
// necessary.
//
// When the extended key is already a public key, the key is simply returned as
// is since it's already in the correct form.  However, when the extended key is
// a private key, the public key will be calculated and memoized so future
// accesses can simply return the cached result.
func (k *ExtendedKeyEcc) pubKeyBytes() []byte {
	// Just return the key if it's already an extended public key.
	if !k.IsPrivateL {
		k.PubKey = k.KeyB
		return k.PubKey
	}

	// This is a private extended key, so calculate and memoize the public
	// key if needed.
	if len(k.PubKey) == 0 {
		pkx, pky := btcec.S256().ScalarBaseMult(k.KeyB)
		pubKey := btcec.PublicKey{Curve: btcec.S256(), X: pkx, Y: pky}
		k.PubKey = pubKey.SerializeCompressed()
	}

	return k.PubKey
}

// Alg 算法ID
func (k *ExtendedKeyEcc) Alg() ksrv.NewHDSeedRequest_AlgId {
	return k.AlgID
}

// IsPrivate returns whether or not the extended key is a private extended key.
//
// A private extended key can be used to derive both hardened and non-hardened
// child private and public extended keys.  A public extended key can only be
// used to derive non-hardened child public extended keys.
func (k *ExtendedKeyEcc) IsPrivate() bool {
	return k.IsPrivateL
}

// Depth returns the current derivation level with respect to the root.
//
// The root key has depth zero, and the field has a maximum of 255 due to
// how depth is serialized.
func (k *ExtendedKeyEcc) Depth() uint8 {
	return k.Depth8
}

// ParentFingerprint returns a fingerprint of the parent extended key from which
// this one was derived.
func (k *ExtendedKeyEcc) ParentFingerprint() uint32 {
	return binary.BigEndian.Uint32(k.ParentFp)
}

// Child returns a derived child extended key at the given index.  When this
// extended key is a private extended key (as determined by the IsPrivate
// function), a private extended key will be derived.  Otherwise, the derived
// extended key will be also be a public extended key.
//
// When the index is greater to or equal than the HardenedKeyStart constant, the
// derived extended key will be a hardened extended key.  It is only possible to
// derive a hardended extended key from a private extended key.  Consequently,
// this function will return ErrDeriveHardFromPublic if a hardened child
// extended key is requested from a public extended key.
//
// A hardened extended key is useful since, as previously mentioned, it requires
// a parent private extended key to derive.  In other words, normal child
// extended public keys can be derived from a parent public extended key (no
// knowledge of the parent private key) whereas hardened extended keys may not
// be.
//
// NOTE: There is an extremely small chance (< 1 in 2^127) the specific child
// index does not derive to a usable child.  The ErrInvalidChild error will be
// returned if this should occur, and the caller is expected to ignore the
// invalid child and simply increment to the next index.
func (k *ExtendedKeyEcc) Child(i uint32) (ExtendedKey, error) {
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
	ilNum := new(big.Int).SetBytes(il)
	if ilNum.Cmp(btcec.S256().N) >= 0 || ilNum.Sign() == 0 {
		return nil, ErrInvalidChild
	}

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
		ilNum.Add(ilNum, keyNum)
		//ilNum.Mod(ilNum, btcec.S256().N)
		//childKey = ilNum.Bytes()
		childKey = big2ByteWithModeNEcc(ilNum)
		isPrivate = true
	} else {
		// Case #3.
		// Calculate the corresponding intermediate public key for
		// intermediate private key.
		ilx, ily := btcec.S256().ScalarBaseMult(il)
		if ilx.Sign() == 0 || ily.Sign() == 0 {
			return nil, ErrInvalidChild
		}

		// Convert the serialized compressed parent public key into X
		// and Y coordinates so it can be added to the intermediate
		// public key.
		pubKey, err := btcec.ParsePubKey(k.KeyB, btcec.S256())
		if err != nil {
			return nil, err
		}

		// Add the intermediate public key to the parent public key to
		// derive the final child key.
		//
		// childKey = serP(point(parse256(Il)) + parentKey)
		childX, childY := btcec.S256().Add(ilx, ily, pubKey.X, pubKey.Y)
		pk := btcec.PublicKey{Curve: btcec.S256(), X: childX, Y: childY}
		childKey = pk.SerializeCompressed()
	}

	// The fingerprint of the parent for the derived child is the first 4
	// bytes of the RIPEMD160(SHA256(parentPubKey)).
	parentFP := btcutil.Hash160(k.PubKey)[:4]
	return NewExtendedKeyExt(k.AlgID, k.VersionB, childKey, childChainCode, parentFP, k.Depth8+1, i, isPrivate)
}

// Neuter returns a new extended public key from this extended private key.  The
// same extended key will be returned unaltered if it is already an extended
// public key.
//
// As the name implies, an extended public key does not have access to the
// private key, so it is not capable of signing transactions or deriving
// child extended private keys.  However, it is capable of deriving further
// child extended public keys.
func (k *ExtendedKeyEcc) Neuter() (ExtendedKey, error) {
	// Already an extended public key.
	if !k.IsPrivateL {
		return k, nil
	}

	// Get the associated public extended key version bytes.
	version, err := chaincfg.HDPrivateKeyToPublicKeyID(k.VersionB)
	if err != nil {
		return nil, err
	}

	// Convert it to an extended public key.  The key for the new extended
	// key will simply be the pubkey of the current extended private key.
	//
	// This is the function N((k,c)) -> (K, c) from [BIP32].
	return NewExtendedKeyExt(k.AlgID, version, k.PubKey, k.ChainCodeB, k.ParentFp, k.Depth8, k.ChildNum, false)
}

// Version returns extends version
func (k *ExtendedKeyEcc) Version() []byte {
	return k.VersionB
}

// ChainCode returns extends chain code
func (k *ExtendedKeyEcc) ChainCode() []byte {
	return k.ChainCodeB
}

// ChildNumber returns extends key child number
func (k *ExtendedKeyEcc) ChildNumber() []byte {
	data := make([]byte, 4)
	binary.BigEndian.PutUint32(data, k.ChildNum)
	return data
}

// ParentFP returns a fingerprint of the parent
func (k *ExtendedKeyEcc) ParentFP() []byte {
	return k.ParentFp
}

// Key returns extends key
func (k *ExtendedKeyEcc) Key() []byte {
	return k.KeyB
}

// ECPubKey converts the extended key to a btcec public key and returns it.
func (k *ExtendedKeyEcc) ECPubKey() ([]byte, error) {
	if len(k.PubKey) == 0 {
		return nil, errors.New("pubkey string is empty")
	}
	return k.PubKey, nil
}

// ECPrivKey converts the extended key to a btcec private key and returns it.
// As you might imagine this is only possible if the extended key is a private
// extended key (as determined by the IsPrivate function).  The ErrNotPrivExtKey
// error will be returned if this function is called on a public extended key.
func (k *ExtendedKeyEcc) ECPrivKey() ([]byte, error) {
	if !k.IsPrivateL {
		return nil, ErrNotPrivExtKey
	}
	return k.KeyB, nil
}

// Address converts the extended key to a standard bitcoin pay-to-pubkey-hash
// address for the passed network.
func (k *ExtendedKeyEcc) Address(net *chaincfg.Params) (*btcutil.AddressPubKeyHash, error) {
	pkHash := btcutil.Hash160(k.PubKey)
	return btcutil.NewAddressPubKeyHash(pkHash, net)
}

// paddedAppend appends the src byte slice to dst, returning the new slice.
// If the length of the source is smaller than the passed size, leading zero
// bytes are appended to the dst slice before appending src.
func paddedAppend(size uint, dst, src []byte) []byte {
	for i := 0; i < int(size)-len(src); i++ {
		dst = append(dst, 0)
	}
	return append(dst, src...)
}

// String returns the extended key as a human-readable base58-encoded string.
func (k *ExtendedKeyEcc) String() string {
	if len(k.KeyB) == 0 {
		return "zeroed extended key"
	}

	// The serialized format is:
	//   version (4) || depth (1) || parent fingerprint (4)) ||
	//   child num (4) || chain code (32) || key data (33) || checksum (4)
	serializedBytes := k.ToBytes()
	serializedBytes = serializedBytes[:len(serializedBytes)-1]
	checkSum := chainhash.DoubleHashB(serializedBytes)[:4]
	serializedBytes = append(serializedBytes, checkSum...)
	return base58.Encode(serializedBytes)
}

// IsForNet returns whether or not the extended key is associated with the
// passed bitcoin network.
func (k *ExtendedKeyEcc) IsForNet(net *chaincfg.Params) bool {
	return bytes.Equal(k.VersionB, net.HDPrivateKeyID[:]) ||
		bytes.Equal(k.VersionB, net.HDPublicKeyID[:])
}

// SetNet associates the extended key, and any child keys yet to be derived from
// it, with the passed network.
func (k *ExtendedKeyEcc) SetNet(net *chaincfg.Params) {
	if k.IsPrivateL {
		k.VersionB = net.HDPrivateKeyID[:]
	} else {
		k.VersionB = net.HDPublicKeyID[:]
	}
}

// zero sets all bytes in the passed slice to zero.  This is used to
// explicitly clear private key material from memory.
func zero(b []byte) {
	lenb := len(b)
	for i := 0; i < lenb; i++ {
		b[i] = 0
	}
}

// Zero manually clears all fields and bytes in the extended key.  This can be
// used to explicitly clear key material from memory for enhanced security
// against memory scraping.  This function only clears this particular key and
// not any children that have already been derived.
func (k *ExtendedKeyEcc) Zero() {
	zero(k.KeyB)
	zero(k.PubKey)
	zero(k.ChainCodeB)
	zero(k.ParentFp)

	k.PubKey = nil
	k.VersionB = nil
	k.KeyB = nil
	k.Depth8 = 0
	k.ChildNum = 0
	k.IsPrivateL = false
}

// ToBytes encodes entends key to bytes
func (k *ExtendedKeyEcc) ToBytes() []byte {
	var keySize int
	if k.IsPrivateL {
		keySize = k.PriKeySize
	} else {
		keySize = k.PubKeySize
	}
	data := make([]byte, versionLen+depthLen+parentFpLen+childNumLen+chainCodeLen+keySize+1)
	// 4 byte: version bytes (mainnet: 0x0488B21E public, 0x0488ADE4 private; testnet: 0x043587CF public, 0x04358394 private)
	copy(data[:4], k.Version())
	// 1 byte: depth: 0x00 for master nodes, 0x01 for level-1 derived keys, ....
	data[4] = k.Depth()
	// 4 bytes: the fingerprint of the parent's key (0x00000000 if master key)
	copy(data[5:9], k.ParentFP())
	// 4 bytes: child number. This is ser32(i) for i in xi = xpar/i, with xi the key being serialized. (0x00000000 if master key)
	copy(data[9:13], k.ChildNumber())
	// 32 bytes: the chain code
	copy(data[13:45], k.ChainCode())
	// 33 bytes: the public key or private key data (serP(K) for public keys, 0x00 || ser256(k) for private keys)
	copy(data[45+int(keySize)-len(k.KeyB):45+keySize], k.Key())
	var isPrivated byte = 0
	if k.IsPrivate() {
		isPrivated = 1
	}
	data[45+keySize] = isPrivated

	return data
}

// FromBytes 从bytes还原ecc key
func (k *ExtendedKeyEcc) FromBytes(data []byte) (ExtendedKey, error) {
	if len(data) != 45+k.PubKeySize+1 && len(data) != 45+k.PriKeySize+1 {
		return nil, ErrInvalidXKey
	}

	serializedKeyLen := len(data) - 1
	var key []byte
	var isPrivate = data[serializedKeyLen] == 1

	key = data[45:serializedKeyLen]

	return NewExtendedKeyExt(k.AlgID, data[:4], key, data[13:45], data[5:9], data[4], binary.BigEndian.Uint32(data[9:13]), isPrivate)
}

// FromString 从字符串反序列化
func (k *ExtendedKeyEcc) FromString(key string) (ExtendedKey, error) {

	// The base58-decoded extended key must consist of a serialized payload
	// plus an additional 4 bytes for the checksum.
	decoded := base58.Decode(key)
	if len(decoded) != 82 {
		return nil, ErrInvalidXKey
	}

	// The serialized format is:
	//   version (4) || depth (1) || parent fingerprint (4)) ||
	//   child num (4) || chain code (32) || key data (33) || checksum (4)

	// Split the payload and checksum up and ensure the checksum matches.
	payload := decoded[:len(decoded)-4]
	checkSum := decoded[len(decoded)-4:]
	expectedCheckSum := chainhash.DoubleHashB(payload)[:4]
	if !bytes.Equal(checkSum, expectedCheckSum) {
		return nil, ErrBadChecksum
	}

	keyData := payload[45:78]

	// The key data is a private key if it starts with 0x00.  Serialized
	// compressed pubkeys either start with 0x02 or 0x03.
	isPrivate := keyData[0] == 0x00

	return NewExtendedKeyExt(k.AlgID, payload[:4], keyData, payload[13:45], payload[5:9], payload[4], binary.BigEndian.Uint32(payload[9:13]), isPrivate)
}

// newExtendedKeyEcc 新建k1曲线上的key
func newExtendedKeyEcc(alg ksrv.NewHDSeedRequest_AlgId, version, key, chainCode, parentFP []byte, depth uint8,
	childNum uint32, isPrivate bool) (*ExtendedKeyEcc, error) {
	var err error
	if isPrivate {
		key, err = modNEcc(key)
		if err != nil {
			return nil, fmt.Errorf("modNEcc : %s", err.Error())
		}
	} else {
		// Ensure the public key parses correctly and is actually on the
		// secp256k1 curve.
		_, err := btcec.ParsePubKey(key, btcec.S256())
		if err != nil {
			return nil, err
		}
	}

	ret := ExtendedKeyEcc{}

	ret.KeyB = key
	ret.ChainCodeB = chainCode
	ret.Depth8 = depth
	ret.ParentFp = parentFP
	ret.ChildNum = childNum
	ret.VersionB = version
	ret.IsPrivateL = isPrivate
	ret.AlgID = alg
	ret.pubKeyBytes() //强制更新公钥

	ret.PriKeySize = eccPriKeySize
	ret.PubKeySize = eccPubKeySize

	return &ret, nil
}

func modNEcc(key []byte) ([]byte, error) {
	if len(key) > 33 || len(key) == 33 && key[0] != 00 {
		return nil, ErrInvalidKey
	}
	// 这里对N取模，防止后面出错
	keyNum := new(big.Int).SetBytes(key)
	return big2ByteWithModeNEcc(keyNum), nil
}

func big2ByteWithModeNEcc(keyNum *big.Int) []byte {
	keyNum = new(big.Int).Mod(keyNum, btcec.S256().N)
	key1 := keyNum.Bytes()
	ret := make([]byte, 32)

	copy(ret[32-len(key1):], key1)
	return ret
}
