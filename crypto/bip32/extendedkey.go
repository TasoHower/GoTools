// Copyright (c) 2014-2016 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package bip32

// References:
//   [BIP32]: BIP0032 - Hierarchical Deterministic Wallets
//   https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha512"
	"errors"
	"fmt"
	"math/big"

	"git.liebaopay.com/ksrv/keyserver/ksrv"

	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/chaincfg"
)

const (
	// RecommendedSeedLen is the recommended length in bytes for a seed
	// to a master node.
	RecommendedSeedLen = 32 // 256 bits

	// HardenedKeyStart is the index at which a hardended key starts.  Each
	// extended key has 2^31 normal child keys and 2^31 hardned child keys.
	// Thus the range for normal child keys is [0, 2^31 - 1] and the range
	// for hardened child keys is [2^31, 2^32 - 1].
	HardenedKeyStart = 0x80000000 // 2^31

	// MinSeedBytes is the minimum number of bytes allowed for a seed to
	// a master node.
	MinSeedBytes = 16 // 128 bits

	// MaxSeedBytes is the maximum number of bytes allowed for a seed to
	// a master node.
	MaxSeedBytes = 64 // 512 bits

	versionLen   = 4
	depthLen     = 1
	parentFpLen  = 4
	childNumLen  = 4
	chainCodeLen = 32

	// maxUint8 is the max positive integer which can be serialized in a uint8
	maxUint8 = 1<<8 - 1
)

var (
	// ErrDeriveHardFromPublic describes an error in which the caller
	// attempted to derive a hardened extended key from a public key.
	ErrDeriveHardFromPublic = errors.New("cannot derive a hardened key " +
		"from a public key")

	// ErrDeriveBeyondMaxDepth describes an error in which the caller
	// has attempted to derive more than 255 keys from a root key.
	ErrDeriveBeyondMaxDepth = errors.New("cannot derive a key with more than " +
		"255 indices in its path")

	// ErrNotPrivExtKey describes an error in which the caller attempted
	// to extract a private key from a public extended key.
	ErrNotPrivExtKey = errors.New("unable to create private keys from a " +
		"public extended key")

	// ErrInvalidChild describes an error in which the child at a specific
	// index is invalid due to the derived key falling outside of the valid
	// range for secp256k1 private keys.  This error indicates the caller
	// should simply ignore the invalid child extended key at this index and
	// increment to the next index.
	ErrInvalidChild = errors.New("the extended key at this index is invalid")

	// ErrUnusableSeed describes an error in which the provided seed is not
	// usable due to the derived key falling outside of the valid range for
	// secp256k1 private keys.  This error indicates the caller must choose
	// another seed.
	ErrUnusableSeed = errors.New("unusable seed")

	// ErrInvalidSeedLen describes an error in which the provided seed or
	// seed length is not in the allowed range.
	ErrInvalidSeedLen = fmt.Errorf("seed length must be between %d and %d "+
		"bits", MinSeedBytes*8, MaxSeedBytes*8)

	// ErrBadChecksum describes an error in which the checksum encoded with
	// a serialized extended key does not match the calculated value.
	ErrBadChecksum = errors.New("bad extended key checksum")

	// ErrInvalidKeyLen describes an error in which the provided serialized
	// key is not the expected length.
	ErrInvalidKeyLen = errors.New("the provided serialized extended key " +
		"length is invalid")

	//ErrInvalidXKey Invalid xkey length
	ErrInvalidXKey = errors.New("Invalid xkey length")
)

// masterKey is the master key used along with a random seed used to generate
// the master node in the hierarchical tree.
var masterKey = []byte("Bitcoin seed")

// ExtendedKey ExtendedKey接口定义
type ExtendedKey interface {
	Alg() ksrv.NewHDSeedRequest_AlgId
	IsPrivate() bool
	Depth() uint8
	ParentFingerprint() uint32
	ParentFP() []byte
	Child(i uint32) (ExtendedKey, error)
	Neuter() (ExtendedKey, error)
	Version() []byte
	ChainCode() []byte
	ChildNumber() []byte
	Key() []byte
	ECPubKey() ([]byte, error)
	ECPrivKey() ([]byte, error)
	ToBytes() []byte
	IsForNet(net *chaincfg.Params) bool
	SetNet(net *chaincfg.Params)
	Zero()
	FromBytes(data []byte) (ExtendedKey, error)
}

// NewExtendedKeyExt returns a new instance of an extended key with the given
// fields.  No error checking is performed here as it's only intended to be a
// convenience method used to create a populated struct. This function should
// only by used by applications that need to create custom ExtendedKeys. All
// other applications should just use NewMaster, Child, or Neuter.
func NewExtendedKeyExt(alg ksrv.NewHDSeedRequest_AlgId, version, key, chainCode, parentFP []byte, depth uint8,
	childNum uint32, isPrivate bool) (ExtendedKey, error) {
	switch alg {
	case ksrv.NewHDSeedRequest_pastaSchnorrMina:
		return newExtendedKeyPasta(version, key, chainCode, parentFP, depth, childNum, isPrivate)
	case ksrv.NewHDSeedRequest_ed25519:
		return newExtendedKeyEd25519(version, key, chainCode, parentFP, depth, childNum, isPrivate)
	case ksrv.NewHDSeedRequest_bls12381:
		return newExtendedKeyBls12381(version, key, chainCode, parentFP, depth, childNum, isPrivate)
	case ksrv.NewHDSeedRequest_Secp256r1:
		return newExtendedKeyP256(version, key, chainCode, parentFP, depth, childNum, isPrivate)
	default:
		return newExtendedKeyEcc(alg, version, key, chainCode, parentFP, depth, childNum, isPrivate)
	}
}

// NewMaster creates a new master node for use in creating a hierarchical
// deterministic key chain.  The seed must be between 128 and 512 bits and
// should be generated by a cryptographically secure random generation source.
//
// NOTE: There is an extremely small chance (< 1 in 2^127) the provided seed
// will derive to an unusable secret key.  The ErrUnusable error will be
// returned if this should occur, so the caller must check for it and generate a
// new seed accordingly.
func NewMaster(alg ksrv.NewHDSeedRequest_AlgId, seed []byte, net *chaincfg.Params) (ExtendedKey, error) {
	if alg == ksrv.NewHDSeedRequest_ed25519 {
		return NewMaster25519(seed)
	}
	// Per [BIP32], the seed must be in range [MinSeedBytes, MaxSeedBytes].
	if len(seed) < MinSeedBytes || len(seed) > MaxSeedBytes {
		return nil, ErrInvalidSeedLen
	}

	// First take the HMAC-SHA512 of the master key and the seed data:
	//   I = HMAC-SHA512(Key = "Bitcoin seed", Data = S)
	hmac512 := hmac.New(sha512.New, masterKey)
	hmac512.Write(seed)
	lr := hmac512.Sum(nil)

	// Split "I" into two 32-byte sequences Il and Ir where:
	//   Il = master secret key
	//   Ir = master chain code
	secretKey := lr[:len(lr)/2]
	chainCode := lr[len(lr)/2:]

	// Ensure the key in usable.
	secretKeyNum := new(big.Int).SetBytes(secretKey)
	if secretKeyNum.Cmp(btcec.S256().N) >= 0 || secretKeyNum.Sign() == 0 {
		return nil, ErrUnusableSeed
	}

	parentFP := []byte{0x00, 0x00, 0x00, 0x00}
	return NewExtendedKeyExt(alg, net.HDPrivateKeyID[:], secretKey, chainCode,
		parentFP, 0, 0, true)
}

// NewMasterByRoot 通过Root获得ExtendedKey
func NewMasterByRoot(alg ksrv.NewHDSeedRequest_AlgId, root []byte) (ExtendedKey, error) {
	var hdPrivateKeyID []byte
	if alg == ksrv.NewHDSeedRequest_ed25519 {
		hdPrivateKeyID = HDPrivateKeyID
	} else {
		hdPrivateKeyID = chaincfg.MainNetParams.HDPrivateKeyID[:]
	}
	parentFP := []byte{0x00, 0x00, 0x00, 0x00}
	return NewExtendedKeyExt(alg, hdPrivateKeyID, root[:len(root)-32], root[len(root)-32:], parentFP, 0, 0, true)
}

// FromBytes decodes bytes to extends key
func FromBytes(alg ksrv.NewHDSeedRequest_AlgId, data []byte) (ret ExtendedKey, err error) {
	switch alg {
	case ksrv.NewHDSeedRequest_ed25519:
		key := ExtendedKey25519{}
		key.PubKeySize = ed25519PubKeySize
		key.PriKeySize = ed25519PrivKeySize
		key.AlgID = alg
		ret = &key
	case ksrv.NewHDSeedRequest_pastaSchnorrMina:
		key := ExtendedKeyPasta{}
		key.PubKeySize = eccPubKeySize
		key.PriKeySize = eccPriKeySize
		key.AlgID = alg
		ret = &key
	case ksrv.NewHDSeedRequest_bls12381:
		key := ExtendedKeyBls12381{}
		key.PubKeySize = blsPubKeySize
		key.PriKeySize = blsPriKeySize
		key.AlgID = alg
		ret = &key
	case ksrv.NewHDSeedRequest_Secp256r1:
		key := ExtendedKeyP256{}
		key.PubKeySize = eccPubKeySize
		key.PriKeySize = eccPriKeySize
		key.AlgID = alg
		ret = &key
	default:
		ret = &ExtendedKeyEcc{AlgID: alg, PubKeySize: eccPubKeySize, PriKeySize: eccPriKeySize}
	}

	ret, err = ret.FromBytes(data)
	if err != nil {
		return nil, err
	}
	return ret, nil
}

// NewKeyFromString returns a new extended key instance from a base58-encoded
// extended key.
func NewKeyFromString(alg ksrv.NewHDSeedRequest_AlgId, key string) (ret ExtendedKey, err error) {
	switch alg {
	case ksrv.NewHDSeedRequest_ed25519:
		result := ExtendedKey25519{}
		ret, err = result.FromString(key)
		if err != nil {
			return nil, err
		}
		return
	case ksrv.NewHDSeedRequest_Secp256k1:
		result := ExtendedKeyEcc{AlgID: alg}
		ret, err = result.FromString(key)
		if err != nil {
			return nil, err
		}
		return
	default:
		return nil, errors.New("up support FromString")
	}
}

// GenerateSeed returns a cryptographically secure random seed that can be used
// as the input for the NewMaster function to generate a new master node.
//
// The length is in bytes and it must be between 16 and 64 (128 to 512 bits).
// The recommended length is 32 (256 bits) as defined by the RecommendedSeedLen
// constant.
func GenerateSeed(length uint8) ([]byte, error) {
	// Per [BIP32], the seed must be in range [MinSeedBytes, MaxSeedBytes].
	if length < MinSeedBytes || length > MaxSeedBytes {
		return nil, ErrInvalidSeedLen
	}

	buf := make([]byte, length)
	_, err := rand.Read(buf)
	if err != nil {
		return nil, err
	}

	return buf, nil
}
