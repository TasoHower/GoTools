package bip32

import (
	"crypto/hmac"
	"crypto/sha512"
	"encoding/binary"
	"fmt"
	"math/big"

	"git.liebaopay.com/ksrv/keyserver/crypto/pasta"
	"git.liebaopay.com/ksrv/keyserver/ksrv"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcutil"
)

// ExtendedKeyPasta pasta
type ExtendedKeyPasta struct {
	ExtendedKeyEcc
}

func (k *ExtendedKeyPasta) pubKeyBytes() []byte {
	// Just return the key if it's already an extended public key.
	if !k.IsPrivateL {
		k.PubKey = k.KeyB
		return k.KeyB
	}
	// This is a private extended key, so calculate and memoize the public
	// key if needed.
	if len(k.PubKey) == 0 {
		var key32 [32]byte
		copy(key32[:], k.KeyB)
		priv, err := pasta.ScalarFromBytes(key32)
		if err != nil {
			return nil
		}
		pub, err := pasta.GeneratePubKey(priv)
		if err != nil {
			return nil
		}
		address, err := pasta.SerializeCompressed(pub)
		if err != nil {
			return nil
		}

		k.PubKey = address[:]
	}

	return k.PubKey
}

// Child 求子密钥, 和k1类似
func (k *ExtendedKeyPasta) Child(i uint32) (ExtendedKey, error) {
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
		copy(data, k.pubKeyBytes())
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

	ilNum := new(big.Int).SetBytes(il)
	ilNum = new(big.Int).Mod(ilNum, pasta.GetN())
	if ilNum.Sign() == 0 {
		return nil, ErrInvalidChild
	}

	// 这里都是大端
	il = big2ByteWithModeN(ilNum)

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
		childKey = big2ByteWithModeN(ilNum)
		isPrivate = true
	} else {
		// Case #3.
		// Calculate the corresponding intermediate public key for
		// intermediate private key.
		var il32 [32]byte
		copy(il32[:], il)
		ilScalar, err := pasta.ScalarFromBytes(il32)
		ilPoint, err := pasta.GeneratePubKey(ilScalar)
		if err != nil {
			return nil, err
		}

		var pub33 [33]byte
		copy(pub33[:], k.KeyB)
		pubPoint, err := pasta.DeserializeCompressed(pub33)
		if err != nil {
			return nil, err
		}
		// Add the intermediate public key to the parent public key to
		// derive the final child key.
		//
		// childKey = serP(point(parse256(Il)) + parentKey)
		childPoint, err := pasta.PointAdd(ilPoint, pubPoint)
		if err != nil {
			return nil, err
		}
		child33, err := pasta.SerializeCompressed(childPoint)
		childKey = child33[:]
	}

	// The fingerprint of the parent for the derived child is the first 4
	// bytes of the RIPEMD160(SHA256(parentPubKey)).
	parentFP := btcutil.Hash160(k.pubKeyBytes())[:4]
	return NewExtendedKeyExt(k.Alg(), k.VersionB, childKey, childChainCode, parentFP,
		k.Depth8+1, i, isPrivate)
}

// Neuter returns a new extended public key from this extended private key.  The
// same extended key will be returned unaltered if it is already an extended
// public key.
//
// As the name implies, an extended public key does not have access to the
// private key, so it is not capable of signing transactions or deriving
// child extended private keys.  However, it is capable of deriving further
// child extended public keys.
func (k *ExtendedKeyPasta) Neuter() (ExtendedKey, error) {
	// Already an extended public key.
	if !k.IsPrivateL {
		return k, nil
	}
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

// IsForNet returns whether or not the extended key is associated with the
// passed bitcoin network.
func (k *ExtendedKeyPasta) IsForNet(net *chaincfg.Params) bool {
	return false
}

// SetNet associates the extended key, and any child keys yet to be derived from
// it, with the passed network.
func (k *ExtendedKeyPasta) SetNet(net *chaincfg.Params) {
	return
}

//// ToBytes encodes entends key to bytes
//func (k *ExtendedKeyPasta) ToBytes() []byte {
//	data := make([]byte, 79)
//
//	// bip32 Serialization format ref:
//	// https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#serialization-format
//
//	// 4 byte: version bytes (mainnet: 0x0488B21E public, 0x0488ADE4 private; testnet: 0x043587CF public, 0x04358394 private)
//	copy(data[:4], k.Version())
//	// 1 byte: depth: 0x00 for master nodes, 0x01 for level-1 derived keys, ....
//	data[4] = k.Depth()
//	// 4 bytes: the fingerprint of the parent's key (0x00000000 if master key)
//	copy(data[5:9], k.ParentFP())
//	// 4 bytes: child number. This is ser32(i) for i in xi = xpar/i, with xi the key being serialized. (0x00000000 if master key)
//	copy(data[9:13], k.ChildNumber())
//	// 32 bytes: the chain code
//	copy(data[13:45], k.ChainCode())
//	// 33 bytes: the public key or private key data (serP(K) for public keys, 0x00 || ser256(k) for private keys)
//	if k.IsPrivate() {
//		copy(data[46:78], k.Key())
//	} else {
//		copy(data[45:78], k.Key())
//	}
//
//	var isPrivated byte = 0
//	if k.IsPrivate() {
//		isPrivated = 1
//	}
//	data[78] = isPrivated
//
//	return data
//}

// newExtendedKeyPasta 新建pasta的key
func newExtendedKeyPasta(version, key, chainCode, parentFP []byte, depth uint8,
	childNum uint32, isPrivate bool) (*ExtendedKeyPasta, error) {
	var err error
	if isPrivate {
		key, err = modN(key)
		if err != nil {
			return nil, fmt.Errorf("modN : %s", err.Error())
		}
	}

	ret := ExtendedKeyPasta{}

	ret.KeyB = key
	ret.ChainCodeB = chainCode
	ret.Depth8 = depth
	ret.ParentFp = parentFP
	ret.ChildNum = childNum
	ret.VersionB = version
	ret.IsPrivateL = isPrivate
	ret.AlgID = ksrv.NewHDSeedRequest_pastaSchnorrMina
	ret.pubKeyBytes() //强制更新公钥
	ret.PriKeySize = eccPriKeySize
	ret.PubKeySize = eccPubKeySize

	return &ret, nil
}

func modN(key []byte) ([]byte, error) {
	if len(key) > 33 || len(key) == 33 && key[0] != 00 {
		return nil, ErrInvalidKey
	}
	// 这里对N取模，防止后面出错
	keyNum := new(big.Int).SetBytes(key)
	return big2ByteWithModeN(keyNum), nil
}

func big2ByteWithModeN(keyNum *big.Int) []byte {
	keyNum = new(big.Int).Mod(keyNum, pasta.GetN())
	key1 := keyNum.Bytes()
	ret := make([]byte, 32)

	copy(ret[32-len(key1):], key1)
	return ret
}
