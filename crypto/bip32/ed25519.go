package bip32

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"errors"

	"git.liebaopay.com/ksrv/keyserver/crypto/ed25519/edwards25519"
	"git.liebaopay.com/ksrv/keyserver/ksrv"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcutil"
	"github.com/btcsuite/btcutil/base58"
)

var (
	//ErrInvalidKey 错误的密钥格式
	ErrInvalidKey = errors.New("invalid key")
	//HDPrivateKeyID key version 填充后可得到edprv
	HDPrivateKeyID = []byte{0x2d, 0x6a, 0x33, 0x76}
	//HDPublicKeyID key version 填充后可得到edpub
	HDPublicKeyID = []byte{0x0d, 0x7d, 0xb4, 0x51}
)

const (
	ed25519PubKeySize          = 32
	ed25519PrivKeySize         = 64
	ed25519PubKeySerializedLen = versionLen + depthLen + parentFpLen + childNumLen + chainCodeLen + ed25519PubKeySize
	ed25519PrivKeySrializedLen = versionLen + depthLen + parentFpLen + childNumLen + chainCodeLen + ed25519PrivKeySize
)

// ExtendedKey25519 houses all the information needed to support a hierarchical
// deterministic extended key.  See the package overview documentation for
// more details on how to use extended keys.
type ExtendedKey25519 struct {
	ExtendedKeyEcc
}

func fieldElement2Bytes(element edwards25519.FieldElement) [32]byte {
	var b32 [32]byte
	edwards25519.FeToBytes(&b32, &element)
	return b32
}

func bytes2FieldElement(bytes []byte) edwards25519.FieldElement {
	var b32 [32]byte
	//小端
	copy(b32[:], bytes)
	var f edwards25519.FieldElement
	edwards25519.FeFromBytes(&f, &b32)
	return f
}

func byte28mul8(x []byte) [32]byte {
	carry := 0
	var out [32]byte
	for i := 0; i < 28; i++ {
		r := (int(x[i]) << 3) + carry
		out[i] = byte(r & 0xff)
		carry = r >> 8
	}
	out[28] = byte(carry & 0xff)
	return out
}

func add256BitsV2(x, y []byte) [32]byte {
	carry := 0
	var out [32]byte
	for i := 0; i < 32; i++ {
		r := int(x[i]) + int(y[i]) + carry
		out[i] = byte(r & 0xff)
		carry = r >> 8
	}
	return out
}

func scalarMultBase(privateKey []byte) []byte {
	var A edwards25519.ExtendedGroupElement
	var private32 [32]byte
	copy(private32[:], privateKey[:])
	edwards25519.GeScalarMultBase(&A, &private32)
	var publicKey32 [32]byte
	A.ToBytes(&publicKey32)

	return publicKey32[:]
}

func (k *ExtendedKey25519) pubKeyBytes() []byte {
	// Just return the key if it's already an extended public key.
	if !k.IsPrivateL {
		k.PubKey = k.KeyB
		return k.KeyB
	}
	// This is a private extended key, so calculate and memoize the public
	// key if needed.
	if len(k.PubKey) == 0 {
		k.PubKey = scalarMultBase(k.KeyB)
	}

	return k.PubKey
}

// Child 求子密钥
func (k *ExtendedKey25519) Child(i uint32) (ExtendedKey, error) {
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

	var zlr []byte
	var childChainCode []byte
	if isChildHardened {
		data := make([]byte, 69)
		copy(data[1:], k.KeyB)
		binary.LittleEndian.PutUint32(data[65:], i)
		data[0] = 0x00
		hmac512 := hmac.New(sha512.New, k.ChainCodeB)
		hmac512.Write(data)
		zlr = hmac512.Sum(nil)

		data[0] = 0x01
		hmac512 = hmac.New(sha512.New, k.ChainCodeB)
		hmac512.Write(data)
		c := hmac512.Sum(nil)
		childChainCode = c[32:]

	} else {
		data := make([]byte, 37)
		copy(data[1:], k.pubKeyBytes())
		binary.LittleEndian.PutUint32(data[33:], i)
		data[0] = 0x02
		hmac512 := hmac.New(sha512.New, k.ChainCodeB)
		hmac512.Write(data)
		zlr = hmac512.Sum(nil)

		data[0] = 0x03
		hmac512 = hmac.New(sha512.New, k.ChainCodeB)
		hmac512.Write(data)
		c := hmac512.Sum(nil)
		childChainCode = c[32:]
	}
	//where ZL is the left 28-byte part of Z,
	//and ZR is the right 32-byte part of Z.
	zl8 := byte28mul8(zlr[:28])
	var isPrivate bool
	var childKey []byte
	if k.IsPrivateL {
		//kl = 8*parse256(Zl) + Kpl
		//If kL is divisible by the base order n, discard the child.
		kl := add256BitsV2(k.KeyB[:32], zl8[:])
		kr := add256BitsV2(k.KeyB[32:], zlr[32:])

		childKey = make([]byte, 64)
		copy(childKey[:32], kl[:])
		copy(childKey[32:], kr[:])

		isPrivate = true
	} else {
		//Ai ← AP +[8ZL]B
		var Ai edwards25519.ProjectiveGroupElement
		var a [32]byte
		a[0] = 1

		var Ap edwards25519.ExtendedGroupElement
		var ap [32]byte
		copy(ap[:], k.KeyB)
		Ap.FromBytes(&ap)
		edwards25519.GeDoubleScalarMultVartime(&Ai, &a, &Ap, &zl8)
		childKey = make([]byte, 32)
		Ai.ToBytes(&a)

		copy(childKey, a[:])
	}

	// The fingerprint of the parent for the derived child is the first 4
	// bytes of the RIPEMD160(SHA256(parentPubKey)).
	parentFP := btcutil.Hash160(k.pubKeyBytes())[:4]
	return NewExtendedKeyExt(ksrv.NewHDSeedRequest_ed25519, k.VersionB, childKey, childChainCode, parentFP, k.Depth8+1, i, isPrivate)
}

// Neuter returns a new extended public key from this extended private key.  The
// same extended key will be returned unaltered if it is already an extended
// public key.
//
// As the name implies, an extended public key does not have access to the
// private key, so it is not capable of signing transactions or deriving
// child extended private keys.  However, it is capable of deriving further
// child extended public keys.
func (k *ExtendedKey25519) Neuter() (ExtendedKey, error) {
	// Already an extended public key.
	if !k.IsPrivateL {
		return k, nil
	}
	// Convert it to an extended public key.  The key for the new extended
	// key will simply be the pubkey of the current extended private key.
	//
	// This is the function N((k,c)) -> (K, c) from [BIP32].
	return NewExtendedKeyExt(ksrv.NewHDSeedRequest_ed25519, HDPublicKeyID, k.pubKeyBytes(), k.ChainCodeB, k.ParentFp, k.Depth8, k.ChildNum, false)
}

// String returns the extended key as a human-readable base58-encoded string.
func (k *ExtendedKey25519) String() string {
	if len(k.KeyB) == 0 {
		return "zeroed extended key"
	}

	// The serialized format is:
	//   version (4) || depth (1) || parent fingerprint (4)) ||
	//   child num (4) || chain code (32) || key data [64 or 32] || checksum (4)
	serializedLen := 4 + 1 + 4 + 4 + 32 + 32
	if k.IsPrivateL {
		serializedLen += 32
	}
	serializedBytes := make([]byte, 0, serializedLen+4)
	serializedBytes = append(serializedBytes, k.VersionB...)
	serializedBytes = append(serializedBytes, k.Depth8)
	serializedBytes = append(serializedBytes, k.ParentFp...)
	serializedBytes = append(serializedBytes, k.ChildNumber()...)
	serializedBytes = append(serializedBytes, k.ChainCodeB...)
	serializedBytes = append(serializedBytes, k.KeyB...)

	checkSum := chainhash.DoubleHashB(serializedBytes)[:4]
	serializedBytes = append(serializedBytes, checkSum...)
	return base58.Encode(serializedBytes)
}

// IsForNet returns whether or not the extended key is associated with the
// passed bitcoin network.
func (k *ExtendedKey25519) IsForNet(net *chaincfg.Params) bool {
	return false
}

// SetNet associates the extended key, and any child keys yet to be derived from
// it, with the passed network.
func (k *ExtendedKey25519) SetNet(net *chaincfg.Params) {
	return
}

// FromString 从字符串反序列化
func (k *ExtendedKey25519) FromString(key string) (*ExtendedKey25519, error) {
	// The base58-decoded extended key must consist of a serialized payload
	// plus an additional 4 bytes for the checksum.
	decoded := base58.Decode(key)
	if len(decoded) != ed25519PubKeySerializedLen+4 && len(decoded) != ed25519PrivKeySrializedLen+4 {
		return nil, ErrInvalidKeyLen
	}

	isPrivate := len(decoded) == ed25519PrivKeySrializedLen+4
	// The serialized format is:
	//   version (4) || depth (1) || parent fingerprint (4)) ||
	//   child num (4) || chain code (32) || key data (64 or 32) || checksum (4)

	// Split the payload and checksum up and ensure the checksum matches.
	payload := decoded[:len(decoded)-4]
	checkSum := decoded[len(decoded)-4:]
	expectedCheckSum := chainhash.DoubleHashB(payload)[:4]
	if !bytes.Equal(checkSum, expectedCheckSum) {
		return nil, ErrBadChecksum
	}

	keyData := payload[45:]
	return newExtendedKeyEd25519(payload[:4], keyData, payload[13:45], payload[5:9], payload[4], binary.BigEndian.Uint32(payload[9:13]), isPrivate)
}

// NewMaster25519 新建25519的Master
func NewMaster25519(seed []byte) (ExtendedKey, error) {
	// 文档里写的32字节，实际应该无所谓
	if len(seed) != 32 {
		return nil, ErrInvalidSeedLen
	}

	// First take the HMAC-SHA512 of the master key and the seed data:
	//   I = HMAC-SHA512(Key = "Bitcoin seed", Data = S)
	hmac512 := hmac.New(sha512.New, masterKey)
	hmac512.Write(seed)
	k := hmac512.Sum(nil)

	// Split "I" into two 32-byte sequences Il and Ir where:
	// If the third highest bit of the last byte of kL is not zero, discard k.
	// 保证在子密钥加上8*Zl后不会因为出现进位造成最高bit为1
	//the lowest 3 bits of the first byte of kL of are cleared,
	k[0] &= 248
	//the highest bit of the last byte is cleared,
	k[31] &= 127 - 32
	//the second highest bit of the last byte is set.
	k[31] |= 64

	hash := sha256.New()
	hash.Write([]byte{0x01})
	hash.Write(seed)
	chainCode := hash.Sum(nil)

	parentFP := []byte{0x00, 0x00, 0x00, 0x00}
	return newExtendedKeyEd25519(HDPrivateKeyID, k, chainCode, parentFP, 0, 0, true)
}

// newExtendedKeyEd25519 新建Ed25519的key
func newExtendedKeyEd25519(version, key, chainCode, parentFP []byte, depth uint8, childNum uint32, isPrivate bool) (*ExtendedKey25519, error) {
	if isPrivate {
		if key[0]&7 != 0 {
			return nil, ErrInvalidKey
		}
		if key[31]&64 == 0 {
			return nil, ErrInvalidKey
		}
		if key[31]&128 != 0 {
			return nil, ErrInvalidKey
		}
	} else {
		var A edwards25519.ExtendedGroupElement
		var publicKeyBytes [32]byte
		copy(publicKeyBytes[:], key)
		if !A.FromBytes(&publicKeyBytes) {
			return nil, ErrInvalidKey
		}
	}

	ret := ExtendedKey25519{}
	ret.KeyB = key
	ret.ChainCodeB = chainCode
	ret.Depth8 = depth
	ret.ParentFp = parentFP
	ret.ChildNum = childNum
	ret.VersionB = version
	ret.IsPrivateL = isPrivate
	ret.AlgID = ksrv.NewHDSeedRequest_ed25519
	ret.pubKeyBytes() //强制更新公钥

	ret.PubKeySize = ed25519PubKeySize
	ret.PriKeySize = ed25519PrivKeySize

	return &ret, nil
}
