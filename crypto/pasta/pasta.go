package pasta

/*
#cgo CFLAGS: -I./libpasta
#cgo LDFLAGS: -L./libpasta -lpasta
#include "crypto.h"
#include "pasta_fp.h"
#include "pasta_fq.h"
*/
import "C"
import (
	"encoding/hex"
	"errors"
	"math/big"
	"unsafe"

	"github.com/btcsuite/btcutil/base58"
)

// GenerateKeypair 生成密钥
func GenerateKeypair(account uint32) *Keypair {
	var keypair Keypair
	var (
		keypairPointer = (*C.Keypair)(unsafe.Pointer(&keypair))
		accountC       = (C.uint32_t)(account)
	)

	C.generate_keypair(keypairPointer, accountC)
	return &keypair
}

// GeneratePubKey 私钥计算公钥
func GeneratePubKey(priKey *Scalar) (*Point, error) {
	var pubKey Point
	var (
		pubKeyPointer = (*C.Affine)(unsafe.Pointer(&pubKey))
		scalarPointer = (*C.uint64_t)(unsafe.Pointer(&priKey[0]))
	)
	C.generate_pubkey(pubKeyPointer, scalarPointer)
	return &pubKey, nil
}

// GenerateAddress 由公钥生成地址
func GenerateAddress(pubKey *Point) (string, error) {
	var address [56]byte //55字节地址，最后1字节/0
	var (
		addressPointer = (*C.char)(unsafe.Pointer(&address))
		pubKeyPointer  = (*C.Affine)(unsafe.Pointer(pubKey))
	)
	ret := C.generate_address(addressPointer, 56, pubKeyPointer)
	if !ret {
		errors.New("generate address filed")
	}
	return string(address[:55]), nil
}

// PublicToAddress 33字节 isodd + x大端
func PublicToAddress(pubKey [33]byte) (string, error) {
	var raw [35]byte
	raw[0] = 0x01 // non_zero_curve_point version
	raw[1] = 0x01 // compressed_poly version
	for i := 0; i < 32; i++ {
		raw[2+i] = pubKey[32-i]
	}
	// y-coordinate parity
	raw[34] = pubKey[0]

	return base58.CheckEncode(raw[:], 0xcb), nil
}

// PointToCompressed point转换为压缩格式
func PointToCompressed(pubKey *Point) (*Compressed, error) {
	var ret Compressed
	ret.X = pubKey.X
	ret.IsOdd = FieldIsOdd(pubKey.Y)
	return &ret, nil
}

// SerializeCompressed isOdd+大端
func SerializeCompressed(pubKey *Point) (*[33]byte, error) {
	isOdd := FieldIsOdd(pubKey.Y)
	x, err := FieldToBytes(&pubKey.X)
	if err != nil {
		return nil, err
	}

	var pub [33]byte
	if isOdd {
		pub[0] = 0x01
	}
	copy(pub[1:], x[:])

	return &pub, nil
}

// DeserializeCompressed isOdd+大端
func DeserializeCompressed(pubKey [33]byte) (*Point, error) {
	var compressed Compressed
	if pubKey[0] != 0 && pubKey[0] != 1 {
		return nil, errors.New("invalid pubKey isOdd byte")
	}
	compressed.IsOdd = pubKey[0] == 1
	var b [32]byte
	copy(b[:], pubKey[1:])
	x, err := FieldFromBytes(b)
	if err != nil {
		return nil, err
	}
	compressed.X = *x

	return Decompress(&compressed)
}

// Decompress Compressed转Point
func Decompress(compressed *Compressed) (*Point, error) {
	var point Point
	var (
		pointPointer      = (*C.Affine)(unsafe.Pointer(&point))
		compressedPointer = (*C.Compressed)(unsafe.Pointer(compressed))
	)
	ret := C.decompress(pointPointer, compressedPointer)
	if !ret {
		return nil, errors.New("decompress failed")
	}

	return &point, nil
}

// AddressToCompressed base58check转Compressed
func AddressToCompressed(address string) (*Compressed, error) {
	pub, ver, err := base58.CheckDecode(address)
	if err != nil {
		return nil, err
	}
	if ver != 0xcb {
		return nil, errors.New("invalid ver")
	}
	if 0x01 != pub[0] || 0x01 != pub[1] {
		return nil, errors.New("invalid prefix")
	}
	var ret Compressed
	var b [32]byte
	copy(b[:], pub[2:34])
	field, err := fieldFromBytes(b)
	if err != nil {
		return nil, err
	}
	ret.X = *field
	ret.IsOdd = pub[34] == 0x01

	return &ret, nil
}

// FieldIsOdd 判断奇偶
func FieldIsOdd(y Field) bool {
	var (
		cField = (*C.uint64_t)(&y[0])
	)
	ret := C.field_is_odd(cField)
	return bool(ret)
}

// ScalarFromHex 大端
func ScalarFromHex(hexS string) (*Scalar, error) {
	if len(hexS) != 64 {
		return nil, errors.New("invalid hexS length")
	}
	b, err := hex.DecodeString(hexS)
	if err != nil {
		return nil, err
	}
	var key32 [32]byte
	copy(key32[:], b[:])

	return ScalarFromBytes(key32)
}

// ScalarToHex 大端
func ScalarToHex(scalar *Scalar) (string, error) {
	b, err := ScalarToBytes(scalar)
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(b[:]), nil
}

// SignatureToHex 大端
func SignatureToHex(sig *Signature) (string, error) {
	rx, err := FieldToBytes(&sig.Rx)
	if err != nil {
		return "", err
	}
	s, err := ScalarToBytes(&sig.S)
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(rx[:]) + hex.EncodeToString(s[:]), nil
}

// SignatureFromBytes 大端
func SignatureFromBytes(sig []byte) (*Signature, error) {
	if len(sig) != 64 {
		return nil, errors.New("invalid sign length")
	}
	var rx32 [32]byte
	var s32 [32]byte
	copy(rx32[:], sig[:32])
	copy(s32[:], sig[32:])
	rx, err := FieldFromBytes(rx32)
	if err != nil {
		return nil, err
	}
	s, err := ScalarFromBytes(s32)
	if err != nil {
		return nil, err
	}

	return &Signature{Rx: *rx, S: *s}, nil
}

// ScalarFromBytes bytes转标量 大端
func ScalarFromBytes(b [32]byte) (*Scalar, error) {
	for i := 0; i < 16; i++ {
		tmp := b[i]
		b[i] = b[31-i]
		b[31-i] = tmp
	}

	return scalarFromBytes(b)
}

// scalarFromBytes bytes转标量 小端
func scalarFromBytes(b [32]byte) (*Scalar, error) {
	var scalar Scalar
	hex := hex.EncodeToString(b[:])
	var (
		hexPointer    = (*C.char)(unsafe.Pointer(&[]byte(hex)[0]))
		scalarPointer = (*C.uint64_t)(unsafe.Pointer(&scalar[0]))
	)
	ret := C.scalar_from_hex(scalarPointer, hexPointer)
	if !ret {
		return nil, errors.New("scalar from bytes failed")
	}

	return &scalar, nil
}

// ScalarToBytes 标量转bytes 大端
func ScalarToBytes(scalar *Scalar) ([32]byte, error) {
	var outs [4]uint64
	var (
		scalarPointer = (*C.uint64_t)(unsafe.Pointer(&scalar[0]))
		arg1Pointer   = (*C.uint64_t)(unsafe.Pointer(&outs[0]))
	)
	C.fiat_pasta_fq_from_montgomery(arg1Pointer, scalarPointer)

	var rets [32]byte
	for i, out := range outs {
		rets[i*8+0] = byte(out & 0xFF)
		rets[i*8+1] = byte((out >> 8) & 0xFF)
		rets[i*8+2] = byte((out >> 16) & 0xFF)
		rets[i*8+3] = byte((out >> 24) & 0xFF)
		rets[i*8+4] = byte((out >> 32) & 0xFF)
		rets[i*8+5] = byte((out >> 40) & 0xFF)
		rets[i*8+6] = byte((out >> 48) & 0xFF)
		rets[i*8+7] = byte((out >> 56) & 0xFF)
	}

	for i := 0; i < 16; i++ {
		tmp := rets[i]
		rets[i] = rets[31-i]
		rets[31-i] = tmp
	}
	return rets, nil
}

// FieldFromBytes bytes转field 大端
func FieldFromBytes(b [32]byte) (*Field, error) {
	for i := 0; i < 16; i++ {
		tmp := b[i]
		b[i] = b[31-i]
		b[31-i] = tmp
	}

	return fieldFromBytes(b)
}

// fieldFromBytes bytes转field 小端
func fieldFromBytes(b [32]byte) (*Field, error) {
	var field Field
	hex := hex.EncodeToString(b[:])
	var (
		hexPointer   = (*C.char)(unsafe.Pointer(&[]byte(hex)[0]))
		fieldPointer = (*C.uint64_t)(unsafe.Pointer(&field[0]))
	)
	ret := C.field_from_hex(fieldPointer, hexPointer)
	if !ret {
		return nil, errors.New("scalar from bytes failed")
	}

	return &field, nil
}

// FieldToBytes filed转bytes大端序
func FieldToBytes(field *Field) ([32]byte, error) {
	rets, err := fieldToBytes(field)
	if err != nil {
		return rets, err
	}
	for i := 0; i < 16; i++ {
		tmp := rets[i]
		rets[i] = rets[31-i]
		rets[31-i] = tmp
	}
	return rets, nil
}

// fieldToBytes filed转bytes小端序
func fieldToBytes(field *Field) ([32]byte, error) {
	var outs [4]uint64
	var (
		fieldPointer = (*C.uint64_t)(unsafe.Pointer(&field[0]))
		arg1Pointer  = (*C.uint64_t)(unsafe.Pointer(&outs[0]))
	)
	C.fiat_pasta_fp_from_montgomery(arg1Pointer, fieldPointer)

	var rets [32]byte
	for i, out := range outs {
		rets[i*8+0] = byte(out & 0xFF)
		rets[i*8+1] = byte((out >> 8) & 0xFF)
		rets[i*8+2] = byte((out >> 16) & 0xFF)
		rets[i*8+3] = byte((out >> 24) & 0xFF)
		rets[i*8+4] = byte((out >> 32) & 0xFF)
		rets[i*8+5] = byte((out >> 40) & 0xFF)
		rets[i*8+6] = byte((out >> 48) & 0xFF)
		rets[i*8+7] = byte((out >> 56) & 0xFF)
	}

	return rets, nil
}

// ScalarAdd 模加
func ScalarAdd(a *Scalar, b *Scalar) (*Scalar, error) {
	var c Scalar
	var (
		aPointer = (*C.uint64_t)(unsafe.Pointer(&a[0]))
		bPointer = (*C.uint64_t)(unsafe.Pointer(&b[0]))
		cPointer = (*C.uint64_t)(unsafe.Pointer(&c[0]))
	)
	C.scalar_add(cPointer, aPointer, bPointer)

	return &c, nil
}

// PointAdd 点加
func PointAdd(p *Point, q *Point) (*Point, error) {
	var r Point
	var (
		pPointer = (*C.Affine)(unsafe.Pointer(p))
		qPointer = (*C.Affine)(unsafe.Pointer(q))
		rPointer = (*C.Affine)(unsafe.Pointer(&r))
	)
	C.affine_add(rPointer, pPointer, qPointer)

	return &r, nil
}

// GetN 获取曲线的阶
func GetN() *big.Int {
	//28948022309329048855892746252171976963363056481941647379679742748393362948097
	ret, _ := big.NewInt(0).SetString("28948022309329048855892746252171976963363056481941647379679742748393362948097", 10)
	return ret
}
