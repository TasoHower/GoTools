//go:build alpine
// +build alpine

package pasta

/*
#cgo CFLAGS: -I./libpasta
#cgo LDFLAGS: -L./libpasta -lpasta
#include "crypto.h"
*/
import "C"
import (
	"encoding/json"
	"unsafe"
)

// Sign mina签名函数
// 输入：
//
//	密钥d：
//	消息m：要签名的消息
//	Network id id：区块链实例标识符
//
// 签署m公钥P = dG：
//
//	让k = derive_nonce(d, P, m, id)
//	让R = [k]G
//
// 如果odd(y(R))那时negate(k)
//
//	e = message_hash(P, x(R), m, id)
//	s = k + e*d
//
// 签名σ = (x(R), s)
func Sign(kp *Keypair, transaction *Transaction, networkID uint8) *Signature {
	var sig Signature
	var (
		kpPointer  = (*C.Keypair)(unsafe.Pointer(kp))
		txPointer  = (*C.Transaction)(unsafe.Pointer(transaction))
		sigPointer = (*C.Signature)(unsafe.Pointer(&sig))
		cNetworkID = (C.uchar)(networkID)
	)
	C.sign(sigPointer, kpPointer, txPointer, cNetworkID)
	return &sig
}

// Verify mina验证签名函数
// 输入：
//
//	公钥P：一个曲线点
//	msg：
//	签名σ:
//	Network id id：区块链实例标识符
//
// 当且仅当下面的算法没有失败时，签名才有效。
//
//		e = message_hash(P, x(R), m, id)
//	 R = [s(σ)]G - [e]P
//	 如果失败infinite(R) OR odd(y(R)) OR x(R) != x(σ)
func Verify(sig *Signature, pub *Compressed, transaction *Transaction, networkID uint8) bool {
	var (
		sigPointer = (*C.Signature)(unsafe.Pointer(sig))
		txPointer  = (*C.Transaction)(unsafe.Pointer(transaction))
		pubPointer = (*C.Compressed)(unsafe.Pointer(pub))
		cNetworkID = (C.uchar)(networkID)
	)
	ret := C.verify(sigPointer, pubPointer, txPointer, cNetworkID)
	return bool(ret)
}

// PrepareMemo 格式化memo
func PrepareMemo(memo string) *Memo {
	var ret Memo
	var (
		//void prepare_memo(uint8_t *out, const char *s)
		memoPointer = (*C.uint8_t)(unsafe.Pointer(&ret[0]))
		sPointer    = (*C.char)(unsafe.Pointer(&[]byte(memo)[0]))
	)
	C.prepare_memo(memoPointer, sPointer)
	return &ret
}

// TransactionFromBytes 反序列化Transaction
func TransactionFromBytes(input []byte) (*Transaction, uint8, error) {
	var request TransactionRequest
	err := json.Unmarshal(input, &request)
	if err != nil {
		return nil, 0, err
	}

	sourcePk, err := AddressToCompressed(request.SourcePk)
	if err != nil {
		return nil, 0, err
	}
	receiverPk, err := AddressToCompressed(request.ReceiverPk)
	if err != nil {
		return nil, 0, err
	}
	feePayerPk, err := AddressToCompressed(request.FeePayerPk)
	if err != nil {
		return nil, 0, err
	}

	tag := Tag{false, false, false}
	if request.Delegation {
		tag[2] = true
	}

	memo := new(Memo)
	memo[0] = 1
	if len(request.Memo) > 0 {
		memo = PrepareMemo(request.Memo)
	}

	tx := Transaction{
		Fee:        request.Fee,
		FeeToken:   request.FeeToken,
		FeePayerPk: *feePayerPk,
		Nonce:      request.Nonce,
		ValidUntil: request.ValidUntil,
		Memo:       *memo,
		//Tag:         tag,
		SourcePk:    *sourcePk,
		ReceiverPk:  *receiverPk,
		TokenID:     request.TokenID,
		Amount:      request.Amount,
		TokenLocked: request.TokenLocked,
	}

	return &tx, request.NetworkID, nil
}
