package main

import (
	"fmt"

	"git.liebaopay.com/ksrv/keyserver/crypto/pasta"
)

// DefaultTokenID 默认token id
const DefaultTokenID = 1

func main() {
	type test struct {
		accountNumber string
		prikey        string
		receiver      string
		amount        pasta.Currency
		fee           pasta.Currency
		nonce         pasta.Nonce
		validUntil    pasta.GlobalSlot
		memo          string
		delegation    bool
		networkID     uint8
		wantSignature string
	}

	tests := []test{{"0", "164244176fddb5d769b7de2027469d027ad428fadcc0c02396e6280142efb718", "B62qicipYxyEHu7QjUqS7QvBipTs5CzgkYZZZkPoKVYBu6tnDUcE9Zt", 1729000000000, 2000000000, 16, 271828, "Hello Mina!", false, 0x00, "11a36a8dfe5b857b95a2a7b7b17c62c3ea33411ae6f4eb3a907064aecae353c60794f1d0288322fe3f8bb69d6fabd4fd7c15f8d09f8783b2f087a80407e299af"}}
	for _, test := range tests {
		priKey, err := pasta.ScalarFromHex(test.prikey)
		if err != nil {
			return
		}

		pubKey, err := pasta.GeneratePubKey(priKey)
		if err != nil {
			return
		}

		pub, err := pasta.PointToCompressed(pubKey)
		if err != nil {
			return
		}

		keypair := pasta.Keypair{PubKey: *pubKey, PriKey: *priKey}
		var tag pasta.Tag
		if test.delegation {
			tag[0] = false
			tag[1] = false
			tag[2] = true
		} else {
			tag[0] = false
			tag[1] = false
			tag[2] = false
		}

		receiverPk, err := pasta.AddressToCompressed(test.receiver)
		if err != nil {
			return
		}

		memo := pasta.PrepareMemo(test.memo)

		tx := pasta.Transaction{
			Fee:         test.fee,
			FeeToken:    DefaultTokenID,
			FeePayerPk:  *pub,
			Nonce:       test.nonce,
			ValidUntil:  test.validUntil,
			Memo:        *memo,
			Tag:         tag,
			SourcePk:    *pub,
			ReceiverPk:  *receiverPk,
			TokenID:     DefaultTokenID,
			Amount:      test.amount,
			TokenLocked: false,
		}

		sig := pasta.Sign(&keypair, &tx, test.networkID)
		sigS, err := pasta.SignatureToHex(sig)
		if err != nil {
			panic(err)
		}

		fmt.Println(sigS)
	}
}
