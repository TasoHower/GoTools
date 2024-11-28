package pasta

import (
	"testing"
)

const DefaultTokenID = 1

func TestSign(t *testing.T) {
	type test struct {
		accountNumber string
		prikey        string
		receiver      string
		amount        Currency
		fee           Currency
		nonce         Nonce
		validUntil    GlobalSlot
		memo          string
		delegation    bool
		networkID     uint8
		wantSignature string
	}

	tests := []test{
		{"0", "164244176fddb5d769b7de2027469d027ad428fadcc0c02396e6280142efb718", "B62qicipYxyEHu7QjUqS7QvBipTs5CzgkYZZZkPoKVYBu6tnDUcE9Zt", 1729000000000, 2000000000, 16, 271828, "Hello Mina!", false, 0x00, "11a36a8dfe5b857b95a2a7b7b17c62c3ea33411ae6f4eb3a907064aecae353c60794f1d0288322fe3f8bb69d6fabd4fd7c15f8d09f8783b2f087a80407e299af"},
		{"1", "164244176fddb5d769b7de2027469d027ad428fadcc0c02396e6280142efb718", "B62qicipYxyEHu7QjUqS7QvBipTs5CzgkYZZZkPoKVYBu6tnDUcE9Zt", 1729000000000, 2000000000, 16, 271828, "Hello Mina!", false, 0x01, "124c592178ed380cdffb11a9f8e1521bf940e39c13f37ba4c55bb4454ea69fba3c3595a55b06dac86261bb8ab97126bf3f7fff70270300cb97ff41401a5ef789"},
		{"2", "1dee867358d4000f1dafa5978341fb515f89eeddbe450bd57df091f1e63d4444", "B62qnzbXmRNo9q32n4SNu2mpB8e7FYYLH8NmaX6oFCBYjjQ8SbD7uzV", 0, 2000000000, 0, 1982, "", false, 0x00, "25bb730a25ce7180b1e5766ff8cc67452631ee46e2d255bccab8662e5f1f0c850a4bb90b3e7399e935fff7f1a06195c6ef89891c0260331b9f381a13e5507a4c"},
		{"3", "1dee867358d4000f1dafa5978341fb515f89eeddbe450bd57df091f1e63d4444", "B62qnzbXmRNo9q32n4SNu2mpB8e7FYYLH8NmaX6oFCBYjjQ8SbD7uzV", 0, 2000000000, 0, 1982, "", false, 0x01, "058ed7fb4e17d9d400acca06fe20ca8efca2af4ac9a3ed279911b0bf93c45eea0e8961519b703c2fd0e431061d8997cac4a7574e622c0675227d27ce2ff357d9"},
		{"4", "3414fc16e86e6ac272fda03cf8dcb4d7d47af91b4b726494dab43bf773ce1779", "B62qrKG4Z8hnzZqp1AL8WsQhQYah3quN1qUj3SyfJA8Lw135qWWg1mi", 314159265359, 1618033988, 0, 4294967295, "", false, 0x00, "23a9e2375dd3d0cd061e05c33361e0ba270bf689c4945262abdcc81d7083d8c311ae46b8bebfc98c584e2fb54566851919b58cf0917a256d2c1113daa1ccb27f"},
		{"5", "3414fc16e86e6ac272fda03cf8dcb4d7d47af91b4b726494dab43bf773ce1779", "B62qrKG4Z8hnzZqp1AL8WsQhQYah3quN1qUj3SyfJA8Lw135qWWg1mi", 314159265359, 1618033988, 0, 4294967295, "", false, 0x01, "204eb1a37e56d0255921edd5a7903c210730b289a622d45ed63a52d9e3e461d13dfcf301da98e218563893e6b30fa327600c5ff0788108652a06b970823a4124"},
	}
	for _, test := range tests {
		priKey, err := ScalarFromHex(test.prikey)
		if err != nil {
			t.Error(err)
		}

		pubKey, err := GeneratePubKey(priKey)
		if err != nil {
			t.Error(err)
		}

		pub, err := PointToCompressed(pubKey)
		if err != nil {
			t.Error(err)
		}

		keypair := Keypair{*pubKey, *priKey}
		var tag Tag
		if test.delegation {
			tag[0] = false
			tag[1] = false
			tag[2] = true
		} else {
			tag[0] = false
			tag[1] = false
			tag[2] = false
		}

		receiverPk, err := AddressToCompressed(test.receiver)
		if err != nil {
			t.Error(err)
		}

		memo := new(Memo)
		memo[0] = 1
		if len(test.memo) > 0 {
			memo = PrepareMemo(test.memo)
		}

		tx := Transaction{
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

		sig := Sign(&keypair, &tx, test.networkID)
		sigStr, err := SignatureToHex(sig)
		if err != nil {
			t.Error(err)
		}

		if sigStr != test.wantSignature {
			t.Errorf("%s != %s", sigStr, test.wantSignature)
		}

		ret := Verify(sig, pub, &tx, test.networkID)
		if !ret {
			t.Error("verify failed")
		}
	}
}
