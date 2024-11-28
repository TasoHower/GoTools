package signer

import (
	"encoding/hex"
	"encoding/json"

	"testing"

	"git.liebaopay.com/ksrv/keyserver/crypto/pasta"
)

func TestPastaSchnorrMina(t *testing.T) {
	type args struct {
		p string
		v pasta.TransactionRequest
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{"0", args{
			p: "164244176fddb5d769b7de2027469d027ad428fadcc0c02396e6280142efb718",
			v: pasta.TransactionRequest{
				Fee:         2000000000,
				FeeToken:    1,
				FeePayerPk:  "B62qnzbXmRNo9q32n4SNu2mpB8e7FYYLH8NmaX6oFCBYjjQ8SbD7uzV",
				Nonce:       16,
				ValidUntil:  271828,
				Memo:        "Hello Mina!",
				SourcePk:    "B62qnzbXmRNo9q32n4SNu2mpB8e7FYYLH8NmaX6oFCBYjjQ8SbD7uzV",
				ReceiverPk:  "B62qicipYxyEHu7QjUqS7QvBipTs5CzgkYZZZkPoKVYBu6tnDUcE9Zt",
				TokenID:     1,
				Amount:      1729000000000,
				TokenLocked: false,
				Delegation:  false,
				NetworkID:   0,
			}}, "11a36a8dfe5b857b95a2a7b7b17c62c3ea33411ae6f4eb3a907064aecae353c60794f1d0288322fe3f8bb69d6fabd4fd7c15f8d09f8783b2f087a80407e299af"},
		{"1", args{
			p: "164244176fddb5d769b7de2027469d027ad428fadcc0c02396e6280142efb718",
			v: pasta.TransactionRequest{
				Fee:         2000000000,
				FeeToken:    1,
				FeePayerPk:  "B62qnzbXmRNo9q32n4SNu2mpB8e7FYYLH8NmaX6oFCBYjjQ8SbD7uzV",
				Nonce:       16,
				ValidUntil:  271828,
				Memo:        "Hello Mina!",
				SourcePk:    "B62qnzbXmRNo9q32n4SNu2mpB8e7FYYLH8NmaX6oFCBYjjQ8SbD7uzV",
				ReceiverPk:  "B62qicipYxyEHu7QjUqS7QvBipTs5CzgkYZZZkPoKVYBu6tnDUcE9Zt",
				TokenID:     1,
				Amount:      1729000000000,
				TokenLocked: false,
				Delegation:  false,
				NetworkID:   1,
			}}, "124c592178ed380cdffb11a9f8e1521bf940e39c13f37ba4c55bb4454ea69fba3c3595a55b06dac86261bb8ab97126bf3f7fff70270300cb97ff41401a5ef789"},
		{"2", args{
			p: "1dee867358d4000f1dafa5978341fb515f89eeddbe450bd57df091f1e63d4444",
			v: pasta.TransactionRequest{
				Fee:         2000000000,
				FeeToken:    1,
				FeePayerPk:  "B62qoqiAgERjCjXhofXiD7cMLJSKD8hE8ZtMh4jX5MPNgKB4CFxxm1N",
				Nonce:       0,
				ValidUntil:  1982,
				Memo:        "",
				SourcePk:    "B62qoqiAgERjCjXhofXiD7cMLJSKD8hE8ZtMh4jX5MPNgKB4CFxxm1N",
				ReceiverPk:  "B62qnzbXmRNo9q32n4SNu2mpB8e7FYYLH8NmaX6oFCBYjjQ8SbD7uzV",
				TokenID:     1,
				Amount:      0,
				TokenLocked: false,
				Delegation:  false,
				NetworkID:   0,
			}}, "25bb730a25ce7180b1e5766ff8cc67452631ee46e2d255bccab8662e5f1f0c850a4bb90b3e7399e935fff7f1a06195c6ef89891c0260331b9f381a13e5507a4c"},
		{"3", args{
			p: "1dee867358d4000f1dafa5978341fb515f89eeddbe450bd57df091f1e63d4444",
			v: pasta.TransactionRequest{
				Fee:         2000000000,
				FeeToken:    1,
				FeePayerPk:  "B62qoqiAgERjCjXhofXiD7cMLJSKD8hE8ZtMh4jX5MPNgKB4CFxxm1N",
				Nonce:       0,
				ValidUntil:  1982,
				Memo:        "",
				SourcePk:    "B62qoqiAgERjCjXhofXiD7cMLJSKD8hE8ZtMh4jX5MPNgKB4CFxxm1N",
				ReceiverPk:  "B62qnzbXmRNo9q32n4SNu2mpB8e7FYYLH8NmaX6oFCBYjjQ8SbD7uzV",
				TokenID:     1,
				Amount:      0,
				TokenLocked: false,
				Delegation:  false,
				NetworkID:   1,
			}}, "058ed7fb4e17d9d400acca06fe20ca8efca2af4ac9a3ed279911b0bf93c45eea0e8961519b703c2fd0e431061d8997cac4a7574e622c0675227d27ce2ff357d9"},
	}

	for _, test := range tests {
		priKey, err := hex.DecodeString(test.args.p)
		if err != nil {
			t.Error(err)
		}
		msg, err := json.Marshal(test.args.v)
		if err != nil {
			t.Error(err)
		}

		sig, err := PastaSchnorrMina(msg, priKey)
		if err != nil {
			t.Error(err)
		}
		sigStr := hex.EncodeToString(sig)

		if sigStr != test.want {
			t.Errorf("%s != %s", sigStr, test.want)
		}
	}
}
