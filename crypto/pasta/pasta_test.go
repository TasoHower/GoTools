package pasta

import (
	"encoding/hex"
	"fmt"
	"math/big"
	"reflect"
	"testing"

	"github.com/btcsuite/btcutil/base58"
)

func TestGenerateKey(t *testing.T) {
	keypair := GenerateKeypair(1)
	fmt.Println("X", keypair.PubKey.X[:])
	fmt.Println("Y", keypair.PubKey.Y[:])
	fmt.Println("Y is odd ? ", FieldIsOdd(keypair.PubKey.Y))
	fmt.Println("D", keypair.PriKey[:])

	pubKey, err := GeneratePubKey(&keypair.PriKey)
	if err != nil {
		t.Error(err)
	}

	if !reflect.DeepEqual(keypair.PubKey.X, pubKey.X) || !reflect.DeepEqual(keypair.PubKey.Y, pubKey.Y) {
		t.Errorf("pubKey not equal keypair.PubKey")
	}

	b, err := ScalarToBytes(&keypair.PriKey)
	if err != nil {
		t.Error(err)
	}

	scalar, err := ScalarFromBytes(b)
	if err != nil {
		t.Error(err)
	}

	if !reflect.DeepEqual(scalar, &keypair.PriKey) {
		t.Errorf("scalar not equal keypair.PriKey")
	}

	xb, err := FieldToBytes(&keypair.PubKey.X)
	if err != nil {
		t.Error(err)
	}
	yb, err := FieldToBytes(&keypair.PubKey.Y)
	if err != nil {
		t.Error(err)
	}
	xField, err := FieldFromBytes(xb)
	if err != nil {
		t.Error(err)
	}
	yField, err := FieldFromBytes(yb)
	if err != nil {
		t.Error(err)
	}
	if !reflect.DeepEqual(xField, &keypair.PubKey.X) {
		t.Errorf("scalar not equal keypair.PriKey")
	}
	if !reflect.DeepEqual(yField, &keypair.PubKey.Y) {
		t.Errorf("scalar not equal keypair.PriKey")
	}
}

func TestGenerateAddress(t *testing.T) {
	type test struct {
		prikey      string
		wantAddress string
	}
	tests := []test{{prikey: "164244176fddb5d769b7de2027469d027ad428fadcc0c02396e6280142efb718", wantAddress: "B62qnzbXmRNo9q32n4SNu2mpB8e7FYYLH8NmaX6oFCBYjjQ8SbD7uzV"},
		{prikey: "3ca187a58f09da346844964310c7e0dd948a9105702b716f4d732e042e0c172e", wantAddress: "B62qicipYxyEHu7QjUqS7QvBipTs5CzgkYZZZkPoKVYBu6tnDUcE9Zt"},
		{prikey: "336eb4a19b3d8905824b0f2254fb495573be302c17582748bf7e101965aa4774", wantAddress: "B62qrKG4Z8hnzZqp1AL8WsQhQYah3quN1qUj3SyfJA8Lw135qWWg1mi"},
		{prikey: "3414fc16e86e6ac272fda03cf8dcb4d7d47af91b4b726494dab43bf773ce1779", wantAddress: "B62qoG5Yk4iVxpyczUrBNpwtx2xunhL48dydN53A2VjoRwF8NUTbVr4"},
		{prikey: "20f84123a26e58dd32b0ea3c80381f35cd01bc22a20346cc65b0a67ae48532ba", wantAddress: "B62qkiT4kgCawkSEF84ga5kP9QnhmTJEYzcfgGuk6okAJtSBfVcjm1M"},
		{prikey: "1dee867358d4000f1dafa5978341fb515f89eeddbe450bd57df091f1e63d4444", wantAddress: "B62qoqiAgERjCjXhofXiD7cMLJSKD8hE8ZtMh4jX5MPNgKB4CFxxm1N"}}

	for _, test := range tests {
		scalar, err := ScalarFromHex(test.prikey)
		if err != nil {
			t.Error(err)
		}

		pubKey, err := GeneratePubKey(scalar)

		address, err := GenerateAddress(pubKey)
		if err != nil {
			t.Error(err)
		}

		pub, err := SerializeCompressed(pubKey)
		if err != nil {
			t.Error(err)
		}
		//fmt.Println(hex.EncodeToString(pub[:]))
		address1, err := PublicToAddress(*pub)
		if err != nil {
			t.Error(err)
		}

		if address != address1 {
			t.Errorf("%s != %s", address, address1)
		}
		if address != test.wantAddress {
			t.Errorf("%s != %s", address, test.wantAddress)
		}
	}
}

// TestGenerateAddress1 这里Base58的私钥是小端的
func TestGenerateAddress1(t *testing.T) {
	type test struct {
		prikey      string
		wantAddress string
	}
	tests := []test{{prikey: "EKFbQz6RHCJLB7khasBdAApcu9cqHW3dwrGWv4mKkuZoCFcLyTjk", wantAddress: "B62qmhvKHAfLG5mNj87BZmj2Hz4ner23vaFrqkSqekRsqQLQ34t8iKA"}}
	for _, test := range tests {
		key, ver, err := base58.CheckDecode(test.prikey)
		if err != nil {
			t.Error(err)
		}
		if ver != 90 {
			t.Errorf("ver = %d", ver)
		}
		var key32 [32]byte
		copy(key32[:], key[1:])

		scalar, err := scalarFromBytes(key32)
		if err != nil {
			t.Error(err)
		}

		pubKey, err := GeneratePubKey(scalar)

		address, err := GenerateAddress(pubKey)
		if err != nil {
			t.Error(err)
		}

		if address != test.wantAddress {
			t.Errorf("%s != %s", address, test.wantAddress)
		}
	}
}

func TestScalarAdd(t *testing.T) {
	hexA := "3ca187a58f09da346844964310c7e0dd948a9105702b716f4d732e042e0c172e"
	hexB := "336eb4a19b3d8905824b0f2254fb495573be302c17582748bf7e101965aa4774"
	hexC := "30103c472a476339ea8fa56565c32a32e60228357deeefda80aa52fc93b65ea1"
	a, err := ScalarFromHex(hexA)
	if err != nil {
		t.Error(err)
	}
	b, err := ScalarFromHex(hexB)
	if err != nil {
		t.Error(err)
	}

	c, err := ScalarAdd(a, b)
	if err != nil {
		t.Error(err)
	}

	hexC1, err := ScalarToHex(c)
	if err != nil {
		t.Error(err)
	}
	if hexC1 != hexC {
		t.Error("hexC1 != hexC")
	}

	bigA, _ := big.NewInt(0).SetString(hexA, 16)
	bigB, _ := big.NewInt(0).SetString(hexB, 16)
	bigC, _ := big.NewInt(0).SetString(hexC, 16)

	bigTemp := big.NewInt(0).Add(bigA, bigB)
	bigC1 := big.NewInt(0).Mod(bigTemp, GetN())

	if bigC.Cmp(bigC1) != 0 {
		t.Error("bigC1 != bigC")
	}
}

func TestSerializeCompressed(t *testing.T) {
	type test struct {
		priKey      string
		address     string
		wantpPubKey string
	}
	tests := []test{{priKey: "164244176fddb5d769b7de2027469d027ad428fadcc0c02396e6280142efb718", address: "B62qnzbXmRNo9q32n4SNu2mpB8e7FYYLH8NmaX6oFCBYjjQ8SbD7uzV", wantpPubKey: "011c4a1a3e8ba719aec0ebd0b09c7a8cd0258b4eb193de53154288a63c29c26f87"},
		{priKey: "3ca187a58f09da346844964310c7e0dd948a9105702b716f4d732e042e0c172e", address: "B62qicipYxyEHu7QjUqS7QvBipTs5CzgkYZZZkPoKVYBu6tnDUcE9Zt", wantpPubKey: "002b6f46b09abad95581af0b5e7875f749d27dc0c996748290919e53ee6f80d504"},
		{priKey: "336eb4a19b3d8905824b0f2254fb495573be302c17582748bf7e101965aa4774", address: "B62qrKG4Z8hnzZqp1AL8WsQhQYah3quN1qUj3SyfJA8Lw135qWWg1mi", wantpPubKey: "003bc04ab5ce0050a55117bd78af0678e70438ee45e80ef6e04ae5dc0cd0e58cea"},
	}
	for _, test := range tests {
		priScalar, err := ScalarFromHex(test.priKey)
		if err != nil {
			t.Error(err)
		}

		pubPoint, err := GeneratePubKey(priScalar)
		if err != nil {
			t.Error(err)
		}

		pubBytes, err := SerializeCompressed(pubPoint)
		if err != nil {
			t.Error(err)
		}

		pubHex := hex.EncodeToString(pubBytes[:])
		if pubHex != test.wantpPubKey {
			t.Errorf("pubkey %s != %s", pubHex, test.wantpPubKey)
		}

		pubPoint1, err := DeserializeCompressed(*pubBytes)
		if err != nil {
			t.Error(err)
		}

		if !reflect.DeepEqual(pubPoint1, pubPoint) {
			t.Error("pubPoint1 != pubPoint")
		}

		pubBytes1, ver, err := base58.CheckDecode(test.address)
		if err != nil {
			t.Error(err)
		}

		if ver != 0xcb {
			t.Error("invalid ver")
		}

		if len(pubBytes1) != 35 {
			t.Error("invalid pubBytes1 size")
		}
		if pubBytes1[0] != 1 || pubBytes1[1] != 1 {
			t.Error("pubBytes1 invalid prefix")
		}

		var pub33 [33]byte
		for i := 0; i < 33; i++ {
			pub33[i] = pubBytes1[35-1-i]
		}

		pubHex1 := hex.EncodeToString(pub33[:])
		if pubHex1 != test.wantpPubKey {
			t.Errorf("pubHex1 %s != %s", pubHex1, test.wantpPubKey)
		}
	}
}
