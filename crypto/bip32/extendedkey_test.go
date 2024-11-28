// Copyright (c) 2014-2017 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package bip32

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"reflect"
	"testing"

	"git.liebaopay.com/ksrv/keyserver/crypto/pasta"
	"git.liebaopay.com/ksrv/keyserver/crypto/signer"
	"git.liebaopay.com/ksrv/keyserver/ksrv"
	"github.com/bmizerany/assert"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcutil"
)

// TestCorrect 测试正确功能
func TestCorrectEcc(t *testing.T) {
	testfun := func(algID ksrv.NewHDSeedRequest_AlgId) int {
		seed, err := GenerateSeed(RecommendedSeedLen)
		if err != nil {
			t.Fatalf("GenerateSeed: unexpected error: %v", err)
		}

		rootKey, err := NewMaster(algID, seed, &chaincfg.MainNetParams)
		if err != nil {
			t.Fatalf("NewMaster: unexpected error: %v", err)
		}

		rootKeyPub, err := rootKey.Neuter()
		if err != nil {
			t.Fatalf(err.Error())
		}

		child0, err := rootKey.Child(1)
		if err != nil {
			t.Fatalf(err.Error())
		}

		child0P, err := child0.Neuter()
		if err != nil {
			t.Fatalf(err.Error())
		}

		child0Pub, err := rootKeyPub.Child(1)
		if err != nil {
			t.Fatalf(err.Error())
		}

		assert.Equal(t, child0P, child0Pub)

		//Alg
		assert.Equal(t, rootKey.Alg(), algID)
		assert.Equal(t, rootKeyPub.Alg(), algID)
		assert.Equal(t, child0.Alg(), algID)
		assert.Equal(t, child0Pub.Alg(), algID)
		//IsPrivate
		assert.Equal(t, rootKey.IsPrivate(), true)
		assert.Equal(t, rootKeyPub.IsPrivate(), false)
		assert.Equal(t, child0.IsPrivate(), true)
		assert.Equal(t, child0Pub.IsPrivate(), false)
		//Depth
		assert.Equal(t, rootKey.Depth(), uint8(0))
		assert.Equal(t, rootKeyPub.Depth(), uint8(0))
		assert.Equal(t, child0.Depth(), uint8(1))
		assert.Equal(t, child0Pub.Depth(), uint8(1))
		//ParentFingerprint
		parentFPRoot := []byte{0x00, 0x00, 0x00, 0x00}
		fpRoot := binary.BigEndian.Uint32(parentFPRoot)
		parentFPChild0 := btcutil.Hash160(rootKeyPub.Key())[:4]
		fpRChild0 := binary.BigEndian.Uint32(parentFPChild0)
		assert.Equal(t, rootKey.ParentFingerprint(), fpRoot)
		assert.Equal(t, rootKeyPub.ParentFingerprint(), fpRoot)
		assert.Equal(t, child0.ParentFingerprint(), fpRChild0)
		assert.Equal(t, child0Pub.ParentFingerprint(), fpRChild0)

		assert.Equal(t, rootKey.ParentFP(), parentFPRoot)
		assert.Equal(t, rootKeyPub.ParentFP(), parentFPRoot)
		assert.Equal(t, child0.ParentFP(), parentFPChild0)
		assert.Equal(t, child0Pub.ParentFP(), parentFPChild0)
		//Version
		assert.Equal(t, rootKey.Version(), child0.Version())
		assert.NotEqual(t, rootKeyPub.Version(), rootKey.Version())
		assert.Equal(t, rootKeyPub.Version(), child0Pub.Version())
		//ChainCode
		assert.Equal(t, len(rootKey.ChainCode()), 32)
		assert.Equal(t, len(child0.ChainCode()), 32)
		assert.Equal(t, rootKey.ChainCode(), rootKeyPub.ChainCode())
		assert.NotEqual(t, child0.ChainCode(), rootKey.ChainCode())
		assert.Equal(t, child0.ChainCode(), child0Pub.ChainCode())
		//ChildNumber
		childNumber := []byte{0, 0, 0, 0}
		childNumber1 := []byte{0, 0, 0, 1}
		assert.Equal(t, rootKey.ChildNumber(), childNumber)
		assert.Equal(t, rootKeyPub.ChildNumber(), childNumber)
		assert.Equal(t, child0.ChildNumber(), childNumber1)
		assert.Equal(t, child0Pub.ChildNumber(), childNumber1)
		//Key() []byte
		//ECPubKey() ([]byte, error)
		//ECPrivKey() ([]byte, error)
		privKeyRoot, err := rootKey.ECPrivKey()
		if err != nil {
			t.Fatalf(err.Error())
		}
		pubKeyRoot, err := rootKey.ECPubKey()
		if err != nil {
			t.Fatalf(err.Error())
		}

		_, err = rootKeyPub.ECPrivKey()
		if err != ErrNotPrivExtKey {
			t.Fatalf(err.Error())
		}
		pubKeyRootPub, err := rootKey.ECPubKey()
		if err != nil {
			t.Fatalf(err.Error())
		}

		assert.Equal(t, rootKey.Key(), privKeyRoot)
		assert.Equal(t, rootKeyPub.Key(), pubKeyRoot)
		assert.Equal(t, pubKeyRootPub, pubKeyRoot)

		privKeyChild0, err := child0.ECPrivKey()
		if err != nil {
			t.Fatalf(err.Error())
		}
		pubKeyChild0, err := child0.ECPubKey()
		if err != nil {
			t.Fatalf(err.Error())
		}

		_, err = child0Pub.ECPrivKey()
		if err != ErrNotPrivExtKey {
			t.Fatalf(err.Error())
		}
		pubKeyChild0Pub, err := child0Pub.ECPubKey()
		if err != nil {
			t.Fatalf(err.Error())
		}

		assert.Equal(t, child0.Key(), privKeyChild0)
		assert.Equal(t, child0Pub.Key(), pubKeyChild0)
		assert.Equal(t, pubKeyChild0Pub, pubKeyChild0)

		//ToBytes() []byte
		rootKeyBytes := rootKey.ToBytes()
		rootKeyPubBytes := rootKeyPub.ToBytes()
		child0Bytes := child0.ToBytes()
		child0PubBytes := child0Pub.ToBytes()

		rootKeyO, err := FromBytes(algID, rootKeyBytes)
		if err != nil {
			t.Fatalf(err.Error())
		}
		rootKeyPubO, err := FromBytes(algID, rootKeyPubBytes)
		if err != nil {
			t.Fatalf(err.Error())
		}
		child0O, err := FromBytes(algID, child0Bytes)
		if err != nil {
			t.Fatalf(err.Error())
		}
		child0PubO, err := FromBytes(algID, child0PubBytes)
		if err != nil {
			t.Fatalf(err.Error())
		}
		rootKeyOPub, err := rootKeyO.ECPubKey()
		if err != nil {
			t.Fatalf(err.Error())
		}
		assert.Equal(t, pubKeyRootPub, rootKeyOPub)
		assert.Equal(t, rootKey, rootKeyO)
		assert.Equal(t, rootKeyPub, rootKeyPubO)

		child0OPub, err := child0O.ECPubKey()
		if err != nil {
			t.Fatalf(err.Error())
		}
		assert.Equal(t, pubKeyChild0, child0OPub)
		assert.Equal(t, child0, child0O)
		assert.Equal(t, child0Pub, child0PubO)

		//Test Sign
		msg := getSignData(algID)
		signature, err := signer.Sign(algID, msg, child0.Key())
		if err != nil {
			t.Fatalf(err.Error())
		}
		fmt.Println(hex.EncodeToString(child0.Key()))
		fmt.Println(hex.EncodeToString(signature))
		if ksrv.NewHDSeedRequest_Secp256k1 == algID {
			signature = signature[:64]
		}
		ret, err := signer.Verify(algID, child0Pub.Key(), msg, signature)
		if err != nil {
			t.Fatalf(err.Error())
		}
		assert.Equal(t, ret, true)

		return len(signature)
	}

	for i := 0; i < 100; i++ {
		fmt.Println("i =================== ", i)
		siglen := testfun(ksrv.NewHDSeedRequest_Secp256k1)
		assert.Equal(t, siglen, 64)
		siglen = testfun(ksrv.NewHDSeedRequest_ed25519)
		assert.Equal(t, siglen, 64)
		siglen = testfun(ksrv.NewHDSeedRequest_k1SchnorrZil)
		assert.Equal(t, siglen, 64)
		siglen = testfun(ksrv.NewHDSeedRequest_bls12381)
		assert.Equal(t, siglen, 96)
		siglen = testfun(ksrv.NewHDSeedRequest_pastaSchnorrMina)
		assert.Equal(t, siglen, 64)
		siglen = testfun(ksrv.NewHDSeedRequest_Secp256r1)
		assert.Equal(t, siglen, 64)
		siglen = testfun(ksrv.NewHDSeedRequest_Ergo)
		assert.Equal(t, siglen, 56)
	}
}

func getSignData(alg ksrv.NewHDSeedRequest_AlgId) []byte {
	if alg == ksrv.NewHDSeedRequest_pastaSchnorrMina {
		request := pasta.TransactionRequest{
			Fee:         20000000,
			FeeToken:    1,
			FeePayerPk:  "B62qkRodi7nj6W1geB12UuW2XAx2yidWZCcDthJvkf9G4A6G5GFasVQ",
			Nonce:       100,
			ValidUntil:  34,
			Memo:        "abc-test-2",
			SourcePk:    "B62qkRodi7nj6W1geB12UuW2XAx2yidWZCcDthJvkf9G4A6G5GFasVQ",
			ReceiverPk:  "B62qmY1YAk8MjkMWMApX8Q5K2WXc4prPwYTpN5NKhumQaoF2vVUV2sv",
			TokenID:     1,
			Amount:      330500000000,
			TokenLocked: false,
			Delegation:  false,
			NetworkID:   1,
		}

		ret, _ := json.Marshal(request)
		return ret
	}
	hashData, _ := hex.DecodeString("377091f0e728463bc2da7d546c53b9f6b81df4a1cc1ab5bf29c5908b7151a32d")
	return hashData
}

// TestBIP0032Vectors tests the vectors provided by [BIP32] to ensure the
// derivation works as intended.
func TestBIP0032Vectors(t *testing.T) {
	// The master seeds for each of the two test vectors in [BIP32].
	testVec1MasterHex := "000102030405060708090a0b0c0d0e0f"
	testVec2MasterHex := "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542"
	testVec3MasterHex := "4b381541583be4423346c643850da4b320e46a87ae3d2a4e6da11eba819cd4acba45d239319ac14f863b8d5ab5a0d0c64d2e8a1e7d1457df2e5a3c51c73235be"
	hkStart := uint32(0x80000000)

	tests := []struct {
		name        string
		master      string
		path        []uint32
		wantPub     string
		wantPriv    string
		wantPubHex  string
		wantPrivHex string
		net         *chaincfg.Params
	}{
		// Test vector 1
		{
			name:        "test vector 1 chain m",
			master:      testVec1MasterHex,
			path:        []uint32{},
			wantPub:     "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8",
			wantPriv:    "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi",
			wantPubHex:  "0488b21e000000000000000000873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d5080339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c200",
			wantPrivHex: "0488ade4000000000000000000873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d50800e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b3501",
			net:         &chaincfg.MainNetParams,
		},
		{
			name:        "test vector 1 chain m/0H",
			master:      testVec1MasterHex,
			path:        []uint32{hkStart},
			wantPub:     "xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw",
			wantPriv:    "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7",
			wantPubHex:  "0488b21e013442193e8000000047fdacbd0f1097043b78c63c20c34ef4ed9a111d980047ad16282c7ae6236141035a784662a4a20a65bf6aab9ae98a6c068a81c52e4b032c0fb5400c706cfccc5600",
			wantPrivHex: "0488ade4013442193e8000000047fdacbd0f1097043b78c63c20c34ef4ed9a111d980047ad16282c7ae623614100edb2e14f9ee77d26dd93b4ecede8d16ed408ce149b6cd80b0715a2d911a0afea01",
			net:         &chaincfg.MainNetParams,
		},
		{
			name:        "test vector 1 chain m/0H/1",
			master:      testVec1MasterHex,
			path:        []uint32{hkStart, 1},
			wantPub:     "xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ",
			wantPriv:    "xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs",
			wantPubHex:  "0488b21e025c1bd648000000012a7857631386ba23dacac34180dd1983734e444fdbf774041578e9b6adb37c1903501e454bf00751f24b1b489aa925215d66af2234e3891c3b21a52bedb3cd711c00",
			wantPrivHex: "0488ade4025c1bd648000000012a7857631386ba23dacac34180dd1983734e444fdbf774041578e9b6adb37c19003c6cb8d0f6a264c91ea8b5030fadaa8e538b020f0a387421a12de9319dc9336801",
			net:         &chaincfg.MainNetParams,
		},
		{
			name:        "test vector 1 chain m/0H/1/2H",
			master:      testVec1MasterHex,
			path:        []uint32{hkStart, 1, hkStart + 2},
			wantPub:     "xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5",
			wantPriv:    "xprv9z4pot5VBttmtdRTWfWQmoH1taj2axGVzFqSb8C9xaxKymcFzXBDptWmT7FwuEzG3ryjH4ktypQSAewRiNMjANTtpgP4mLTj34bhnZX7UiM",
			wantPubHex:  "0488b21e03bef5a2f98000000204466b9cc8e161e966409ca52986c584f07e9dc81f735db683c3ff6ec7b1503f0357bfe1e341d01c69fe5654309956cbea516822fba8a601743a012a7896ee8dc200",
			wantPrivHex: "0488ade403bef5a2f98000000204466b9cc8e161e966409ca52986c584f07e9dc81f735db683c3ff6ec7b1503f00cbce0d719ecf7431d88e6a89fa1483e02e35092af60c042b1df2ff59fa424dca01",
			net:         &chaincfg.MainNetParams,
		},
		{
			name:        "test vector 1 chain m/0H/1/2H/2",
			master:      testVec1MasterHex,
			path:        []uint32{hkStart, 1, hkStart + 2, 2},
			wantPub:     "xpub6FHa3pjLCk84BayeJxFW2SP4XRrFd1JYnxeLeU8EqN3vDfZmbqBqaGJAyiLjTAwm6ZLRQUMv1ZACTj37sR62cfN7fe5JnJ7dh8zL4fiyLHV",
			wantPriv:    "xprvA2JDeKCSNNZky6uBCviVfJSKyQ1mDYahRjijr5idH2WwLsEd4Hsb2Tyh8RfQMuPh7f7RtyzTtdrbdqqsunu5Mm3wDvUAKRHSC34sJ7in334",
			wantPubHex:  "0488b21e04ee7ab90c00000002cfb71883f01676f587d023cc53a35bc7f88f724b1f8c2892ac1275ac822a3edd02e8445082a72f29b75ca48748a914df60622a609cacfce8ed0e35804560741d2900",
			wantPrivHex: "0488ade404ee7ab90c00000002cfb71883f01676f587d023cc53a35bc7f88f724b1f8c2892ac1275ac822a3edd000f479245fb19a38a1954c5c7c0ebab2f9bdfd96a17563ef28a6a4b1a2a764ef401",
			net:         &chaincfg.MainNetParams,
		},
		{
			name:        "test vector 1 chain m/0H/1/2H/2/1000000000",
			master:      testVec1MasterHex,
			path:        []uint32{hkStart, 1, hkStart + 2, 2, 1000000000},
			wantPub:     "xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy",
			wantPriv:    "xprvA41z7zogVVwxVSgdKUHDy1SKmdb533PjDz7J6N6mV6uS3ze1ai8FHa8kmHScGpWmj4WggLyQjgPie1rFSruoUihUZREPSL39UNdE3BBDu76",
			wantPubHex:  "0488b21e05d880d7d83b9aca00c783e67b921d2beb8f6b389cc646d7263b4145701dadd2161548a8b078e65e9e022a471424da5e657499d1ff51cb43c47481a03b1e77f951fe64cec9f5a48f701100",
			wantPrivHex: "0488ade405d880d7d83b9aca00c783e67b921d2beb8f6b389cc646d7263b4145701dadd2161548a8b078e65e9e00471b76e389e528d6de6d816857e012c5455051cad6660850e58372a6c3e6e7c801",
			net:         &chaincfg.MainNetParams,
		},

		// Test vector 2
		{
			name:        "test vector 2 chain m",
			master:      testVec2MasterHex,
			path:        []uint32{},
			wantPub:     "xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB",
			wantPriv:    "xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U",
			wantPubHex:  "0488b21e00000000000000000060499f801b896d83179a4374aeb7822aaeaceaa0db1f85ee3e904c4defbd968903cbcaa9c98c877a26977d00825c956a238e8dddfbd322cce4f74b0b5bd6ace4a700",
			wantPrivHex: "0488ade400000000000000000060499f801b896d83179a4374aeb7822aaeaceaa0db1f85ee3e904c4defbd9689004b03d6fc340455b363f51020ad3ecca4f0850280cf436c70c727923f6db46c3e01",
			net:         &chaincfg.MainNetParams,
		},
		{
			name:        "test vector 2 chain m/0",
			master:      testVec2MasterHex,
			path:        []uint32{0},
			wantPub:     "xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH",
			wantPriv:    "xprv9vHkqa6EV4sPZHYqZznhT2NPtPCjKuDKGY38FBWLvgaDx45zo9WQRUT3dKYnjwih2yJD9mkrocEZXo1ex8G81dwSM1fwqWpWkeS3v86pgKt",
			wantPubHex:  "0488b21e01bd16bee500000000f0909affaa7ee7abe5dd4e100598d4dc53cd709d5a5c2cac40e7412f232f7c9c02fc9e5af0ac8d9b3cecfe2a888e2117ba3d089d8585886c9c826b6b22a98d12ea00",
			wantPrivHex: "0488ade401bd16bee500000000f0909affaa7ee7abe5dd4e100598d4dc53cd709d5a5c2cac40e7412f232f7c9c00abe74a98f6c7eabee0428f53798f0ab8aa1bd37873999041703c742f15ac7e1e01",
			net:         &chaincfg.MainNetParams,
		},
		{
			name:        "test vector 2 chain m/0/2147483647H",
			master:      testVec2MasterHex,
			path:        []uint32{0, hkStart + 2147483647},
			wantPub:     "xpub6ASAVgeehLbnwdqV6UKMHVzgqAG8Gr6riv3Fxxpj8ksbH9ebxaEyBLZ85ySDhKiLDBrQSARLq1uNRts8RuJiHjaDMBU4Zn9h8LZNnBC5y4a",
			wantPriv:    "xprv9wSp6B7kry3Vj9m1zSnLvN3xH8RdsPP1Mh7fAaR7aRLcQMKTR2vidYEeEg2mUCTAwCd6vnxVrcjfy2kRgVsFawNzmjuHc2YmYRmagcEPdU9",
			wantPubHex:  "0488b21e025a61ff8effffffffbe17a268474a6bb9c61e1d720cf6215e2a88c5406c4aee7b38547f585c9a37d903c01e7425647bdefa82b12d9bad5e3e6865bee0502694b94ca58b666abc0a5c3b00",
			wantPrivHex: "0488ade4025a61ff8effffffffbe17a268474a6bb9c61e1d720cf6215e2a88c5406c4aee7b38547f585c9a37d900877c779ad9687164e9c2f4f0f4ff0340814392330693ce95a58fe18fd52e6e9301",
			net:         &chaincfg.MainNetParams,
		},
		{
			name:        "test vector 2 chain m/0/2147483647H/1",
			master:      testVec2MasterHex,
			path:        []uint32{0, hkStart + 2147483647, 1},
			wantPub:     "xpub6DF8uhdarytz3FWdA8TvFSvvAh8dP3283MY7p2V4SeE2wyWmG5mg5EwVvmdMVCQcoNJxGoWaU9DCWh89LojfZ537wTfunKau47EL2dhHKon",
			wantPriv:    "xprv9zFnWC6h2cLgpmSA46vutJzBcfJ8yaJGg8cX1e5StJh45BBciYTRXSd25UEPVuesF9yog62tGAQtHjXajPPdbRCHuWS6T8XA2ECKADdw4Ef",
			wantPubHex:  "0488b21e03d8ab493700000001f366f48f1ea9f2d1d3fe958c95ca84ea18e4c4ddb9366c336c927eb246fb38cb03a7d1d856deb74c508e05031f9895dab54626251b3806e16b4bd12e781a7df5b900",
			wantPrivHex: "0488ade403d8ab493700000001f366f48f1ea9f2d1d3fe958c95ca84ea18e4c4ddb9366c336c927eb246fb38cb00704addf544a06e5ee4bea37098463c23613da32020d604506da8c0518e1da4b701",
			net:         &chaincfg.MainNetParams,
		},
		{
			name:        "test vector 2 chain m/0/2147483647H/1/2147483646H",
			master:      testVec2MasterHex,
			path:        []uint32{0, hkStart + 2147483647, 1, hkStart + 2147483646},
			wantPub:     "xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL",
			wantPriv:    "xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc",
			wantPubHex:  "0488b21e0478412e3afffffffe637807030d55d01f9a0cb3a7839515d796bd07706386a6eddf06cc29a65a0e2902d2b36900396c9282fa14628566582f206a5dd0bcc8d5e892611806cafb0301f000",
			wantPrivHex: "0488ade40478412e3afffffffe637807030d55d01f9a0cb3a7839515d796bd07706386a6eddf06cc29a65a0e2900f1c7c871a54a804afe328b4c83a1c33b8e5ff48f5087273f04efa83b247d6a2d01",
			net:         &chaincfg.MainNetParams,
		},
		{
			name:        "test vector 2 chain m/0/2147483647H/1/2147483646H/2",
			master:      testVec2MasterHex,
			path:        []uint32{0, hkStart + 2147483647, 1, hkStart + 2147483646, 2},
			wantPub:     "xpub6FnCn6nSzZAw5Tw7cgR9bi15UV96gLZhjDstkXXxvCLsUXBGXPdSnLFbdpq8p9HmGsApME5hQTZ3emM2rnY5agb9rXpVGyy3bdW6EEgAtqt",
			wantPriv:    "xprvA2nrNbFZABcdryreWet9Ea4LvTJcGsqrMzxHx98MMrotbir7yrKCEXw7nadnHM8Dq38EGfSh6dqA9QWTyefMLEcBYJUuekgW4BYPJcr9E7j",
			wantPubHex:  "0488b21e0531a507b8000000029452b549be8cea3ecb7a84bec10dcfd94afe4d129ebfd3b3cb58eedf394ed271024d902e1a2fc7a8755ab5b694c575fce742c48d9ff192e63df5193e4c7afe1f9c00",
			wantPrivHex: "0488ade40531a507b8000000029452b549be8cea3ecb7a84bec10dcfd94afe4d129ebfd3b3cb58eedf394ed27100bb7d39bdb83ecf58f2fd82b6d918341cbef428661ef01ab97c28a4842125ac2301",
			net:         &chaincfg.MainNetParams,
		},

		// Test vector 3
		{
			name:        "test vector 3 chain m",
			master:      testVec3MasterHex,
			path:        []uint32{},
			wantPub:     "xpub661MyMwAqRbcEZVB4dScxMAdx6d4nFc9nvyvH3v4gJL378CSRZiYmhRoP7mBy6gSPSCYk6SzXPTf3ND1cZAceL7SfJ1Z3GC8vBgp2epUt13",
			wantPriv:    "xprv9s21ZrQH143K25QhxbucbDDuQ4naNntJRi4KUfWT7xo4EKsHt2QJDu7KXp1A3u7Bi1j8ph3EGsZ9Xvz9dGuVrtHHs7pXeTzjuxBrCmmhgC6",
			wantPubHex:  "0488b21e00000000000000000001d28a3e53cffa419ec122c968b3259e16b65076495494d97cae10bbfec3c36f03683af1ba5743bdfc798cf814efeeab2735ec52d95eced528e692b8e34c4e566900",
			wantPrivHex: "0488ade400000000000000000001d28a3e53cffa419ec122c968b3259e16b65076495494d97cae10bbfec3c36f0000ddb80b067e0d4993197fe10f2657a844a384589847602d56f0c629c81aae3201",
			net:         &chaincfg.MainNetParams,
		},
		{
			name:        "test vector 3 chain m/0H",
			master:      testVec3MasterHex,
			path:        []uint32{hkStart},
			wantPub:     "xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y",
			wantPriv:    "xprv9uPDJpEQgRQfDcW7BkF7eTya6RPxXeJCqCJGHuCJ4GiRVLzkTXBAJMu2qaMWPrS7AANYqdq6vcBcBUdJCVVFceUvJFjaPdGZ2y9WACViL4L",
			wantPubHex:  "0488b21e0141d63b5080000000e5fea12a97b927fc9dc3d2cb0d1ea1cf50aa5a1fdc1f933e8906bb38df3377bd026557fdda1d5d43d79611f784780471f086d58e8126b8c40acb82272a7712e7f200",
			wantPrivHex: "0488ade40141d63b5080000000e5fea12a97b927fc9dc3d2cb0d1ea1cf50aa5a1fdc1f933e8906bb38df3377bd00491f7a2eebc7b57028e0d3faa0acda02e75c33b03c48fb288c41e2ea44e1daef01",
			net:         &chaincfg.MainNetParams,
		},

		// Test vector 1 - Testnet
		{
			name:        "test vector 1 chain m - testnet",
			master:      testVec1MasterHex,
			path:        []uint32{},
			wantPub:     "tpubD6NzVbkrYhZ4XgiXtGrdW5XDAPFCL9h7we1vwNCpn8tGbBcgfVYjXyhWo4E1xkh56hjod1RhGjxbaTLV3X4FyWuejifB9jusQ46QzG87VKp",
			wantPriv:    "tprv8ZgxMBicQKsPeDgjzdC36fs6bMjGApWDNLR9erAXMs5skhMv36j9MV5ecvfavji5khqjWaWSFhN3YcCUUdiKH6isR4Pwy3U5y5egddBr16m",
			wantPubHex:  "043587cf000000000000000000873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d5080339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c200",
			wantPrivHex: "04358394000000000000000000873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d50800e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b3501",
			net:         &chaincfg.TestNet3Params,
		},
		{
			name:        "test vector 1 chain m/0H - testnet",
			master:      testVec1MasterHex,
			path:        []uint32{hkStart},
			wantPub:     "tpubD8eQVK4Kdxg3gHrF62jGP7dKVCoYiEB8dFSpuTawkL5YxTus5j5pf83vaKnii4bc6v2NVEy81P2gYrJczYne3QNNwMTS53p5uzDyHvnw2jm",
			wantPriv:    "tprv8bxNLu25VazNnppTCP4fyhyCvBHcYtzE3wr3cwYeL4HA7yf6TLGEUdS4QC1vLT63TkjRssqJe4CvGNEC8DzW5AoPUw56D1Ayg6HY4oy8QZ9",
			wantPubHex:  "043587cf013442193e8000000047fdacbd0f1097043b78c63c20c34ef4ed9a111d980047ad16282c7ae6236141035a784662a4a20a65bf6aab9ae98a6c068a81c52e4b032c0fb5400c706cfccc5600",
			wantPrivHex: "04358394013442193e8000000047fdacbd0f1097043b78c63c20c34ef4ed9a111d980047ad16282c7ae623614100edb2e14f9ee77d26dd93b4ecede8d16ed408ce149b6cd80b0715a2d911a0afea01",
			net:         &chaincfg.TestNet3Params,
		},
		{
			name:        "test vector 1 chain m/0H/1 - testnet",
			master:      testVec1MasterHex,
			path:        []uint32{hkStart, 1},
			wantPub:     "tpubDApXh6cD2fZ7WjtgpHd8yrWyYaneiFuRZa7fVjMkgxsmC1QzoXW8cgx9zQFJ81Jx4deRGfRE7yXA9A3STsxXj4CKEZJHYgpMYikkas9DBTP",
			wantPriv:    "tprv8e8VYgZxtHsSdGrtvdxYaSrryZGiYviWzGWtDDKTGh5NMXAEB8gYSCLHpFCywNs5uqV7ghRjimALQJkRFZnUrLHpzi2pGkwqLtbubgWuQ8q",
			wantPubHex:  "043587cf025c1bd648000000012a7857631386ba23dacac34180dd1983734e444fdbf774041578e9b6adb37c1903501e454bf00751f24b1b489aa925215d66af2234e3891c3b21a52bedb3cd711c00",
			wantPrivHex: "04358394025c1bd648000000012a7857631386ba23dacac34180dd1983734e444fdbf774041578e9b6adb37c19003c6cb8d0f6a264c91ea8b5030fadaa8e538b020f0a387421a12de9319dc9336801",
			net:         &chaincfg.TestNet3Params,
		},
		{
			name:        "test vector 1 chain m/0H/1/2H - testnet",
			master:      testVec1MasterHex,
			path:        []uint32{hkStart, 1, hkStart + 2},
			wantPub:     "tpubDDRojdS4jYQXNugn4t2WLrZ7mjfAyoVQu7MLk4eurqFCbrc7cHLZX8W5YRS8ZskGR9k9t3PqVv68bVBjAyW4nWM9pTGRddt3GQftg6MVQsm",
			wantPriv:    "tprv8gjmbDPpbAirVSezBEMuwSu1Ci9EpUJWKokZTYccSZSomNMLytWyLdtDNHRbucNaRJWWHANf9AzEdWVAqahfyRjVMKbNRhBmxAM8EJr7R15",
			wantPubHex:  "043587cf03bef5a2f98000000204466b9cc8e161e966409ca52986c584f07e9dc81f735db683c3ff6ec7b1503f0357bfe1e341d01c69fe5654309956cbea516822fba8a601743a012a7896ee8dc200",
			wantPrivHex: "0435839403bef5a2f98000000204466b9cc8e161e966409ca52986c584f07e9dc81f735db683c3ff6ec7b1503f00cbce0d719ecf7431d88e6a89fa1483e02e35092af60c042b1df2ff59fa424dca01",
			net:         &chaincfg.TestNet3Params,
		},
		{
			name:        "test vector 1 chain m/0H/1/2H/2 - testnet",
			master:      testVec1MasterHex,
			path:        []uint32{hkStart, 1, hkStart + 2, 2},
			wantPub:     "tpubDFfCa4Z1v25WTPAVm9EbEMiRrYwucPocLbEe12BPBGooxxEUg42vihy1DkRWyftztTsL23snYezF9uXjGGwGW6pQjEpcTpmsH6ajpf4CVPn",
			wantPriv:    "tprv8iyAReWmmePqZv8hsVZzpx4KHXRyT4chmHdriW95m11R8Tyi3fDLYDM93bq4NGn1V6eCu5cE3zSQ6hPd31F2ApKXkZgTyn1V78pHjkq1V2v",
			wantPubHex:  "043587cf04ee7ab90c00000002cfb71883f01676f587d023cc53a35bc7f88f724b1f8c2892ac1275ac822a3edd02e8445082a72f29b75ca48748a914df60622a609cacfce8ed0e35804560741d2900",
			wantPrivHex: "0435839404ee7ab90c00000002cfb71883f01676f587d023cc53a35bc7f88f724b1f8c2892ac1275ac822a3edd000f479245fb19a38a1954c5c7c0ebab2f9bdfd96a17563ef28a6a4b1a2a764ef401",
			net:         &chaincfg.TestNet3Params,
		},
		{
			name:        "test vector 1 chain m/0H/1/2H/2/1000000000 - testnet",
			master:      testVec1MasterHex,
			path:        []uint32{hkStart, 1, hkStart + 2, 2, 1000000000},
			wantPub:     "tpubDHNy3kAG39ThyiwwsgoKY4iRenXDRtce8qdCFJZXPMCJg5dsCUHayp84raLTpvyiNA9sXPob5rgqkKvkN8S7MMyXbnEhGJMW64Cf4vFAoaF",
			wantPriv:    "tprv8kgvuL81tmn36Fv9z38j8f4K5m1HGZRjZY2QxnXDy5PuqbP6a5TzoKWCgTcGHBu66W3TgSbAu2yX6sPza5FkHmy564Sh6gmCPUNeUt4yj2x",
			wantPubHex:  "043587cf05d880d7d83b9aca00c783e67b921d2beb8f6b389cc646d7263b4145701dadd2161548a8b078e65e9e022a471424da5e657499d1ff51cb43c47481a03b1e77f951fe64cec9f5a48f701100",
			wantPrivHex: "0435839405d880d7d83b9aca00c783e67b921d2beb8f6b389cc646d7263b4145701dadd2161548a8b078e65e9e00471b76e389e528d6de6d816857e012c5455051cad6660850e58372a6c3e6e7c801",
			net:         &chaincfg.TestNet3Params,
		},
	}

tests:
	for i, test := range tests {
		masterSeed, err := hex.DecodeString(test.master)
		if err != nil {
			t.Errorf("DecodeString #%d (%s): unexpected error: %v",
				i, test.name, err)
			continue
		}

		extKey, err := NewMaster(ksrv.NewHDSeedRequest_Secp256k1, masterSeed, test.net)
		if err != nil {
			t.Errorf("NewMaster #%d (%s): unexpected error when "+
				"creating new master key: %v", i, test.name,
				err)
			continue
		}

		for _, childNum := range test.path {
			var err error
			extKey, err = extKey.Child(childNum)
			if err != nil {
				t.Errorf("err: %v", err)
				continue tests
			}
		}

		if extKey.Depth() != uint8(len(test.path)) {
			t.Errorf("Depth of key %d should match fixture path: %v",
				extKey.Depth(), len(test.path))
			continue
		}

		extKeyEcc, ok := extKey.(*ExtendedKeyEcc)
		assert.Equal(t, ok, true)
		privStr := extKeyEcc.String()
		if privStr != test.wantPriv {
			t.Errorf("Serialize #%d (%s): mismatched serialized "+
				"private extended key -- got: %s, want: %s", i,
				test.name, privStr, test.wantPriv)
			continue
		}
		privHex := hex.EncodeToString(extKey.ToBytes())
		if privHex != test.wantPrivHex {
			t.Errorf("Serialize #%d (%s): mismatched serialized "+
				"private bytes extended key -- got: %s, want: %s", i,
				test.name, privHex, test.wantPrivHex)
			continue
		}

		pubKey, err := extKey.Neuter()
		if err != nil {
			t.Errorf("Neuter #%d (%s): unexpected error: %v ", i,
				test.name, err)
			continue
		}

		// Neutering a second time should have no effect.
		pubKey, err = pubKey.Neuter()
		if err != nil {
			t.Errorf("Neuter #%d (%s): unexpected error: %v", i,
				test.name, err)
			return
		}

		pubKeyEcc, ok := pubKey.(*ExtendedKeyEcc)
		assert.Equal(t, ok, true)
		pubStr := pubKeyEcc.String()
		if pubStr != test.wantPub {
			t.Errorf("Neuter #%d (%s): mismatched serialized "+
				"public extended key -- got: %s, want: %s", i,
				test.name, pubStr, test.wantPub)
			continue
		}

		pubHex := hex.EncodeToString(pubKey.ToBytes())
		if pubHex != test.wantPubHex {
			t.Errorf("Serialize #%d (%s): mismatched serialized "+
				"publice bytes extended key -- got: %s, want: %s", i,
				test.name, pubHex, test.wantPubHex)
			continue
		}
	}
}

// TestPrivateDerivation tests several vectors which derive private keys from
// other private keys works as intended.
func TestPrivateDerivation(t *testing.T) {
	// The private extended keys for test vectors in [BIP32].
	testVec1MasterPrivKey := "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"
	testVec2MasterPrivKey := "xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U"

	tests := []struct {
		name     string
		master   string
		path     []uint32
		wantPriv string
	}{
		// Test vector 1
		{
			name:     "test vector 1 chain m",
			master:   testVec1MasterPrivKey,
			path:     []uint32{},
			wantPriv: "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi",
		},
		{
			name:     "test vector 1 chain m/0",
			master:   testVec1MasterPrivKey,
			path:     []uint32{0},
			wantPriv: "xprv9uHRZZhbkedL37eZEnyrNsQPFZYRAvjy5rt6M1nbEkLSo378x1CQQLo2xxBvREwiK6kqf7GRNvsNEchwibzXaV6i5GcsgyjBeRguXhKsi4R",
		},
		{
			name:     "test vector 1 chain m/0/1",
			master:   testVec1MasterPrivKey,
			path:     []uint32{0, 1},
			wantPriv: "xprv9ww7sMFLzJMzy7bV1qs7nGBxgKYrgcm3HcJvGb4yvNhT9vxXC7eX7WVULzCfxucFEn2TsVvJw25hH9d4mchywguGQCZvRgsiRaTY1HCqN8G",
		},
		{
			name:     "test vector 1 chain m/0/1/2",
			master:   testVec1MasterPrivKey,
			path:     []uint32{0, 1, 2},
			wantPriv: "xprv9xrdP7iD2L1YZCgR9AecDgpDMZSTzP5KCfUykGXgjBxLgp1VFHsEeL3conzGAkbc1MigG1o8YqmfEA2jtkPdf4vwMaGJC2YSDbBTPAjfRUi",
		},
		{
			name:     "test vector 1 chain m/0/1/2/2",
			master:   testVec1MasterPrivKey,
			path:     []uint32{0, 1, 2, 2},
			wantPriv: "xprvA2J8Hq4eiP7xCEBP7gzRJGJnd9CHTkEU6eTNMrZ6YR7H5boik8daFtDZxmJDfdMSKHwroCfAfsBKWWidRfBQjpegy6kzXSkQGGoMdWKz5Xh",
		},
		{
			name:     "test vector 1 chain m/0/1/2/2/1000000000",
			master:   testVec1MasterPrivKey,
			path:     []uint32{0, 1, 2, 2, 1000000000},
			wantPriv: "xprvA3XhazxncJqJsQcG85Gg61qwPQKiobAnWjuPpjKhExprZjfse6nErRwTMwGe6uGWXPSykZSTiYb2TXAm7Qhwj8KgRd2XaD21Styu6h6AwFz",
		},

		// Test vector 2
		{
			name:     "test vector 2 chain m",
			master:   testVec2MasterPrivKey,
			path:     []uint32{},
			wantPriv: "xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U",
		},
		{
			name:     "test vector 2 chain m/0",
			master:   testVec2MasterPrivKey,
			path:     []uint32{0},
			wantPriv: "xprv9vHkqa6EV4sPZHYqZznhT2NPtPCjKuDKGY38FBWLvgaDx45zo9WQRUT3dKYnjwih2yJD9mkrocEZXo1ex8G81dwSM1fwqWpWkeS3v86pgKt",
		},
		{
			name:     "test vector 2 chain m/0/2147483647",
			master:   testVec2MasterPrivKey,
			path:     []uint32{0, 2147483647},
			wantPriv: "xprv9wSp6B7cXJWXZRpDbxkFg3ry2fuSyUfvboJ5Yi6YNw7i1bXmq9QwQ7EwMpeG4cK2pnMqEx1cLYD7cSGSCtruGSXC6ZSVDHugMsZgbuY62m6",
		},
		{
			name:     "test vector 2 chain m/0/2147483647/1",
			master:   testVec2MasterPrivKey,
			path:     []uint32{0, 2147483647, 1},
			wantPriv: "xprv9ysS5br6UbWCRCJcggvpUNMyhVWgD7NypY9gsVTMYmuRtZg8izyYC5Ey4T931WgWbfJwRDwfVFqV3b29gqHDbuEpGcbzf16pdomk54NXkSm",
		},
		{
			name:     "test vector 2 chain m/0/2147483647/1/2147483646",
			master:   testVec2MasterPrivKey,
			path:     []uint32{0, 2147483647, 1, 2147483646},
			wantPriv: "xprvA2LfeWWwRCxh4iqigcDMnUf2E3nVUFkntc93nmUYBtb9rpSPYWa8MY3x9ZHSLZkg4G84UefrDruVK3FhMLSJsGtBx883iddHNuH1LNpRrEp",
		},
		{
			name:     "test vector 2 chain m/0/2147483647/1/2147483646/2",
			master:   testVec2MasterPrivKey,
			path:     []uint32{0, 2147483647, 1, 2147483646, 2},
			wantPriv: "xprvA48ALo8BDjcRET68R5RsPzF3H7WeyYYtHcyUeLRGBPHXu6CJSGjwW7dWoeUWTEzT7LG3qk6Eg6x2ZoqD8gtyEFZecpAyvchksfLyg3Zbqam",
		},

		// Custom tests to trigger specific conditions.
		{
			// Seed 000000000000000000000000000000da.
			name:     "Derived privkey with zero high byte m/0",
			master:   "xprv9s21ZrQH143K4FR6rNeqEK4EBhRgLjWLWhA3pw8iqgAKk82ypz58PXbrzU19opYcxw8JDJQF4id55PwTsN1Zv8Xt6SKvbr2KNU5y8jN8djz",
			path:     []uint32{0},
			wantPriv: "xprv9uC5JqtViMmgcAMUxcsBCBFA7oYCNs4bozPbyvLfddjHou4rMiGEHipz94xNaPb1e4f18TRoPXfiXx4C3cDAcADqxCSRSSWLvMBRWPctSN9",
		},
	}

tests:
	for i, test := range tests {
		extKey, err := NewKeyFromString(ksrv.NewHDSeedRequest_Secp256k1, test.master)
		if err != nil {
			t.Errorf("NewKeyFromString #%d (%s): unexpected error "+
				"creating extended key: %v", i, test.name,
				err)
			continue
		}

		for _, childNum := range test.path {
			var err error
			extKey, err = extKey.Child(childNum)
			if err != nil {
				t.Errorf("err: %v", err)
				continue tests
			}
		}

		extKeyEcc, ok := extKey.(*ExtendedKeyEcc)
		assert.Equal(t, ok, true)
		privStr := extKeyEcc.String()
		if privStr != test.wantPriv {
			t.Errorf("Child #%d (%s): mismatched serialized "+
				"private extended key -- got: %s, want: %s", i,
				test.name, privStr, test.wantPriv)
			continue
		}
	}
}

// TestPublicDerivation tests several vectors which derive public keys from
// other public keys works as intended.
func TestPublicDerivation(t *testing.T) {
	// The public extended keys for test vectors in [BIP32].
	testVec1MasterPubKey := "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8"
	testVec2MasterPubKey := "xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB"

	tests := []struct {
		name    string
		master  string
		path    []uint32
		wantPub string
	}{
		// Test vector 1
		{
			name:    "test vector 1 chain m",
			master:  testVec1MasterPubKey,
			path:    []uint32{},
			wantPub: "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8",
		},
		{
			name:    "test vector 1 chain m/0",
			master:  testVec1MasterPubKey,
			path:    []uint32{0},
			wantPub: "xpub68Gmy5EVb2BdFbj2LpWrk1M7obNuaPTpT5oh9QCCo5sRfqSHVYWex97WpDZzszdzHzxXDAzPLVSwybe4uPYkSk4G3gnrPqqkV9RyNzAcNJ1",
		},
		{
			name:    "test vector 1 chain m/0/1",
			master:  testVec1MasterPubKey,
			path:    []uint32{0, 1},
			wantPub: "xpub6AvUGrnEpfvJBbfx7sQ89Q8hEMPM65UteqEX4yUbUiES2jHfjexmfJoxCGSwFMZiPBaKQT1RiKWrKfuDV4vpgVs4Xn8PpPTR2i79rwHd4Zr",
		},
		{
			name:    "test vector 1 chain m/0/1/2",
			master:  testVec1MasterPubKey,
			path:    []uint32{0, 1, 2},
			wantPub: "xpub6BqyndF6rhZqmgktFCBcapkwubGxPqoAZtQaYewJHXVKZcLdnqBVC8N6f6FSHWUghjuTLeubWyQWfJdk2G3tGgvgj3qngo4vLTnnSjAZckv",
		},
		{
			name:    "test vector 1 chain m/0/1/2/2",
			master:  testVec1MasterPubKey,
			path:    []uint32{0, 1, 2, 2},
			wantPub: "xpub6FHUhLbYYkgFQiFrDiXRfQFXBB2msCxKTsNyAExi6keFxQ8sHfwpogY3p3s1ePSpUqLNYks5T6a3JqpCGszt4kxbyq7tUoFP5c8KWyiDtPp",
		},
		{
			name:    "test vector 1 chain m/0/1/2/2/1000000000",
			master:  testVec1MasterPubKey,
			path:    []uint32{0, 1, 2, 2, 1000000000},
			wantPub: "xpub6GX3zWVgSgPc5tgjE6ogT9nfwSADD3tdsxpzd7jJoJMqSY12Be6VQEFwDCp6wAQoZsH2iq5nNocHEaVDxBcobPrkZCjYW3QUmoDYzMFBDu9",
		},

		// Test vector 2
		{
			name:    "test vector 2 chain m",
			master:  testVec2MasterPubKey,
			path:    []uint32{},
			wantPub: "xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB",
		},
		{
			name:    "test vector 2 chain m/0",
			master:  testVec2MasterPubKey,
			path:    []uint32{0},
			wantPub: "xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH",
		},
		{
			name:    "test vector 2 chain m/0/2147483647",
			master:  testVec2MasterPubKey,
			path:    []uint32{0, 2147483647},
			wantPub: "xpub6ASAVgeWMg4pmutghzHG3BohahjwNwPmy2DgM6W9wGegtPrvNgjBwuZRD7hSDFhYfunq8vDgwG4ah1gVzZysgp3UsKz7VNjCnSUJJ5T4fdD",
		},
		{
			name:    "test vector 2 chain m/0/2147483647/1",
			master:  testVec2MasterPubKey,
			path:    []uint32{0, 2147483647, 1},
			wantPub: "xpub6CrnV7NzJy4VdgP5niTpqWJiFXMAca6qBm5Hfsry77SQmN1HGYHnjsZSujoHzdxf7ZNK5UVrmDXFPiEW2ecwHGWMFGUxPC9ARipss9rXd4b",
		},
		{
			name:    "test vector 2 chain m/0/2147483647/1/2147483646",
			master:  testVec2MasterPubKey,
			path:    []uint32{0, 2147483647, 1, 2147483646},
			wantPub: "xpub6FL2423qFaWzHCvBndkN9cbkn5cysiUeFq4eb9t9kE88jcmY63tNuLNRzpHPdAM4dUpLhZ7aUm2cJ5zF7KYonf4jAPfRqTMTRBNkQL3Tfta",
		},
		{
			name:    "test vector 2 chain m/0/2147483647/1/2147483646/2",
			master:  testVec2MasterPubKey,
			path:    []uint32{0, 2147483647, 1, 2147483646, 2},
			wantPub: "xpub6H7WkJf547AiSwAbX6xsm8Bmq9M9P1Gjequ5SipsjipWmtXSyp4C3uwzewedGEgAMsDy4jEvNTWtxLyqqHY9C12gaBmgUdk2CGmwachwnWK",
		},
	}

tests:
	for i, test := range tests {
		extKey, err := NewKeyFromString(ksrv.NewHDSeedRequest_Secp256k1, test.master)
		if err != nil {
			t.Errorf("NewKeyFromString #%d (%s): unexpected error "+
				"creating extended key: %v", i, test.name,
				err)
			continue
		}

		for _, childNum := range test.path {
			var err error
			extKey, err = extKey.Child(childNum)
			if err != nil {
				t.Errorf("err: %v", err)
				continue tests
			}
		}

		extKeyEcc, ok := extKey.(*ExtendedKeyEcc)
		assert.Equal(t, ok, true)
		pubStr := extKeyEcc.String()
		if pubStr != test.wantPub {
			t.Errorf("Child #%d (%s): mismatched serialized "+
				"public extended key -- got: %s, want: %s", i,
				test.name, pubStr, test.wantPub)
			continue
		}
	}
}

// TestGenenerateSeed ensures the GenerateSeed function works as intended.
func TestGenenerateSeed(t *testing.T) {
	wantErr := errors.New("seed length must be between 128 and 512 bits")

	tests := []struct {
		name   string
		length uint8
		err    error
	}{
		// Test various valid lengths.
		{name: "16 bytes", length: 16},
		{name: "17 bytes", length: 17},
		{name: "20 bytes", length: 20},
		{name: "32 bytes", length: 32},
		{name: "64 bytes", length: 64},

		// Test invalid lengths.
		{name: "15 bytes", length: 15, err: wantErr},
		{name: "65 bytes", length: 65, err: wantErr},
	}

	for i, test := range tests {
		seed, err := GenerateSeed(test.length)
		if !reflect.DeepEqual(err, test.err) {
			t.Errorf("GenerateSeed #%d (%s): unexpected error -- "+
				"want %v, got %v", i, test.name, test.err, err)
			continue
		}

		if test.err == nil && len(seed) != int(test.length) {
			t.Errorf("GenerateSeed #%d (%s): length mismatch -- "+
				"got %d, want %d", i, test.name, len(seed),
				test.length)
			continue
		}
	}
}

// TestExtendedKeyAPI ensures the API on the ExtendedKey type works as intended.
func TestExtendedKeyAPI(t *testing.T) {
	tests := []struct {
		name       string
		extKey     string
		isPrivate  bool
		parentFP   uint32
		privKey    string
		privKeyErr error
		pubKey     string
		address    string
	}{
		{
			name:      "test vector 1 master node private",
			extKey:    "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi",
			isPrivate: true,
			parentFP:  0,
			privKey:   "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35",
			pubKey:    "0339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2",
			address:   "15mKKb2eos1hWa6tisdPwwDC1a5J1y9nma",
		},
		{
			name:       "test vector 1 chain m/0H/1/2H public",
			extKey:     "xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5",
			isPrivate:  false,
			parentFP:   3203769081,
			privKeyErr: ErrNotPrivExtKey,
			pubKey:     "0357bfe1e341d01c69fe5654309956cbea516822fba8a601743a012a7896ee8dc2",
			address:    "1NjxqbA9aZWnh17q1UW3rB4EPu79wDXj7x",
		},
	}

	for i, test := range tests {
		key, err := NewKeyFromString(ksrv.NewHDSeedRequest_Secp256k1, test.extKey)
		if err != nil {
			t.Errorf("NewKeyFromString #%d (%s): unexpected "+
				"error: %v", i, test.name, err)
			continue
		}

		if key.IsPrivate() != test.isPrivate {
			t.Errorf("IsPrivate #%d (%s): mismatched key type -- "+
				"want private %v, got private %v", i, test.name,
				test.isPrivate, key.IsPrivate())
			continue
		}

		parentFP := key.ParentFingerprint()
		if parentFP != test.parentFP {
			t.Errorf("ParentFingerprint #%d (%s): mismatched "+
				"parent fingerprint -- want %d, got %d", i,
				test.name, test.parentFP, parentFP)
			continue
		}

		keyEcc, ok := key.(*ExtendedKeyEcc)
		assert.Equal(t, ok, true)
		serializedKey := keyEcc.String()
		if serializedKey != test.extKey {
			t.Errorf("String #%d (%s): mismatched serialized key "+
				"-- want %s, got %s", i, test.name, test.extKey,
				serializedKey)
			continue
		}

		privKey, err := key.ECPrivKey()
		if !reflect.DeepEqual(err, test.privKeyErr) {
			t.Errorf("ECPrivKey #%d (%s): mismatched error: want "+
				"%v, got %v", i, test.name, test.privKeyErr, err)
			continue
		}
		if test.privKeyErr == nil {
			privKeyStr := hex.EncodeToString(privKey)
			if privKeyStr != test.privKey {
				t.Errorf("ECPrivKey #%d (%s): mismatched "+
					"private key -- want %s, got %s", i,
					test.name, test.privKey, privKeyStr)
				continue
			}
		}

		pubKey, err := key.ECPubKey()
		if err != nil {
			t.Errorf("ECPubKey #%d (%s): unexpected error: %v", i,
				test.name, err)
			continue
		}
		pubKeyStr := hex.EncodeToString(pubKey)
		if pubKeyStr != test.pubKey {
			t.Errorf("ECPubKey #%d (%s): mismatched public key -- "+
				"want %s, got %s", i, test.name, test.pubKey,
				pubKeyStr)
			continue
		}

		addr, err := key.(*ExtendedKeyEcc).Address(&chaincfg.MainNetParams)
		if err != nil {
			t.Errorf("Address #%d (%s): unexpected error: %v", i,
				test.name, err)
			continue
		}
		if addr.EncodeAddress() != test.address {
			t.Errorf("Address #%d (%s): mismatched address -- want "+
				"%s, got %s", i, test.name, test.address,
				addr.EncodeAddress())
			continue
		}
	}
}

// TestNet ensures the network related APIs work as intended.
func TestNet(t *testing.T) {
	tests := []struct {
		name      string
		key       string
		origNet   *chaincfg.Params
		newNet    *chaincfg.Params
		newPriv   string
		newPub    string
		isPrivate bool
	}{
		// Private extended keys.
		{
			name:      "mainnet -> simnet",
			key:       "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi",
			origNet:   &chaincfg.MainNetParams,
			newNet:    &chaincfg.SimNetParams,
			newPriv:   "sprv8Erh3X3hFeKunvVdAGQQtambRPapECWiTDtvsTGdyrhzhbYgnSZajRRWbihzvq4AM4ivm6uso31VfKaukwJJUs3GYihXP8ebhMb3F2AHu3P",
			newPub:    "spub4Tr3T2ab61tD1Qa6GHwRFiiKyRRJdfEZpSpXfqgFYCEyaPsqKysqHDjzSzMJSiUEGbcsG3w2SLMoTqn44B8x6u3MLRRkYfACTUBnHK79THk",
			isPrivate: true,
		},
		{
			name:      "simnet -> mainnet",
			key:       "sprv8Erh3X3hFeKunvVdAGQQtambRPapECWiTDtvsTGdyrhzhbYgnSZajRRWbihzvq4AM4ivm6uso31VfKaukwJJUs3GYihXP8ebhMb3F2AHu3P",
			origNet:   &chaincfg.SimNetParams,
			newNet:    &chaincfg.MainNetParams,
			newPriv:   "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi",
			newPub:    "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8",
			isPrivate: true,
		},
		{
			name:      "mainnet -> regtest",
			key:       "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi",
			origNet:   &chaincfg.MainNetParams,
			newNet:    &chaincfg.RegressionNetParams,
			newPriv:   "tprv8ZgxMBicQKsPeDgjzdC36fs6bMjGApWDNLR9erAXMs5skhMv36j9MV5ecvfavji5khqjWaWSFhN3YcCUUdiKH6isR4Pwy3U5y5egddBr16m",
			newPub:    "tpubD6NzVbkrYhZ4XgiXtGrdW5XDAPFCL9h7we1vwNCpn8tGbBcgfVYjXyhWo4E1xkh56hjod1RhGjxbaTLV3X4FyWuejifB9jusQ46QzG87VKp",
			isPrivate: true,
		},
		{
			name:      "regtest -> mainnet",
			key:       "tprv8ZgxMBicQKsPeDgjzdC36fs6bMjGApWDNLR9erAXMs5skhMv36j9MV5ecvfavji5khqjWaWSFhN3YcCUUdiKH6isR4Pwy3U5y5egddBr16m",
			origNet:   &chaincfg.RegressionNetParams,
			newNet:    &chaincfg.MainNetParams,
			newPriv:   "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi",
			newPub:    "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8",
			isPrivate: true,
		},

		// Public extended keys.
		{
			name:      "mainnet -> simnet",
			key:       "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8",
			origNet:   &chaincfg.MainNetParams,
			newNet:    &chaincfg.SimNetParams,
			newPub:    "spub4Tr3T2ab61tD1Qa6GHwRFiiKyRRJdfEZpSpXfqgFYCEyaPsqKysqHDjzSzMJSiUEGbcsG3w2SLMoTqn44B8x6u3MLRRkYfACTUBnHK79THk",
			isPrivate: false,
		},
		{
			name:      "simnet -> mainnet",
			key:       "spub4Tr3T2ab61tD1Qa6GHwRFiiKyRRJdfEZpSpXfqgFYCEyaPsqKysqHDjzSzMJSiUEGbcsG3w2SLMoTqn44B8x6u3MLRRkYfACTUBnHK79THk",
			origNet:   &chaincfg.SimNetParams,
			newNet:    &chaincfg.MainNetParams,
			newPub:    "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8",
			isPrivate: false,
		},
		{
			name:      "mainnet -> regtest",
			key:       "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8",
			origNet:   &chaincfg.MainNetParams,
			newNet:    &chaincfg.RegressionNetParams,
			newPub:    "tpubD6NzVbkrYhZ4XgiXtGrdW5XDAPFCL9h7we1vwNCpn8tGbBcgfVYjXyhWo4E1xkh56hjod1RhGjxbaTLV3X4FyWuejifB9jusQ46QzG87VKp",
			isPrivate: false,
		},
		{
			name:      "regtest -> mainnet",
			key:       "tpubD6NzVbkrYhZ4XgiXtGrdW5XDAPFCL9h7we1vwNCpn8tGbBcgfVYjXyhWo4E1xkh56hjod1RhGjxbaTLV3X4FyWuejifB9jusQ46QzG87VKp",
			origNet:   &chaincfg.RegressionNetParams,
			newNet:    &chaincfg.MainNetParams,
			newPub:    "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8",
			isPrivate: false,
		},
	}

	for i, test := range tests {
		extKey, err := NewKeyFromString(ksrv.NewHDSeedRequest_Secp256k1, test.key)
		if err != nil {
			t.Errorf("NewKeyFromString #%d (%s): unexpected error "+
				"creating extended key: %v", i, test.name,
				err)
			continue
		}

		if !extKey.IsForNet(test.origNet) {
			t.Errorf("IsForNet #%d (%s): key is not for expected "+
				"network %v", i, test.name, test.origNet.Name)
			continue
		}

		extKey.SetNet(test.newNet)
		if !extKey.IsForNet(test.newNet) {
			t.Errorf("SetNet/IsForNet #%d (%s): key is not for "+
				"expected network %v", i, test.name,
				test.newNet.Name)
			continue
		}

		if test.isPrivate {
			extKeyEcc, ok := extKey.(*ExtendedKeyEcc)
			assert.Equal(t, ok, true)
			privStr := extKeyEcc.String()
			if privStr != test.newPriv {
				t.Errorf("Serialize #%d (%s): mismatched serialized "+
					"private extended key -- got: %s, want: %s", i,
					test.name, privStr, test.newPriv)
				continue
			}

			extKey, err = extKey.Neuter()
			if err != nil {
				t.Errorf("Neuter #%d (%s): unexpected error: %v ", i,
					test.name, err)
				continue
			}
		}

		extKeyEcc, ok := extKey.(*ExtendedKeyEcc)
		assert.Equal(t, ok, true)
		pubStr := extKeyEcc.String()
		if pubStr != test.newPub {
			t.Errorf("Neuter #%d (%s): mismatched serialized "+
				"public extended key -- got: %s, want: %s", i,
				test.name, pubStr, test.newPub)
			continue
		}
	}
}

// TestErrors performs some negative tests for various invalid cases to ensure
// the errors are handled properly.
func TestErrors(t *testing.T) {
	// Should get an error when seed has too few bytes.
	net := &chaincfg.MainNetParams
	_, err := NewMaster(ksrv.NewHDSeedRequest_Secp256k1, bytes.Repeat([]byte{0x00}, 15), net)
	if err != ErrInvalidSeedLen {
		t.Fatalf("NewMaster: mismatched error -- got: %v, want: %v",
			err, ErrInvalidSeedLen)
	}

	// Should get an error when seed has too many bytes.
	_, err = NewMaster(ksrv.NewHDSeedRequest_Secp256k1, bytes.Repeat([]byte{0x00}, 65), net)
	if err != ErrInvalidSeedLen {
		t.Fatalf("NewMaster: mismatched error -- got: %v, want: %v",
			err, ErrInvalidSeedLen)
	}

	// Generate a new key and neuter it to a public extended key.
	seed, err := GenerateSeed(RecommendedSeedLen)
	if err != nil {
		t.Fatalf("GenerateSeed: unexpected error: %v", err)
	}
	extKey, err := NewMaster(ksrv.NewHDSeedRequest_Secp256k1, seed, net)
	if err != nil {
		t.Fatalf("NewMaster: unexpected error: %v", err)
	}
	pubKey, err := extKey.Neuter()
	if err != nil {
		t.Fatalf("Neuter: unexpected error: %v", err)
	}

	// Deriving a hardened child extended key should fail from a public key.
	_, err = pubKey.Child(HardenedKeyStart)
	if err != ErrDeriveHardFromPublic {
		t.Fatalf("Child: mismatched error -- got: %v, want: %v",
			err, ErrDeriveHardFromPublic)
	}

	// NewKeyFromString failure tests.
	tests := []struct {
		name      string
		key       string
		err       error
		neuter    bool
		neuterErr error
	}{
		{
			name: "invalid key length",
			key:  "xpub1234",
			err:  ErrInvalidXKey,
		},
		{
			name: "bad checksum",
			key:  "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EBygr15",
			err:  ErrBadChecksum,
		},
		{
			name: "pubkey not on curve",
			key:  "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ1hr9Rwbk95YadvBkQXxzHBSngB8ndpW6QH7zhhsXZ2jHyZqPjk",
			err:  errors.New("invalid square root"),
		},
		{
			name:      "unsupported version",
			key:       "xbad4LfUL9eKmA66w2GJdVMqhvDmYGJpTGjWRAtjHqoUY17sGaymoMV9Cm3ocn9Ud6Hh2vLFVC7KSKCRVVrqc6dsEdsTjRV1WUmkK85YEUujAPX",
			err:       nil,
			neuter:    true,
			neuterErr: chaincfg.ErrUnknownHDKeyID,
		},
	}

	for i, test := range tests {
		extKey, err := NewKeyFromString(ksrv.NewHDSeedRequest_Secp256k1, test.key)
		if !reflect.DeepEqual(err, test.err) {
			t.Errorf("NewKeyFromString #%d (%s): mismatched error "+
				"-- got: %v, want: %v", i, test.name, err,
				test.err)
			continue
		}

		if test.neuter {
			_, err := extKey.Neuter()
			if !reflect.DeepEqual(err, test.neuterErr) {
				t.Errorf("Neuter #%d (%s): mismatched error "+
					"-- got: %v, want: %v", i, test.name,
					err, test.neuterErr)
				continue
			}
		}
	}
}

// TestZero ensures that zeroing an extended key works as intended.
func TestZero(t *testing.T) {
	tests := []struct {
		name   string
		master string
		extKey string
		net    *chaincfg.Params
	}{
		// Test vector 1
		{
			name:   "test vector 1 chain m",
			master: "000102030405060708090a0b0c0d0e0f",
			extKey: "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi",
			net:    &chaincfg.MainNetParams,
		},

		// Test vector 2
		{
			name:   "test vector 2 chain m",
			master: "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542",
			extKey: "xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U",
			net:    &chaincfg.MainNetParams,
		},
	}

	// Use a closure to test that a key is zeroed since the tests create
	// keys in different ways and need to test the same things multiple
	// times.
	testZeroed := func(i int, testName string, key ExtendedKey) bool {
		// Zeroing a key should result in it no longer being private
		if key.IsPrivate() {
			t.Errorf("IsPrivate #%d (%s): mismatched key type -- "+
				"want private %v, got private %v", i, testName,
				false, key.IsPrivate())
			return false
		}

		parentFP := key.ParentFingerprint()
		if parentFP != 0 {
			t.Errorf("ParentFingerprint #%d (%s): mismatched "+
				"parent fingerprint -- want %d, got %d", i,
				testName, 0, parentFP)
			return false
		}

		wantKey := "zeroed extended key"
		keyEcc, ok := key.(*ExtendedKeyEcc)
		assert.Equal(t, ok, true)
		serializedKey := keyEcc.String()
		if serializedKey != wantKey {
			t.Errorf("String #%d (%s): mismatched serialized key "+
				"-- want %s, got %s", i, testName, wantKey,
				serializedKey)
			return false
		}

		wantErr := ErrNotPrivExtKey
		_, err := key.ECPrivKey()
		if !reflect.DeepEqual(err, wantErr) {
			t.Errorf("ECPrivKey #%d (%s): mismatched error: want "+
				"%v, got %v", i, testName, wantErr, err)
			return false
		}

		wantErr = errors.New("pubkey string is empty")
		_, err = key.ECPubKey()
		if !reflect.DeepEqual(err, wantErr) {
			t.Errorf("ECPubKey #%d (%s): mismatched error: want "+
				"%v, got %v", i, testName, wantErr, err)
			return false
		}

		wantAddr := "1HT7xU2Ngenf7D4yocz2SAcnNLW7rK8d4E"
		addr, err := key.(*ExtendedKeyEcc).Address(&chaincfg.MainNetParams)
		if err != nil {
			t.Errorf("Addres s #%d (%s): unexpected error: %v", i,
				testName, err)
			return false
		}
		if addr.EncodeAddress() != wantAddr {
			t.Errorf("Address #%d (%s): mismatched address -- want "+
				"%s, got %s", i, testName, wantAddr,
				addr.EncodeAddress())
			return false
		}

		return true
	}

	for i, test := range tests {
		// Create new key from seed and get the neutered version.
		masterSeed, err := hex.DecodeString(test.master)
		if err != nil {
			t.Errorf("DecodeString #%d (%s): unexpected error: %v",
				i, test.name, err)
			continue
		}
		key, err := NewMaster(ksrv.NewHDSeedRequest_Secp256k1, masterSeed, test.net)
		if err != nil {
			t.Errorf("NewMaster #%d (%s): unexpected error when "+
				"creating new master key: %v", i, test.name,
				err)
			continue
		}
		neuteredKey, err := key.Neuter()
		if err != nil {
			t.Errorf("Neuter #%d (%s): unexpected error: %v", i,
				test.name, err)
			continue
		}

		// Ensure both non-neutered and neutered keys are zeroed
		// properly.
		key.Zero()
		if !testZeroed(i, test.name+" from seed not neutered", key) {
			continue
		}
		neuteredKey.Zero()
		if !testZeroed(i, test.name+" from seed neutered", key) {
			continue
		}

		// Deserialize key and get the neutered version.
		key, err = NewKeyFromString(ksrv.NewHDSeedRequest_Secp256k1, test.extKey)
		if err != nil {
			t.Errorf("NewKeyFromString #%d (%s): unexpected "+
				"error: %v", i, test.name, err)
			continue
		}
		neuteredKey, err = key.Neuter()
		if err != nil {
			t.Errorf("Neuter #%d (%s): unexpected error: %v", i,
				test.name, err)
			continue
		}

		// Ensure both non-neutered and neutered keys are zeroed
		// properly.
		key.Zero()
		if !testZeroed(i, test.name+" deserialized not neutered", key) {
			continue
		}
		neuteredKey.Zero()
		if !testZeroed(i, test.name+" deserialized neutered", key) {
			continue
		}
	}
}

// TestMaximumDepth ensures that attempting to retrieve a child key when already
// at the maximum depth is not allowed.  The serialization of a BIP32 key uses
// uint8 to encode the depth.  This implicitly bounds the depth of the tree to
// 255 derivations.  Here we test that an error is returned after 'max uint8'.
func TestMaximumDepth(t *testing.T) {
	net := &chaincfg.MainNetParams
	extKey, err := NewMaster(ksrv.NewHDSeedRequest_Secp256k1, []byte(`abcd1234abcd1234abcd1234abcd1234`), net)
	if err != nil {
		t.Fatalf("NewMaster: unexpected error: %v", err)
	}

	for i := uint8(0); i < math.MaxUint8; i++ {
		if extKey.Depth() != i {
			t.Fatalf("extendedkey depth %d should match expected value %d",
				extKey.Depth(), i)
		}
		newKey, err := extKey.Child(1)
		if err != nil {
			t.Fatalf("Child: unexpected error: %v", err)
		}
		extKey = newKey
	}

	noKey, err := extKey.Child(1)
	if err != ErrDeriveBeyondMaxDepth {
		t.Fatalf("Child: mismatched error: want %v, got %v",
			ErrDeriveBeyondMaxDepth, err)
	}
	if noKey != nil {
		t.Fatal("Child: deriving 256th key should not succeed")
	}
}

func TestExtendedKey_ChildNumber(t *testing.T) {
	type fields struct {
		childNum uint32
	}
	tests := []struct {
		name   string
		fields fields
		want   []byte
	}{
		{
			name:   "1",
			fields: fields{1},
			want:   []byte{0, 0, 0, 1},
		},
		{
			name:   "1",
			fields: fields{10},
			want:   []byte{0, 0, 0, 10},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k := &ExtendedKeyEcc{
				ChildNum: tt.fields.childNum,
			}
			if got := k.ChildNumber(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ExtendedKey.ChildNumber() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestExtendedKey_Key(t *testing.T) {
	a := make([]byte, 32-3)
	a = append(a, 1, 2, 3)
	type fields struct {
		key []byte
	}
	tests := []struct {
		name   string
		fields fields
		want   []byte
	}{
		{"1", fields{[]byte{1, 2, 3}}, a},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k, _ := NewExtendedKeyExt(ksrv.NewHDSeedRequest_pastaSchnorrMina, nil, tt.fields.key, nil, nil, 0, 0, true)
			if got := k.Key(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ExtendedKey.Key() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestExtendedKey_ChainCode(t *testing.T) {
	type fields struct {
		chainCode []byte
	}
	tests := []struct {
		name   string
		fields fields
		want   []byte
	}{
		{"1", fields{[]byte{1, 2, 3}}, []byte{1, 2, 3}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k := &ExtendedKeyEcc{
				ChainCodeB: tt.fields.chainCode,
			}
			if got := k.ChainCode(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ExtendedKey.ChainCode() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestExtendedKey_Version(t *testing.T) {
	type fields struct {
		version []byte
	}
	tests := []struct {
		name   string
		fields fields
		want   []byte
	}{
		{"1", fields{[]byte{1, 2, 3}}, []byte{1, 2, 3}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k := &ExtendedKeyEcc{
				VersionB: tt.fields.version,
			}
			if got := k.Version(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ExtendedKey.Version() = %v, want %v", got, tt.want)
			}
		})
	}
}
