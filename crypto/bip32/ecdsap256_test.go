// Copyright (c) 2014-2017 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package bip32

import (
	"encoding/hex"
	"math"
	"reflect"
	"testing"

	"git.liebaopay.com/ksrv/keyserver/ksrv"
	"github.com/bmizerany/assert"
	"github.com/btcsuite/btcd/chaincfg"
)

const alg = ksrv.NewHDSeedRequest_Secp256r1

// TestBIP0032Vectors tests the vectors provided by [BIP32] to ensure the
// derivation works as intended.
func TestBIP0032VectorsP256(t *testing.T) {
	// The master seeds for each of the two test vectors in [BIP32].
	testVec1MasterHex := "000102030405060708090a0b0c0d0e0f"
	testVec2MasterHex := "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542"
	testVec3MasterHex := "4b381541583be4423346c643850da4b320e46a87ae3d2a4e6da11eba819cd4acba45d239319ac14f863b8d5ab5a0d0c64d2e8a1e7d1457df2e5a3c51c73235be"
	hkStart := uint32(0x80000000)

	tests := []struct {
		name        string
		master      string
		path        []uint32
		wantPubHex  string
		wantPrivHex string
		net         *chaincfg.Params
	}{
		// Test vector 1
		{
			name:        "test vector 1 chain m",
			master:      testVec1MasterHex,
			path:        []uint32{},
			wantPubHex:  "0488b21e000000000000000000873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d5080314affa492c60963f9521376771544907ed98b6afca1a508712e1210089f9d63000",
			wantPrivHex: "0488ade4000000000000000000873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d50800e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b3501",
			net:         &chaincfg.MainNetParams,
		},
		{
			name:        "test vector 1 chain m/0H",
			master:      testVec1MasterHex,
			path:        []uint32{hkStart},
			wantPubHex:  "0488b21e01b6c19e5b8000000047fdacbd0f1097043b78c63c20c34ef4ed9a111d980047ad16282c7ae623614103e4e6cb0bc650ac3c4008eaeea1b9d16e1c80a51c00631d5476b14b044308c8ab00",
			wantPrivHex: "0488ade401b6c19e5b8000000047fdacbd0f1097043b78c63c20c34ef4ed9a111d980047ad16282c7ae623614100edb2e14f9ee77d26dd93b4ecede8d16ed408ce149b6cd80b0715a2d911a0afea01",
			net:         &chaincfg.MainNetParams,
		},
		{
			name:        "test vector 1 chain m/0H/1",
			master:      testVec1MasterHex,
			path:        []uint32{hkStart, 1},
			wantPubHex:  "0488b21e02bc7f9516000000010eb6b8243a372f98e712f99ef64ba18130eb6f23e99f1c7f2008816c4be2a6b00208066f7bad8c8c6b65ced4a6132f93675552402fc78a24852c32fc0f967040eb00",
			wantPrivHex: "0488ade402bc7f9516000000010eb6b8243a372f98e712f99ef64ba18130eb6f23e99f1c7f2008816c4be2a6b000169032b76929a8948ca798c848e7988e6db07ab50b86b3466dabe0f0ca59e67201",
			net:         &chaincfg.MainNetParams,
		},
		{
			name:        "test vector 1 chain m/0H/1/2H",
			master:      testVec1MasterHex,
			path:        []uint32{hkStart, 1, hkStart + 2},
			wantPubHex:  "0488b21e03d90e2a8f80000002b21f1cd3ff142428463c45025c3d5b06ac57ff47c9c887703a4a4a57be6a1a9e0335809381c886b5ece1a62446d69ef54726ffd179ee1f1d5c5c957d2d436ee1fa00",
			wantPrivHex: "0488ade403d90e2a8f80000002b21f1cd3ff142428463c45025c3d5b06ac57ff47c9c887703a4a4a57be6a1a9e00b9f7297a2f9dded4bf4c379f2a84aa5d14098659d628da40106e1946acfc843201",
			net:         &chaincfg.MainNetParams,
		},
		{
			name:        "test vector 1 chain m/0H/1/2H/2",
			master:      testVec1MasterHex,
			path:        []uint32{hkStart, 1, hkStart + 2, 2},
			wantPubHex:  "0488b21e0476434a280000000264cbcb475e87575e8e065141fd1250f20260937e9c8fdff07f6ca6ac0d2f67e60299ef5471dd384a45f76ff72de030232ef89f1bba160284a21ff9ef575b51a52f00",
			wantPrivHex: "0488ade40476434a280000000264cbcb475e87575e8e065141fd1250f20260937e9c8fdff07f6ca6ac0d2f67e600f2aa70b3f23afe1a470956625569c9576b67d7024b2c1ddb8742375be363496b01",
			net:         &chaincfg.MainNetParams,
		},
		{
			name:        "test vector 1 chain m/0H/1/2H/2/1000000000",
			master:      testVec1MasterHex,
			path:        []uint32{hkStart, 1, hkStart + 2, 2, 1000000000},
			wantPubHex:  "0488b21e055c752ddc3b9aca002af0ffde47b4b49b255e3545116a2df857d95d54c5db607841231b70e02b60f5030bbefae497d68751cce6634bc670c83f4f92f881b74f7dd03aabc30b92c1d20100",
			wantPrivHex: "0488ade4055c752ddc3b9aca002af0ffde47b4b49b255e3545116a2df857d95d54c5db607841231b70e02b60f500cc5fc9e20c05fb09e99d4f39c71242d6dba2f396019b0296a842c79c0cd9202401",
			net:         &chaincfg.MainNetParams,
		},

		// Test vector 2
		{
			name:        "test vector 2 chain m",
			master:      testVec2MasterHex,
			path:        []uint32{},
			wantPubHex:  "0488b21e00000000000000000060499f801b896d83179a4374aeb7822aaeaceaa0db1f85ee3e904c4defbd968903be91f902298e2d5131377399251de50982f99ad60516b8592a95bb6fb71582a700",
			wantPrivHex: "0488ade400000000000000000060499f801b896d83179a4374aeb7822aaeaceaa0db1f85ee3e904c4defbd9689004b03d6fc340455b363f51020ad3ecca4f0850280cf436c70c727923f6db46c3e01",
			net:         &chaincfg.MainNetParams,
		},
		{
			name:        "test vector 2 chain m/0",
			master:      testVec2MasterHex,
			path:        []uint32{0},
			wantPubHex:  "0488b21e0149ba82d100000000803411e2255bb5d0deb2c60dd48fabe78758e32201b0ef19fa50618b2f109ca20310b4aa732ec2dd34d949512f03445728c6a325685976ce5fc7a3601a83fce44900",
			wantPrivHex: "0488ade40149ba82d100000000803411e2255bb5d0deb2c60dd48fabe78758e32201b0ef19fa50618b2f109ca200a6b620cd2a6fcc22986429a322b5d57aff7d7874b25b0d8d793fa5338f66a25d01",
			net:         &chaincfg.MainNetParams,
		},
		{
			name:        "test vector 2 chain m/0/2147483647H",
			master:      testVec2MasterHex,
			path:        []uint32{0, hkStart + 2147483647},
			wantPubHex:  "0488b21e0248049054fffffffffda5cf2aa21f22ad07a45dc2c4c50f4c80b388e470bec8d000d83b2df8ceb84e032e16926f05d938c5c4d5e6851e87fe32dc0763082661a3ad9665b93629c661ac00",
			wantPrivHex: "0488ade40248049054fffffffffda5cf2aa21f22ad07a45dc2c4c50f4c80b388e470bec8d000d83b2df8ceb84e0057116986c8445bdcbb0e8d6bcfaf3268810b094f71e762f1c176f5e6a66dbdb601",
			net:         &chaincfg.MainNetParams,
		},
		{
			name:        "test vector 2 chain m/0/2147483647H/1",
			master:      testVec2MasterHex,
			path:        []uint32{0, hkStart + 2147483647, 1},
			wantPubHex:  "0488b21e03238da30400000001edf36492ecc528a57301ba1017f6413834aeaa13111a60c3e50fa4348160d229028f515def4b084bb56fc78ad8cc4e0d0fe78abf5d66b268c3c1bedf78864272c100",
			wantPrivHex: "0488ade403238da30400000001edf36492ecc528a57301ba1017f6413834aeaa13111a60c3e50fa4348160d22900f3b2c54121720415ea240fc0cf941bf4ee7604cf17dd9788b8b2a856ab952e8901",
			net:         &chaincfg.MainNetParams,
		},
		{
			name:        "test vector 2 chain m/0/2147483647H/1/2147483646H",
			master:      testVec2MasterHex,
			path:        []uint32{0, hkStart + 2147483647, 1, hkStart + 2147483646},
			wantPubHex:  "0488b21e04992bde14fffffffeb089deecc85f6aa69d1fc1852b4d1d866c0c28d9da15be5952f4f10d4c5a81bc020ed89abe78dd07b3e4a3ea4bdc3e81cb382a9c6e0cde65259d5ecee8e542e46b00",
			wantPrivHex: "0488ade404992bde14fffffffeb089deecc85f6aa69d1fc1852b4d1d866c0c28d9da15be5952f4f10d4c5a81bc0065b0bfdda6738544264a80c8b45b57970ae38b908233c59d50e9fc7096ea106401",
			net:         &chaincfg.MainNetParams,
		},
		{
			name:        "test vector 2 chain m/0/2147483647H/1/2147483646H/2",
			master:      testVec2MasterHex,
			path:        []uint32{0, hkStart + 2147483647, 1, hkStart + 2147483646, 2},
			wantPubHex:  "0488b21e05d4d607b5000000023f13f4edea113c53cb8b0d5bd82e441524d1c28f039016611ef2de8fc2412ea502ce06fe7b99dca9aeaaf7bf5b21ad94bdb72a552ff68fbc36cc744941cd4c9bfd00",
			wantPrivHex: "0488ade405d4d607b5000000023f13f4edea113c53cb8b0d5bd82e441524d1c28f039016611ef2de8fc2412ea50037af7c81ab4af6e36a6c7292d0d1c7c723d06204144eb365278999f578e1ff1501",
			net:         &chaincfg.MainNetParams,
		},

		// Test vector 3
		{
			name:        "test vector 3 chain m",
			master:      testVec3MasterHex,
			path:        []uint32{},
			wantPubHex:  "0488b21e00000000000000000001d28a3e53cffa419ec122c968b3259e16b65076495494d97cae10bbfec3c36f02556640d65d4ae0ee407e7774e63097d3d6cc8749858b52b0fe0e87eec25e20c200",
			wantPrivHex: "0488ade400000000000000000001d28a3e53cffa419ec122c968b3259e16b65076495494d97cae10bbfec3c36f0000ddb80b067e0d4993197fe10f2657a844a384589847602d56f0c629c81aae3201",
			net:         &chaincfg.MainNetParams,
		},
		{
			name:        "test vector 3 chain m/0H",
			master:      testVec3MasterHex,
			path:        []uint32{hkStart},
			wantPubHex:  "0488b21e0117eaf08280000000e5fea12a97b927fc9dc3d2cb0d1ea1cf50aa5a1fdc1f933e8906bb38df3377bd02d67dc2c390bf4e8616d7b5d79d9cc210a2a4a6651b95ffd3f54e6f92fd04732a00",
			wantPrivHex: "0488ade40117eaf08280000000e5fea12a97b927fc9dc3d2cb0d1ea1cf50aa5a1fdc1f933e8906bb38df3377bd00491f7a2eebc7b57028e0d3faa0acda02e75c33b03c48fb288c41e2ea44e1daef01",
			net:         &chaincfg.MainNetParams,
		},

		// Test vector 1 - Testnet
		{
			name:        "test vector 1 chain m - testnet",
			master:      testVec1MasterHex,
			path:        []uint32{},
			wantPubHex:  "043587cf000000000000000000873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d5080314affa492c60963f9521376771544907ed98b6afca1a508712e1210089f9d63000",
			wantPrivHex: "04358394000000000000000000873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d50800e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b3501",
			net:         &chaincfg.TestNet3Params,
		},
		{
			name:        "test vector 1 chain m/0H - testnet",
			master:      testVec1MasterHex,
			path:        []uint32{hkStart},
			wantPubHex:  "043587cf01b6c19e5b8000000047fdacbd0f1097043b78c63c20c34ef4ed9a111d980047ad16282c7ae623614103e4e6cb0bc650ac3c4008eaeea1b9d16e1c80a51c00631d5476b14b044308c8ab00",
			wantPrivHex: "0435839401b6c19e5b8000000047fdacbd0f1097043b78c63c20c34ef4ed9a111d980047ad16282c7ae623614100edb2e14f9ee77d26dd93b4ecede8d16ed408ce149b6cd80b0715a2d911a0afea01",
			net:         &chaincfg.TestNet3Params,
		},
		{
			name:        "test vector 1 chain m/0H/1 - testnet",
			master:      testVec1MasterHex,
			path:        []uint32{hkStart, 1},
			wantPubHex:  "043587cf02bc7f9516000000010eb6b8243a372f98e712f99ef64ba18130eb6f23e99f1c7f2008816c4be2a6b00208066f7bad8c8c6b65ced4a6132f93675552402fc78a24852c32fc0f967040eb00",
			wantPrivHex: "0435839402bc7f9516000000010eb6b8243a372f98e712f99ef64ba18130eb6f23e99f1c7f2008816c4be2a6b000169032b76929a8948ca798c848e7988e6db07ab50b86b3466dabe0f0ca59e67201",
			net:         &chaincfg.TestNet3Params,
		},
		{
			name:        "test vector 1 chain m/0H/1/2H - testnet",
			master:      testVec1MasterHex,
			path:        []uint32{hkStart, 1, hkStart + 2},
			wantPubHex:  "043587cf03d90e2a8f80000002b21f1cd3ff142428463c45025c3d5b06ac57ff47c9c887703a4a4a57be6a1a9e0335809381c886b5ece1a62446d69ef54726ffd179ee1f1d5c5c957d2d436ee1fa00",
			wantPrivHex: "0435839403d90e2a8f80000002b21f1cd3ff142428463c45025c3d5b06ac57ff47c9c887703a4a4a57be6a1a9e00b9f7297a2f9dded4bf4c379f2a84aa5d14098659d628da40106e1946acfc843201",
			net:         &chaincfg.TestNet3Params,
		},
		{
			name:        "test vector 1 chain m/0H/1/2H/2 - testnet",
			master:      testVec1MasterHex,
			path:        []uint32{hkStart, 1, hkStart + 2, 2},
			wantPubHex:  "043587cf0476434a280000000264cbcb475e87575e8e065141fd1250f20260937e9c8fdff07f6ca6ac0d2f67e60299ef5471dd384a45f76ff72de030232ef89f1bba160284a21ff9ef575b51a52f00",
			wantPrivHex: "043583940476434a280000000264cbcb475e87575e8e065141fd1250f20260937e9c8fdff07f6ca6ac0d2f67e600f2aa70b3f23afe1a470956625569c9576b67d7024b2c1ddb8742375be363496b01",
			net:         &chaincfg.TestNet3Params,
		},
		{
			name:        "test vector 1 chain m/0H/1/2H/2/1000000000 - testnet",
			master:      testVec1MasterHex,
			path:        []uint32{hkStart, 1, hkStart + 2, 2, 1000000000},
			wantPubHex:  "043587cf055c752ddc3b9aca002af0ffde47b4b49b255e3545116a2df857d95d54c5db607841231b70e02b60f5030bbefae497d68751cce6634bc670c83f4f92f881b74f7dd03aabc30b92c1d20100",
			wantPrivHex: "04358394055c752ddc3b9aca002af0ffde47b4b49b255e3545116a2df857d95d54c5db607841231b70e02b60f500cc5fc9e20c05fb09e99d4f39c71242d6dba2f396019b0296a842c79c0cd9202401",
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

		extKey, err := NewMaster(alg, masterSeed, test.net)
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
func TestPrivateDerivationP256(t *testing.T) {
	// The private extended keys for test vectors in [BIP32].
	testVec1MasterPrivKey, _ := hex.DecodeString("0488ade4000000000000000000873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d50800e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b3501")
	testVec2MasterPrivKey, _ := hex.DecodeString("0488ade400000000000000000060499f801b896d83179a4374aeb7822aaeaceaa0db1f85ee3e904c4defbd9689004b03d6fc340455b363f51020ad3ecca4f0850280cf436c70c727923f6db46c3e01")
	tests := []struct {
		name     string
		master   []byte
		path     []uint32
		wantPriv string
	}{
		// Test vector 1
		{
			name:     "test vector 1 chain m",
			master:   testVec1MasterPrivKey,
			path:     []uint32{},
			wantPriv: "0488ade4000000000000000000873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d50800e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b3501",
		},
		{
			name:     "test vector 1 chain m/0",
			master:   testVec1MasterPrivKey,
			path:     []uint32{0},
			wantPriv: "0488ade401b6c19e5b00000000d945fb6052631ea93b61294c5f55d5aee60f7ba41fcd17a0efadc55d17366d6800aa99fd5bdbefd92f802f278e0c8998ac0408b8afab8a77e695dcb9dc3addcc8101",
		},
		{
			name:     "test vector 1 chain m/0/1",
			master:   testVec1MasterPrivKey,
			path:     []uint32{0, 1},
			wantPriv: "0488ade4029491141000000001f8d5b5267f29684155453f6001a06a1c2c5baa2904898f581d2bae94644caff800bd4b69bd90bebb903dbb5db065a8b70dac23b3dbda5d31995f2ff6efcdae903001",
		},
		{
			name:     "test vector 1 chain m/0/1/2",
			master:   testVec1MasterPrivKey,
			path:     []uint32{0, 1, 2},
			wantPriv: "0488ade4039baa2bc3000000029db9a47cf52da2efdcb9230bd115e8f6dd6d5c8d4ff7b9015a7f555f7ce23ed50083e5143bc8365e0f45b9c0952790c7810e15c8580a0a583487874feabc86088c01",
		},
		{
			name:     "test vector 1 chain m/0/1/2/2",
			master:   testVec1MasterPrivKey,
			path:     []uint32{0, 1, 2, 2},
			wantPriv: "0488ade4044f07ae5100000002eb1a70c4798d0b27fda34782015a994ffd5fb8f8cdc6a6a3c280fef805cace25000a89373308fc1aa1ed71b686380e0c9b0fb4bea0f3ac2ec4f02f3d2f98ae0fad01",
		},
		{
			name:     "test vector 1 chain m/0/1/2/2/1000000000",
			master:   testVec1MasterPrivKey,
			path:     []uint32{0, 1, 2, 2, 1000000000},
			wantPriv: "0488ade4055d91d3583b9aca0024d994b5509d8060176a7386f238ebcec46a0a43dbd3a3366ab94aec4d0e4c0c008d7ddc65a5948028abb59177bd6127457ad52b90fa57deba86fc9b66e9fe637201",
		},

		// Test vector 2
		{
			name:     "test vector 2 chain m",
			master:   testVec2MasterPrivKey,
			path:     []uint32{},
			wantPriv: "0488ade400000000000000000060499f801b896d83179a4374aeb7822aaeaceaa0db1f85ee3e904c4defbd9689004b03d6fc340455b363f51020ad3ecca4f0850280cf436c70c727923f6db46c3e01",
		},
		{
			name:     "test vector 2 chain m/0",
			master:   testVec2MasterPrivKey,
			path:     []uint32{0},
			wantPriv: "0488ade40149ba82d100000000803411e2255bb5d0deb2c60dd48fabe78758e32201b0ef19fa50618b2f109ca200a6b620cd2a6fcc22986429a322b5d57aff7d7874b25b0d8d793fa5338f66a25d01",
		},
		{
			name:     "test vector 2 chain m/0/2147483647",
			master:   testVec2MasterPrivKey,
			path:     []uint32{0, 2147483647},
			wantPriv: "0488ade402480490547fffffff627f480abf50b95ec77b2c7953bbed49c13aa30cdd22cf7ef670d2a3c7725c6a007ab3bf707f5157250d950405a80edd99471b60636cef2277a12369c94341236401",
		},
		{
			name:     "test vector 2 chain m/0/2147483647/1",
			master:   testVec2MasterPrivKey,
			path:     []uint32{0, 2147483647, 1},
			wantPriv: "0488ade403eac6cbc800000001f9b68dc0487789069f9ebd205668751ace039056fa7571f80f89045a8b374c330083a6b33504dc33f6588b4a1859fb496866ed36e3060e693238226115ebf99e8e01",
		},
		{
			name:     "test vector 2 chain m/0/2147483647/1/2147483646",
			master:   testVec2MasterPrivKey,
			path:     []uint32{0, 2147483647, 1, 2147483646},
			wantPriv: "0488ade4046da4e81c7ffffffe2036c8558db4c9079647ece24166ad045b5fbc57d7763916f6beababa3767b7400a34895f3cd46ab07d618ffd93884b7c395ad607fba372b259a031ac5ddb1793b01",
		},
		{
			name:     "test vector 2 chain m/0/2147483647/1/2147483646/2",
			master:   testVec2MasterPrivKey,
			path:     []uint32{0, 2147483647, 1, 2147483646, 2},
			wantPriv: "0488ade405fc63a0d4000000023ddd172681ac4c8f06dcfe8504d18a475334c2c294862bc213ba5c2b71043caf00a920bbd1c36493ec292b142ebc26940a592bfb325b3d63b237b046c8f13125ee01",
		},
	}

tests:
	for i, test := range tests {
		extKey, err := FromBytes(alg, test.master)
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

		extKeyEcc, ok := extKey.(*ExtendedKeyP256)
		assert.Equal(t, ok, true)
		privStr := hex.EncodeToString(extKeyEcc.ToBytes())
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
func TestPublicDerivationP256(t *testing.T) {
	// The public extended keys for test vectors in [BIP32].
	testVec1MasterPubKey, _ := hex.DecodeString("0488b21e000000000000000000873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d5080339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c200")
	testVec2MasterPubKey, _ := hex.DecodeString("0488b21e00000000000000000060499f801b896d83179a4374aeb7822aaeaceaa0db1f85ee3e904c4defbd968903be91f902298e2d5131377399251de50982f99ad60516b8592a95bb6fb71582a700")

	tests := []struct {
		name    string
		master  []byte
		path    []uint32
		wantPub string
	}{
		// Test vector 1
		{
			name:    "test vector 1 chain m",
			master:  testVec1MasterPubKey,
			path:    []uint32{},
			wantPub: "0488b21e000000000000000000873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d5080339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c200",
		},
		{
			name:    "test vector 1 chain m/0",
			master:  testVec1MasterPubKey,
			path:    []uint32{0},
			wantPub: "0488b21e013442193e00000000d323f1be5af39a2d2f08f5e8f664633849653dbe329802e9847cfc85f8d7b52a02fef9c2561464ef0ec59a2e2cc7f0545d9a722499a6c45a7ded1c6af8bf903bee00",
		},
		{
			name:    "test vector 1 chain m/0/1",
			master:  testVec1MasterPubKey,
			path:    []uint32{0, 1},
			wantPub: "0488b21e029867004e00000001888b7ea2fdf5e712e18e32f962fe035aabce2767a22e3e9683e5dc66ffd93e2702f82dc6088914cc84ec0cb1864060efb58460a7cb62a0c85e6e52d96bf0fa863b00",
		},
		{
			name:    "test vector 1 chain m/0/1/2",
			master:  testVec1MasterPubKey,
			path:    []uint32{0, 1, 2},
			wantPub: "0488b21e03aa1ca2a300000002f28c42b7e8ce210bf14de53a97f1da95d1702abf497432f8ff8cd55a7dbae49c0289e1907ed1aacb45223dda8763b2ffd602fa913b7618a1ff6b85454698a6f63700",
		},
		{
			name:    "test vector 1 chain m/0/1/2/2",
			master:  testVec1MasterPubKey,
			path:    []uint32{0, 1, 2, 2},
			wantPub: "0488b21e04b5c8022800000002253a452cd9d6ceda16e9a4ae461ab85b506a300a72be760f377294bde30ee28202d1b1d6f5d7e198f59a8f7511fd441a408bf2cfb0ef7b11b1080ccc01364db32a00",
		},
		{
			name:    "test vector 1 chain m/0/1/2/2/1000000000",
			master:  testVec1MasterPubKey,
			path:    []uint32{0, 1, 2, 2, 1000000000},
			wantPub: "0488b21e05c9df68e23b9aca00c1af37c3c715abc74a2852f80ac4a8268ae7188f228800e9010ddf8e5ec670db03178fffbd4282aa1bd11fec7cf5ed4cb5ad9048f3e6950abe35ef1b72eaad4cc700",
		},

		// Test vector 2
		{
			name:    "test vector 2 chain m",
			master:  testVec2MasterPubKey,
			path:    []uint32{},
			wantPub: "0488b21e00000000000000000060499f801b896d83179a4374aeb7822aaeaceaa0db1f85ee3e904c4defbd968903be91f902298e2d5131377399251de50982f99ad60516b8592a95bb6fb71582a700",
		},
		{
			name:    "test vector 2 chain m/0",
			master:  testVec2MasterPubKey,
			path:    []uint32{0},
			wantPub: "0488b21e0149ba82d100000000803411e2255bb5d0deb2c60dd48fabe78758e32201b0ef19fa50618b2f109ca20310b4aa732ec2dd34d949512f03445728c6a325685976ce5fc7a3601a83fce44900",
		},
		{
			name:    "test vector 2 chain m/0/2147483647",
			master:  testVec2MasterPubKey,
			path:    []uint32{0, 2147483647},
			wantPub: "0488b21e02480490547fffffff627f480abf50b95ec77b2c7953bbed49c13aa30cdd22cf7ef670d2a3c7725c6a03b23e90ddd4abd922698a4c82baef36df7c29875da4a98a02bba807a2dfaced3a00",
		},
		{
			name:    "test vector 2 chain m/0/2147483647/1",
			master:  testVec2MasterPubKey,
			path:    []uint32{0, 2147483647, 1},
			wantPub: "0488b21e03eac6cbc800000001f9b68dc0487789069f9ebd205668751ace039056fa7571f80f89045a8b374c330359f206d979f77ee4b2e21441445ccb36b19247eef0d753384e7aca86e0bd155d00",
		},
		{
			name:    "test vector 2 chain m/0/2147483647/1/2147483646",
			master:  testVec2MasterPubKey,
			path:    []uint32{0, 2147483647, 1, 2147483646},
			wantPub: "0488b21e046da4e81c7ffffffe2036c8558db4c9079647ece24166ad045b5fbc57d7763916f6beababa3767b7403c1c016d70bb3a7d926ce231f08e119a7fbf2ed3ef9fb1e1ee97984f92f2efbd800",
		},
		{
			name:    "test vector 2 chain m/0/2147483647/1/2147483646/2",
			master:  testVec2MasterPubKey,
			path:    []uint32{0, 2147483647, 1, 2147483646, 2},
			wantPub: "0488b21e05fc63a0d4000000023ddd172681ac4c8f06dcfe8504d18a475334c2c294862bc213ba5c2b71043caf0264aec1043c5bd92ae472ae0835296c6d823d5ced5943abf841e6ab307a93805f00",
		},
	}

tests:
	for i, test := range tests {
		extKey, err := FromBytes(alg, test.master)
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

		extKeyEcc, ok := extKey.(*ExtendedKeyP256)
		assert.Equal(t, ok, true)
		pubStr := hex.EncodeToString(extKeyEcc.ToBytes())
		if pubStr != test.wantPub {
			t.Errorf("Child #%d (%s): mismatched serialized "+
				"public extended key -- got: %s, want: %s", i,
				test.name, pubStr, test.wantPub)
			continue
		}
	}
}

// TestExtendedKeyAPI ensures the API on the ExtendedKey type works as intended.
func TestExtendedKeyAPIP256(t *testing.T) {
	tests := []struct {
		name       string
		extKey     string
		isPrivate  bool
		parentFP   uint32
		privKey    string
		privKeyErr error
		pubKey     string
	}{
		{
			name:      "test vector 1 master node private",
			extKey:    "0488ade4000000000000000000873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d50800e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b3501",
			isPrivate: true,
			parentFP:  0,
			privKey:   "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35",
			pubKey:    "0314affa492c60963f9521376771544907ed98b6afca1a508712e1210089f9d630",
		},
		{
			name:       "test vector 1 chain m/0H/1/2H public",
			extKey:     "0488b21e03bef5a2f98000000204466b9cc8e161e966409ca52986c584f07e9dc81f735db683c3ff6ec7b1503f0357bfe1e341d01c69fe5654309956cbea516822fba8a601743a012a7896ee8dc200",
			isPrivate:  false,
			parentFP:   3203769081,
			privKeyErr: ErrNotPrivExtKey,
			pubKey:     "0357bfe1e341d01c69fe5654309956cbea516822fba8a601743a012a7896ee8dc2",
		},
	}

	for i, test := range tests {
		extKey, _ := hex.DecodeString(test.extKey)
		key, err := FromBytes(alg, extKey)
		if err != nil {
			t.Errorf("FromBytes #%d (%s): unexpected "+
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

		keyEcc, ok := key.(*ExtendedKeyP256)
		assert.Equal(t, ok, true)
		serializedKey := hex.EncodeToString(keyEcc.ToBytes())
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
	}
}

// TestMaximumDepthP256 ensures that attempting to retrieve a child key when already
// at the maximum depth is not allowed.  The serialization of a BIP32 key uses
// uint8 to encode the depth.  This implicitly bounds the depth of the tree to
// 255 derivations.  Here we test that an error is returned after 'max uint8'.
func TestMaximumDepthP256(t *testing.T) {
	net := &chaincfg.MainNetParams
	extKey, err := NewMaster(alg, []byte(`abcd1234abcd1234abcd1234abcd1234`), net)
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

func TestExtendedKey_ChildNumber_P256(t *testing.T) {
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
			k := &ExtendedKeyP256{}
			k.ChildNum = tt.fields.childNum

			if got := k.ChildNumber(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ExtendedKey.ChildNumber() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestExtendedKey_Key_P256(t *testing.T) {
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
			k, _ := NewExtendedKeyExt(alg, nil, tt.fields.key, nil, nil, 0, 0, true)
			if got := k.Key(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ExtendedKey.Key() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestExtendedKey_ChainCode_P256(t *testing.T) {
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
			k := &ExtendedKeyP256{}
			k.ChainCodeB = tt.fields.chainCode
			if got := k.ChainCode(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ExtendedKey.ChainCode() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestExtendedKey_Version_P256(t *testing.T) {
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
			k := &ExtendedKeyP256{}
			k.VersionB = tt.fields.version
			if got := k.Version(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ExtendedKey.Version() = %v, want %v", got, tt.want)
			}
		})
	}
}
