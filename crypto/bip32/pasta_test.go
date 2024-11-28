package bip32

import (
	"encoding/hex"
	"fmt"
	"reflect"
	"testing"

	"git.liebaopay.com/ksrv/keyserver/ksrv"
	"github.com/btcsuite/btcd/chaincfg"
)

func TestBIP0032VectorsPasta(t *testing.T) {
	// The master seeds for each of the two test vectors in [BIP32].
	testVec1MasterHex := "000102030405060708090a0b0c0d0e0f"
	testVec2MasterHex := "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542"
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
			wantPubHex:  "0488b21e000000000000000000873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508001da2d6ea20ae88b9904036a71782f5457045756629b0d0344e0aec3b687b873a00",
			wantPrivHex: "0488ade4000000000000000000873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d5080028f32e723decf4051aefac8e2c93c9c54b406643fb0fb5816fbff7b4c8436b3201",
			net:         &chaincfg.MainNetParams,
		},
		{
			name:        "test vector 1 chain m/0H",
			master:      testVec1MasterHex,
			path:        []uint32{hkStart},
			wantPubHex:  "0488b21e012288ebca80000000d6cfed604e1d0f221390a4633c7d2774050f3a064e0762bdc342cc67904a7a8a0014e7cf678c31baf1d88c4807129bda6b7bcb7aaed11bd01e1f6c86926d71425d00",
			wantPrivHex: "0488ade4012288ebca80000000d6cfed604e1d0f221390a4633c7d2774050f3a064e0762bdc342cc67904a7a8a00232e7b05267390d6ad6dffab0145afbf2c1d3450024d2697582785100d46941801",
			net:         &chaincfg.MainNetParams,
		},
		{
			name:        "test vector 1 chain m/0H/1",
			master:      testVec1MasterHex,
			path:        []uint32{hkStart, 1},
			wantPubHex:  "0488b21e028c10308d00000001a5a043eb6335942ac3476df6fb7fee68f6395ccaffffb9166e36ab63c345bbaf010fb41d0c3a222bbfc99665a5b3e6ab6b447566e6a69c0ecca230883ab8d885ed00",
			wantPrivHex: "0488ade4028c10308d00000001a5a043eb6335942ac3476df6fb7fee68f6395ccaffffb9166e36ab63c345bbaf000e9f18252ceb268227cada124ad0d12acf6fe7de5309f18d0363bf83c43dbc5301",
			net:         &chaincfg.MainNetParams,
		},
		{
			name:        "test vector 1 chain m/0H/1/2H",
			master:      testVec1MasterHex,
			path:        []uint32{hkStart, 1, hkStart + 2},
			wantPubHex:  "0488b21e03596045a78000000270b7e1feaa0496cc5b7285015d43902fc3d102fc2c4588c14c08fc180ef9fafa010e68428adf2bb6b1dc0d13bd0b852c20e157836462b5c4da599f2891929786a600",
			wantPrivHex: "0488ade403596045a78000000270b7e1feaa0496cc5b7285015d43902fc3d102fc2c4588c14c08fc180ef9fafa0023efe067d66aaef51a74ef2a885f695094055b0483b9704630bafd4fcec4115801",
			net:         &chaincfg.MainNetParams,
		},

		// Test vector 2
		{
			name:        "test vector 2 chain m",
			master:      testVec2MasterHex,
			path:        []uint32{},
			wantPubHex:  "0488b21e00000000000000000060499f801b896d83179a4374aeb7822aaeaceaa0db1f85ee3e904c4defbd96890134eee0196b79dec2c829fd9169123d29749f8a0f91c35e54b11d3b256aef300400",
			wantPrivHex: "0488ade400000000000000000060499f801b896d83179a4374aeb7822aaeaceaa0db1f85ee3e904c4defbd9689000b03d6fc340455b363f51020ad3ecca4ce3e6984c5aec3933ae0a71e6db46c3d01",
			net:         &chaincfg.MainNetParams,
		},
		{
			name:        "test vector 2 chain m/0",
			master:      testVec2MasterHex,
			path:        []uint32{0},
			wantPubHex:  "0488b21e016cf824df000000008e2e4a3c7bbae8d35ea662e35655a6d4c3bdd86c5a59196ca4e4b798f2841aff011f36a054056e3c7370b99a656cf09bf3b67346d649ce59adac47c944f74ad1b900",
			wantPrivHex: "0488ade4016cf824df000000008e2e4a3c7bbae8d35ea662e35655a6d4c3bdd86c5a59196ca4e4b798f2841aff002921b756a5987fd25daca994a2e6a133037171270b6c45346ad15d93e2c9638c01",
			net:         &chaincfg.MainNetParams,
		},
		{
			name:        "test vector 2 chain m/0/2147483647H",
			master:      testVec2MasterHex,
			path:        []uint32{0, hkStart + 2147483647},
			wantPubHex:  "0488b21e02d343e19affffffff0fc77a211643d95ff9f0d2bdb2a53392d7fec1e97dceb8e46bdca9e24aafeba400148b6e4f64d8cef097faf21f693c2730064df4ffc9d2d03564935176760be76a00",
			wantPrivHex: "0488ade402d343e19affffffff0fc77a211643d95ff9f0d2bdb2a53392d7fec1e97dceb8e46bdca9e24aafeba40027878472ea2c57161e7a47f7523bdf3bb4f579874f4ac133eb18025128325b4901",
			net:         &chaincfg.MainNetParams,
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

		extKey, err := NewMaster(ksrv.NewHDSeedRequest_pastaSchnorrMina, masterSeed, test.net)
		if err != nil {
			t.Errorf("NewMaster #%d (%s): unexpected error when "+
				"creating new master key: %v", i, test.name,
				err)
			continue
		}

		for _, childNum := range test.path {
			var err error
			var extKey1 ExtendedKey
			if childNum < hkStart {
				pub, err := extKey.Neuter()
				if err != nil {
					t.Errorf("err: %v", err)
					continue tests
				}

				extKey1, err = pub.Child(childNum)
			}

			extKey, err = extKey.Child(childNum)
			if err != nil {
				t.Errorf("err: %v", err)
				continue tests
			}

			if childNum < hkStart {
				childPub1, err := extKey1.ECPubKey()
				if err != nil {
					t.Errorf("err: %v", err)
					continue tests
				}
				childPub, err := extKey.ECPubKey()
				if err != nil {
					t.Errorf("err: %v", err)
					continue tests
				}
				if !reflect.DeepEqual(childPub1, childPub) {
					t.Error("extKey1 != extKey")
					continue tests
				}
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

		extKeyR, err := FromBytes(ksrv.NewHDSeedRequest_pastaSchnorrMina, extKey.ToBytes())
		if err != nil {
			t.Errorf("FromBytes #%d (%s): unexpected error: %v", i,
				test.name, err)
			return
		}

		if hex.EncodeToString(extKeyR.ToBytes()) != privHex {
			t.Errorf("%s FromBytes err : %s != %s", test.name, hex.EncodeToString(extKeyR.ToBytes()), privHex)
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

		extKeyR, err = FromBytes(ksrv.NewHDSeedRequest_pastaSchnorrMina, pubKey.ToBytes())
		if err != nil {
			t.Errorf("FromBytes #%d (%s): unexpected error: %v", i,
				test.name, err)
			return
		}
		if hex.EncodeToString(extKeyR.ToBytes()) != pubHex {
			t.Errorf("%s FromBytes err : %s != %s", test.name, hex.EncodeToString(extKeyR.ToBytes()), pubHex)
			continue
		}
	}
}

func TestBIP0032ChildPasta(t *testing.T) {
	// The master seeds for each of the two test vectors in [BIP32].
	testVec1MasterHex := "000102030405060708090a0b0c0d0e0f"
	hkStart := uint32(0x80000000)

	type Test struct {
		name   string
		master string
		net    *chaincfg.Params
	}
	test := Test{
		"test vector 1 chain m", testVec1MasterHex, &chaincfg.MainNetParams,
	}

	masterSeed, err := hex.DecodeString(test.master)
	if err != nil {
		t.Error(err)
	}

	extKey, err := NewMaster(ksrv.NewHDSeedRequest_pastaSchnorrMina, masterSeed, test.net)
	if err != nil {
		t.Error(err)
	}

	for childNum := uint32(0); childNum < 1000; childNum++ {
		fmt.Println("childNum == ", childNum)
		var err error
		var extKey1 ExtendedKey
		pub, err := extKey.Neuter()
		if err != nil {
			t.Error(err)
		}

		extKey1, err = pub.Child(childNum)
		if err != nil {
			t.Error(err)
		}

		extKey2, err := extKey.Child(childNum)
		if err != nil {
			t.Error(err)
		}

		if childNum < hkStart {
			childPub1, err := extKey1.ECPubKey()
			if err != nil {
				t.Error(err)
			}
			childPub2, err := extKey2.ECPubKey()
			if err != nil {
				t.Error(err)
			}
			if !reflect.DeepEqual(childPub1, childPub2) {
				t.Error("extKey1 != extKey")
			}
		}
	}

	pubKey, err := extKey.Neuter()
	if err != nil {
		t.Error(err)
	}

	// Neutering a second time should have no effect.
	pubKey1, err := pubKey.Neuter()
	if err != nil {
		t.Error(err)
	}

	if !reflect.DeepEqual(pubKey1, pubKey) {
		t.Errorf("Neuter : %x != %x", pubKey1, pubKey)
	}
}
