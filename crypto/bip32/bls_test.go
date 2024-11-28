package bip32

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"reflect"
	"testing"

	"github.com/btcsuite/btcd/chaincfg"

	"git.liebaopay.com/ksrv/keyserver/crypto/signer"
	"git.liebaopay.com/ksrv/keyserver/ksrv"
	"github.com/bmizerany/assert"
	"github.com/btcsuite/btcutil"
)

// TestCorrect 测试正确功能
func TestCorrectBls(t *testing.T) {
	algID := ksrv.NewHDSeedRequest_bls12381
	//	algID := ksrv.NewHDSeedRequest_Secp256k1
	// Generate a new key and neuter it to a public extended key.
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
	msg := []byte("message")
	signature, err := signer.Sign(algID, msg, child0.Key())
	if err != nil {
		t.Fatalf(err.Error())
	}
	fmt.Println(hex.EncodeToString(child0.Key()))
	fmt.Println(hex.EncodeToString(signature))
	assert.Equal(t, len(signature), 96)
	ret, err := signer.Bls12381Verify(child0Pub.Key(), msg, signature)
	if err != nil {
		t.Fatalf(err.Error())
	}
	assert.Equal(t, ret, true)
}

// TestBIP0032Vectors_Bls tests the vectors provided by [BIP32] to ensure the
// derivation works as intended.
func TestBIP0032Vectors_Bls(t *testing.T) {
	// The master seeds for each of the two test vectors in [BIP32].
	testVec1MasterHex := "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a2"
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
			wantPubHex:  "0488b21e000000000000000000ca0da6fc28f2c01d91c505bece78b8c697e299d3fcfece72d07943b14e3b48308df07500b62d50a4794d66219817ab445669fef0e5596236c262ca510b716ffe91d0998745eee58c43d3efae2466376100",
			wantPrivHex: "0488ade4000000000000000000ca0da6fc28f2c01d91c505bece78b8c697e299d3fcfece72d07943b14e3b4830140fb6af60e45811ea36198f8aaa7a003aa9ea36fc44a81f29ad3e745b733f8301",
			net:         &chaincfg.MainNetParams,
		},
		{
			name:        "test vector 1 chain m/0H",
			master:      testVec1MasterHex,
			path:        []uint32{hkStart},
			wantPubHex:  "0488b21e014d13e45f8000000092e76ff485ecf5c2df559c23300f13c416a2994a0fee8ae5dfffcb15453d61f68213545be13cfcaa4c5ad1972dc27216d7e1bb8c382066ae13cf147512c40f51b160d8db319b8e663a0ecfc0a014979f00",
			wantPrivHex: "0488ade4014d13e45f8000000092e76ff485ecf5c2df559c23300f13c416a2994a0fee8ae5dfffcb15453d61f61b241d5e942c908e77ffe36da6098dfbf5109766dc13cbb7482174148debd7db01",
			net:         &chaincfg.MainNetParams,
		},
		{
			name:        "test vector 1 chain m/0H/1",
			master:      testVec1MasterHex,
			path:        []uint32{hkStart, 1},
			wantPubHex:  "0488b21e021bb18eb9000000010ed113a132e78152446a53801cfa5ac266fb1884520a43f53f7b8699bd26bbf9a45b0c594640095b26154c2334f2eefa3107b51bdd8bcc33b677e0d26c45ee6f5f8db544ea940801e8eeb407b63695d900",
			wantPrivHex: "0488ade4021bb18eb9000000010ed113a132e78152446a53801cfa5ac266fb1884520a43f53f7b8699bd26bbf9515b5b0381fc9c070e4e94cc1388087bdf89c983491d5a37339b0fd86463fbba01",
			net:         &chaincfg.MainNetParams,
		},
		{
			name:        "test vector 1 chain m/0H/1/2H",
			master:      testVec1MasterHex,
			path:        []uint32{hkStart, 1, hkStart + 2},
			wantPubHex:  "0488b21e03d4569f78800000025246ce38f13ab9d61e49b98c861d4f234d865961ab71a09d6a75bc07e0709d9facd6de9128452fd5c519a7895f988c4a44f33fc50e10afc8df32fa89e7864df3230a90855bc35f08bf227f1f6993656f00",
			wantPrivHex: "0488ade403d4569f78800000025246ce38f13ab9d61e49b98c861d4f234d865961ab71a09d6a75bc07e0709d9f04de51609e909f4d05963e2a6144ef425355b2a525fde2c32a4610e6d28eede501",
			net:         &chaincfg.MainNetParams,
		},
		{
			name:        "test vector 1 chain m/0H/1/2H/2",
			master:      testVec1MasterHex,
			path:        []uint32{hkStart, 1, hkStart + 2, 2},
			wantPubHex:  "0488b21e04ba48f1970000000281e7d43c416c4f88da876ca8859a671ba8d078897706a8b5cccdbde4aa13d4459584034929ff42da171e33f4b916220d1c9905efb7d0018681254f4d3d8c63c15010a24852eae9c4d85e545cf4a9e8cf00",
			wantPrivHex: "0488ade404ba48f1970000000281e7d43c416c4f88da876ca8859a671ba8d078897706a8b5cccdbde4aa13d4453e142d5dff7de45fb03c6aee11f1ed01549fb38ff9db9321bc26d00d2508e5b501",
			net:         &chaincfg.MainNetParams,
		},
		{
			name:        "test vector 1 chain m/0H/1/2H/2/1000000000",
			master:      testVec1MasterHex,
			path:        []uint32{hkStart, 1, hkStart + 2, 2, 1000000000},
			wantPubHex:  "0488b21e05688986253b9aca0017c34f186d82cca9a89d5799052cea6488ce0ab09a7c2d2d53bbdd2b47fa9b82abbff771421b69b5215d51f2ddc589178d17a73b1840be80f17093124218851f2e0d4c9d630dc9a2d8f2e5f369757f4300",
			wantPrivHex: "0488ade405688986253b9aca0017c34f186d82cca9a89d5799052cea6488ce0ab09a7c2d2d53bbdd2b47fa9b82445f82569cb3dad472895f566364b3be9c403ff857dcffe68403bea3a6916f9401",
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

		extKey, err := NewMaster(ksrv.NewHDSeedRequest_bls12381, masterSeed, test.net)
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

// TestPrivateDerivation_Bls tests several vectors which derive private keys from
// other private keys works as intended.
func TestPrivateDerivation_Bls(t *testing.T) {
	// The private extended keys for test vectors in [BIP32].
	testVec1MasterPrivKey := "0488ade4000000000000000000ca0da6fc28f2c01d91c505bece78b8c697e299d3fcfece72d07943b14e3b4830fbeb0555b41f52a250a9c99f9dee2a0ae225323cfc41601d29ad3e725b733f8501"
	testVec2MasterPrivKey := "0488ade4014d13e45f800000005ca95ed460fc0ec0857d9815a5b1e23ece803ab168b4444897dd0bee1b755e52475a811223d8e566f30197d79633a40d42599ce3cfb810763ec2efdfa032f11001"
	tests := []struct {
		name          string
		master        string
		path          []uint32
		wantPrivHex   string
		wantPubKeyHex string
	}{
		// Test vector 1
		{
			name:          "test vector 1 chain m",
			master:        testVec1MasterPrivKey,
			path:          []uint32{},
			wantPrivHex:   "0488ade4000000000000000000ca0da6fc28f2c01d91c505bece78b8c697e299d3fcfece72d07943b14e3b4830140fb6af60e45811ea36198f8aaa7a003aa9ea36fc44a81f29ad3e745b733f8301",
			wantPubKeyHex: "0488b21e000000000000000000ca0da6fc28f2c01d91c505bece78b8c697e299d3fcfece72d07943b14e3b48308df07500b62d50a4794d66219817ab445669fef0e5596236c262ca510b716ffe91d0998745eee58c43d3efae2466376100",
		},
		{
			name:          "test vector 1 chain m/0",
			master:        testVec1MasterPrivKey,
			path:          []uint32{0},
			wantPrivHex:   "0488ade4014d13e45f00000000a6d920be2d8b3ef27daeb500569362c9f6ca7702be0202b562e3afe496aa843838b989f73970a5732aeefe1cbc52fb2e52f02d11fe0f1f9ed785750b831bf0d001",
			wantPubKeyHex: "0488b21e014d13e45f00000000a6d920be2d8b3ef27daeb500569362c9f6ca7702be0202b562e3afe496aa84388840678926a9ffa1619ece7bc1d59406345195b019c8a0edfef54b5f4a539de185461978f6ea8da0ef6229fcd20afe6900",
		},
		{
			name:          "test vector 1 chain m/0/1",
			master:        testVec1MasterPrivKey,
			path:          []uint32{0, 1},
			wantPrivHex:   "0488ade402b84bc5200000000144afc621fe3f7c476fd83a73f90770ade0c95f7bc58e10e868c4eae7f5cb016e4612fe1fb8d8a4c0277221ca7c44de810e08a88f1be75e0646e5669e41ac4c1b01",
			wantPubKeyHex: "0488b21e02b84bc5200000000144afc621fe3f7c476fd83a73f90770ade0c95f7bc58e10e868c4eae7f5cb016eb0f01db6e7c2491a1ccfd4b27ab4685fe8eb806f22fdbc5a33ecdfa3e3fd82a2a68b47f63bb39f22d11d8f85163fc4b600",
		},
		{
			name:          "test vector 1 chain m/0/1/2",
			master:        testVec1MasterPrivKey,
			path:          []uint32{0, 1, 2},
			wantPrivHex:   "0488ade4035d2a549900000002b9f1d613e55b3243043e776debd1f51632c6d3c5031d8510c27a3ea5fed19f7e497d4bc49f6dc14975a96c9955646d9ba978a5771659bd40f2e886fed5cc95b501",
			wantPubKeyHex: "0488b21e035d2a549900000002b9f1d613e55b3243043e776debd1f51632c6d3c5031d8510c27a3ea5fed19f7ea109cf74831231a79b36395fef3cdcb7c0c11564e12fc5cc99e0646eebf1d77a99acac0081beab834580ee76729b4efa00",
		},
		{
			name:          "test vector 1 chain m/0/1/2/2",
			master:        testVec1MasterPrivKey,
			path:          []uint32{0, 1, 2, 2},
			wantPrivHex:   "0488ade40469199a8400000002cb42032226484d6889f3127706907090f584b40409f145cd371a61c451f36ca058f6ba1028a869a8a08fe80cefe4472de6aedaaff6fdd88ecfbc9276c001003101",
			wantPubKeyHex: "0488b21e0469199a8400000002cb42032226484d6889f3127706907090f584b40409f145cd371a61c451f36ca08db1b1ca17adc8a137e22aecdc0757d23e3cb791d2b278fc7001cb77c586e63e02a19c6fae8ad0b7d4936329673f07df00",
		},
		{
			name:          "test vector 1 chain m/0/1/2/2/1000000000",
			master:        testVec1MasterPrivKey,
			path:          []uint32{0, 1, 2, 2, 1000000000},
			wantPrivHex:   "0488ade405d4098c103b9aca009713bb43bec1685472c9e99e4caa5b640c60d3bf915c36ef2749fb032c39a36e1c12f858007e7be5c32ec02cc2aa3d9e5e3be437c61f026e55ebc219cf28404101",
			wantPubKeyHex: "0488b21e05d4098c103b9aca009713bb43bec1685472c9e99e4caa5b640c60d3bf915c36ef2749fb032c39a36eb24d78c09db902f519a07a81af5bcbb6ecef58ba765efe4ce60686593264a44787500d82f7ea2d32e2483ce460b14bb300",
		},

		// Test vector 2
		{
			name:          "test vector 2 chain m",
			master:        testVec2MasterPrivKey,
			path:          []uint32{},
			wantPrivHex:   "0488ade4014d13e45f800000005ca95ed460fc0ec0857d9815a5b1e23ece803ab168b4444897dd0bee1b755e52475a811223d8e566f30197d79633a40d42599ce3cfb810763ec2efdfa032f11001",
			wantPubKeyHex: "0488b21e014d13e45f800000005ca95ed460fc0ec0857d9815a5b1e23ece803ab168b4444897dd0bee1b755e528f781a170d4f983557afb53bf15a2e64d7e2f247b2a27362b2adad72d7a030e621901ae6f8a132675c466c88770b2e2700",
		},
		{
			name:          "test vector 2 chain m/0",
			master:        testVec2MasterPrivKey,
			path:          []uint32{0},
			wantPrivHex:   "0488ade4026da00186000000000059eb342fca5711dccc7386643e6f49b428aea02f327b71cb51512936cc820d3b1205e7081a4a28c2a2033c0c189051e848fa573724c27d308c7014c6a2071201",
			wantPubKeyHex: "0488b21e026da00186000000000059eb342fca5711dccc7386643e6f49b428aea02f327b71cb51512936cc820da985c28933e48358bbce788a826b8ee1c9e273deb501c54c67a35fe6a4a0f00a9889d2d1a0e68dea61fafb3ad1d6273900",
		},
		{
			name:          "test vector 2 chain m/0/2147483647",
			master:        testVec2MasterPrivKey,
			path:          []uint32{0, 2147483647},
			wantPrivHex:   "0488ade403ea3be84a7fffffff87d889dfbb26eed81bc3cde4416c415c71c49810773ad84c57898c5bc56d0921482c47ecd52e9b4a09fe5c17c0d7337888e36911d1bbc3885c05126dfd3b7cfc01",
			wantPubKeyHex: "0488b21e03ea3be84a7fffffff87d889dfbb26eed81bc3cde4416c415c71c49810773ad84c57898c5bc56d092198f6391a2b1b03df67eb835dae388b4ab74720148fff4f1db2d7bcd1e08c0f0d9701573fa91be57179d9e0a0618413db00",
		},
		{
			name:          "test vector 2 chain m/0/2147483647/1",
			master:        testVec2MasterPrivKey,
			path:          []uint32{0, 2147483647, 1},
			wantPrivHex:   "0488ade404fbfb4596000000019cdc36590fd633c73f5f206e78ec1249f14d99eb6d2dcc8b805837067fda11f523dc9d51d8a8c94ae419448e3e78a497bb5a7c24d2cbc66e24891791d4009f8501",
			wantPubKeyHex: "0488b21e04fbfb4596000000019cdc36590fd633c73f5f206e78ec1249f14d99eb6d2dcc8b805837067fda11f5b0dc71cd07643e084f6b579096797bcce59325ae47377a418a3417c6a02e30ae806691bd724eb3728b4f85a10f398c6a00",
		},
		{
			name:          "test vector 2 chain m/0/2147483647/1/2147483646",
			master:        testVec2MasterPrivKey,
			path:          []uint32{0, 2147483647, 1, 2147483646},
			wantPrivHex:   "0488ade40537d22e6e7ffffffe28b788248bb26061beecd40dcafffe6ccf3b8ee265be9105e3abe29eb0f1b90a271f5b654556b17d56882b9c33e7d0cfbdf9fd5948bd78a718363adfb554c71501",
			wantPubKeyHex: "0488b21e0537d22e6e7ffffffe28b788248bb26061beecd40dcafffe6ccf3b8ee265be9105e3abe29eb0f1b90aa07f9b0176bbac0e7a1affb2c95b1252b11371e4b32438014bd7a3b1f4cb5a78f94f50277958e1d851720ef24d35eed500",
		},
		{
			name:          "test vector 2 chain m/0/2147483647/1/2147483646/2",
			master:        testVec2MasterPrivKey,
			path:          []uint32{0, 2147483647, 1, 2147483646, 2},
			wantPrivHex:   "0488ade40669479d0c000000028460ad06e54fc9675919915901874e6eda29b1d416358d651ccc99ea9231510d210e1f2a866076c5123bb7af57fcd598fe4b06d5efafc8a35b20f6b137740b9601",
			wantPubKeyHex: "0488b21e0669479d0c000000028460ad06e54fc9675919915901874e6eda29b1d416358d651ccc99ea9231510d9690f3ff1d823f49ef4dc038d2c0e2c40f9d670792be5fa17d75bdf8e5712e9fba3b007369c9edebded96a25046d335e00",
		},
	}

tests:
	for i, test := range tests {
		master, _ := hex.DecodeString(test.master)
		extKey, err := FromBytes(ksrv.NewHDSeedRequest_bls12381, master)
		if err != nil {
			t.Errorf("FromBytes #%d (%s): unexpected error "+
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

		privHex := hex.EncodeToString(extKey.ToBytes())
		if privHex != test.wantPrivHex {
			t.Errorf("Child #%d (%s): mismatched serialized "+
				"private bytes extended key -- got: %s, want: %s", i,
				test.name, privHex, test.wantPrivHex)
			continue
		}

		pubKey, err := extKey.Neuter()
		if err != nil {
			t.Errorf("Child #%d (%s): neuter got error: %s", i,
				test.name, err.Error())
			continue
		}
		pubHex := hex.EncodeToString(pubKey.ToBytes())
		if pubHex != test.wantPubKeyHex {
			t.Errorf("Child #%d (%s): mismatched serialized "+
				"private bytes extended key -- got: %s, want: %s", i,
				test.name, pubHex, test.wantPubKeyHex)
			continue
		}

	}
}

// TestPublicDerivation_Bls tests several vectors which derive public keys from
// other public keys works as intended.
func TestPublicDerivation_Bls(t *testing.T) {
	// The public extended keys for test vectors in [BIP32].
	testVec1MasterPubKey := "0488b21e000000000000000000ca0da6fc28f2c01d91c505bece78b8c697e299d3fcfece72d07943b14e3b48308df07500b62d50a4794d66219817ab445669fef0e5596236c262ca510b716ffe91d0998745eee58c43d3efae2466376100"
	testVec2MasterPubKey := "0488b21e014d13e45f800000005ca95ed460fc0ec0857d9815a5b1e23ece803ab168b4444897dd0bee1b755e528f781a170d4f983557afb53bf15a2e64d7e2f247b2a27362b2adad72d7a030e621901ae6f8a132675c466c88770b2e2700"

	tests := []struct {
		name       string
		master     string
		path       []uint32
		wantPubHex string
	}{
		// Test vector 1
		{
			name:       "test vector 1 chain m",
			master:     testVec1MasterPubKey,
			path:       []uint32{},
			wantPubHex: "0488b21e000000000000000000ca0da6fc28f2c01d91c505bece78b8c697e299d3fcfece72d07943b14e3b48308df07500b62d50a4794d66219817ab445669fef0e5596236c262ca510b716ffe91d0998745eee58c43d3efae2466376100",
		},
		{
			name:       "test vector 1 chain m/0",
			master:     testVec1MasterPubKey,
			path:       []uint32{0},
			wantPubHex: "0488b21e014d13e45f00000000a6d920be2d8b3ef27daeb500569362c9f6ca7702be0202b562e3afe496aa84388840678926a9ffa1619ece7bc1d59406345195b019c8a0edfef54b5f4a539de185461978f6ea8da0ef6229fcd20afe6900",
		},
		{
			name:       "test vector 1 chain m/0/1",
			master:     testVec1MasterPubKey,
			path:       []uint32{0, 1},
			wantPubHex: "0488b21e02b84bc5200000000144afc621fe3f7c476fd83a73f90770ade0c95f7bc58e10e868c4eae7f5cb016eb0f01db6e7c2491a1ccfd4b27ab4685fe8eb806f22fdbc5a33ecdfa3e3fd82a2a68b47f63bb39f22d11d8f85163fc4b600",
		},
		{
			name:       "test vector 1 chain m/0/1/2",
			master:     testVec1MasterPubKey,
			path:       []uint32{0, 1, 2},
			wantPubHex: "0488b21e035d2a549900000002b9f1d613e55b3243043e776debd1f51632c6d3c5031d8510c27a3ea5fed19f7ea109cf74831231a79b36395fef3cdcb7c0c11564e12fc5cc99e0646eebf1d77a99acac0081beab834580ee76729b4efa00",
		},
		{
			name:       "test vector 1 chain m/0/1/2/2",
			master:     testVec1MasterPubKey,
			path:       []uint32{0, 1, 2, 2},
			wantPubHex: "0488b21e0469199a8400000002cb42032226484d6889f3127706907090f584b40409f145cd371a61c451f36ca08db1b1ca17adc8a137e22aecdc0757d23e3cb791d2b278fc7001cb77c586e63e02a19c6fae8ad0b7d4936329673f07df00",
		},
		{
			name:       "test vector 1 chain m/0/1/2/2/1000000000",
			master:     testVec1MasterPubKey,
			path:       []uint32{0, 1, 2, 2, 1000000000},
			wantPubHex: "0488b21e05d4098c103b9aca009713bb43bec1685472c9e99e4caa5b640c60d3bf915c36ef2749fb032c39a36eb24d78c09db902f519a07a81af5bcbb6ecef58ba765efe4ce60686593264a44787500d82f7ea2d32e2483ce460b14bb300",
		},

		// Test vector 2
		{
			name:       "test vector 2 chain m",
			master:     testVec2MasterPubKey,
			path:       []uint32{},
			wantPubHex: "0488b21e014d13e45f800000005ca95ed460fc0ec0857d9815a5b1e23ece803ab168b4444897dd0bee1b755e528f781a170d4f983557afb53bf15a2e64d7e2f247b2a27362b2adad72d7a030e621901ae6f8a132675c466c88770b2e2700",
		},
		{
			name:       "test vector 2 chain m/0",
			master:     testVec2MasterPubKey,
			path:       []uint32{0},
			wantPubHex: "0488b21e026da00186000000000059eb342fca5711dccc7386643e6f49b428aea02f327b71cb51512936cc820da985c28933e48358bbce788a826b8ee1c9e273deb501c54c67a35fe6a4a0f00a9889d2d1a0e68dea61fafb3ad1d6273900",
		},
		{
			name:       "test vector 2 chain m/0/2147483647",
			master:     testVec2MasterPubKey,
			path:       []uint32{0, 2147483647},
			wantPubHex: "0488b21e03ea3be84a7fffffff87d889dfbb26eed81bc3cde4416c415c71c49810773ad84c57898c5bc56d092198f6391a2b1b03df67eb835dae388b4ab74720148fff4f1db2d7bcd1e08c0f0d9701573fa91be57179d9e0a0618413db00",
		},
		{
			name:       "test vector 2 chain m/0/2147483647/1",
			master:     testVec2MasterPubKey,
			path:       []uint32{0, 2147483647, 1},
			wantPubHex: "0488b21e04fbfb4596000000019cdc36590fd633c73f5f206e78ec1249f14d99eb6d2dcc8b805837067fda11f5b0dc71cd07643e084f6b579096797bcce59325ae47377a418a3417c6a02e30ae806691bd724eb3728b4f85a10f398c6a00",
		},
		{
			name:       "test vector 2 chain m/0/2147483647/1/2147483646",
			master:     testVec2MasterPubKey,
			path:       []uint32{0, 2147483647, 1, 2147483646},
			wantPubHex: "0488b21e0537d22e6e7ffffffe28b788248bb26061beecd40dcafffe6ccf3b8ee265be9105e3abe29eb0f1b90aa07f9b0176bbac0e7a1affb2c95b1252b11371e4b32438014bd7a3b1f4cb5a78f94f50277958e1d851720ef24d35eed500",
		},
		{
			name:       "test vector 2 chain m/0/2147483647/1/2147483646/2",
			master:     testVec2MasterPubKey,
			path:       []uint32{0, 2147483647, 1, 2147483646, 2},
			wantPubHex: "0488b21e0669479d0c000000028460ad06e54fc9675919915901874e6eda29b1d416358d651ccc99ea9231510d9690f3ff1d823f49ef4dc038d2c0e2c40f9d670792be5fa17d75bdf8e5712e9fba3b007369c9edebded96a25046d335e00",
		},
	}

tests:
	for i, test := range tests {
		master, _ := hex.DecodeString(test.master)
		extKey, err := FromBytes(ksrv.NewHDSeedRequest_bls12381, master)
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

		pubHex := hex.EncodeToString(extKey.ToBytes())
		if pubHex != test.wantPubHex {
			t.Errorf("Child #%d (%s): mismatched serialized "+
				"public bytes extended key -- got: %s, want: %s", i,
				test.name, pubHex, test.wantPubHex)
			continue
		}
	}
}

// TestExtendedKeyAPI_Bls ensures the API on the ExtendedKey type works as intended.
func TestExtendedKeyAPI_Bls(t *testing.T) {
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
			extKey:    "0488ade4000000000000000000ca0da6fc28f2c01d91c505bece78b8c697e299d3fcfece72d07943b14e3b4830140fb6af60e45811ea36198f8aaa7a003aa9ea36fc44a81f29ad3e745b733f8301",
			isPrivate: true,
			parentFP:  0,
			privKey:   "140fb6af60e45811ea36198f8aaa7a003aa9ea36fc44a81f29ad3e745b733f83",
			pubKey:    "8df07500b62d50a4794d66219817ab445669fef0e5596236c262ca510b716ffe91d0998745eee58c43d3efae24663761",
		},
		{
			name:       "test vector 1 chain m/0H/1/2H public",
			extKey:     "0488b21e033c6097ac80000002624d58eafc82e214a49b61da6cd222c6a42332b584bad8f25729f0d43255fbf68208c90970392715024cfef7c512f8bdcf0cdf8df0196fc6ec8f172a91622274b268c220a55adc7ca730849ca15169a500",
			isPrivate:  false,
			parentFP:   1012963244,
			privKeyErr: ErrNotPrivExtKey,
			pubKey:     "8208c90970392715024cfef7c512f8bdcf0cdf8df0196fc6ec8f172a91622274b268c220a55adc7ca730849ca15169a5",
		},
	}

	for i, test := range tests {
		extKey, _ := hex.DecodeString(test.extKey)
		key, err := FromBytes(ksrv.NewHDSeedRequest_bls12381, extKey)
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

		serializedKey := hex.EncodeToString(key.ToBytes())
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

// TestErrors_Bls performs some negative tests for various invalid cases to ensure
// the errors are handled properly.
func TestErrors_Bls(t *testing.T) {
	// Should get an error when seed has too few bytes.
	net := &chaincfg.MainNetParams
	_, err := NewMaster(ksrv.NewHDSeedRequest_bls12381, bytes.Repeat([]byte{0x00}, 15), net)
	if err != ErrInvalidSeedLen {
		t.Fatalf("NewMaster: mismatched error -- got: %v, want: %v",
			err, ErrInvalidSeedLen)
	}

	// Should get an error when seed has too many bytes.
	_, err = NewMaster(ksrv.NewHDSeedRequest_bls12381, bytes.Repeat([]byte{0x00}, 65), net)
	if err != ErrInvalidSeedLen {
		t.Fatalf("NewMaster: mismatched error -- got: %v, want: %v",
			err, ErrInvalidSeedLen)
	}

	// Generate a new key and neuter it to a public extended key.
	seed, err := GenerateSeed(RecommendedSeedLen)
	if err != nil {
		t.Fatalf("GenerateSeed: unexpected error: %v", err)
	}
	extKey, err := NewMaster(ksrv.NewHDSeedRequest_bls12381, seed, net)
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
			err:  ErrInvalidKeyLen,
		},
		{
			name: "bad checksum",
			key:  "edpubLwPb4VGbWR9yaX3ky6Fb5B3oSdSBGWHmfA4PjPqQJcKmjaV8RSbJq68aqajkmW36SUVJkEvtWDcEvuJYAnKMvGjvQE95fLbHZeRZ9hEKy",
			err:  ErrBadChecksum,
		},
	}

	for i, test := range tests {
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

// TestZero_Bls ensures that zeroing an extended key works as intended.
func TestZero_Bls(t *testing.T) {
	tests := []struct {
		name   string
		master string
		extKey string
		net    *chaincfg.Params
	}{
		// Test vector 1
		{
			name:   "test vector 1 chain m",
			master: "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a2",
			extKey: "0488ade4000000000000000000ca0da6fc28f2c01d91c505bece78b8c697e299d3fcfece72d07943b14e3b4830fbeb0555b41f52a250a9c99f9dee2a0ae225323cfc41601d29ad3e725b733f8501",
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

		wantKey := "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
		serializedKey := hex.EncodeToString(key.ToBytes())
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
		key, err := NewMaster(ksrv.NewHDSeedRequest_bls12381, masterSeed, test.net)
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
		extKey, _ := hex.DecodeString(test.extKey)
		key, err = FromBytes(ksrv.NewHDSeedRequest_bls12381, extKey)
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

func TestExtendedKey_ChildNumber_Bls(t *testing.T) {
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
			name:   "10",
			fields: fields{10},
			want:   []byte{0, 0, 0, 10},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k := &ExtendedKeyBls12381{}
			k.ChildNum = tt.fields.childNum
			if got := k.ChildNumber(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ExtendedKey.ChildNumber() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestExtendedKey_Key_Bls(t *testing.T) {
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
		{"1", fields{[]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3}}, a},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k := &ExtendedKeyBls12381{}
			k.KeyB = tt.fields.key
			if got := k.Key(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ExtendedKey.Key() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestExtendedKey_ChainCode_Bls(t *testing.T) {
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
			k := &ExtendedKeyBls12381{}
			k.ChainCodeB = tt.fields.chainCode
			if got := k.ChainCode(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ExtendedKey.ChainCode() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestExtendedKey_Version_Bls(t *testing.T) {
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
			k := &ExtendedKeyBls12381{}
			k.VersionB = tt.fields.version
			if got := k.Version(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ExtendedKey.Version() = %v, want %v", got, tt.want)
			}
		})
	}
}
