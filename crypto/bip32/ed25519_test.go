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
func TestCorrect(t *testing.T) {
	algID := ksrv.NewHDSeedRequest_ed25519
	//	algID := ksrv.NewHDSeedRequest_Secp256k1
	// Generate a new key and neuter it to a public extended key.
	seed, err := GenerateSeed(RecommendedSeedLen)
	if err != nil {
		t.Fatalf("GenerateSeed: unexpected error: %v", err)
	}

	rootKey, err := NewMaster(algID, seed, nil)
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
	assert.Equal(t, len(signature), 64)
	ret, err := signer.Verify(algID, child0Pub.Key(), msg, signature)
	if err != nil {
		t.Fatalf(err.Error())
	}
	assert.Equal(t, ret, true)
}

// TestBIP0032Vectors_ED25519 tests the vectors provided by [BIP32] to ensure the
// derivation works as intended.
func TestBIP0032Vectors_ED25519(t *testing.T) {
	// The master seeds for each of the two test vectors in [BIP32].
	testVec1MasterHex := "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a2"
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
			wantPub:     "edpubJvbz2mMfyqs3vcYWmX7ZJKr71hXw51xeJC9BHR3eRUnXtTrFSuvtn9F3FPga4HNXRgVdkWAP2dERGYaNdZFE1quTMZQp9eD4FK3GYZcHj",
			wantPriv:    "edprvKxPVAhTZvBiJr5AM7S78fR1jDVYjegWEwjUTCxc3QJ25Svcjr2TbnNZiGURfStMSzwDZbK45BjiUbSwZNNArsNJevrazjqGX1KsQoMtPuYyyxrtuGmQXhppCHrxp6fMKCz2GaXiN1RZLp3LYTgPdw",
			wantPubHex:  "0d7db4510000000000000000004dd9d338bb17939ab4bd4eaa0d16a866090750e9a3ab2b3972016f0db5c98a96e785473e5e8ef8162eee345404bfa8dba6e0bb180cf71c0633348a7104ab13df00",
			wantPrivHex: "2d6a33760000000000000000004dd9d338bb17939ab4bd4eaa0d16a866090750e9a3ab2b3972016f0db5c98a96f8eb0555b41f52a250a9c99f9dee2a0ae225323cfc41601d29ad3e725b733f45ca0da6fc28f2c01d91c505bece78b8c697e299d3fcfece72d07943b14e3b483001",
			net:         &chaincfg.MainNetParams,
		},
		{
			name:        "test vector 1 chain m/0H",
			master:      testVec1MasterHex,
			path:        []uint32{hkStart},
			wantPub:     "edpubKgcAaHMYKbAamrRydwwddcuQxd8RSfe9DkZDAmtxAmyoBpo24ryH1iNyGPtbXhtdELugwqxLatxtwfs377u4Ui9njtRAwkRov9SEAoPaA",
			wantPriv:    "edprvLBTeEfVeg1CV8vQgrZaqJ5BZtCm8UPD5AYsQ23gQKwW1785vriYuJ232RT6Naxe4qjCSLZrZfmNZx9UeyUbTFBbxrYyJcpYTHrHAvXoxykAeRtxKKbLZ5gfBHcp6mVMErry5TTyyQJxURJNfAVFTu",
			wantPubHex:  "0d7db45101c795cbb0800000009c7bc36dadf6f4f4359707d0788305d831cf8244632646bfffe2b981f1ff08ed04f494c6e51b510fa59a3559f16524c75afe71edb9d382abd883928a0d569bcf00",
			wantPrivHex: "2d6a337601c795cbb0800000009c7bc36dadf6f4f4359707d0788305d831cf8244632646bfffe2b981f1ff08ed20be029c76ae0049b0a86f9b3a301fffcd71b6c3906486ccbf68b87c60733f45bdd284527e04e26028cb0af5f6cc3cb162b80f9ecd96526c11b72eaa240a114901",
			net:         &chaincfg.MainNetParams,
		},
		{
			name:        "test vector 1 chain m/0H/1",
			master:      testVec1MasterHex,
			path:        []uint32{hkStart, 1},
			wantPub:     "edpubL2D8erQhzSaeEPAeyS97CSZtTS9NicDhShiFu1a1NVficXMJYNuN5Tkp3T32aqLxQ1TbkfWy7BacRrRBVJZSMoxtoNKKxVb6y2Hsg5WKd",
			wantPriv:    "edprvLHHPih144ugGPks1h4TKMjhCDnzy9kgKi3NHJwjFn2BnoQj86aDa9RwtdMwwzsYqPQXNmBnNz53JMj4Ez4f7VZ31hAeTrMWYemp32u9Dhpq98BMp7HxRcrUAXtLAKcA3212bNThdkgFTeR2XsfjRy",
			wantPubHex:  "0d7db45102928afe6500000001d0a3ad7bf062f0368c20fa88907e9cfd3fa49e42ff2296b3cd2583568f52db8aafd3e15b94a42b8d52c19a1c769671f3eb987610a366f3cb047f38b3c0be6a7b00",
			wantPrivHex: "2d6a337602928afe6500000001d0a3ad7bf062f0368c20fa88907e9cfd3fa49e42ff2296b3cd2583568f52db8af03f31a53262ff42d512abc7c7cdd1cdd4fbed05581c1d1789ae3c8463733f4593a40cc8f8fca565e850db81c89eb5b7580ea0c7141d15262856e8116eee2f0f01",
			net:         &chaincfg.MainNetParams,
		},
		{
			name:        "test vector 1 chain m/0H/1/2H",
			master:      testVec1MasterHex,
			path:        []uint32{hkStart, 1, hkStart + 2},
			wantPub:     "edpubLX5wj4cztjXyTUKa27qcGbe7djtnk3BFepixW2iLa5JLC5vpcPwPu6f2mZh8N98LJYmdX9aZXgmoBE2gunWe2iBFTUd4Q72qg3fw7NBT1",
			wantPriv:    "edprvLRrv3ws3woqRDnjZmusbVMieFVnRbp4pDDjkHaGy976VvQ6sk2rYKB4jckAk664Fzpp2qt26fuMHn7u2AaMb7qk3CmBHirNzWb9PANmGCRKNYRCRkWugyoTjn8z3KaWtYV3RzvmATXyoaWqpgYjkD",
			wantPubHex:  "0d7db45103bd82a9118000000214c8defde788b810d017dbe7b23e3fc58d74a74a71f75aba6f06e5eda73bcaccdb34ca34f4cf2777c8e3e04f4d50f225f0fb06de4c117d87a9402f7ca161a80200",
			wantPrivHex: "2d6a337603bd82a9118000000214c8defde788b810d017dbe7b23e3fc58d74a74a71f75aba6f06e5eda73bcacc5882136767a8868da56f0c5bfc804fd58b612597710e758432e2e92c66733f45e37e848d41416a530e1a542cd7f07aa473b7254cf1df6048fdc91ebcc33a904d01",
			net:         &chaincfg.MainNetParams,
		},
		{
			name:        "test vector 1 chain m/0H/1/2H/2",
			master:      testVec1MasterHex,
			path:        []uint32{hkStart, 1, hkStart + 2, 2},
			wantPub:     "edpubM2Rw2PfGRX4msVVosLT3zZPyxcTnig63xSvSLsGCPgcu5sXMSKQ3fPNgSEo52Cmp5wfHqtHxhdmQio9Qn258wc4wk7v5paWtUfSzPmhCg",
			wantPriv:    "edprvLaaWcwuuR9rNJmpUanqRvQFREGQFjvqoxtG1EjdFQ4JkLEZFeRF4JKW1SZQUHWb2TriXGhfmaPQdW4vv6LtKKGJyeDG6cYyhfRuHZQ2H2YgnioL6gigYELxKmsdhBjLHBz9ayAGQrhpC5ruasE5M2",
			wantPubHex:  "0d7db45104ed543b7a00000002b09ef2575068e40993ed0f42bb47cfe50dc9e9b26fa0af44a785c290a2effaf5d3fc56c0c23e6a3f0925be1385f503ecf127f78bf96c47b1ac0da93b66eed19700",
			wantPrivHex: "2d6a337604ed543b7a00000002b09ef2575068e40993ed0f42bb47cfe50dc9e9b26fa0af44a785c290a2effaf578f44de19a3a12e85da6b2c49924b669ab109092c618279c8282a7286a733f452a41703569af4593e1ed876e2d99eb66044101a076f94760929bf5adee9fd0e201",
			net:         &chaincfg.MainNetParams,
		},
		{
			name:        "test vector 1 chain m/0H/1/2H/2/1000000000",
			master:      testVec1MasterHex,
			path:        []uint32{hkStart, 1, hkStart + 2, 2, 1000000000},
			wantPub:     "edpubMTbJJCb2FuECyExrWsjaPi3eH8VbRpH3bykM88KyKHJ9NjANdoDWPTCqWKV2w6Fgbvez2QAHegqH4G3B35JGG7eZiz6yeR6vjXLRHxvZt",
			wantPriv:    "edprvLi42vahA41R9r9vaGQGb8CANek5snFbWCSoGvXvbpUgt3hxKxHRLXG1h51t5vEHyADP6cSiYv6zcSwSMrnRrDjnoobiScjZqoCFLpKMoam8APRyyaYQXjZBxBcgogCeTmrUm6GdBVDKuNLHM5rU1Q",
			wantPubHex:  "0d7db45105f1d67c2a3b9aca003234c5a18e3534a85249a77b5ec15da167bd55685dff608a781fadc92352ffabe2a72f94fc9404f612f8afd9d0ce42a2861b29186024b7109f5ae3a649e643b300",
			wantPrivHex: "2d6a337605f1d67c2a3b9aca003234c5a18e3534a85249a77b5ec15da167bd55685dff608a781fadc92352ffabb8aacf567de9d1c4c0e251ecfaf1413b91c7330bfb30e7400f932a1c71733f45532780ee7806a5926365c3aa78e4ccec75ab01ab533a67ffeb0646f713a02b7001",
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

		extKey, err := NewMaster(ksrv.NewHDSeedRequest_ed25519, masterSeed, test.net)
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

		extKey25519, ok := extKey.(*ExtendedKey25519)
		assert.Equal(t, ok, true)

		privStr := extKey25519.String()
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

		pubKey25519, ok := pubKey.(*ExtendedKey25519)
		assert.Equal(t, ok, true)
		pubStr := pubKey25519.String()

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

// TestPrivateDerivation_ED25519 tests several vectors which derive private keys from
// other private keys works as intended.
func TestPrivateDerivation_ED25519(t *testing.T) {
	// The private extended keys for test vectors in [BIP32].
	testVec1MasterPrivKey := "edprvKxPVAhTZvBiJr5AM7S78fR1jDVYjegWEwjUTCxc3QJ25Svcjr2TbnNZiGURfStMSzwDZbK45BjiUbSwZNNArsNJevrazjqGX1KsQoMtPuYyyxrtuGmQXhppCHrxp6fMKCz2GaXiN1RZLp3LYTgPdw"
	testVec2MasterPrivKey := "edprvLBTeEfV67ysEnnS44ZWdMoEf1LGt3QN8huAGwmRBfnekd34gbMYDBSvXk2i7jYhQkv1Rfua1qnEdGPrXDCxYuXQZHyrQ9P6esQe8Dhf6jPGHwmpW4jy33kgkUXYTvHBizYE2jvDPVwUZbvJ1gf74Q"

	tests := []struct {
		name        string
		master      string
		path        []uint32
		wantPriv    string
		wantPrivHex string
		wantPubKey  string
	}{
		// Test vector 1
		{
			name:        "test vector 1 chain m",
			master:      testVec1MasterPrivKey,
			path:        []uint32{},
			wantPriv:    "edprvKxPVAhTZvBiJr5AM7S78fR1jDVYjegWEwjUTCxc3QJ25Svcjr2TbnNZiGURfStMSzwDZbK45BjiUbSwZNNArsNJevrazjqGX1KsQoMtPuYyyxrtuGmQXhppCHrxp6fMKCz2GaXiN1RZLp3LYTgPdw",
			wantPrivHex: "2d6a33760000000000000000004dd9d338bb17939ab4bd4eaa0d16a866090750e9a3ab2b3972016f0db5c98a96f8eb0555b41f52a250a9c99f9dee2a0ae225323cfc41601d29ad3e725b733f45ca0da6fc28f2c01d91c505bece78b8c697e299d3fcfece72d07943b14e3b483001",
			wantPubKey:  "edpubJvbz2mMfyqs3vcYWmX7ZJKr71hXw51xeJC9BHR3eRUnXtTrFSuvtn9F3FPga4HNXRgVdkWAP2dERGYaNdZFE1quTMZQp9eD4FK3GYZcHj",
		},
		{
			name:        "test vector 1 chain m/0",
			master:      testVec1MasterPrivKey,
			path:        []uint32{0},
			wantPriv:    "edprvLBTeEfV67yrrmxZ3HL6VBH8EX5GwvUQpyWhs5PHdaxR9k6SNAbgN6zQxhQFad9Xrdx4z6CqNHkLf2kway4n35hjhLes4VrADHNgxHgAfFtz2L5Mv668AeGzP589B4UchwAiPjJTru4u6LrbJG4VaK",
			wantPrivHex: "2d6a337601c795cbb00000000046f2bc79fd365c5d0196201148183e044fb079056a30fa621ebfe7ecea2a884b70b2a0641a21dd475ace2b8b0d87dbdf199043d1c217d02bb6ca6ab462733f45c47c4b335e4e64e3fa266fd8e025b6af083abff18f77e23f902c8b2f8026113901",
			wantPubKey:  "edpubKgcAaHKejwLWSSXGCJzVBtQuv8SnxGDFxVkB5rmkh94BTUzf7qezs8MaAH31NZPNhxqhCNwy8SmFfpL4SM7bx7CDVn5dt7Hxf6vjkUHav",
		},
		{
			name:        "test vector 1 chain m/0/1",
			master:      testVec1MasterPrivKey,
			path:        []uint32{0, 1},
			wantPriv:    "edprvLHv3VPo7dYxgbxww2cKPJUVshE2rHtBV62Kk4AGwiec5qaEaQkbyaTLof5Rh3Nmfm9yRk2HottaJgH878BnW7cqr1EVABkYq4LqVCpshHjVDe7hP3WRncknR5tGipqXidEKDMadDAZZNeZJHKETt6",
			wantPrivHex: "2d6a337602a8912d4000000001f396cd4f836ab0bfe5597250d7292bc7410287bb7f6f7009a2e57df9ccd4c3dbb0e46954e20c20913c86af5af7d091c5381412177daee6072b90ba2867733f45fc2021047021fa21525ba22ebc3c7ac39692a51a91bd4da58a9438c5399db85701",
			wantPubKey:  "edpubL4LWdpcw1P2eQHLzVEyKpXkNig7qJg41bSxhrxCeVThF4vRW68jwh5et1Y94hyiJ8wiB41dojmP7DGSnKkCAL3pR8A5HM22kwbh4VFaAT",
		},
		{
			name:        "test vector 1 chain m/0/1/2",
			master:      testVec1MasterPrivKey,
			path:        []uint32{0, 1, 2},
			wantPriv:    "edprvLQnubiUfenqXyfh94n5qZ9FQNA298Uo8nBGe56T8NtZBw5NK9prj6NMpukG9SvQS8QwtuxGqQwyttSaAnHHsQgFfq5sNdKJGpt99VtRuKjfYJHJ5rjnfWe3c6J4ruH1u1xvzcAC4Q85iCva2nazGd",
			wantPrivHex: "2d6a337603983fc9b7000000029dd9cbc879a06acdf8803b2787bac6553b4040e8e5015ca5d0740cedf145742a40d5084db3c520e31c37a7fbe2d66dea7fe98aab9ec24edf8b3f8a9d6c733f45c842d073ab519fd3ed40c5a2845b1c3461036cbbc6eb5f4a67712f876438541401",
			wantPubKey:  "edpubLTVCzHgZkDYi5ck55p6pKWM2PgCdDcLctMjK8AXiv3en3hd2rsnqPQPLvsmk3mL3YmGqSURsGXZuKyvYigiabiroLyzH5wR5D5f1acUzA",
		},
		{
			name:        "test vector 1 chain m/0/1/2/2",
			master:      testVec1MasterPrivKey,
			path:        []uint32{0, 1, 2, 2},
			wantPriv:    "edprvLYz8zdAN8K8yUpCr5DVPnPJdyCTpqkT7na6FfypgwSUqV7pL6BxyKNA2E2E9j3f81dBLr7TXkHRcTAZ99sdkunoswpo3jfKEVP25Uadho59pRpWpLJDkL5sbiJPXiwwDkgNsqjhe7F4CiqaQw5emf",
			wantPrivHex: "2d6a337604b5d2326d0000000212ef3e8cd05c60eed3412979c2c9a4193f28a3b6feb91ccbad3a5b7c996fe3eed86921a9fec3625116a16dc99c344cc7f42e8886567eb6ba95d139b86f733f457b823e520bcaeee8ecd98eb7f0a9f339b971a87aded0f70be24c88d2208732c601",
			wantPubKey:  "edpubLw4yeV6dt8hHR8G3ffqYji4MYnK37WM51j3oe1zBcAXqvkM3NYr6UUD4RdSZbC5XViQJAHX9LZiPQDsSgkFLtuhgudCFd3xjV2xboPkt8",
		},
		{
			name:        "test vector 1 chain m/0/1/2/2/1000000000",
			master:      testVec1MasterPrivKey,
			path:        []uint32{0, 1, 2, 2, 1000000000},
			wantPriv:    "edprvLfcNEnE64osW223h7e8MEJLmJRP7QvmQRVCaWosasQDSgw9mc7zUBVmhMWw8DRr6q48XmN9a7mtT1TsL2XiD9AXvhqLP2sELPyD62RPwss3i6JJEfqhPki6dRdZLMwrdNbKyA1rRLWPmhJjM3rQVK",
			wantPrivHex: "2d6a3376059cb55cfb3b9aca008d887c7803de6bd239155706eea5b94a6c638035ebf02ea0e6c67eaa3fcf37dbc8bd065f3b417142ea6c92073574037ac5e13e7f036e57993e15134977733f45c5ca98a8558a4631fe500f67b23bdd20c25e0f2a107a3d4db6d7a05c1a0661b901",
			wantPubKey:  "edpubMKNQTyYdHGxVsdsLjCyigX5A1yYy6Q4Pvn1MBjTxsJ9Aayg2TU9WcGCdoNicXUacewBDQwbzYmhaB1A8rTjh7138dhKT5R2CPY9Cqyhqg",
		},

		// Test vector 2
		{
			name:        "test vector 2 chain m",
			master:      testVec2MasterPrivKey,
			path:        []uint32{},
			wantPriv:    "edprvLBTeEfV67ysEnnS44ZWdMoEf1LGt3QN8huAGwmRBfnekd34gbMYDBSvXk2i7jYhQkv1Rfua1qnEdGPrXDCxYuXQZHyrQ9P6esQe8Dhf6jPGHwmpW4jy33kgkUXYTvHBizYE2jvDPVwUZbvJ1gf74Q",
			wantPrivHex: "2d6a337601c795cbb0000000809c7bc36dadf6f4f4359707d0788305d831cf8244632646bfffe2b981f1ff08ed20be029c76ae0049b0a86f9b3a301fffcd71b6c3906486ccbf68b87c60733f45bdd284527e04e26028cb0af5f6cc3cb162b80f9ecd96526c11b72eaa240a114901",
			wantPubKey:  "edpubKgcAaHKejwMnYcqQhP8PSfRFpzn8yWMG6BCNoBskNWd9u1pAyBT15V3FQrRgiQCcY5nxZr9TK78LDBwbvSH9HgHT6x5EtACj9UZPU5CrF",
		},
		{
			name:        "test vector 2 chain m/0",
			master:      testVec2MasterPrivKey,
			path:        []uint32{0},
			wantPriv:    "edprvLHHPih144ugGAp8cs4MzqgHBgm1MC6RawrNjJDfnGW1wMGRQvRZrHGnYXoHcdXJuWEHZfhVGTBLV4RaBr1iPmGbgiswkiavQ3gfimVLpCWCBB4aqiFMmVotxW7MLnqC421AGfpr7YiXht6vfbzuSv",
			wantPrivHex: "2d6a337602928afe6500000000839761b6d91c10a9ca0b96dbcf4aed950e51400d7d6b154c220609270149271f689cc987bea34f1427825b0f6fa323563b8ae04d69bf9d023b6bc64e61733f453661a4ad5b7b5eb639b4c4d241891c8f5ad32b334bbec8fc9aa6081907365ca401",
			wantPubKey:  "edpubL2D8erQhzSadUoytjSMhgs6nRDcrgysq8zHAZEPyoBNQy9UfHRMv7w3xdyCoiZiv3VRAT5EsY3TiaK3TjLqN7BLjUy44dLigdzdwcJKGK",
		},
		{
			name:        "test vector 2 chain m/0/2147483647",
			master:      testVec2MasterPrivKey,
			path:        []uint32{0, 2147483647},
			wantPriv:    "edprvLTXs4HLN7QEG4NnGa4Lvcno7WNsTZBssvZi4RwjQSBPDEpQjAC2QpwsXWwDuQbvPyfZ2FJT8r7biybpE1SgQYiGktUFue5j25EQKcLHQZr37e4YZMyCK9oiKbsrmzExHC5LBHqSNSS8F2qtpktGRZ",
			wantPrivHex: "2d6a337603f7c48fe27fffffff518a7b4ff59cf52c50cf6fcc8c509d572a63974531aa22bde32bbae2821ed9b72013ad6104e0fa92040006d5c60e54e8f893ae109f3ec2c956b1a98264733f457e3b3561003f8e32d51b226f22e6b615b1c8e05fccb1adcd2f81ae0daf63902301",
			wantPubKey:  "edpubLciJT6sZSKy2ek6p2v53dPgEky6hEBAGQadLuVHm14kRN9iAgbCDkYdqfdRQ93FbbG6LTSbG9x8XgLegJvBBNSjHc4ozoHGqVavjCwThC",
		},
		{
			name:        "test vector 2 chain m/0/2147483647/1",
			master:      testVec2MasterPrivKey,
			path:        []uint32{0, 2147483647, 1},
			wantPriv:    "edprvLZ5feVUpvsaZDo5W4kRx63xv7NTq8GHjz5yJmp3dwAmPukYZiXaSppkPnEVaiquJwunrWDfTGqpojtAhwwJaavRHimacU7Nv6xDkbYvst6KMg5QH18uMWWtwYFcXCGiqH7kGZPdNeyQgubdagoSvM",
			wantPrivHex: "2d6a337604b924aa320000000132d068baf08cd2958fe1a06175e6a722eecfb0e29d0c7ac283e36ff2b91b46408052bd654cea7bfcf36314c51100a81cbfe3768ac649dc5946b38de768733f451db7119f531a3e990b054899b50dff327868ed9257b0251adc0adecbed47da1701",
			wantPubKey:  "edpubLwPb4VGaemFW2hN4qR2XnmxbbBKg93Uy3JQcwuvq8jTKANLXbpVBTNLfViCHAhE7LisTUfQAR7MpCtBKjn1Qg92Hzq4PpNbBdpzdiACAy",
		},
		{
			name:        "test vector 2 chain m/0/2147483647/1/2147483646",
			master:      testVec2MasterPrivKey,
			path:        []uint32{0, 2147483647, 1, 2147483646},
			wantPriv:    "edprvLeHf54QnYamJoA14EKJifT8HNBBvmvpWge8cFcLBi31xbeHw1JZApfJcfgiG4MsEPuZhciFmwFssbkXp6zNprPtoKek6cHnYeZbeKJcqu9MjDcf9kmpqm7V8f82SwstLtZJczXBGv2PyJi1XE5Dku",
			wantPrivHex: "2d6a3376056e9cd5537ffffffe093d7d86cc1a474555e7f5b29bcb7c6c48e7a08e7fb82e7324111f302a621da098822deb13a14edb7989299dbc3131ecca68e9449f9fbcc143a226746b733f45d8422cb02b764f8f15ea6cda8b09e2ccfd2c725f433bf87a97ba22a8849792d101",
			wantPubKey:  "edpubMEvBESwZFkqYEMDtVTJo3TVd35ZXJhNRe39PqPcPr33SWkuc8oWHpUWxWE5irSTBood77Jt1BZmEXnGeNL5GwJ3vFjZuSS6dvJhubvKgj",
		},
		{
			name:        "test vector 2 chain m/0/2147483647/1/2147483646/2",
			master:      testVec2MasterPrivKey,
			path:        []uint32{0, 2147483647, 1, 2147483646, 2},
			wantPriv:    "edprvLmKEbUqEUyJbJwK1Doei5MKAfJtKCiQU9TVvZrcSc8uude1HvKpfPYq95az2AWPN3HuuhdYCdrqUAwHYes4xJv67G6Pa3iZgsqhaeuWCLMdeVEidaysqLNCnzArcMVBQFD6ypySqtHnLj7EzaMHA3",
			wantPrivHex: "2d6a3376066387f55500000002c7ed4a52e8de2a90ac5a8907373d128f828332cb05a067880bd5152b073b5eaa0890f7b982235dcd4a4bef17b71094344065bed44e753146a7005b496e733f45c877ad78beac7b35d0f7f1828fe85c9b235c7a5ccba5a1e9f67cede078ed699c01",
			wantPubKey:  "edpubMeaCxy7FnrBWtGKp43Cm9C5wzbAKPtz2vkpN1s3cp9Fzr9mNgXHpMq59JhfswRzpvHVf4xnrcRXZiVkCt5mxVF8WLkHrbTJyNy3GyMQDR",
		},
	}

tests:
	for i, test := range tests {
		extKey, err := NewKeyFromString(ksrv.NewHDSeedRequest_ed25519, test.master)
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

		extKey25519, ok := extKey.(*ExtendedKey25519)
		assert.Equal(t, ok, true)
		privStr := extKey25519.String()
		if privStr != test.wantPriv {
			t.Errorf("Child #%d (%s): mismatched serialized "+
				"private extended key -- got: %s, want: %s", i,
				test.name, privStr, test.wantPriv)
			continue
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

		pubKey25519, ok := pubKey.(*ExtendedKey25519)
		assert.Equal(t, ok, true)
		pubStr := pubKey25519.String()

		if pubStr != test.wantPubKey {
			t.Errorf("Child #%d (%s): mismatched serialized "+
				"private extended key -- got: %s, want: %s", i,
				test.name, pubStr, test.wantPubKey)
			continue
		}
	}
}

// TestPublicDerivation_ED25519 tests several vectors which derive public keys from
// other public keys works as intended.
func TestPublicDerivation_ED25519(t *testing.T) {
	// The public extended keys for test vectors in [BIP32].
	testVec1MasterPubKey := "edpubJvbz2mMfyqs3vcYWmX7ZJKr71hXw51xeJC9BHR3eRUnXtTrFSuvtn9F3FPga4HNXRgVdkWAP2dERGYaNdZFE1quTMZQp9eD4FK3GYZcHj"
	testVec2MasterPubKey := "edpubKgcAaHKejwMnYcqQhP8PSfRFpzn8yWMG6BCNoBskNWd9u1pAyBT15V3FQrRgiQCcY5nxZr9TK78LDBwbvSH9HgHT6x5EtACj9UZPU5CrF"

	tests := []struct {
		name       string
		master     string
		path       []uint32
		wantPub    string
		wantPubHex string
	}{
		// Test vector 1
		{
			name:       "test vector 1 chain m",
			master:     testVec1MasterPubKey,
			path:       []uint32{},
			wantPub:    "edpubJvbz2mMfyqs3vcYWmX7ZJKr71hXw51xeJC9BHR3eRUnXtTrFSuvtn9F3FPga4HNXRgVdkWAP2dERGYaNdZFE1quTMZQp9eD4FK3GYZcHj",
			wantPubHex: "0d7db4510000000000000000004dd9d338bb17939ab4bd4eaa0d16a866090750e9a3ab2b3972016f0db5c98a96e785473e5e8ef8162eee345404bfa8dba6e0bb180cf71c0633348a7104ab13df00",
		},
		{
			name:       "test vector 1 chain m/0",
			master:     testVec1MasterPubKey,
			path:       []uint32{0},
			wantPub:    "edpubKgcAaHKejwLWSSXGCJzVBtQuv8SnxGDFxVkB5rmkh94BTUzf7qezs8MaAH31NZPNhxqhCNwy8SmFfpL4SM7bx7CDVn5dt7Hxf6vjkUHav",
			wantPubHex: "0d7db45101c795cbb00000000046f2bc79fd365c5d0196201148183e044fb079056a30fa621ebfe7ecea2a884b09114c976a365b97f62d4c4cf1b60917e6f8986a2010ad7415b2a71365d439f800",
		},
		{
			name:       "test vector 1 chain m/0/1",
			master:     testVec1MasterPubKey,
			path:       []uint32{0, 1},
			wantPub:    "edpubL4LWdpcw1P2eQHLzVEyKpXkNig7qJg41bSxhrxCeVThF4vRW68jwh5et1Y94hyiJ8wiB41dojmP7DGSnKkCAL3pR8A5HM22kwbh4VFaAT",
			wantPubHex: "0d7db45102a8912d4000000001f396cd4f836ab0bfe5597250d7292bc7410287bb7f6f7009a2e57df9ccd4c3db6fb238a0aadd473e8e4f2aed3fe08425e502a0bc0e7d44f5f799bcc142e3255600",
		},
		{
			name:       "test vector 1 chain m/0/1/2",
			master:     testVec1MasterPubKey,
			path:       []uint32{0, 1, 2},
			wantPub:    "edpubLTVCzHgZkDYi5ck55p6pKWM2PgCdDcLctMjK8AXiv3en3hd2rsnqPQPLvsmk3mL3YmGqSURsGXZuKyvYigiabiroLyzH5wR5D5f1acUzA",
			wantPubHex: "0d7db45103983fc9b7000000029dd9cbc879a06acdf8803b2787bac6553b4040e8e5015ca5d0740cedf145742ad7598da47906eda7ed319e1beddce2d878f63c3e770fc33aba86ae727da189ed00",
		},
		{
			name:       "test vector 1 chain m/0/1/2/2",
			master:     testVec1MasterPubKey,
			path:       []uint32{0, 1, 2, 2},
			wantPub:    "edpubLw4yeV6dt8hHR8G3ffqYji4MYnK37WM51j3oe1zBcAXqvkM3NYr6UUD4RdSZbC5XViQJAHX9LZiPQDsSgkFLtuhgudCFd3xjV2xboPkt8",
			wantPubHex: "0d7db45104b5d2326d0000000212ef3e8cd05c60eed3412979c2c9a4193f28a3b6feb91ccbad3a5b7c996fe3ee7692285e4f1efe14c6c3730cec3ee8c601b189084cc52c01f8abf83d193ce5e100",
		},
		{
			name:       "test vector 1 chain m/0/1/2/2/1000000000",
			master:     testVec1MasterPubKey,
			path:       []uint32{0, 1, 2, 2, 1000000000},
			wantPub:    "edpubMKNQTyYdHGxVsdsLjCyigX5A1yYy6Q4Pvn1MBjTxsJ9Aayg2TU9WcGCdoNicXUacewBDQwbzYmhaB1A8rTjh7138dhKT5R2CPY9Cqyhqg",
			wantPubHex: "0d7db451059cb55cfb3b9aca008d887c7803de6bd239155706eea5b94a6c638035ebf02ea0e6c67eaa3fcf37db0a02d5ddfad7b27374bce3f30eaacde042ad3b541f5f98ee5b0644a685b5bab500",
		},

		// Test vector 2
		{
			name:       "test vector 2 chain m",
			master:     testVec2MasterPubKey,
			path:       []uint32{},
			wantPub:    "edpubKgcAaHKejwMnYcqQhP8PSfRFpzn8yWMG6BCNoBskNWd9u1pAyBT15V3FQrRgiQCcY5nxZr9TK78LDBwbvSH9HgHT6x5EtACj9UZPU5CrF",
			wantPubHex: "0d7db45101c795cbb0000000809c7bc36dadf6f4f4359707d0788305d831cf8244632646bfffe2b981f1ff08ed04f494c6e51b510fa59a3559f16524c75afe71edb9d382abd883928a0d569bcf00",
		},
		{
			name:       "test vector 2 chain m/0",
			master:     testVec2MasterPubKey,
			path:       []uint32{0},
			wantPub:    "edpubL2D8erQhzSadUoytjSMhgs6nRDcrgysq8zHAZEPyoBNQy9UfHRMv7w3xdyCoiZiv3VRAT5EsY3TiaK3TjLqN7BLjUy44dLigdzdwcJKGK",
			wantPubHex: "0d7db45102928afe6500000000839761b6d91c10a9ca0b96dbcf4aed950e51400d7d6b154c220609270149271fa9880ec14dded964763aa61c5b5d549d040f4f650b60ca97278bfb09ef6c698400",
		},
		{
			name:       "test vector 2 chain m/0/2147483647",
			master:     testVec2MasterPubKey,
			path:       []uint32{0, 2147483647},
			wantPub:    "edpubLciJT6sZSKy2ek6p2v53dPgEky6hEBAGQadLuVHm14kRN9iAgbCDkYdqfdRQ93FbbG6LTSbG9x8XgLegJvBBNSjHc4ozoHGqVavjCwThC",
			wantPubHex: "0d7db45103f7c48fe27fffffff518a7b4ff59cf52c50cf6fcc8c509d572a63974531aa22bde32bbae2821ed9b7aea80e0a7128cfcb9b0f7cc103d516aee5396a3d588bbf6075f3e6397b90fab900",
		},
		{
			name:       "test vector 2 chain m/0/2147483647/1",
			master:     testVec2MasterPubKey,
			path:       []uint32{0, 2147483647, 1},
			wantPub:    "edpubLwPb4VGaemFW2hN4qR2XnmxbbBKg93Uy3JQcwuvq8jTKANLXbpVBTNLfViCHAhE7LisTUfQAR7MpCtBKjn1Qg92Hzq4PpNbBdpzdiACAy",
			wantPubHex: "0d7db45104b924aa320000000132d068baf08cd2958fe1a06175e6a722eecfb0e29d0c7ac283e36ff2b91b4640cf9a3cc67cd45cb792db1c66cad153c9f318f088c3b3f502361556e9ed70c33000",
		},
		{
			name:       "test vector 2 chain m/0/2147483647/1/2147483646",
			master:     testVec2MasterPubKey,
			path:       []uint32{0, 2147483647, 1, 2147483646},
			wantPub:    "edpubMEvBESwZFkqYEMDtVTJo3TVd35ZXJhNRe39PqPcPr33SWkuc8oWHpUWxWE5irSTBood77Jt1BZmEXnGeNL5GwJ3vFjZuSS6dvJhubvKgj",
			wantPubHex: "0d7db451056e9cd5537ffffffe093d7d86cc1a474555e7f5b29bcb7c6c48e7a08e7fb82e7324111f302a621da07e765f10ea6cfdccb6e3abe90912f40ceb6c24bdf5e3cf5c5fbbb5d4b4aeddb100",
		},
		{
			name:       "test vector 2 chain m/0/2147483647/1/2147483646/2",
			master:     testVec2MasterPubKey,
			path:       []uint32{0, 2147483647, 1, 2147483646, 2},
			wantPub:    "edpubMeaCxy7FnrBWtGKp43Cm9C5wzbAKPtz2vkpN1s3cp9Fzr9mNgXHpMq59JhfswRzpvHVf4xnrcRXZiVkCt5mxVF8WLkHrbTJyNy3GyMQDR",
			wantPubHex: "0d7db451066387f55500000002c7ed4a52e8de2a90ac5a8907373d128f828332cb05a067880bd5152b073b5eaa3376141e9716ef48c4d21a55c81b79b3e0f06efa1f4709054c0934bedc055f3000",
		},
	}

tests:
	for i, test := range tests {
		extKey, err := NewKeyFromString(ksrv.NewHDSeedRequest_ed25519, test.master)
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

		extKey25519, ok := extKey.(*ExtendedKey25519)
		assert.Equal(t, ok, true)
		pubStr := extKey25519.String()
		if pubStr != test.wantPub {
			t.Errorf("Child #%d (%s): mismatched serialized "+
				"public extended key -- got: %s, want: %s", i,
				test.name, pubStr, test.wantPub)
			continue
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

// TestGenenerateSeed ensures the GenerateSeed function works as intended.
func TestGenenerateSeed_ED25519(t *testing.T) {
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

// TestExtendedKeyAPI_ED25519 ensures the API on the ExtendedKey type works as intended.
func TestExtendedKeyAPI_ED25519(t *testing.T) {
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
			extKey:    "edprvKxPVAhTZvBiJr5AM7S78fR1jDVYjegWEwjUTCxc3QJ25Svcjr2TbnNZiGURfStMSzwDZbK45BjiUbSwZNNArsNJevrazjqGX1KsQoMtPuYyyxrtuGmQXhppCHrxp6fMKCz2GaXiN1RZLp3LYTgPdw",
			isPrivate: true,
			parentFP:  0,
			privKey:   "f8eb0555b41f52a250a9c99f9dee2a0ae225323cfc41601d29ad3e725b733f45ca0da6fc28f2c01d91c505bece78b8c697e299d3fcfece72d07943b14e3b4830",
			pubKey:    "e785473e5e8ef8162eee345404bfa8dba6e0bb180cf71c0633348a7104ab13df",
		},
		{
			name:       "test vector 1 chain m/0H/1/2H public",
			extKey:     "edpubLX5wj4b92PY8Kt6PLuUUeSLND1mWXoVykxffhQWH7Zgc3hFB9xdNiJu9bmKAkT4HontbgJq8S7S5tnMgb7WdKwkAdLSW2Soxm1emHrrfQ",
			isPrivate:  false,
			parentFP:   3179456785,
			privKeyErr: ErrNotPrivExtKey,
			pubKey:     "db34ca34f4cf2777c8e3e04f4d50f225f0fb06de4c117d87a9402f7ca161a802",
		},
	}

	for i, test := range tests {
		key, err := NewKeyFromString(ksrv.NewHDSeedRequest_ed25519, test.extKey)
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

		key25519, ok := key.(*ExtendedKey25519)
		assert.Equal(t, ok, true)
		serializedKey := key25519.String()
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

// TestErrors_ED25519 performs some negative tests for various invalid cases to ensure
// the errors are handled properly.
func TestErrors_ED25519(t *testing.T) {
	// Should get an error when seed has too few bytes.
	net := &chaincfg.MainNetParams
	_, err := NewMaster(ksrv.NewHDSeedRequest_ed25519, bytes.Repeat([]byte{0x00}, 15), net)
	if err != ErrInvalidSeedLen {
		t.Fatalf("NewMaster: mismatched error -- got: %v, want: %v",
			err, ErrInvalidSeedLen)
	}

	// Should get an error when seed has too many bytes.
	_, err = NewMaster(ksrv.NewHDSeedRequest_ed25519, bytes.Repeat([]byte{0x00}, 65), net)
	if err != ErrInvalidSeedLen {
		t.Fatalf("NewMaster: mismatched error -- got: %v, want: %v",
			err, ErrInvalidSeedLen)
	}

	// Generate a new key and neuter it to a public extended key.
	seed, err := GenerateSeed(RecommendedSeedLen)
	if err != nil {
		t.Fatalf("GenerateSeed: unexpected error: %v", err)
	}
	extKey, err := NewMaster(ksrv.NewHDSeedRequest_ed25519, seed, net)
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
		extKey, err := NewKeyFromString(ksrv.NewHDSeedRequest_ed25519, test.key)
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

// TestZero_ED25519 ensures that zeroing an extended key works as intended.
func TestZero_ED25519(t *testing.T) {
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
			extKey: "edprvKxPVAhTZvBiJr5AM7S78fR1jDVYjegWEwjUTCxc3QJ25Svcjr2TbnNZiGURfStMSzwDZbK45BjiUbSwZNNArsNJevrazjqGX1KsQoMtPuYyyxrtuGmQXhppCHrxp6fMKCz2GaXiN1RZLp3LYTgPdw",
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
		key25519, ok := key.(*ExtendedKey25519)
		assert.Equal(t, ok, true)
		serializedKey := key25519.String()
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
		key, err := NewMaster(ksrv.NewHDSeedRequest_ed25519, masterSeed, test.net)
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
		key, err = NewKeyFromString(ksrv.NewHDSeedRequest_ed25519, test.extKey)
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

func TestExtendedKey_ChildNumber_ED25519(t *testing.T) {
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
			k := &ExtendedKey25519{}
			k.ChildNum = tt.fields.childNum
			if got := k.ChildNumber(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ExtendedKey.ChildNumber() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestExtendedKey_Key_ED25519(t *testing.T) {
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
			k := &ExtendedKey25519{}
			k.KeyB = tt.fields.key
			if got := k.Key(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ExtendedKey.Key() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestExtendedKey_ChainCode_ED25519(t *testing.T) {
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
			k := &ExtendedKey25519{}
			k.ChainCodeB = tt.fields.chainCode
			if got := k.ChainCode(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ExtendedKey.ChainCode() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestExtendedKey_Version_ED25519(t *testing.T) {
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
			k := &ExtendedKey25519{}
			k.VersionB = tt.fields.version
			if got := k.Version(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ExtendedKey.Version() = %v, want %v", got, tt.want)
			}
		})
	}
}
