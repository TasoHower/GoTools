package bls

import (
	"fmt"
	"log"
	"testing"

	"github.com/herumi/bls-go-binary/bls"
)

func TestKeys(t *testing.T) {
	err := bls.Init(bls.BLS12_381)
	if err != nil {
		log.Fatalf("Failed to initialize BLS: %v", err)
	}

	// Step 1: 每个参与者生成自己的私钥和公钥
	var sk1, sk2, sk3 bls.SecretKey
	sk1.SetByCSPRNG()
	sk2.SetByCSPRNG()
	sk3.SetByCSPRNG()

	pk1 := sk1.GetPublicKey()
	pk2 := sk2.GetPublicKey()
	pk3 := sk3.GetPublicKey()

	fmt.Println("生成的公钥:")
	fmt.Printf("PK1: %s\n", pk1.SerializeToHexStr())
	fmt.Printf("PK2: %s\n", pk2.SerializeToHexStr())
	fmt.Printf("PK3: %s\n", pk3.SerializeToHexStr())

	var tempPK bls.PublicKey
	tempPK.Add(pk1)
	tempPK.Add(pk2)
	tempPK.Add(pk3)
	fmt.Println("tempPK:", tempPK.SerializeToHexStr())

	// Step 2: 聚合公钥
	var aggPK []string
	aggPK = append(aggPK, pk1.SerializeToHexStr())
	aggPK = append(aggPK, pk2.SerializeToHexStr())
	aggPK = append(aggPK, pk3.SerializeToHexStr())

	// Step 3: 每个参与者对消息签名
	message := "Hello, Threshold Signature!"
	sig1 := sk1.Sign(message)
	sig2 := sk2.Sign(message)
	sig3 := sk3.Sign(message)

	fmt.Println("生成的部分签名:")
	fmt.Printf("Sig1: %s\n", sig1.SerializeToHexStr())
	fmt.Printf("Sig2: %s\n", sig2.SerializeToHexStr())
	fmt.Printf("Sig3: %s\n", sig3.SerializeToHexStr())

	// Step 4: 聚合签名
	var aggSig []string
	aggSig = append(aggSig, sig1.SerializeToHexStr())
	aggSig = append(aggSig, sig2.SerializeToHexStr())
	aggSig = append(aggSig, sig3.SerializeToHexStr())

	var tempSig bls.Sign
	tempSig.Add(sig1)
	tempSig.Add(sig1)
	tempSig.Add(sig1)
	fmt.Println("tempSig:", tempSig.SerializeToHexStr())

	// Step 5: 验证聚合签名
	if CheckAggSign(aggPK, message, aggSig) {
		fmt.Println("聚合签名验证通过！")
	} else {
		fmt.Println("聚合签名验证失败！")
	}
}
