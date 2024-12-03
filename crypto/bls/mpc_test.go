package bls

import (
	"fmt"
	"log"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/secp256k1"
	"github.com/hashicorp/vault/shamir"
)

const (
	threshold = 3 // 门限数量，至少需要3个参与者
	total     = 5 // 总参与者数量
)

func TestMPC(t *testing.T) {

	privKey, err := crypto.GenerateKey()
	if err != nil {
		log.Fatalf("failed to generate key: %v", err)
	}

	// 分割私钥
	thresholdPrivateKeys := splitPrivateKey(privKey.D, 5, 3)

	// 使用门限数量的私钥部分来生成签名
	signature := generateThresholdSignature(thresholdPrivateKeys[:threshold], "hello world")

	// 打印签名
	fmt.Printf("Threshold Signature: %x\n", signature)
}

// 将完整的私钥分割成多个部分
func splitPrivateKey(privKey *big.Int, total, threshold int) []*big.Int {
	// 使用 Shamir's Secret Sharing 将私钥分割成多个部分
	shares, err := shamir.Split(privKey.Bytes(), total, threshold)
	if err != nil {
		log.Fatalf("failed to split private key: %v", err)
	}

	// 返回分割的私钥部分
	var privateKeys []*big.Int
	for _, share := range shares {
		privateKeys = append(privateKeys, new(big.Int).SetBytes(share))
	}
	return privateKeys
}

// 使用至少 threshold 个私钥部分来生成门限签名
func generateThresholdSignature(privateKeys []*big.Int, message string) []byte {
	// 需要至少 threshold 个参与者来生成签名
	if len(privateKeys) < threshold {
		log.Fatalf("not enough private keys to sign")
	}

	// 合成最终的私钥：这里是简单地将多个私钥部分相加
	finalPrivateKey := new(big.Int)
	for _, key := range privateKeys {
		finalPrivateKey.Add(finalPrivateKey, key)
	}

	// 生成消息的哈希
	hash := crypto.Keccak256Hash([]byte(message))

	// 使用合成的私钥进行签名
	signature, err := secp256k1.Sign(hash.Bytes(), finalPrivateKey.Bytes())
	if err != nil {
		log.Fatalf("failed to sign message: %v", err)
	}

	return signature
}
