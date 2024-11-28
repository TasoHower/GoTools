package signer

import (
	"encoding/hex"
	"fmt"
	"testing"

	go_schnorr "github.com/Zilliqa/gozilliqa-sdk/schnorr"
)

func TestK1SchnorrZil(t *testing.T) {
	msg, _ := hex.DecodeString("906171c32abf50d6ec125d7e898a39332918b5cbc45ffed9582ff20ebb335f69")
	privkey, _ := hex.DecodeString("906171c32abf50d6ec125d7e898a39332918b5cbc45ffed9582ff20ebb335f69")
	pubkey, _ := hex.DecodeString("026de57c149d94a67232942e2dd8b61145e4f30f02c5f49831cedf833f8333109d")
	signature, err := K1SchnorrZil(msg, privkey)
	if err != nil {
		panic(err)
	}
	if len(signature) != 64 {
		panic("签名长度错误")
	}
	result := go_schnorr.Verify(pubkey, msg, signature[:32], signature[32:])
	if !result {
		panic("验证签名失败")
	}
	fmt.Println("验证签名成功")
}

func Test(t *testing.T) {
	for i := 0; i < 1000; i++ {
		msg, _ := hex.DecodeString("906171c32abf50d6ec125d7e898a39332918b5cbc45ffed9582ff20ebb335f69")
		privkey, _ := hex.DecodeString("906171c32abf50d6ec125d7e898a39332918b5cbc45ffed9582ff20ebb335f69")
		pubkey, _ := hex.DecodeString("026de57c149d94a67232942e2dd8b61145e4f30f02c5f49831cedf833f8333109d")
		signature, err := K1SchnorrZil(msg, privkey)
		if err != nil {
			panic(err)
		}
		if len(signature) != 64 {
			panic("签名长度错误")
		}
		result := go_schnorr.Verify(pubkey, msg, signature[:32], signature[32:])
		if !result {
			panic("验证签名失败")
		}
		fmt.Println("验证签名成功")
	}
}
