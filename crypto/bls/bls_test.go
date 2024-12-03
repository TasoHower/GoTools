package bls

import (
	"fmt"
	"testing"

	"github.com/herumi/bls-go-binary/bls"
)

func TestKeys(t *testing.T) {
	// 初始化 BLS 库
	err := bls.Init(bls.BLS12_381)
	if err != nil {
		t.Logf("Failed to initialize BLS: %v", err)
	}

	// Step 1: 每个参与者生成私钥分片
	var sk1, sk2, sk3 bls.SecretKey
	sk1.SetByCSPRNG() // 随机生成私钥
	sk2.SetByCSPRNG()
	sk3.SetByCSPRNG()

	// 输出每个分片的私钥
	fmt.Printf("Private Key 1: %s\n", sk1.SerializeToHexStr())
	fmt.Printf("Private Key 2: %s\n", sk2.SerializeToHexStr())
	fmt.Printf("Private Key 3: %s\n", sk3.SerializeToHexStr())

	// Step 2: 每个参与者对消息签名
	message := "Threshold Signature using MPC Example"
	sig1 := sk1.Sign(message)
	sig2 := sk2.Sign(message)
	sig3 := sk3.Sign(message)

	// 输出每个部分签名
	fmt.Println("部分签名:")
	fmt.Printf("Sig1: %s\n", sig1.SerializeToHexStr())
	fmt.Printf("Sig2: %s\n", sig2.SerializeToHexStr())
	fmt.Printf("Sig3: %s\n", sig3.SerializeToHexStr())

	// Step 3: 聚合部分签名（门限签名需要至少 t=2 个签名）
	// 使用 Lagrange 插值将部分签名聚合成一个最终的签名
	var aggregatedSig bls.Sign

	// 假设我们选择参与者 1 和 2 进行聚合
	//indexes := []int{0, 1} // 参与者 1 和 2 的索引
	signatures := []*bls.Sign{sig1, sig2}

	// 计算每个部分签名的拉格朗日系数
	for _, sig := range signatures {
		var tempSig bls.Sign
		tempSig.SetHexString(sig.GetHexString())
		// 加权并聚合签名
		aggregatedSig.Add(&tempSig)
	}

	// 输出聚合签名
	fmt.Printf("聚合后的签名: %s\n", aggregatedSig.SerializeToHexStr())

	// Step 4: 验证聚合签名
	// 使用生成的公钥验证聚合签名
	var combinedPK bls.PublicKey
	combinedPK.Add(sk1.GetPublicKey())
	combinedPK.Add(sk2.GetPublicKey())
	combinedPK.Add(sk3.GetPublicKey())

	if aggregatedSig.Verify(&combinedPK, message) {
		fmt.Println("聚合签名验证成功！")
	} else {
		fmt.Println("聚合签名验证失败！")
	}
}
