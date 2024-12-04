package bls

import (
	"errors"
	"fmt"

	"github.com/herumi/bls-go-binary/bls"
)

type BLSKey struct {
	priv *bls.SecretKey
	pub  *bls.PublicKey
}

// 风险函数，将 私钥分片 聚合为私钥，输入为 16 进制的私钥明文
func (c *BLSKey) AggSK(sk []string) {
	var aggSK bls.SecretKey

	for _, k := range sk {
		temp := bls.SecretKey{}
		temp.DeserializeHexStr(k)
		aggSK.Add(&temp)
	}

	c.priv = &aggSK
}

func (c *BLSKey) AggPK(pk []string) {
	var aggPK bls.PublicKey

	for _, k := range pk {
		temp := bls.PublicKey{}
		temp.DeserializeHexStr(k)
		aggPK.Add(&temp)
	}

	c.pub = &aggPK
}

func (c *BLSKey) Sign(msg string) (string, error) {
	if c.priv == nil {
		return "", errors.New("private key has not init")
	}
	return c.priv.Sign(msg).GetHexString(), nil
}

func CheckAggSign(pk []string, msg string, sig []string) bool {
	// 聚合公钥
	blsKey := BLSKey{}
	blsKey.AggPK(pk)

	// 聚合签名
	var aggSig bls.Sign
	for _, s := range sig {
		var tempSig bls.Sign

		tempSig.DeserializeHexStr(s)
		aggSig.Add(&tempSig)
	}

	fmt.Println("聚合公钥：", blsKey.pub.SerializeToHexStr())
	fmt.Println("聚合签名：", aggSig.SerializeToHexStr())
	return aggSig.Verify(blsKey.pub, msg)
}
