package rsa

import (
	"encoding/base64"
	"testing"
)

func TestGenRSAKey(t *testing.T) {
	keys, _ := GenRSAKey()

	keys.SaveKey("./")

}

func TestRSA(t *testing.T) {
	keys, _ := GenRSAKey()

	sourceMsg := "韩媒发现：“抢枪”女子身份不简单"

	t.Logf("原始字符串：%s", sourceMsg)

	cipher := keys.Encrypt(sourceMsg)

	t.Logf("秘文:%s", base64.RawStdEncoding.EncodeToString(cipher))

	de := keys.Decrypt(cipher)

	t.Logf("解密结果：%s", de)
}

func TestRSASign(t *testing.T) {
	keys, _ := GenRSAKey()

	sourceMsg := "韩媒发现：“抢枪”女子身份不简单"

	t.Logf("原始字符串：%s", sourceMsg)

	sign, err := keys.Sign(sourceMsg)
	if err != nil {
		panic(err)
	}

	pass := CheckSign(sourceMsg, sign, keys.pub)

	t.Logf("pass:%t", pass)
}
