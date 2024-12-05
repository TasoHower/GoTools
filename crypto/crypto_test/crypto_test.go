package crypto

import (
	"encoding/base64"
	"testing"
	aes "tools/crypto/AES"
	"tools/crypto/rsa"
	"tools/crypto/shamir"
)

func TestCrypto(t *testing.T) {
	keys, _ := rsa.GenRSAKey()

	sourceMsg := "韩媒发现：“抢枪”女子身份不简单"

	t.Logf("原始字符串：%s", sourceMsg)

	aesK, _ := aes.GenAESkey([]byte("12ui34y8123ty891248946192637461234612348011023848102349123"))
	t.Logf("AES Key:%s", aesK.StringKey())

	msgC, _ := aesK.Encrypt([]byte(sourceMsg))
	t.Logf("AES 加密后的密文：%s", base64.RawStdEncoding.EncodeToString(msgC))

	aesKC := keys.Encrypt(aesK.StringKey())

	t.Logf("加密后的密钥：%s", base64.RawStdEncoding.EncodeToString(aesKC))

	aesKD := keys.Decrypt(aesKC)
	t.Logf("解密后的密钥：%s", string(aesKD))

	aesK, _ = aes.GenAESkey([]byte(aesKD))
	t.Logf("New AES Key:%s", aesK.StringKey())

	msg, _ := aesK.Decrypt(msgC)
	t.Logf("解密后的密文：%s", msg)
}

func TestShamir(t *testing.T) {
	sourceMsg := "韩媒发现：“抢枪”女子身份不简单"

	t.Logf("原始字符串：%s", sourceMsg)

	aesK, _ := aes.GenAESkey([]byte("kashdf79y19fhq90q3rt1rad9sf17t3419ryfhawpdfu1yfg11fhq7w0efu1"))
	t.Logf("AES Key:%s", aesK.StringKey())

	msgC, _ := aesK.Encrypt([]byte(sourceMsg))
	t.Logf("AES 加密后的密文：%s", base64.RawStdEncoding.EncodeToString(msgC))

	// shamir 密文分片
	keys, err := shamir.Split([]byte(aesK.StringKey()), 5, 3)
	if err != nil {
		t.Log(err)
		return
	}

	for _, k := range keys {
		t.Logf("密钥分片：%s", base64.RawStdEncoding.EncodeToString(k))
	}

	var temp [][]byte

	temp = append(temp, keys[0])
	temp = append(temp, keys[3])
	temp = append(temp, keys[4])

	for _, k := range temp {
		t.Logf("选中的密钥分片：%s", base64.RawStdEncoding.EncodeToString(k))
	}

	combined, err := shamir.Combine(temp)
	if err != nil {
		t.Logf("恢复密钥失败：%v", err)
		return
	}

	rootKey, _ := aes.GenAESkey(combined[:])

	t.Logf("恢复的密钥：%s", rootKey.StringKey())

	d, _ := rootKey.Decrypt(msgC)
	t.Logf("解密后的明文:%s", d)
}
