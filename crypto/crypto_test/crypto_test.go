package crypto

import (
	"encoding/base64"
	"testing"
	aes "tools/crypto/AES"
	"tools/crypto/rsa"
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
