package crypto

import (
	"encoding/base64"
	"fmt"
	"testing"
	aes "tools/crypto/AES"
	"tools/crypto/rsa"
	"tools/crypto/shamir"
)

const sourceMsg = `KFC 疯狂星期四 v我50！`

func TestCrypto(t *testing.T) {
	keys, _ := rsa.GenRSAKey()

	fmt.Printf("原始字符串：%s", sourceMsg)

	aesK, _ := aes.GenAESkey([]byte("12ui34y8123ty891248946192637461234612348011023848102349123"))
	fmt.Printf("AES Key:%s", aesK.StringKey())

	msgC, _ := aesK.Encrypt([]byte(sourceMsg))
	fmt.Printf("AES 加密后的密文：%s", base64.RawStdEncoding.EncodeToString(msgC))

	aesKC := keys.Encrypt(aesK.StringKey())

	fmt.Printf("加密后的密钥：%s", base64.RawStdEncoding.EncodeToString(aesKC))

	aesKD := keys.Decrypt(aesKC)
	fmt.Printf("解密后的密钥：%s", string(aesKD))

	aesK, _ = aes.GenAESkey([]byte(aesKD))
	fmt.Printf("New AES Key:%s", aesK.StringKey())

	msg, _ := aesK.Decrypt(msgC)
	fmt.Printf("解密后的密文：%s", msg)
}

func TestShamir(t *testing.T) {
	// fmt.Printf("原始字符串：%s", sourceMsg)

	aesK, _ := aes.GenAESkey([]byte("kashdf79y19fhq90q3rt1rad9sf17t3419ryfhawpdfu1yfg11fhq7w0efu1"))
	fmt.Printf("AES Key:%s\n", aesK.StringKey())

	msgC, _ := aesK.Encrypt([]byte(sourceMsg))
	fmt.Printf("AES 加密后的密文：%s\n", base64.RawStdEncoding.EncodeToString(msgC))

	// shamir 密文分片
	keys, err := shamir.Split([]byte(aesK.StringKey()), 5, 3)
	if err != nil {
		t.Log(err)
		return
	}

	for _, k := range keys {
		fmt.Printf("密钥分片：%s\n", base64.RawStdEncoding.EncodeToString(k))
	}

	var temp [][]byte

	temp = append(temp, keys[0])
	temp = append(temp, keys[3])
	temp = append(temp, keys[4])

	for _, k := range temp {
		fmt.Printf("选中的密钥分片：%s\n", base64.RawStdEncoding.EncodeToString(k))
	}

	combined, err := shamir.Combine(temp)
	if err != nil {
		fmt.Printf("恢复密钥失败：%v \n", err)
		return
	}

	rootKey, _ := aes.GenAESkey(combined[:])

	fmt.Printf("恢复的密钥：%s\n", rootKey.StringKey())

	d, _ := rootKey.Decrypt(msgC)
	fmt.Printf("解密后的明文:%s\n", d)
}
