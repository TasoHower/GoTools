package chacha

import (
	"encoding/base64"
	"fmt"
	"testing"
)

func TestChaCha(t *testing.T) {
	msg := []byte("在Go语言中，你可以使用golang.org/x/crypto库来实现ChaCha20加密算法。以下是一个简单的示例代码，展示了如何使用ChaCha20算法对数据进行加密：")
	key := GenKey()

	cipher, nonce, err := key.Encrypt(msg)
	if err != nil {
		t.Logf("报错：%v\n", err)
		return
	}

	fmt.Printf("明文: %s\n", msg)
	fmt.Printf("Nonce: %v\n", base64.RawStdEncoding.EncodeToString(nonce))
	fmt.Printf("script: %v\n", base64.RawStdEncoding.EncodeToString(cipher))

	decrypted, err := key.Decrypt(cipher, nonce)
	if err != nil {
		t.Logf("报错：%v\n", err)
		return
	}

	fmt.Printf("解密明文：%s\n", decrypted)
}
