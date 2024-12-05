package chacha

import (
	"crypto/rand"
	"fmt"
	"log"

	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/chacha20poly1305"
)

type ChaCha20 struct {
	priv []byte
}

func GenKey() ChaCha20 {
	key := make([]byte, chacha20poly1305.KeySize)
	if _, err := rand.Read(key); err != nil {
		panic(err)
	}

	return ChaCha20{
		priv: key[:],
	}
}

func (c *ChaCha20) Encrypt(msg []byte) ([]byte, []byte, error) {
	plaintext := []byte(msg)

	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		fmt.Printf("无法生成Nonce: %v \n", err)
		return nil, nil, err
	}

	// 初始化加密流
	cipher, err := chacha20.NewUnauthenticatedCipher(c.priv, nonce)
	if err != nil {
		fmt.Printf("无法初始化ChaCha20: %v \n", err)
	}

	ciphertext := make([]byte, len(plaintext))
	cipher.XORKeyStream(ciphertext, plaintext)

	return ciphertext, nonce, nil
}

func (c *ChaCha20) Decrypt(cipherText []byte, nonce []byte) (string, error) {
	cipher, err := chacha20.NewUnauthenticatedCipher(c.priv, nonce)
	if err != nil {
		log.Fatalf("无法重新初始化ChaCha20: %v", err)
	}

	decrypted := make([]byte, len(cipherText))
	cipher.XORKeyStream(decrypted, cipherText)

	return string(decrypted), nil
}
