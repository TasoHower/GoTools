package aes

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
)

type AESKey struct {
	private []byte
}

var (
	ErrGenKeyInputError = errors.New("input text length must more than 32 bytes")
	ErrWrongKeyBytes    = errors.New("key bytes must length 32")
)

func GenAESkey(in []byte) (*AESKey, error) {
	if len(in) < 32 {
		return nil, ErrGenKeyInputError
	}

	slipt := in[:32]

	return &AESKey{
		private: append([]byte{}, slipt...),
	}, nil
}

func (c *AESKey) StringKey() string {
	return string(c.private)
}

func (c *AESKey) Encrypt(msg string) ([]byte, error) {
	block, _ := aes.NewCipher(c.private)

	plaintextBytes := []byte(msg)
	plaintextBytes = pkcs5Padding(plaintextBytes, aes.BlockSize)

	cipherText := make([]byte, aes.BlockSize+len(plaintextBytes))
	iv := cipherText[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(cipherText[aes.BlockSize:], plaintextBytes)

	return cipherText, nil
}

func (c *AESKey) Decrypt(cipherText []byte) (string, error) {
	block, _ := aes.NewCipher(c.private)

	if len(cipherText) < aes.BlockSize {
		return "", fmt.Errorf("cipher text too short")
	}

	iv := cipherText[:aes.BlockSize]
	cipherText = cipherText[aes.BlockSize:]

	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(cipherText, cipherText)

	plaintext := pkcs5UnPadding(cipherText)
	return string(plaintext), nil
}

func pkcs5Padding(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	padText := make([]byte, padding)
	for i := 0; i < padding; i++ {
		padText[i] = byte(padding)
	}
	return append(data, padText...)
}

func pkcs5UnPadding(data []byte) []byte {
	length := len(data)
	unpadding := int(data[length-1])
	return data[:(length - unpadding)]
}
