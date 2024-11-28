package encde

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
)

// Error list
var (
	ErrInvalidKeySize        = errors.New("Key size is not 32 bytes")
	ErrInvalidNonceSize      = errors.New("Nonce size is not 12 bytes")
	ErrInvalidCiphertextSize = errors.New("Invalid ciphertext length")
)

var _ Cipher = (*AES256GCM)(nil)

// AES256GCM 加解密
type AES256GCM struct{}

// Encrypt 加密数据，其中前12字节为 gcm nonce
func (AES256GCM) Encrypt(key, plaintext, nonce []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, ErrInvalidKeySize
	}

	if len(nonce) != 12 {
		return nil, ErrInvalidKeySize
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	ciphertext := aesgcm.Seal(nil, nonce, plaintext, nil)
	return append(nonce, ciphertext...), nil
}

// Decrypt 解密数据
func (AES256GCM) Decrypt(key, ciphertext []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, ErrInvalidKeySize
	}

	if len(ciphertext) < 13 {
		return nil, ErrInvalidCiphertextSize
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return aesgcm.Open(nil, ciphertext[:12], ciphertext[12:], nil)
}
