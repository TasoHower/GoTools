package encde

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"golang.org/x/crypto/pbkdf2"
)

const SALTLEN = 16

func EncryptSecret(password string, data []byte) ([]byte, error) {
	salt := make([]byte, SALTLEN)
	nonce := make([]byte, 12)

	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	key := Derive([]byte(password), salt)
	cipher := AES256GCM{}
	cipherText, err := cipher.Encrypt(key, data, nonce)
	if err != nil {
		return nil, err
	}
	cipherText = append(salt, cipherText...)
	return cipherText, nil
}

func DecryptSecret(password string, data []byte) ([]byte, error) {
	if len(data) <= SALTLEN {
		return nil, errors.New("密文长度太短")
	}
	salt := data[:SALTLEN]
	cipherText := data[SALTLEN:]
	key := Derive([]byte(password), salt)
	cipher := AES256GCM{}
	plainText, err := cipher.Decrypt(key, cipherText)
	if err != nil {
		return nil, err
	}
	return plainText, nil
}

// Derive 生成新的密码
func Derive(passwd, salt []byte) []byte {
	const (
		iterInit  = 655360
		iterFinal = 1000
		keyLen    = 32
	)
	return pbkdf2.Key(passwd, salt, iterInit, keyLen, sha256.New)
}
