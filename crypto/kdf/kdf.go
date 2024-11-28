package kdf

import (
	"crypto/sha256"

	"golang.org/x/crypto/pbkdf2"
)

// Derive 生成新的密码
func Derive(passwd, salt []byte, init bool) []byte {
	const (
		iterInit  = 655360
		iterFinal = 1000
		keyLen    = 32
	)

	var iter int = iterFinal
	if init {
		iter = iterInit
	}
	return pbkdf2.Key(passwd, salt, iter, keyLen, sha256.New)
}
