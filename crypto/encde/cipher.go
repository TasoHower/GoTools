package encde

// Cipher 加解密
type Cipher interface {
	Encrypt(key, plaintext, nonce []byte) ([]byte, error)
	Decrypt(key, ciphertext []byte) ([]byte, error)
}
