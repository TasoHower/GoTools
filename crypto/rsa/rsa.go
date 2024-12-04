package rsa

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"sync"
)

type RSAKey struct {
	priv *rsa.PrivateKey
	pub  *rsa.PublicKey
}

const defaultRSAKeySize = 4096

func GenRSAKey() (*RSAKey, error) {
	// 生成私钥
	privateKey, err := rsa.GenerateKey(rand.Reader, defaultRSAKeySize)
	if err != nil {
		return nil, errors.New("gen rsa key failed")
	}

	// 通过私钥获取公钥
	publicKey := &privateKey.PublicKey

	return &RSAKey{
		priv: privateKey,
		pub:  publicKey,
	}, nil
}

func (c *RSAKey) SaveKey(Path string) {
	wg := sync.WaitGroup{}

	wg.Add(2)

	go func() {
		defer wg.Done()
		file, err := os.Create(Path + "prv.pem")
		if err != nil {
			fmt.Println("Failed to create key file:", err)
			return
		}
		defer file.Close()

		// 将私钥编码为PEM格式
		privateKeyPEM := pem.EncodeToMemory(
			&pem.Block{
				Type:  "RSA PRIVATE KEY",
				Bytes: x509.MarshalPKCS1PrivateKey(c.priv),
			},
		)

		file.Write(privateKeyPEM)
	}()

	go func() {
		defer wg.Done()
		file, err := os.Create(Path + "pub.pem")
		if err != nil {
			fmt.Println("Failed to create key file:", err)
			return
		}

		defer file.Close()

		// 将公钥编码为PKIX格式的PEM
		pubKeyBytes, err := x509.MarshalPKIXPublicKey(c.pub)
		if err != nil {
			fmt.Println("Failed to marshal public key:", err)
			return
		}
		publicKeyPEM := pem.EncodeToMemory(
			&pem.Block{
				Type:  "PUBLIC KEY",
				Bytes: pubKeyBytes,
			},
		)
		file.Write(publicKeyPEM)
	}()

	wg.Wait()
}

func (c *RSAKey) Encrypt(msg string) []byte {
	text, err := rsa.EncryptOAEP(
		sha256.New(),
		rand.Reader,
		c.pub,
		[]byte(msg),
		nil,
	)
	if err != nil {
		fmt.Println("Encryption failed:", err)
		return nil
	}
	return text
}

func (c *RSAKey) Decrypt(cipher []byte) string {
	plaintext, err := rsa.DecryptOAEP(
		sha256.New(),
		rand.Reader,
		c.priv,
		cipher,
		nil,
	)

	if err != nil {
		fmt.Println("Decryption failed:", err)
		return ""
	}

	return string(plaintext)
}

func (c *RSAKey) Sign(msg string) (string, error) {
	hash := sha512.Sum512([]byte(msg))

	signature, err := rsa.SignPSS(
		rand.Reader,
		c.priv,
		crypto.SHA512, hash[:], nil)

	return string(signature), err
}

func CheckSign(msg, signature string, pub *rsa.PublicKey) bool {
	hash := sha512.Sum512([]byte(msg))

	err := rsa.VerifyPSS(pub, crypto.SHA512, hash[:], []byte(signature), nil)

	return err == nil
}
