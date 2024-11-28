package bip39

import (
	"crypto/sha512"
	"errors"

	"git.liebaopay.com/ksrv/keyserver/ksrv"
	"git.liebaopay.com/ksrv/keyserver/lib/go-bip39"
	"golang.org/x/crypto/pbkdf2"
)

// Bip39 Bip39
type Bip39 interface {
	Mnemonic2Root(mnemonic string, password string) ([]byte, error)
}

// Bip39ADA Bip39ADA
type bip39ADA struct {
}

// NewBip39 获得BIP39实例
func NewBip39(alg ksrv.NewHDSeedRequest_AlgId, coin string) (Bip39, error) {
	if alg == ksrv.NewHDSeedRequest_ed25519 {
		return &bip39ADA{}, nil
	}
	//其它情况看要求再实现
	return nil, errors.New("un support alg")
}

// newSeed 这里是ADA特有的方式
func newSeed(mnemonic []byte, password string) []byte {
	return pbkdf2.Key([]byte(password), mnemonic, 4096, 96, sha512.New)
}

func (a *bip39ADA) Mnemonic2Root(mnemonic string, password string) ([]byte, error) {
	entropy, err := bip39.EntropyFromMnemonic(mnemonic)
	if err != nil {
		return nil, err
	}

	// Generate a Bip32 HD wallet for the mnemonic and a user supplied password
	root := newSeed(entropy, "")
	root[0] &= 248
	//the highest bit of the last byte is cleared,
	root[31] &= 127 - 32
	//the second highest bit of the last byte is set.
	root[31] |= 64
	return root, nil
}
