package hdkey

import (
	"errors"
	"strconv"
	"strings"

	"git.liebaopay.com/ksrv/keyserver/crypto/bip32"
	"git.liebaopay.com/ksrv/keyserver/crypto/bip39"
	"git.liebaopay.com/ksrv/keyserver/crypto/rander"
	"git.liebaopay.com/ksrv/keyserver/ksrv"
	"github.com/btcsuite/btcd/chaincfg"
)

// Error list
var (
	ErrDeriveNotMaster = errors.New("Derive master seed from child")
	ErrNotNuberic      = errors.New("Not a positive integer")
)

// PubKey 从扩展公钥中获取公钥（压缩格式）
func PubKey(xpub bip32.ExtendedKey, index uint32) ([]byte, error) {
	child, err := xpub.Child(index)
	if err != nil {
		return nil, err
	}

	return child.ECPubKey()
}

// XPubKey 从扩展公钥中获取子扩展公钥
func XPubKey(xpub bip32.ExtendedKey, index uint32) (bip32.ExtendedKey, error) {
	return xpub.Child(index)
}

// PrivKey 从扩展私钥中获取私钥
func PrivKey(xprv bip32.ExtendedKey, index uint32) ([]byte, error) {
	child, err := xprv.Child(index)
	if err != nil {
		return nil, err
	}
	return child.ECPrivKey()
}

// NewMasterKeyByMnemonics 从助记词获得RootKey
func NewMasterKeyByMnemonics(alg ksrv.NewHDSeedRequest_AlgId, coin, mnemonics string) (bip32.ExtendedKey, error) {
	bip39I, err := bip39.NewBip39(alg, coin)
	if err != nil {
		return nil, err
	}

	root, err := bip39I.Mnemonic2Root(mnemonics, "")
	if err != nil {
		return nil, err
	}

	return bip32.NewMasterByRoot(alg, root)
}

// NewMasterKey 获取
func NewMasterKey(alg ksrv.NewHDSeedRequest_AlgId, random rander.Rander) (bip32.ExtendedKey, error) {
	for {
		seed, err := random.Get(bip32.RecommendedSeedLen)
		if err != nil {
			return nil, err
		}

		key, err := bip32.NewMaster(alg, seed, &chaincfg.MainNetParams)
		if err != nil {
			if err == bip32.ErrUnusableSeed {
				continue
			}
			return nil, err
		}
		return key, nil
	}
}

// DerivePath 通过地址衍生新的扩展公私钥
func DerivePath(xprv bip32.ExtendedKey, path string) (bip32.ExtendedKey, error) {
	const (
		bip32MasterSymbol   = `m`
		bip32HardenedSymbol = `'`
		bip32PathDelimiter  = `/`
	)

	splitPath := strings.Split(path, bip32PathDelimiter)

	// 判断是否从主种子开始衍生
	if splitPath[0] == bip32MasterSymbol {
		if xprv.ParentFingerprint() > 0 {
			return nil, ErrDeriveNotMaster
		}
		if len(splitPath) == 1 {
			return xprv, nil
		}
		splitPath = splitPath[1:]
	}

	next := xprv
	for _, item := range splitPath {
		// 跳过空字符串
		if item == "" {
			continue
		}

		var err error
		var index uint64

		lastIndex := len(item) - 1

		// 取出最后一个字符，判断是否为硬化编码
		if string(item[lastIndex]) == bip32HardenedSymbol {
			index, err = strconv.ParseUint(item[:lastIndex], 10, 32)
			index += bip32.HardenedKeyStart
		} else {
			index, err = strconv.ParseUint(item, 10, 32)
		}

		if err != nil {
			return nil, ErrNotNuberic
		}

		// 计算下一层扩展 key
		next, err = next.Child(uint32(index))
		if err != nil {
			return nil, err
		}
	}
	return next, nil
}
