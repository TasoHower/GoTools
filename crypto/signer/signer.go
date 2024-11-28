package signer

import (
	"errors"

	"git.liebaopay.com/ksrv/keyserver/ksrv"
)

// Sign 签名算法
func Sign(alg ksrv.NewHDSeedRequest_AlgId, hash, privKey []byte) ([]byte, error) {
	switch alg {
	case ksrv.NewHDSeedRequest_Secp256k1:
		return Secp256k1(hash, privKey)
	case ksrv.NewHDSeedRequest_ed25519:
		return Ed25519(hash, privKey)
	case ksrv.NewHDSeedRequest_k1SchnorrZil:
		return K1SchnorrZil(hash, privKey)
	case ksrv.NewHDSeedRequest_RSA:
		return Rsa4096(hash, privKey)
	case ksrv.NewHDSeedRequest_pastaSchnorrMina:
		return PastaSchnorrMina(hash, privKey)
	case ksrv.NewHDSeedRequest_bls12381:
		return Bls12381(hash, privKey)
	case ksrv.NewHDSeedRequest_Secp256r1:
		return Secp256r1(hash, privKey)
	case ksrv.NewHDSeedRequest_Ergo:
		return ErgoSchnorr(hash, privKey)

	}
	return nil, errors.New("unsupported alg")
}

// Verify 验证
func Verify(alg ksrv.NewHDSeedRequest_AlgId, pubKey, hash, sig []byte) (bool, error) {
	switch alg {
	case ksrv.NewHDSeedRequest_Secp256k1:
		return Secp256k1Veify(pubKey, hash, sig), nil
	case ksrv.NewHDSeedRequest_ed25519:
		return Ed25519Verify(pubKey, hash, sig), nil
	case ksrv.NewHDSeedRequest_k1SchnorrZil:
		return K1SchnorrZilVerify(pubKey, hash, sig), nil
	case ksrv.NewHDSeedRequest_RSA:
		err := Rsa4096Verify(pubKey, hash, sig)
		if err != nil {
			return false, err
		}
		return true, nil
	case ksrv.NewHDSeedRequest_pastaSchnorrMina:
		return PastaSchnorrMinaVerify(pubKey, hash, sig)
	case ksrv.NewHDSeedRequest_bls12381:
		return Bls12381Verify(pubKey, hash, sig)
	case ksrv.NewHDSeedRequest_Secp256r1:
		return Secp256r1Veify(pubKey, hash, sig), nil
	case ksrv.NewHDSeedRequest_Ergo:
		return ErgoVerify(pubKey, hash, sig)
	}
	return false, errors.New("unsupported alg")
}
