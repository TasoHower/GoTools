package signer

import (
	"encoding/hex"
	"fmt"

	"git.liebaopay.com/ksrv/keyserver/crypto/pasta"
)

// PastaSchnorrMina msg为完整的签名数据
func PastaSchnorrMina(msg, privKey []byte) ([]byte, error) {
	var priv32 [32]byte
	copy(priv32[:], privKey)
	tx, networkID, err := pasta.TransactionFromBytes(msg)
	if err != nil {
		return nil, err
	}

	privKeyS, err := pasta.ScalarFromBytes(priv32)
	if err != nil {
		return nil, err
	}

	pub, err := pasta.GeneratePubKey(privKeyS)
	if err != nil {
		return nil, err
	}

	kp := pasta.Keypair{PubKey: *pub, PriKey: *privKeyS}

	sig := pasta.Sign(&kp, tx, networkID)

	sigHex, err := pasta.SignatureToHex(sig)
	if err != nil {
		return nil, err
	}

	return hex.DecodeString(sigHex)
}

// PastaSchnorrMinaVerify msg为完整的签名数据
func PastaSchnorrMinaVerify(pubKey, msg, sig []byte) (bool, error) {
	tx, networkID, err := pasta.TransactionFromBytes(msg)
	if err != nil {
		return false, err
	}

	var pubkey33 [33]byte
	copy(pubkey33[:], pubKey)
	pub, err := pasta.DeserializeCompressed(pubkey33)
	if err != nil {
		return false, err
	}

	pubK, err := pasta.PointToCompressed(pub)
	if err != nil {
		return false, err
	}

	signature, err := pasta.SignatureFromBytes(sig)
	if err != nil {
		return false, fmt.Errorf("invalid sig : %s", err.Error())
	}
	ret := pasta.Verify(signature, pubK, tx, networkID)

	return ret, nil
}
