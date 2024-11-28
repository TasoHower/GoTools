package bls

import (
	"fmt"

	bls12381 "github.com/kilic/bls12-381"
)

var (
	//AugSchemeDst 签名solt
	AugSchemeDst = []byte("BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_AUG_")
)

// AugSchemeMPL 签名对象结构体
type AugSchemeMPL struct{}

// Sign 签名
func (asm *AugSchemeMPL) Sign(sk PrivateKey, message []byte) ([]byte, error) {
	pointG2, err := coreSignMpl(sk, sk.GetPublicKey(), message, AugSchemeDst)
	if err != nil {
		return nil, fmt.Errorf("coreSignMpl : %s", err.Error())
	}
	return bls12381.NewG2().ToCompressed(pointG2), nil
}

// Verify 验证
func (asm *AugSchemeMPL) Verify(pk PublicKey, message []byte, sig []byte) bool {
	return coreVerifyMpl(
		pk,
		append(pk.Bytes(), message...),
		sig,
		AugSchemeDst,
	)
}

func coreSignMpl(sk PrivateKey, pk PublicKey, message, dst []byte) (*bls12381.PointG2, error) {
	g2Map := bls12381.NewG2()

	q, err := g2Map.HashToCurve(append(pk.Bytes(), message...), dst)
	if err != nil {
		return nil, fmt.Errorf("HashToCurve : %s", err.Error())
	}

	return g2Map.MulScalar(g2Map.New(), q, bls12381.NewFr().FromBytes(sk.Bytes())), nil
}

func coreVerifyMpl(pk PublicKey, message []byte, sig, dst []byte) bool {

	g2Map := bls12381.NewG2()
	q, err := g2Map.HashToCurve(message, dst)
	if err != nil {
		return false
	}
	// 校验
	signature, err := bls12381.NewG2().FromCompressed(sig)
	if err != nil {
		return false
	}

	engine := bls12381.NewEngine()

	g1Neg := new(bls12381.PointG1)
	g1Neg = bls12381.NewG1().Neg(g1Neg, G1Generator())

	engine = engine.AddPair(pk.G1(), q)
	engine = engine.AddPair(g1Neg, signature)

	return engine.Check()
}
