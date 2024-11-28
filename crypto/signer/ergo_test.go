package signer

import (
	"encoding/hex"
	"testing"

	"github.com/Zilliqa/gozilliqa-sdk/keytools"
)

func TestErgo(t *testing.T) {
	msg, _ := hex.DecodeString("01bd46b6eb59ad844c848dd7a7435c0f4845cd93d2a820e85237332f44e6a6a38a000000000380c2d72f0008cd02b37480545a185ac8e8b339165df784563de1a4881fb61e1fc28fbe21857dd5cf949f060000c0843d1005040004000e36100204a00b08cd0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798ea02d192a39a8cc7a701730073011001020402d19683030193a38cc7b2a57300000193c2b2a57301007473027303830108cdeeac93b1a57304949f06000080e9a1c8180008cd039ed10b413d1b18ef51a4f32ff947ec43592c6376fd13ee1a693f1f3ebc57aa40949f060000")
	sk, _ := hex.DecodeString("912bc25566d51ba4123abdf1dc2f0f974225cd027ddbfce01d3f3e131bced9a8")
	pk := keytools.GetPublicKeyFromPrivateKey(sk, true)

	sig, err := ErgoSchnorr(msg, sk)
	if err != nil {
		t.Errorf(err.Error())
	}

	ret, err := ErgoVerify(pk, msg, sig)
	if err != nil {
		t.Errorf(err.Error())
	}

	if !ret {
		t.Errorf("verify failed")
	}
}
