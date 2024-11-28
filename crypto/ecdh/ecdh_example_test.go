package ecdh

import (
	"bytes"
	"crypto/elliptic"
	"encoding/hex"
	"fmt"
)

func ExampleKeyExchange_GenerateKey() {
	dh := Create(elliptic.P256())
	dh.GenerateKey(nil)

	data, _ := hex.DecodeString("19ce3de1041c7d3d538bd2501112a221543a14060173f01933cc7ab118056b0b")
	pv, pb, _ := dh.GenerateKey(bytes.NewReader(data))
	fmt.Printf("%x\n", pv)
	fmt.Printf("%x\n", pb)

	// Output:
	// 198c3de1041c7d3d538bd2501112a221543a14060173f01933cc7ab118056b0b
	// 04712848c70ab6b5daeac50b7a66d1ecdc062da2862d69ddd20c7ff0988ea81f26f9a9b8c02f8a39f7a1a8f4d0ed9cbc2351857380c843b6b6cb4b622943158410
}

func ExampleKeyExchange_ComputeSecret() {
	dh := Create(nil)

	// get pubkey and privkey from nodejs
	selfPriv, _ := hex.DecodeString("a568587f46c4a6028ff186e6da8775a73823e1ea819e3dde4f0da15b1962850c")
	peerPub, _ := hex.DecodeString("0417fc453d456c4762b1b4d402d61f9ffa723275ad6af57b0e5b0f140fcd97848f6fa3970caba8f513bc9cce63f90078844e7be576785002c337abcf811613dc78")
	secret, _ := dh.ComputeSecret(selfPriv, peerPub)
	fmt.Printf("%x\n", secret)
	// Output:
	// a2f95f84375d5e266a565d4e8d9a5c52b390a3abcd04c91eb9b9c706df63c189
}
