package shamirs

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"testing"
)

func TestCombine(t *testing.T) {
	var test [][]byte
	test0, _ := hex.DecodeString("317f5f271ee0c738b858f406366f973b7fa24bd286f7b6761966cc90104dbef730f263450134036b4c4e3a65b1f2f229c13961490892ada3a5ef4a4f12bc768f")
	test1, _ := hex.DecodeString("e0f921792ffe4e04b0df06fc2ebd5da049bcb33445bafb042fc82c12a64f69e51b3b28d0ca058c8177952553b8fb23c6f975ff0e88da77ec0bcc15d30c1fcbe8")
	test2, _ := hex.DecodeString("02cffe3d2fd9921f83df820b00b355a948d2061a22c5a7df02d0ece6fb1946d6a21b09b560740c220972e08357f0a926f6fece0f9133d475bbc26745ef1822d7")
	test3, _ := hex.DecodeString("5371f27ac4b87c2a506b56ef50fd93b453ecadf0cdd6f433b1f7cc97d9ae7cea05e0f324e9ed30ce9bb331db333402dd486e2c9463ccd8d293ed296141b1188b")
	test4, _ := hex.DecodeString("2e4167195e6a2c23ee455730e814ad17a646e3323913238d86d860d920b12075ba0ab4e75394f2cd370ab06ce4197540e1fb7027e80e85aec3e8b0ac8d89d674")

	test = append(test, test0)
	test = append(test, test1)
	test = append(test, test2)
	test = append(test, test3)
	test = append(test, test4)

	var shares [][]byte

	//随机取n个
	rands := make(map[int]int, 3)
	j := 0
	for j < 3 {
		var tmp [1]byte
		_, err := rand.Read(tmp[:])
		if err != nil {
			continue
		}
		r := int(tmp[0] % 5)
		_, ok := rands[r]
		if ok {
			continue
		}
		rands[r] = r
		j++
		shares = append(shares, test[r])
	}

	fmt.Println(rands)

	rets, err := Combine(shares)
	if err != nil {
		t.Error(err)
		return
	}
	if hex.EncodeToString(rets) != "e39ce94378da661e6c84d801d561dc5e9e53bdcdf6f40f28f782a2c1187198dd" {
		t.Error(hex.EncodeToString(rets))
		return
	}
}
