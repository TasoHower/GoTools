package aes

import (
	"encoding/base64"
	"testing"
)

func TestAES(t *testing.T) {
	keys, _ := GenAESkey([]byte("197tabkldhf891gfbipASDOFY01GFBasdhfp891t2gf8ashdfhp"))

	sourceMsg := "韩媒发现：“抢枪”女子身份不简单"

	t.Logf("原始字符串：%s", sourceMsg)

	cipher, err := keys.Encrypt(sourceMsg)
	t.Log(err)
	t.Logf("秘文:%s", base64.RawStdEncoding.EncodeToString(cipher))

	de, err := keys.Decrypt(cipher)
	t.Log(err)

	t.Logf("解密结果：%s", de)
}
