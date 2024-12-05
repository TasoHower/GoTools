package blake2

import (
	"encoding/base64"
	"testing"
)

func TestHash(t *testing.T) {
	input := []byte(`以下是一个在Go语言中使用golang.org/x/crypto/blake2b包来实现BLAKE2b哈希算法的示例代码`)

	hash, _ := Hash(input, 256)

	t.Log(base64.RawStdEncoding.EncodeToString(hash))

	hash, _ = Hash(input, 384)

	t.Log(base64.RawStdEncoding.EncodeToString(hash))

	hash, _ = Hash(input, 512)

	t.Log(base64.RawStdEncoding.EncodeToString(hash))
}
