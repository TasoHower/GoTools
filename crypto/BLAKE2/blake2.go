package blake2

import (
	"errors"
	"fmt"

	"golang.org/x/crypto/blake2b"
)

// blake2 是一个 Hash 算法
func Hash(data []byte, bytes int) ([]byte, error) {
	switch bytes {
	case 384:
		hash, err := blake2b.New384(nil)
		if err != nil {
			fmt.Println("Error creating hash:", err)
			return nil, err
		}

		// 将数据写入哈希对象
		hash.Write(data)

		// 计算哈希值
		result := hash.Sum(nil)
		return result, nil

	case 512:
		hash, err := blake2b.New512(nil)
		if err != nil {
			fmt.Println("Error creating hash:", err)
			return nil, err
		}

		// 将数据写入哈希对象
		hash.Write(data)

		// 计算哈希值
		result := hash.Sum(nil)
		return result, nil

	case 256:
		hash, err := blake2b.New256(nil)
		if err != nil {
			fmt.Println("Error creating hash:", err)
			return nil, err
		}

		// 将数据写入哈希对象
		hash.Write(data)

		// 计算哈希值
		result := hash.Sum(nil)
		return result, nil

	default:

	}

	return nil, errors.New("undefined hash bytes")
}
