package main

import (
	"fmt"
	"io"
	"os"
	"time"
	"tools/crypto/chacha"
	// "tools/crypto/chacha"
)

func main() {
	file, err := os.Open("/Users/taso/Downloads/cities_202410291811.csv")
	if err != nil {
		fmt.Printf("打开文件时出错: %v\n", err)
		return
	}
	// 别忘了关闭文件
	defer file.Close()

	bytes, err := io.ReadAll(file)
	if err != nil {
		fmt.Printf("读取文件出错: %v \n", err)
		return
	}

	// start := time.Now()

	// hashSHA := sha512.Sum512(bytes)
	// fmt.Println("Hash 结果：", base64.RawStdEncoding.EncodeToString(hashSHA[:]))
	// fmt.Println("耗时：", time.Since(start).Seconds())

	// start = time.Now()

	// hashBLAKE2, _ := blake2.Hash(bytes, 512)
	// fmt.Println("Hash 结果：", base64.RawStdEncoding.EncodeToString(hashBLAKE2[:]))
	// fmt.Println("耗时：", time.Since(start).Seconds())
	// fmt.Println("------AES-----")
	// var n = 1000000
	// for n > 0 {
	// 	start := time.Now()
	// 	keys, _ := aes.GenAESkey([]byte("aieyg9y127ry8qhefoajd80fy16fgqaw9dfg6781gf4g6awgdf8y1278tf8hwdfgaw8tf"))

	// 	cipher, _ := keys.Encrypt(bytes)
	// 	fmt.Println("秘文长度:", len(cipher))
	// 	fmt.Println("加密用时：", time.Since(start).Seconds())

	// 	start = time.Now()
	// 	_, _ = keys.Decrypt(cipher)
	// 	fmt.Println("解密用时：", time.Since(start).Seconds())
	// 	fmt.Println("----AES END---")
	// 	n--

	// }
	key := chacha.GenKey()
	fmt.Println("------CHACHA-----")
	var nn = 1000000
	for nn > 0 {
		start := time.Now()

		cipherCC, nonce, _ := key.Encrypt(bytes)
		if err != nil {
			fmt.Println("报错：", err)
			return
		}

		fmt.Println("秘文长度:", len(cipherCC))
		fmt.Println("加密用时：", time.Since(start).Seconds())
		start = time.Now()
		_, err = key.Decrypt(cipherCC, nonce)
		if err != nil {
			return
		}

		fmt.Println("解密用时：", time.Since(start).Seconds())
		fmt.Println("----CHACHA END---")
		nn--
	}
}
