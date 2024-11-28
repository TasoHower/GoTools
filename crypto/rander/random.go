package rander

import "crypto/rand"

var _ Rander = (*Random)(nil)

// Rander 随机数生成器
type Rander interface {
	// Get 获取给定长度的随机序列
	Get(size int) ([]byte, error)
}

// Random 密码学安全的随机源
type Random struct{}

// Get 获取给定长度的随机序列
func (Random) Get(size int) ([]byte, error) {
	data := make([]byte, size)
	if _, err := rand.Read(data); err != nil {
		return nil, err
	}
	return data, nil
}
