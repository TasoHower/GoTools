package hdkey

import (
	"fmt"
	"strconv"
	"strings"
)

// Path 通过币种名称获取路径
// CoinName 每个字符必须都在 [A-Z0-9] 范围内
// 如果长度为0，则返回默认的 `m/21'/28'/13'/0`
func Path(coinName string) (string, error) {
	if coinName == "ADA" {
		return "m/44'/1815'/0'/0", nil
	}

	const alphabet = `ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789`
	const (
		len3DefPath    = `m`
		len2DefPath    = `m/21'`
		len1DefPath    = `m/21'/28'`
		defaultPath    = `m/21'/28'/13'/0`
		handenSymbol   = `'`
		delimateSymbol = `/`
		changeDefPath  = `/0`
	)

	var path strings.Builder
	switch len(coinName) {
	case 3:
		path.WriteString(len3DefPath)
	case 2:
		path.WriteString(len2DefPath)
	case 1:
		path.WriteString(len1DefPath)
	case 0:
		return defaultPath, nil
	}

	for _, item := range coinName {
		path.WriteString(delimateSymbol)
		index := strings.IndexRune(alphabet, item)
		if index == -1 {
			return "", fmt.Errorf("%s not a valid symbol", string(item))
		}
		path.WriteString(strconv.Itoa(index))
		path.WriteString(handenSymbol)
	}
	path.WriteString(changeDefPath)
	return path.String(), nil
}
