      
package tools

import (
	"encoding/hex"
	"encoding/json"

	"github.com/ethereum/go-ethereum/crypto"
)

type ABI []struct {
	Constant        bool      `json:"constant,omitempty"`
	Inputs          []Outputs `json:"inputs"`
	Name            string    `json:"name,omitempty"`
	Outputs         []Outputs `json:"outputs,omitempty"`
	Payable         bool      `json:"payable,omitempty"`
	StateMutability string    `json:"stateMutability,omitempty"`
	Type            string    `json:"type"`
	Anonymous       bool      `json:"anonymous,omitempty"`
}
type Outputs struct {
	Name string `json:"name"`
	Type string `json:"type"`
}

type Checker struct {
	Type string `json:"type"`
	Name string `json:"name"`
	Short string `json:"short"`
	Full string `json:"full"`
}

// EncodeFunc 通过标准化的函数名格式获取 string 类型的函数 id
func EncodeFunc(formatFunc string) (string,string) {
	hashed := crypto.Keccak256([]byte(formatFunc))[:4]
	return "0x" + hex.EncodeToString(hashed),"0x"+string(hex.EncodeToString(crypto.Keccak256([]byte(formatFunc))))
}

func GetFuncChecker(abi string) []Checker {
	var abis ABI
	var ret []Checker
	err := json.Unmarshal([]byte(abi), &abis)
	if err != nil {
		return nil
	}
	for _, abi := range abis {
		input := abi.Name + "("

		for _, inputS := range abi.Inputs {
			input = input + inputS.Type + ","
		}

		if input[len(input)-1] != uint8('(') {
			input = input[:len(input)-1]
		}
		input += ")"
		s,f := EncodeFunc(input)
		
		ret = append(ret, Checker{
			Type: abi.Type,
			Name: abi.Name,
			Short: s,
			Full: f,
		})
	}

	return ret
}
