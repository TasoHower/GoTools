package signer

import (
	"encoding/hex"
	"reflect"
	"testing"
)

func TestEd25519(t *testing.T) {
	type args struct {
		msg     []byte
		privkey []byte
	}

	var MustBase64Decode = func(row string) []byte {
		res, err := hex.DecodeString(row)
		if err != nil {
			panic(err)
		}
		return res
	}

	msg, _ := hex.DecodeString("011a2d964a095820dd09b6a20dc8dfa65015518e3037d93e8b0e6bbac3f54490f1224ad28f638dca")

	tests := []struct {
		name          string
		args          args
		wantSignature []byte
		wantErr       bool
	}{
		{
			name:          "invalid private key size",
			args:          args{make([]byte, 10), make([]byte, 10)},
			wantSignature: nil,
			wantErr:       true},
		{
			name: "64bytes private key size",
			args: args{
				msg:     msg,
				privkey: MustBase64Decode("209522c551a8dd2dc57188abf3895e106f77048eafe222e2fa5082c1c88c6858fb173f8eefa0de2514a1786961cf0225e226dd1f014e3342213a3e0c0d285f8e"),
			},
			wantSignature: MustBase64Decode("3e2e379d7ba66ab785adcce984ea4dc4e2e502214f05cda8c219573620ca0ff4a6e7a787d7a901612b3960bff415db8de9afd824e7ecb22f618ddcd63f180c0a"),
			wantErr:       false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotSignature, err := Ed25519(tt.args.msg, tt.args.privkey)
			if (err != nil) != tt.wantErr {
				t.Errorf("Ed25519() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(gotSignature, tt.wantSignature) {
				t.Errorf("Ed25519() = %v, want %v", gotSignature, tt.wantSignature)
			}
		})
	}
}
