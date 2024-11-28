package encde

import (
	"encoding/hex"
	"reflect"
	"testing"
)

func TestAES256GCM_Encrypt(t *testing.T) {
	var MustHexDecode = func(row string) []byte {
		data, err := hex.DecodeString(row)
		if err != nil {
			panic(err)
		}
		return data
	}
	type args struct {
		key       []byte
		plaintext []byte
		nonce     []byte
	}
	tests := []struct {
		name    string
		args    args
		want    []byte
		wantErr bool
	}{
		{
			name:    "invalid key length",
			args:    args{make([]byte, 10), make([]byte, 10), make([]byte, 10)},
			want:    nil,
			wantErr: true,
		},
		{
			name:    "invalid nonce length",
			args:    args{make([]byte, 10), make([]byte, 10), make([]byte, 10)},
			want:    nil,
			wantErr: true,
		},
		{
			name: "valid",
			args: args{
				key:       MustHexDecode("6368616e676520746869732070617373776f726420746f206120736563726574"),
				plaintext: []byte("exampleplaintext"),
				nonce:     MustHexDecode("6b2994fb5a6bf6654f12dc87"),
			},
			want:    MustHexDecode("6b2994fb5a6bf6654f12dc87756de358d960b2f35d2cca43306454f6619e2d50b9d3dd02e813a8efaa5c8b0a"),
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := AES256GCM{}
			got, err := a.Encrypt(tt.args.key, tt.args.plaintext, tt.args.nonce)
			if (err != nil) != tt.wantErr {
				t.Errorf("AES256GCM.Encrypt() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("AES256GCM.Encrypt() = %v, want %v", hex.EncodeToString(got), hex.EncodeToString(tt.want))
			}
		})
	}
}

func TestAES256GCM_Decrypt(t *testing.T) {
	var MustHexDecode = func(row string) []byte {
		data, err := hex.DecodeString(row)
		if err != nil {
			panic(err)
		}
		return data
	}

	type args struct {
		key        []byte
		ciphertext []byte
	}
	tests := []struct {
		name    string
		args    args
		want    []byte
		wantErr bool
	}{
		{
			name:    "invalid ciphertext length",
			args:    args{ciphertext: make([]byte, 10)},
			want:    nil,
			wantErr: true,
		},
		{
			name:    "invalid key length",
			args:    args{ciphertext: make([]byte, 20), key: make([]byte, 10)},
			want:    nil,
			wantErr: true,
		},
		{
			name: "valid",
			args: args{
				key:        MustHexDecode("6368616e676520746869732070617373776f726420746f206120736563726574"),
				ciphertext: MustHexDecode("6b2994fb5a6bf6654f12dc87756de358d960b2f35d2cca43306454f6619e2d50b9d3dd02e813a8efaa5c8b0a"),
			},
			want:    []byte("exampleplaintext"),
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := AES256GCM{}
			got, err := a.Decrypt(tt.args.key, tt.args.ciphertext)
			if (err != nil) != tt.wantErr {
				t.Errorf("AES256GCM.Decrypt() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("AES256GCM.Decrypt() = %v, want %v", got, tt.want)
			}
		})
	}
}
