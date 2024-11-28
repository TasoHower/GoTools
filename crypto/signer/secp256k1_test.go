package signer

import (
	"encoding/hex"
	"reflect"
	"testing"
)

func TestSecp256k1(t *testing.T) {
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
	tests := []struct {
		name    string
		args    args
		want    []byte
		wantErr bool
	}{
		{
			name: "not 32bytes message",
			args: args{
				msg:     []byte("message"),
				privkey: MustBase64Decode("d7405785618c4f1b3fb6174e1758ab77a0a4df0f32574ad2b0a36010fa7f0e8e"),
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "valid message",
			args: args{
				msg:     make([]byte, 32),
				privkey: MustBase64Decode("d7405785618c4f1b3fb6174e1758ab77a0a4df0f32574ad2b0a36010fa7f0e8e"),
			},
			want: MustBase64Decode(("fc2557a73afaa4df46d27c1c4426fc28f81d772749e0b44411c3b3dd5825866a38ed1d40e5afc7abc997edae56ab8b3610d3f43d57e412345ace4b98c163033700")),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Secp256k1(tt.args.msg, tt.args.privkey)
			if (err != nil) != tt.wantErr {
				t.Errorf("Secp256k1() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Secp256k1() got = %v, want %v", got, tt.want)
			}
		})
	}
}
