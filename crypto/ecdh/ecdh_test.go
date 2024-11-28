package ecdh

import (
	"bytes"
	"crypto/elliptic"
	"encoding/hex"
	"fmt"
	"io"
	"reflect"
	"testing"
)

func TestCreate(t *testing.T) {
	type args struct {
		curve elliptic.Curve
	}
	tests := []struct {
		name string
		args args
		want KeyExchange
	}{
		{
			name: "未提供曲线",
			args: args{},
			want: &ecdh{curve: elliptic.P256()},
		},
		{
			name: "提供曲线",
			args: args{elliptic.P384()},
			want: &ecdh{curve: elliptic.P384()},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Create(tt.args.curve); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Create() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_ecdh_GenerateKey(t *testing.T) {
	var MustDecodeHex = func(raw string) []byte {
		res, err := hex.DecodeString(raw)
		if err != nil {
			panic(err)
		}
		return res
	}

	type fields struct {
		curve elliptic.Curve
	}
	type args struct {
		random io.Reader
	}
	tests := []struct {
		name       string
		fields     fields
		args       args
		wantPriv   []byte
		wantPubkey []byte
		wantErr    bool
	}{
		{
			name:       "1",
			fields:     fields{elliptic.P256()},
			args:       args{bytes.NewReader(MustDecodeHex("e1c83afec0b61a746c29fc8cdc645a99613f6b4adacb929376828b994ed73611"))},
			wantPriv:   MustDecodeHex("e18a3afec0b61a746c29fc8cdc645a99613f6b4adacb929376828b994ed73611"),
			wantPubkey: MustDecodeHex("043cd064b72f353a142860c2596b975dde840fa0d32e8b4745c5ad7f0036f8e4e9e3b34840c91e9bb78bc1e4261c7ade7381ede936eaa21b1ac6d356e8dd8ad5db"),
			// verify pubkey from nodejs 043cd064b72f353a142860c2596b975dde840fa0d32e8b4745c5ad7f0036f8e4e9e3b34840c91e9bb78bc1e4261c7ade7381ede936eaa21b1ac6d356e8dd8ad5db
		},
		{
			name:       "2",
			fields:     fields{elliptic.P256()},
			args:       args{bytes.NewReader(MustDecodeHex("9e0b5f1b5f8d35184c5d53b56ceda9bd0517191d3d75879188eda82e5e054af8"))},
			wantPriv:   MustDecodeHex("9e495f1b5f8d35184c5d53b56ceda9bd0517191d3d75879188eda82e5e054af8"),
			wantPubkey: MustDecodeHex("046f32ad84cc028410e7fb45933fdd57358271f060ae89f31d14573da20a7f2c76da96353f2d08cf6703de42579abbbd926eae1963ebe2077fc9cf952be7386a57"),
			// verify pubkey from nodejs 046f32ad84cc028410e7fb45933fdd57358271f060ae89f31d14573da20a7f2c76da96353f2d08cf6703de42579abbbd926eae1963ebe2077fc9cf952be7386a57
		},
		{
			name:       "3",
			fields:     fields{elliptic.P256()},
			args:       args{bytes.NewReader(MustDecodeHex("950ad255a7d7422ff291ac49be8b9bc66c98983563bd2679ae5a014aef09c889"))},
			wantPriv:   MustDecodeHex("9548d255a7d7422ff291ac49be8b9bc66c98983563bd2679ae5a014aef09c889"),
			wantPubkey: MustDecodeHex("049ce1f0fc5e33b766010ce77c3f77f497b66ad4ee17574c0bb2a67ebe0d1ecaaef286476af453bffd7afbdfcaac488f487360a52b2c9387aab92f6c7c83ba9246"),
			// verify pubkey from nodejs 049ce1f0fc5e33b766010ce77c3f77f497b66ad4ee17574c0bb2a67ebe0d1ecaaef286476af453bffd7afbdfcaac488f487360a52b2c9387aab92f6c7c83ba9246
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dh := &ecdh{
				curve: tt.fields.curve,
			}
			gotPriv, gotPubkey, err := dh.GenerateKey(tt.args.random)
			if (err != nil) != tt.wantErr {
				t.Errorf("ecdh.GenerateKey() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(gotPriv, tt.wantPriv) {
				t.Errorf("ecdh.GenerateKey() gotPriv = %v, want %v", fmt.Sprintf("%x", gotPriv), fmt.Sprintf("%x", tt.wantPriv))
			}
			if !reflect.DeepEqual(gotPubkey, tt.wantPubkey) {
				t.Errorf("ecdh.GenerateKey() gotPubkey = %v, want %v", fmt.Sprintf("%x", gotPubkey), fmt.Sprintf("%x", tt.wantPubkey))
			}
		})
	}
}

func Test_ecdh_ComputeSecret(t *testing.T) {
	var MustDecodeHex = func(raw string) []byte {
		res, err := hex.DecodeString(raw)
		if err != nil {
			panic(err)
		}
		return res
	}

	type fields struct {
		curve elliptic.Curve
	}
	type args struct {
		selfPriv       []byte
		otherPublicKey []byte
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    []byte
		wantErr bool
	}{
		{
			name:   "successful",
			fields: fields{elliptic.P256()},
			args: args{
				selfPriv:       MustDecodeHex("f6f4ed211c82d62c06c514ac3e26f7bb321b4e45a005d0b57197f0279aa1f434"),
				otherPublicKey: MustDecodeHex("04336c7280b208484490753f63b68132943956b709b8ee74b56914c21c49eedb05cf23f1c4b0c626caaeaa6195b4798c95b6d03b0c7e066005742fc2b6d3c450b0"),
			},
			want:    MustDecodeHex("c09480795bfb6ba31593439c61ad82a795d992cdc8b638ea0d2bb40ee47e947b"),
			wantErr: false,
		},
		{
			name:   "ErrInvlidPeerPub",
			fields: fields{elliptic.P256()},
			args: args{
				selfPriv:       MustDecodeHex("f6f4ed211c82d62c06c514ac3e26f7bb321b4e45a005d0b57197f0279aa1f434"),
				otherPublicKey: make([]byte, 10),
			},
			want:    nil,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dh := &ecdh{
				curve: tt.fields.curve,
			}
			got, err := dh.ComputeSecret(tt.args.selfPriv, tt.args.otherPublicKey)
			if (err != nil) != tt.wantErr {
				t.Errorf("ecdh.ComputeSecret() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ecdh.ComputeSecret() = %v, want %v", got, tt.want)
			}
		})
	}
}
