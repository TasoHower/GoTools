package hdkey

import (
	"encoding/hex"
	"errors"
	"reflect"
	"testing"

	"git.liebaopay.com/ksrv/keyserver/ksrv"

	"git.liebaopay.com/ksrv/keyserver/crypto/bip32"
	"git.liebaopay.com/ksrv/keyserver/crypto/rander"
)

type gotErrRander struct{}

func (gotErrRander) Get(size int) ([]byte, error) {
	return nil, errors.New("any error")
}

type notEnoughRander struct{}

func (notEnoughRander) Get(size int) ([]byte, error) {
	return nil, nil
}

type validRander struct{}

func (validRander) Get(size int) ([]byte, error) {
	seed, _ := hex.DecodeString("f9664335350db1ebae64e82adf85d3a8af93e11585272e99b09923d4f48b5b773228e6d45e045ff9f17c0374b5a8d3fa810b2b1afa2f19dd25c7e3fd6544b982")
	return seed, nil
}

func TestNewMasterKey(t *testing.T) {
	var mustFromSeed = func(seed string) bip32.ExtendedKey {
		res, err := bip32.NewKeyFromString(ksrv.NewHDSeedRequest_Secp256k1, seed)
		if err != nil {
			t.Errorf("Decode %s failed", seed)
			return nil
		}
		return res
	}

	type args struct {
		random rander.Rander
	}
	tests := []struct {
		name    string
		args    args
		want    bip32.ExtendedKey
		wantErr bool
	}{
		{
			name:    "got error from rander",
			args:    args{gotErrRander{}},
			want:    nil,
			wantErr: true,
		},
		{
			name:    "got error from rander",
			args:    args{notEnoughRander{}},
			want:    nil,
			wantErr: true,
		},
		{
			name: "valid",
			args: args{validRander{}},
			want: mustFromSeed("xprv9s21ZrQH143K47G7Pst4JnzPHpY6FHVjQNN2yg3okbHtACdVer9SxNxDfGh259wDQTe9iXgMKR5XQujRAdhc8Y1TmdKvQYepRU2UjhRcWaU"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewMasterKey(ksrv.NewHDSeedRequest_Secp256k1, tt.args.random)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewMasterKey() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewMasterKey() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDerivePath(t *testing.T) {
	var mustFromSeed = func(seed string) bip32.ExtendedKey {
		res, err := bip32.NewKeyFromString(ksrv.NewHDSeedRequest_Secp256k1, seed)
		if err != nil {
			t.Errorf("Decode %s failed", seed)
			return nil
		}
		return res
	}

	type args struct {
		xprv bip32.ExtendedKey
		path string
	}
	tests := []struct {
		name    string
		args    args
		want    bip32.ExtendedKey
		wantErr bool
	}{
		{
			name: "valid",
			args: args{
				xprv: mustFromSeed("xprv9s21ZrQH143K2PunsF7pUyYnUBzJLRkg9RNYhVDRCGqJpKkAys6tH1LA49zw9t4jA61oh5AA6jCyXWTXbbLti6QSELWiTvcUTwKZcG4V8iA"),
				path: "m/44'/0'/0'/0",
			},
			want:    mustFromSeed("xprv9zc7gcUh94ThWj8kU4zkR3E8nKb5B7aNGYMW7ho3DqVdVfgfF2LZWUU2ykXLirVKxsjrC64AmopY23gZMV7t2gK582JWnpz8HVD73iPXD9P"),
			wantErr: false,
		},
		{
			name: "has redundant backslash",
			args: args{
				xprv: mustFromSeed("xprv9s21ZrQH143K2PunsF7pUyYnUBzJLRkg9RNYhVDRCGqJpKkAys6tH1LA49zw9t4jA61oh5AA6jCyXWTXbbLti6QSELWiTvcUTwKZcG4V8iA"),
				path: "m/44'/0'/0'/0/",
			},
			want:    mustFromSeed("xprv9zc7gcUh94ThWj8kU4zkR3E8nKb5B7aNGYMW7ho3DqVdVfgfF2LZWUU2ykXLirVKxsjrC64AmopY23gZMV7t2gK582JWnpz8HVD73iPXD9P"),
			wantErr: false,
		},
		{
			name: "only master symbol",
			args: args{
				xprv: mustFromSeed("xprv9s21ZrQH143K2PunsF7pUyYnUBzJLRkg9RNYhVDRCGqJpKkAys6tH1LA49zw9t4jA61oh5AA6jCyXWTXbbLti6QSELWiTvcUTwKZcG4V8iA"),
				path: "m",
			},
			want:    mustFromSeed("xprv9s21ZrQH143K2PunsF7pUyYnUBzJLRkg9RNYhVDRCGqJpKkAys6tH1LA49zw9t4jA61oh5AA6jCyXWTXbbLti6QSELWiTvcUTwKZcG4V8iA"),
			wantErr: false,
		},
		{
			name: "ErrDeriveNotMaster",
			args: args{
				xprv: mustFromSeed("xprvA19DxK9gkX44JVprp97UZEfVNCs587r8M6715rRaVkiy5azYHjDrJxMqeD8EWeSVupVz9NycS57gE17URk3TCNTdyMMuWw2VrXUg83iRfHN"),
				path: "m/44'/0'/0'/0",
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "invalid numberic",
			args: args{
				xprv: mustFromSeed("xprv9s21ZrQH143K3E3GR69HdDJZ3B6ncLa4sCdGeFJe4EoF1rnQSxmsAtqdQyBF1vZGga5VpCVjUZ6sba8RMihUzYVppAQiPAotbCkE6bmPGPF"),
				path: "abc/abc/abc/efg",
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "derive privkey from pubkey",
			args: args{
				xprv: mustFromSeed("xpub6FJ1fCip99xH43PykfeBhSwR2rh5WQtX8Tt3XSh7fWLZ71Rw1RNqtCLBPS2oGzWUoL4aBGPah2b92uV4E8wqUtp4HF17ZkWe3Yh8SMYhGYq"),
				path: `0'/0'/1`,
			},
			want:    nil,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := DerivePath(tt.args.xprv, tt.args.path)
			if (err != nil) != tt.wantErr {
				t.Errorf("DerivePath() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("DerivePath() = %v, want %v", got, tt.want)
			}
		})
	}
}
