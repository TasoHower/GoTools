package hdkey

import "testing"

func TestPath(t *testing.T) {
	type args struct {
		coinName string
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{
			name:    "BTC",
			args:    args{"BTC"},
			want:    `m/1'/19'/2'/0`,
			wantErr: false,
		},
		{
			name:    "length 0",
			args:    args{""},
			want:    `m/21'/28'/13'/0`,
			wantErr: false,
		},
		{
			name:    "length 1-D",
			args:    args{"D"},
			want:    `m/21'/28'/3'/0`,
			wantErr: false,
		},
		{
			name:    "length 1-C",
			args:    args{"C"},
			want:    `m/21'/28'/2'/0`,
			wantErr: false,
		},
		{
			name:    "length 2-77",
			args:    args{"77"},
			want:    `m/21'/33'/33'/0`,
			wantErr: false,
		},
		{
			name:    "length 3-ETH",
			args:    args{"ETH"},
			want:    `m/4'/19'/7'/0`,
			wantErr: false,
		},
		{
			name:    "lower case",
			args:    args{"btc"},
			want:    "",
			wantErr: true,
		},
		{
			name:    "invalid case",
			args:    args{"(,.)"},
			want:    "",
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Path(tt.args.coinName)
			if (err != nil) != tt.wantErr {
				t.Errorf("Path() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("Path() = %v, want %v", got, tt.want)
			}
		})
	}
}
