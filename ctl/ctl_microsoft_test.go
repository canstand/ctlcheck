package ctl

import (
	"os"
	"testing"
)

func Test_parseAuthroot(t *testing.T) {
	type args struct {
		b []byte
	}
	stlAuthroot, err := os.ReadFile("testdata/authroot.stl")
	if err != nil {
		t.Fatalf("parseAuthroot() error: %v", err)
	}
	tests := []struct {
		name       string
		args       args
		wantLength int
		wantErr    bool
	}{
		{
			name: "empty data",
			args: args{
				b: []byte{},
			},
			wantLength: 0,
			wantErr:    true,
		},
		{
			name: "real authroot.stl",
			args: args{
				b: stlAuthroot,
			},
			wantLength: 436,
			wantErr:    false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseAuthroot(tt.args.b)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseAuthroot() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if len(got) != tt.wantLength {
				t.Errorf("parseAuthroot(), len(Entrys) = %v, want >= %v", len(got), tt.wantLength)
			}
			// if !reflect.DeepEqual(got, tt.want) {
			// 	t.Errorf("parseAuthroot() = %v, want %v", got, tt.want)
			// }
		})
	}
}

func TestMicrosoftCTL_Fetch(t *testing.T) {
	ctl := NewMicrosoftCTL()
	err := ctl.Fetch()
	if err != nil {
		t.Errorf("MicrosoftCTL.Fetch() error = %v", err)
	}
	if len(ctl.CTL.Trusted) == 0 {
		t.Errorf("MicrosoftCTL.Fetch() error = %v", "no trusted certs, may be parse error")
	}
}
