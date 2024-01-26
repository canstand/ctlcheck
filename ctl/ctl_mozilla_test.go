package ctl

import "testing"

func TestMozillaCTL_Fetch(t *testing.T) {
	ctl := NewMozillaCTL()
	err := ctl.Fetch()
	if err != nil {
		t.Errorf("MozillaCTL.Fetch() error = %v", err)
	}
	if len(ctl.CTL.Trusted) == 0 {
		t.Errorf("MozillaCTL.Fetch() error = %v", "no trusted certs, may be parse error")
	}
}
