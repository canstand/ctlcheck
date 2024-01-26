package ctl

import "testing"

func TestAppleCTL_Fetch(t *testing.T) {

	ctl := NewAppleCTL()
	err := ctl.Fetch()
	if err != nil {
		t.Errorf("AppleCTL.Fetch() error = %v", err)
	}
	if len(ctl.CTL.Trusted) == 0 {
		t.Errorf("AppleCTL.Fetch() error = %v", "no trusted certs, may be parse error")
	}
}
