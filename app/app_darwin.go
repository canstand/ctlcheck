//go:build darwin && !ios

package app

import "github.com/canstand/ctlcheck/ctl"

func (app *appEnv) verify(certs []*ctl.Cert, allowedCerts ctl.Entrys) *ctl.VerifyResult {
	return app.AppleCTL.Verify(certs, app.Allow)
}

func (app *appEnv) fetchCtl() error {
	return app.AppleCTL.Fetch()
}
