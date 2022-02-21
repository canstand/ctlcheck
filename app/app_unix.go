//go:build aix || dragonfly || freebsd || (js && wasm) || linux || netbsd || openbsd || solaris

package app

import "github.com/canstand/ctlcheck/ctl"

func (app *appEnv) verify(certs []*ctl.Cert, allowedCerts ctl.Entrys) *ctl.VerifyResult {
	return app.MozillaCTL.Verify(certs, app.Allow)
}

func (app *appEnv) fetchCtl() error {
	return app.MozillaCTL.Fetch()
}
