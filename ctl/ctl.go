package ctl

import (
	"time"
)

const (
	MICROSOFT   = "microsoft"
	MOZILLA_NSS = "mozilla_nss"
	OPENJDK     = "openjdk"
)

type CTL struct {
	UpdatedAt time.Time `yaml:"updated_at,omitempty"`
	Trusted   Items     `yaml:"trusted"`
	Removed   Items     `yaml:"removed,omitempty"`
}

// Items maps from sum256(cert.Raw) to subject name.
type Items map[string]string

type VerifyResult struct {
	Total        int
	TrustedCerts []*Cert
	AllowedCerts []*Cert
	RemovedCerts []*Cert
	UnknownCerts []*Cert
}

func NewCTL() *CTL {
	return &CTL{
		Trusted: Items{},
		Removed: Items{},
	}
}

// Verify that the specified certificate is included in the CTL or has been removed
func (ctl *CTL) Verify(certs []*Cert, allowedCerts Items) *VerifyResult {
	ret := VerifyResult{
		Total:        len(certs),
		TrustedCerts: []*Cert{},
		AllowedCerts: []*Cert{},
		RemovedCerts: []*Cert{},
		UnknownCerts: []*Cert{},
	}
	for _, cert := range certs {
		_, ok := ctl.Trusted[cert.Checksum]
		if ok {
			ret.TrustedCerts = append(ret.TrustedCerts, cert)
		} else {
			_, ok := allowedCerts[cert.Checksum]
			if ok {
				ret.AllowedCerts = append(ret.AllowedCerts, cert)
			} else {
				_, ok = ctl.Removed[cert.Checksum]
				if ok {
					ret.RemovedCerts = append(ret.RemovedCerts, cert)
				} else {
					ret.UnknownCerts = append(ret.UnknownCerts, cert)
				}
			}
		}
	}
	return &ret
}
