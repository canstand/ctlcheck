package ctl

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
)

type sum256 [sha256.Size]byte

// Cert adds Checksum field to x509.Cerificate to store SHA256
type Cert struct {
	*x509.Certificate `json:"_"`
	Checksum          string `json:"checksum,omitempty"`
}

// CertStore is a set of certificates.
type CertStore struct {
	Certs   []*Cert
	haveSum map[sum256]bool
}

// NewCertStore returns a new, empty CertStore.
func NewCertStore() *CertStore {
	return &CertStore{
		Certs:   []*Cert{},
		haveSum: map[sum256]bool{},
	}
}

// AddCert adds a certificate to CertStore.
func (s *CertStore) AddCert(cert *x509.Certificate) {
	if cert == nil {
		panic("adding nil Certificate to CertStore")
	}

	rawSum256 := sha256.Sum256(cert.Raw)

	if s.haveSum[rawSum256] {
		return
	}

	s.Certs = append(s.Certs, &Cert{
		Certificate: cert,
		Checksum:    getChecksum(cert.Raw),
	})
	s.haveSum[rawSum256] = true
}

// AppendCertsFromPEM attempts to parse a series of PEM encoded certificates.
// It appends any certificates found to s and reports whether any certificates
// were successfully parsed.
//
// On many Linux systems, /etc/ssl/cert.pem will contain the system wide set
// of root CAs in a format suitable for this function.
func (s *CertStore) AppendCertsFromPEM(pemCerts []byte) (ok bool) {
	for len(pemCerts) > 0 {
		var block *pem.Block
		block, pemCerts = pem.Decode(pemCerts)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			continue
		}

		certBytes := block.Bytes
		cert, err := x509.ParseCertificate(certBytes)
		if err != nil {
			continue
		}

		s.AddCert(cert)
		ok = true
	}

	return ok
}

func (s *CertStore) contains(cert *x509.Certificate) bool { //nolint:unused
	if s == nil {
		return false
	}
	return s.haveSum[sha256.Sum256(cert.Raw)]
}
