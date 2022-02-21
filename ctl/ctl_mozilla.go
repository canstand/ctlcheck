package ctl

import (
	"bytes"
	"fmt"
	"time"
)

const (
	MozillaIncludedCACertificateReportCSV = "https://ccadb-public.secure.force.com/mozilla/IncludedCACertificateReportCSVFormat"
	MozillaRemovedCACertificateReportCSV  = "https://ccadb-public.secure.force.com/mozilla/RemovedCACertificateReportCSVFormat"
)

type MozillaCTL struct {
	*CTL             `yaml:",inline"`
	URLIncluded      string `yaml:"url_included,omitempty"`
	ChecksumIncluded string `yaml:"checksum_included,omitempty"`
	URLRemoved       string `yaml:"url_removed,omitempty"`
	ChecksumRemoved  string `yaml:"checksum_removed,omitempty"`
}

func NewMozillaCTL() *MozillaCTL {
	return &MozillaCTL{
		CTL:              NewCTL(),
		URLIncluded:      MozillaIncludedCACertificateReportCSV,
		ChecksumIncluded: "",
		URLRemoved:       MozillaRemovedCACertificateReportCSV,
		ChecksumRemoved:  "",
	}
}

// Verify that the specified certificate is included in the CTL or has been removed
func (ctl *MozillaCTL) Verify(certs []*Cert, allowedCerts Entrys) *VerifyResult {
	ret := VerifyResult{
		Total:        len(certs),
		TrustedCerts: []*Cert{},
		AllowedCerts: []*Cert{},
		allowedDesc:  "Allow by yourself in the config file.\n",
		RemovedCerts: []*Cert{},
		removedDesc:  "Use SHA256 to find the reason for removal (Removal Bug No. or Date) in: \nhttps://ccadb-public.secure.force.com/mozilla/RemovedCACertificateReport\n",
		UnknownCerts: []*Cert{},
		unknownDesc:  "",
	}
	ctl.verify(certs, allowedCerts, &ret)
	return &ret
}

// Fetch Mozilla's CA certificate report from https://www.ccadb.org
func (ctl *MozillaCTL) Fetch() error {
	if ctl.CTL == nil {
		ctl.CTL = NewCTL()
	}

	body, err := getBody(MozillaIncludedCACertificateReportCSV)
	if err != nil {
		return err
	}

	if err := ctl.parseIncludedCSV(body); err != nil {
		return err
	}

	body, err = getBody(MozillaRemovedCACertificateReportCSV)
	if err != nil {
		return err
	}

	err = ctl.parseRemovedCSV(body)

	return err
}

func (ctl *MozillaCTL) parseIncludedCSV(body []byte) error {
	checksum := getChecksum(body)
	if checksum == ctl.ChecksumIncluded { //no update
		return nil
	}
	c, err := csvReadToMap(bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("read csv file err: %w", err)
	}

	for _, v := range c {
		name := v["Common Name or Certificate Name"]
		sha256 := v["SHA-256 Fingerprint"]
		ctl.Trusted[sha256] = name
	}
	ctl.ChecksumIncluded = checksum
	ctl.UpdatedAt = time.Now()

	return nil
}

func (ctl *MozillaCTL) parseRemovedCSV(body []byte) error {
	checksum := getChecksum(body)
	if checksum == ctl.ChecksumRemoved { //no update
		return nil
	}

	c, err := csvReadToMap(bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("read csv file err: %w", err)
	}

	for _, v := range c {
		name := v["Root Certificate Name"]
		sha256 := v["SHA-256 Fingerprint"]
		ctl.Removed[sha256] = name
	}
	ctl.ChecksumRemoved = checksum
	ctl.UpdatedAt = time.Now()

	return nil
}
