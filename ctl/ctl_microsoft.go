package ctl

import (
	"bytes"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"
	"time"
	"unicode/utf16"

	"github.com/github/smimesign/ietf-cms/protocol"
)

const (
	MicrosoftCACertificateReportCSV = "https://ccadb-public.secure.force.com/microsoft/IncludedCACertificateReportForMSFTCSV"
	MicrosoftAuthrootStl            = "http://ctldl.windowsupdate.com/msdownload/update/v3/static/trustedr/en/authroot.stl"
)

type MicrosoftCTL struct {
	*CTL          `yaml:",inline"`
	CCADBUrl      string `yaml:"ccadb_url"`
	CCADBChecksum string `yaml:"ccadb_checksum,omitempty"`
}

func NewMicrosoftCTL() *MicrosoftCTL {
	return &MicrosoftCTL{
		CTL:           NewCTL(),
		CCADBUrl:      MicrosoftCACertificateReportCSV,
		CCADBChecksum: "",
	}
}

// Verify that the specified certificate is included in the CTL or has been removed
func (ctl *MicrosoftCTL) Verify(certs []*Cert, allowedCerts Entrys) *VerifyResult {
	ret := VerifyResult{
		Total:        len(certs),
		TrustedCerts: []*Cert{},
		AllowedCerts: []*Cert{},
		allowedDesc:  "Allow by yourself in the config file.\n",
		RemovedCerts: []*Cert{},
		removedDesc:  "Use SHA256 to find the details in: \nhttps://ccadb-public.secure.force.com/microsoft/IncludedCACertificateReportForMSFT\nDeprecation definitions:\nhttps://docs.microsoft.com/en-us/security/trusted-root/deprecation\n",
		UnknownCerts: []*Cert{},
		unknownDesc:  "",
	}
	ctl.verify(certs, allowedCerts, &ret)
	return &ret
}

// Fetch Microsoft's CTL from two sources, ccadb and authroot.stl
func (ctl *MicrosoftCTL) Fetch() error {
	if ctl.CTL == nil {
		ctl.CTL = NewCTL()
	}

	body, err := getBody(MicrosoftCACertificateReportCSV)
	if err != nil {
		return err
	}

	hash := getChecksum(body)
	if hash != ctl.CCADBChecksum { //updated
		c, err := csvReadToMap(bytes.NewReader(body))
		if err != nil {
			return fmt.Errorf("read csv file err: %w", err)
		}

		for _, v := range c {
			name := v["CA Common Name or Certificate Name"]
			sha256 := v["SHA-256 Fingerprint"]

			switch name {
			case "", "Example Root Case", "Example Root Certificate":
				continue
			default:
				//https://docs.microsoft.com/en-us/security/trusted-root/deprecation
				switch v["Microsoft Status"] {
				case "Included", "NotBefore":
					ctl.Trusted[sha256] = name
				// case "NotBefore", "Removal":
				// 	ctl.Removed[sha256] = name
				default:
					ctl.Removed[sha256] = name
				}
			}
		}
		ctl.CCADBChecksum = hash
	}

	authroot, err := getBody(MicrosoftAuthrootStl)
	if err != nil {
		return err
	}
	items, err := parseAuthroot(authroot)
	if err != nil {
		return err
	}
	for k, v := range items {
		_, ok := ctl.Removed[k]
		if ok {
			continue
		}
		ctl.Trusted[k] = v
	}

	// OS built-in, not included in authroot.stl or ccadb.
	// https://docs.microsoft.com/en-us/troubleshoot/windows-server/identity/trusted-root-certificates-are-required
	// -- Friendly name: Microsoft Authenticode(tm) Root
	// -- Thumbprint: 7f88cd7223f3c813818c994614a89c99fa3b5247
	ctl.Trusted["4898B1749717A594A2030F47C83C272BD14BAE3DCEB2EAE382174EF2EC1C75C9"] = "Microsoft Authenticode(tm) Root Authority"
	// -- Friendly name: Microsoft Timestamp Root
	// -- Thumbprint: 245c97df7514e7cf2df8be72ae957b9e04741e85
	ctl.Trusted["6EF914723F089D2ADAFF98D470A3651CCF1768E559FBDCC0FAAA640AA12E5753"] = "Microsoft Timestamp Root"

	ctl.UpdatedAt = time.Now()
	return nil
}

var (
	// RFC3852 CMS message, ContentType Object Identifier for Certificate Trust List (CTL)
	szOID_CTL = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 10, 1}
	// Signer of a CTL containing trusted roots
	szOID_ROOT_LIST_SIGNER           = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 10, 3, 9}
	szOID_CERT_FRIENDLY_NAME_PROP_ID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 10, 11, 11}
	szOID_CERT_AUTHROOT_SHA256_HASH  = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 10, 11, 98}
	// szOID_AUTO_ENROLL_CTL_USAGE      = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 20, 1}
)

// https://winprotocoldoc.blob.core.windows.net/productionwindowsarchives/WinArchive/%5bMS-CAESO%5d.pdf
type certificateTrustList struct {
	// CTLVersion       int `asn1:"default:0"`
	SubjectUsage     []asn1.ObjectIdentifier
	ListIdentifier   []byte   `asn1:"optional"`
	SequenceNumber   *big.Int `asn1:"optional"`
	CTLThisUpdate    time.Time
	CTLNextUpdate    time.Time `asn1:"optional"`
	SubjectAlgorithm pkix.AlgorithmIdentifier
	Subjects         []subject        `asn1:"optional"`
	CTLExtensions    []pkix.Extension `asn1:"explicit,optional,omitempty,tag:0"`
}

type subject struct {
	Thumbprint []byte
	Attributes []attribute `asn1:"optional,set"`
}

type attribute struct {
	Type  asn1.ObjectIdentifier
	Value asn1.RawValue `asn1:"set"`
}

func parseAuthroot(b []byte) (Entrys, error) {
	ret := Entrys{}

	content, err := getUnsignedData(b, szOID_CTL)
	if err != nil {
		return ret, err
	}

	var ctl certificateTrustList
	_, err = asn1.Unmarshal(content, &ctl)
	if err != nil {
		return ret, fmt.Errorf("parse error, %v", err)
	}

	if len(ctl.SubjectUsage) != 1 || !ctl.SubjectUsage[0].Equal(szOID_ROOT_LIST_SIGNER) {
		return ret, fmt.Errorf("unknown SubjectUsage")
	}

	for _, subject := range ctl.Subjects {
		// thumbprint := strings.ToUpper(hex.EncodeToString(subject.Thumbprint))
		var sha256Hash, friendlyName string
		for _, attr := range subject.Attributes {
			var value []byte
			_, err := asn1.Unmarshal(attr.Value.Bytes, &value)
			if err != nil {
				return ret, err
			}
			switch attr.Type.String() {
			case szOID_CERT_AUTHROOT_SHA256_HASH.String():
				sha256Hash = strings.ToUpper(hex.EncodeToString(value))
			case szOID_CERT_FRIENDLY_NAME_PROP_ID.String():
				name, err := wstrToString(value)
				if err != nil {
					return ret, err
				}
				friendlyName = name
			}
		}
		if sha256Hash != "" {
			ret[sha256Hash] = friendlyName
		}
	}

	return ret, nil
}

// getUnsignedData parse CMS (rfc3852) message, return eContent
func getUnsignedData(b []byte, contentType asn1.ObjectIdentifier) ([]byte, error) {
	ci, err := protocol.ParseContentInfo(b)
	if err != nil {
		return nil, err
	}
	sd, err := ci.SignedDataContent()
	if err != nil {
		return nil, err
	}
	if !sd.EncapContentInfo.EContentType.Equal(contentType) {
		return nil, fmt.Errorf("wrong contentType: %v", sd.EncapContentInfo.EContentType)
	}
	return sd.EncapContentInfo.EContent.Bytes, nil
}

func wstrToString(b []byte) (string, error) {
	count := len(b)
	if count == 0 {
		return "", nil
	}
	if count%2 != 0 {
		return "", fmt.Errorf("length must be even")
	}
	var order binary.ByteOrder
	order = binary.LittleEndian
	bom := [2]byte{b[0], b[1]}
	switch bom {
	case [2]byte{0xff, 0xfe}:
		b = b[2:]
	case [2]byte{0xfe, 0xff}:
		b = b[2:]
		order = binary.BigEndian
	}

	buf := make([]uint16, len(b)/2)
	if err := binary.Read(bytes.NewReader(b), order, &buf); err != nil {
		return "", err
	}

	return string(bytes.Trim([]byte(string(utf16.Decode(buf))), "\x00")), nil
}
