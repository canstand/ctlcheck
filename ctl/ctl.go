package ctl

import (
	"bytes"
	"crypto/x509/pkix"
	"fmt"
	"text/template"
	"time"

	"github.com/pterm/pterm"
)

const (
	MICROSOFT   = "microsoft"
	MOZILLA_NSS = "mozilla_nss"
	OPENJDK     = "openjdk"
)

type CTL struct {
	UpdatedAt time.Time `yaml:"updated_at,omitempty"`
	Trusted   Entrys    `yaml:"trusted"`
	Removed   Entrys    `yaml:"removed,omitempty"`
}

// Entrys maps from sum256(cert.Raw) to subject name.
type Entrys map[string]string

type VerifyResult struct {
	Total        int
	TrustedCerts []*Cert `json:"_"`
	AllowedCerts []*Cert `json:"allowed_certs,omitempty"`
	allowedDesc  string
	RemovedCerts []*Cert `json:"removed_certs,omitempty"`
	removedDesc  string
	UnknownCerts []*Cert `json:"unknown_certs,omitempty"`
	unknownDesc  string
}

func NewCTL() *CTL {
	return &CTL{
		Trusted: Entrys{},
		Removed: Entrys{},
	}
}

// verify that the specified certificate is included in the CTL or has been removed
func (ctl *CTL) verify(certs []*Cert, allowedCerts Entrys, ret *VerifyResult) {
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
}

func (result *VerifyResult) ConsoleReport() (output string) {
	var (
		countTrusted = len(result.TrustedCerts)
		countRemoved = len(result.RemovedCerts)
		countAllowed = len(result.AllowedCerts)
		countUnknown = len(result.UnknownCerts)
	)
	table, err := pterm.DefaultTable.WithHasHeader().WithRightAlignment().WithData(
		pterm.TableData{
			{"Total", "Trust", "Allow", "Removal", "Unknown"},
			{fmt.Sprint(result.Total), fmt.Sprint(countTrusted), fmt.Sprint(countAllowed), fmt.Sprint(countRemoved), fmt.Sprint(countUnknown)},
		}).Srender()
	if err != nil {
		output += pterm.Error.Sprintf("%v", err)
		return
	}
	output += table + "\n"
	output += formatCerts("Allowed Certificates", result.allowedDesc, result.AllowedCerts)
	output += formatCerts("Removed Certificates", result.removedDesc, result.RemovedCerts)
	output += formatCerts("Unknown Certificates", result.unknownDesc, result.UnknownCerts)
	return
}

func formatCerts(title, desc string, certs []*Cert) (output string) {
	if len(certs) < 1 {
		return
	}
	output += pterm.DefaultSection.WithLevel(3).Sprintf("%s:%4d", title, len(certs))
	if desc != "" {
		output += pterm.ThemeDefault.InfoMessageStyle.Sprintln(desc)
	}

	tpl := template.Must(template.New("").Funcs(template.FuncMap{
		"redIfNotExpired": func(t time.Time) string {
			txt := t.Format("2006-01-02T15:04:05Z")
			if t.After(time.Now()) {
				txt = pterm.Red(txt)
			}
			return txt
		},
		"pkixName": func(n pkix.Name) string {
			if len(n.CommonName) > 0 {
				return n.CommonName
			}
			if len(n.OrganizationalUnit) > 0 {
				return n.OrganizationalUnit[0]
			}
			if len(n.Organization) > 0 {
				return n.Organization[0]
			}
			return n.String()
		},
	}).Parse(`
{{- range . -}}
SHA256:	{{ .Checksum }}
  Subject:    {{ .Subject | pkixName }}
  Issuer:     {{ .Issuer | pkixName }}
  Valid from: {{ .NotBefore.Format "2006-01-02T15:04:05Z" }}
          to: {{ .NotAfter | redIfNotExpired }}
{{ end -}}
	`))

	var buf bytes.Buffer
	if err := tpl.Execute(&buf, &certs); err != nil {
		output += pterm.Error.Sprintf("%v", err)
		return
	}
	output += buf.String()
	return
}
