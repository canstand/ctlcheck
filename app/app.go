package app

import (
	"flag"
	"fmt"
	"os"
	"text/template"
	"time"

	"github.com/canstand/ctlcheck/ctl"
	"github.com/carlmjohnson/flagext"
	"github.com/carlmjohnson/versioninfo"
	"github.com/pterm/pterm"
	"gopkg.in/yaml.v3"
)

const AppName = "ctlcheck"

func CLI(args []string) error {
	var app appEnv
	err := app.ParseArgs(args)
	if err != nil {
		return err
	}
	if err = app.Exec(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
	}
	return err
}

func (app *appEnv) ParseArgs(args []string) error {
	fl := flag.NewFlagSet(AppName, flag.ContinueOnError)
	app.MozillaCTL = ctl.NewMozillaCTL()
	app.Allow = ctl.Items{}

	var (
		offline bool
		save    bool
		raw     bool
	)

	fl.BoolVar(&offline, "offline", false, "load data from ctlcheck.yml instead of fetch from CCADB")
	fl.BoolVar(&save, "save", false, "save data to ctlcheck.yml")
	fl.BoolVar(&raw, "raw", false, "print unstyled raw output (set it if output is written to a file)")

	fl.Usage = func() {
		fmt.Fprintf(fl.Output(), `ctlcheck - %s

A utility to check the certificate trust list (CTL) of the linux system

Usage:
  ctlcheck [options]

Options:
`, versioninfo.Version)
		fl.PrintDefaults()
	}
	if err := fl.Parse(args); err != nil {
		return err
	}
	if err := flagext.ParseEnv(fl, AppName); err != nil {
		return err
	}
	app.offline = offline
	app.save = save
	if raw {
		pterm.DisableStyling()
	}
	return nil
}

type appEnv struct {
	MozillaCTL *ctl.MozillaCTL `yaml:"mozilla_ctl,omitempty"`
	Allow      ctl.Items       `yaml:"allow,omitempty"`
	offline    bool            `yaml:"-"`
	save       bool            `yaml:"-"`
}

func (app *appEnv) Exec() (err error) {
	spinnerLoading, _ := pterm.DefaultSpinner.Start("Load CTL...")

	if app.offline {
		spinnerLoading.UpdateText("Load CTL...from file")
		err = app.Load("ctlcheck.yml")
		if err != nil {
			spinnerLoading.Fail(err)
			return err
		}
	} else {
		_ = app.Load("ctlcheck.yml") // load allow items if file exist
		spinnerLoading.UpdateText("Fetch CTL from CCADB")
		err = app.MozillaCTL.FetchMozilla()
		if err != nil {
			spinnerLoading.Fail(err)
			return err
		}
		if app.save {
			spinnerLoading.UpdateText("Fetch CTL from CCADB, save to file")
			err = app.Save("ctlcheck.yml")
			if err != nil {
				spinnerLoading.Fail(err)
				return err
			}
		}
	}
	spinnerLoading.Success()

	roots, err := ctl.LoadSystemRoots()
	if err != nil {
		pterm.PrintOnErrorf("load system root CAs failed: %v", err)
		return err
	}
	results := app.MozillaCTL.Verify(roots.Certs, app.Allow)
	Output(results)

	return err
}

func Output(certs *ctl.VerifyResult) {
	var (
		countTrusted = len(certs.TrustedCerts)
		countRemoved = len(certs.RemovedCerts)
		countAllowed = len(certs.AllowedCerts)
		countUnknown = len(certs.UnknownCerts)
	)
	pterm.DefaultSection.WithLevel(2).Print("Summary")
	pterm.DefaultTable.WithHasHeader().WithRightAlignment().WithData(
		pterm.TableData{
			{"Total", "Trust", "Allow", "Removal", "Unknown"},
			{fmt.Sprint(certs.Total), fmt.Sprint(countTrusted), fmt.Sprint(countAllowed), fmt.Sprint(countRemoved), fmt.Sprint(countUnknown)},
		}).Render()

	output("Allowed Certificates", "Allow by yourself in the config file.\n", certs.AllowedCerts)
	output("Removed Certificates", "Use SHA256 to find the reason for removal (Removal Bug No. or Date) in: \nhttps://ccadb-public.secure.force.com/mozilla/RemovedCACertificateReport\n", certs.RemovedCerts)
	output("Unknown Certificates", "", certs.UnknownCerts)
}

func output(title, desc string, certs []*ctl.Cert) {
	if len(certs) < 1 {
		return
	}
	pterm.DefaultSection.WithLevel(2).Print(title)
	if desc != "" {
		pterm.ThemeDefault.InfoMessageStyle.Println(desc)
	}

	t := template.Must(template.New("").Funcs(template.FuncMap{
		"redIfNotExpired": func(t time.Time) string {
			txt := t.Format("2006-01-02T15:04:05Z")
			if t.After(time.Now()) {
				txt = pterm.Red(txt)
			}
			return txt
		},
	}).Parse(`
{{- range . -}}
SHA256:	{{ .Checksum }}
  Subject:    {{ if .Subject.CommonName }}{{ .Subject.CommonName }}{{ else }}{{ index .Subject.OrganizationalUnit 0 }}{{ end }}
  Issuer:     {{ if .Issuer.CommonName }}{{ .Issuer.CommonName }}{{ else }}{{ index .Issuer.OrganizationalUnit 0 }}{{ end }}
  Valid from: {{ .NotBefore.Format "2006-01-02T15:04:05Z" }}
          to: {{ .NotAfter | redIfNotExpired }}
{{ end -}}
	`))
	err := t.Execute(os.Stdout, &certs)
	pterm.PrintOnError(err)
}

// Save as yaml file
func (app *appEnv) Save(file string) error {

	data, err := yaml.Marshal(app)
	if err != nil {
		return err
	}

	err = os.WriteFile(file, data, 0644)

	return err
}

// Load from yaml file
func (app *appEnv) Load(file string) error {
	data, err := os.ReadFile(file)
	if err != nil {
		return err
	}

	err = yaml.Unmarshal(data, app)

	return err
}
