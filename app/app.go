package app

import (
	"flag"
	"fmt"
	"os"

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
	app.AppleCTL = ctl.NewAppleCTL()
	app.MozillaCTL = ctl.NewMozillaCTL()
	app.Allow = ctl.Entrys{}

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

A utility to check the certificate trust list (CTL)

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
	AppleCTL   *ctl.AppleCTL   `yaml:"apple_ctl,omitempty"`
	MozillaCTL *ctl.MozillaCTL `yaml:"mozilla_ctl,omitempty"`
	Allow      ctl.Entrys      `yaml:"allow,omitempty"`
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

		spinnerLoading.UpdateText("Fetch CTL...")

		err = app.fetchCtl()
		if err != nil {
			spinnerLoading.Fail(err)
			return err
		}
		if app.save {
			spinnerLoading.UpdateText("Fetch CTL..., save to file")
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
	results := app.verify(roots.Certs, app.Allow)

	pterm.DefaultSection.WithLevel(2).Print("System Root CA")
	pterm.Print(results.ConsoleReport())

	return err
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
