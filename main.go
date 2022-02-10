package main

import (
	"os"

	"github.com/canstand/ctlcheck/app"
	"github.com/carlmjohnson/exitcode"
)

func main() {
	exitcode.Exit(app.CLI(os.Args[1:]))
}
