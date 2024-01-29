package app

import (
	"fmt"
	"runtime/debug"
	"time"
)

var AppVersion string

func getAppVersion() string {
	if len(AppVersion) != 0 {
		return AppVersion
	}

	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return "(dev)"
	}

	if bi.Main.Version != "(devel)" {
		return bi.Main.Version
	}

	var vcsRevision string
	var vcsTime time.Time
	for _, setting := range bi.Settings {
		switch setting.Key {
		case "vcs.revision":
			vcsRevision = setting.Value
		case "vcs.time":
			vcsTime, _ = time.Parse(time.RFC3339, setting.Value)
		}
	}

	if vcsRevision != "" {
		return fmt.Sprintf("%s, (%s)", vcsRevision, vcsTime)
	}

	return "(dev)"
}
