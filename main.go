package main

import (
	"runtime/debug"

	"github.com/retlehs/quien/cmd"
)

var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	if version == "dev" {
		if info, ok := debug.ReadBuildInfo(); ok {
			if v := info.Main.Version; v != "" && v != "(devel)" {
				version = v
			}
		}
	}
	cmd.Execute(version, commit, date)
}
