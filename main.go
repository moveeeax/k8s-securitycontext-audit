package main

import (
	"os"

	"github.com/moveeeax/k8s-securitycontext-audit/cmd"
)

// version is overridden at build time: -ldflags "-X main.version=v0.1.0".
var version = "dev"

func main() {
	cmd.SetVersion(version)
	os.Exit(cmd.Execute())
}
