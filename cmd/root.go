// Package cmd wires the cobra CLI for k8s-securitycontext-audit.
package cmd

import (
	"github.com/spf13/cobra"
)

// version is set at build time via -ldflags, defaulting to "dev".
var version = "dev"

// SetVersion lets main inject the build version.
func SetVersion(v string) {
	if v != "" {
		version = v
	}
}

func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "k8s-securitycontext-audit",
		Short: "Statically audit Kubernetes manifests for weak securityContext settings",
		Long: "k8s-securitycontext-audit reads Kubernetes YAML and reports containers " +
			"that run as root, run privileged, allow privilege escalation, use a writable " +
			"root filesystem, or add dangerous Linux capabilities. It never talks to a cluster.",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.AddCommand(newAuditCmd())
	root.Version = version
	return root
}

// Execute runs the CLI and returns a process exit code.
func Execute() int {
	root := newRootCmd()
	if err := root.Execute(); err != nil {
		if ec, ok := err.(exitError); ok {
			return ec.code
		}
		root.PrintErrln("error:", err)
		return 2
	}
	return 0
}

// exitError carries a specific process exit code (used by --fail-on).
type exitError struct{ code int }

func (e exitError) Error() string { return "exit" }
