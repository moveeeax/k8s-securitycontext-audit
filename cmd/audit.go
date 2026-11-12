package cmd

import (
	"fmt"
	"io"
	"time"

	"github.com/moveeeax/k8s-securitycontext-audit/internal/audit"
	"github.com/spf13/cobra"
)

func newAuditCmd() *cobra.Command {
	var (
		output     string
		failOn     string
		ignoreFile string
	)
	c := &cobra.Command{
		Use:   "audit [path]",
		Short: "Audit a manifest file or a directory of manifests",
		Long: "Audit reads a YAML file or every .yaml/.yml file under a directory " +
			"(or stdin with '-') and reports securityContext findings. Findings can be " +
			"suppressed with workload annotations or --ignore-file; suppressed findings " +
			"stay in the output but do not count toward --fail-on.",
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			path := "-"
			if len(args) == 1 {
				path = args[0]
			}

			var (
				report  *audit.Report
				ignores *audit.IgnoreFile
				err     error
			)
			if ignoreFile != "" {
				if ignores, err = audit.LoadIgnoreFile(ignoreFile); err != nil {
					return fmt.Errorf("--ignore-file: %w", err)
				}
			}
			if path == "-" {
				var data []byte
				data, err = io.ReadAll(cmd.InOrStdin())
				if err == nil {
					report, err = audit.AuditBytes(data, "")
				}
			} else {
				report, err = audit.AuditPath(path)
			}
			if err != nil {
				return err
			}
			if ignores != nil {
				report.ApplyIgnoreFile(ignores, time.Now())
			}
			for _, warn := range report.Warnings {
				fmt.Fprintln(cmd.ErrOrStderr(), "warning:", warn)
			}

			w := cmd.OutOrStdout()
			switch output {
			case "table":
				err = report.WriteTable(w)
			case "json":
				err = report.WriteJSON(w)
			case "sarif":
				err = report.WriteSARIF(w, version)
			default:
				return fmt.Errorf("unknown --output %q (want table, json, or sarif)", output)
			}
			if err != nil {
				return err
			}

			if failOn != "" {
				threshold, ok := audit.ParseSeverity(failOn)
				if !ok {
					return fmt.Errorf("unknown --fail-on %q (want high, medium, or low)", failOn)
				}
				if report.FailAt(threshold) {
					fmt.Fprintf(cmd.ErrOrStderr(),
						"failing: findings at or above %q severity\n", failOn)
					return exitError{code: 1}
				}
			}
			return nil
		},
	}
	c.Flags().StringVarP(&output, "output", "o", "table", "output format: table, json, sarif")
	c.Flags().StringVar(&ignoreFile, "ignore-file", "", "YAML file of accepted findings (kind, namespace, name, container, ignore, reason, expires)")
	c.Flags().StringVar(&failOn, "fail-on", "", "exit non-zero if any finding is at or above this severity: high, medium, low")
	return c
}
