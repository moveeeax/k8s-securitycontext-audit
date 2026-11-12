package audit

import (
	"encoding/json"
	"fmt"
	"io"
	"text/tabwriter"
)

// WriteTable renders a human-readable table of findings. Suppressed findings
// are listed in a separate section with their reason.
func (r *Report) WriteTable(w io.Writer) error {
	var active, suppressed []Finding
	for _, f := range r.Findings {
		if f.Suppressed {
			suppressed = append(suppressed, f)
		} else {
			active = append(active, f)
		}
	}
	if len(r.Findings) == 0 {
		_, err := fmt.Fprintln(w, "No securityContext findings. All audited containers are hardened.")
		return err
	}
	if len(active) > 0 {
		tw := tabwriter.NewWriter(w, 0, 2, 2, ' ', 0)
		fmt.Fprintln(tw, "SEVERITY\tRESOURCE\tCONTAINER\tRULE\tMESSAGE")
		for _, f := range active {
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n",
				f.SeverityName, resourceRef(f), containerRef(f), f.Rule, f.Message)
		}
		if err := tw.Flush(); err != nil {
			return err
		}
	}
	if len(suppressed) > 0 {
		if len(active) > 0 {
			fmt.Fprintln(w)
		}
		fmt.Fprintln(w, "Suppressed:")
		tw := tabwriter.NewWriter(w, 0, 2, 2, ' ', 0)
		fmt.Fprintln(tw, "SEVERITY\tRESOURCE\tCONTAINER\tRULE\tMESSAGE\tREASON")
		for _, f := range suppressed {
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n",
				f.SeverityName, resourceRef(f), containerRef(f), f.Rule,
				f.Message, f.Suppression.Reason)
		}
		if err := tw.Flush(); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprintf(w, "\n%d finding(s): %d high, %d medium, %d low",
		len(active), r.Summary["high"], r.Summary["medium"], r.Summary["low"]); err != nil {
		return err
	}
	if len(suppressed) > 0 {
		if _, err := fmt.Fprintf(w, "; %d suppressed", len(suppressed)); err != nil {
			return err
		}
	}
	_, err := fmt.Fprintln(w)
	return err
}

// WriteJSON renders the report as indented JSON.
func (r *Report) WriteJSON(w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

func resourceRef(f Finding) string {
	return resourceLabel(f.Kind, f.Namespace, f.Name)
}

// containerRef names the container, or "(pod)" for pod-level findings.
func containerRef(f Finding) string {
	if f.Container == "" {
		return "(pod)"
	}
	if f.Init {
		return f.Container + " (init)"
	}
	return f.Container
}
