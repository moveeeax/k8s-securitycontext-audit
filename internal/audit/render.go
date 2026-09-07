package audit

import (
	"encoding/json"
	"fmt"
	"io"
	"text/tabwriter"
)

// WriteTable renders a human-readable table of findings.
func (r *Report) WriteTable(w io.Writer) error {
	if len(r.Findings) == 0 {
		_, err := fmt.Fprintln(w, "No securityContext findings. All audited containers are hardened.")
		return err
	}
	tw := tabwriter.NewWriter(w, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "SEVERITY\tRESOURCE\tCONTAINER\tRULE\tMESSAGE")
	for _, f := range r.Findings {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n",
			f.SeverityName, resourceRef(f), containerRef(f), f.Rule, f.Message)
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	_, err := fmt.Fprintf(w, "\n%d finding(s): %d high, %d medium, %d low\n",
		len(r.Findings), r.Summary["high"], r.Summary["medium"], r.Summary["low"])
	return err
}

// WriteJSON renders the report as indented JSON.
func (r *Report) WriteJSON(w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

func resourceRef(f Finding) string {
	name := f.Name
	if f.Namespace != "" {
		name = f.Namespace + "/" + name
	}
	return fmt.Sprintf("%s %s", f.Kind, name)
}

func containerRef(f Finding) string {
	if f.Init {
		return f.Container + " (init)"
	}
	return f.Container
}
