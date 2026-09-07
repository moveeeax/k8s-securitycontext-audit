// Package audit statically inspects Kubernetes manifests for missing or weak
// securityContext settings. It never talks to a cluster: it reads YAML files
// and reports findings, so it is safe in CI and pre-commit hooks.
package audit

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"sigs.k8s.io/yaml"
)

// baselineCapabilities are the added capabilities we do not flag as dangerous.
// Everything else added (NET_RAW, SYS_ADMIN, ...) is a high-severity finding.
var baselineCapabilities = map[string]bool{
	"NET_BIND_SERVICE": true,
}

// docSep splits a multi-document YAML stream on lines that are exactly "---".
var docSep = regexp.MustCompile(`(?m)^---\s*$`)

// AuditPath walks path (a file or directory) and audits every YAML manifest.
func AuditPath(path string) (*Report, error) {
	files, err := collectYAML(path)
	if err != nil {
		return nil, err
	}
	var findings []Finding
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", f, err)
		}
		fs, err := auditBytes(data, f)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", f, err)
		}
		findings = append(findings, fs...)
	}
	return newReport(findings), nil
}

// AuditBytes audits a single in-memory YAML stream. label tags each finding's
// File field (use "" for none). Exposed for tests and piped input.
func AuditBytes(data []byte, label string) (*Report, error) {
	fs, err := auditBytes(data, label)
	if err != nil {
		return nil, err
	}
	return newReport(fs), nil
}

func newReport(findings []Finding) *Report {
	sortFindings(findings)
	summary := map[string]int{"high": 0, "medium": 0, "low": 0}
	for _, f := range findings {
		summary[f.SeverityName]++
	}
	if findings == nil {
		findings = []Finding{}
	}
	return &Report{Findings: findings, Summary: summary}
}

func collectYAML(path string) ([]string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return []string{path}, nil
	}
	var files []string
	err = filepath.WalkDir(path, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(p))
		if ext == ".yaml" || ext == ".yml" {
			files = append(files, p)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Strings(files)
	return files, nil
}

func auditBytes(data []byte, label string) ([]Finding, error) {
	var findings []Finding
	for _, doc := range docSep.Split(string(data), -1) {
		if strings.TrimSpace(doc) == "" {
			continue
		}
		var r resource
		if err := yaml.Unmarshal([]byte(doc), &r); err != nil {
			return nil, fmt.Errorf("parse manifest: %w", err)
		}
		if r.Kind == "" {
			continue
		}
		spec, ok := r.podSpec()
		if !ok {
			continue // not a workload kind
		}
		findings = append(findings, auditPodSpec(&r, spec, label)...)
	}
	return findings, nil
}

func auditPodSpec(r *resource, spec podSpec, file string) []Finding {
	var findings []Finding
	for _, c := range spec.Containers {
		findings = append(findings, auditContainer(r, spec.SecurityContext, c, false, file)...)
	}
	for _, c := range spec.InitContainers {
		findings = append(findings, auditContainer(r, spec.SecurityContext, c, true, file)...)
	}
	return findings
}

func auditContainer(r *resource, pod *podSecurityContext, c container, isInit bool, file string) []Finding {
	var out []Finding
	add := func(rule string, sev Severity, msg string) {
		out = append(out, Finding{
			Kind:         r.Kind,
			Namespace:    r.Metadata.Namespace,
			Name:         r.Metadata.Name,
			Container:    c.Name,
			Init:         isInit,
			Rule:         rule,
			Severity:     sev,
			SeverityName: sev.String(),
			Message:      msg,
			File:         file,
		})
	}
	sc := c.SecurityContext

	// runAsNonRoot: the container value wins, otherwise inherit the pod value.
	if !runsAsNonRoot(sc, pod) {
		add("run-as-root", SeverityHigh,
			"container may run as root: runAsNonRoot is not set to true (container or pod level)")
	}

	// privileged
	if sc != nil && sc.Privileged != nil && *sc.Privileged {
		add("privileged", SeverityHigh, "container runs in privileged mode")
	}

	// allowPrivilegeEscalation must be explicitly false.
	if sc == nil || sc.AllowPrivilegeEscalation == nil || *sc.AllowPrivilegeEscalation {
		add("allow-privilege-escalation", SeverityMedium,
			"allowPrivilegeEscalation is not set to false")
	}

	// readOnlyRootFilesystem must be explicitly true.
	if sc == nil || sc.ReadOnlyRootFilesystem == nil || !*sc.ReadOnlyRootFilesystem {
		add("writable-root-filesystem", SeverityMedium,
			"readOnlyRootFilesystem is not set to true")
	}

	// dangerous added capabilities
	if sc != nil && sc.Capabilities != nil {
		for _, cap := range sc.Capabilities.Add {
			up := strings.ToUpper(strings.TrimSpace(cap))
			if up == "ALL" || !baselineCapabilities[up] {
				add("added-capability", SeverityHigh,
					fmt.Sprintf("adds Linux capability %q beyond the safe baseline", up))
			}
		}
	}

	// missing drop: ALL
	if !dropsAll(sc) {
		add("missing-drop-all", SeverityLow,
			"capabilities.drop does not include ALL")
	}

	return out
}

func runsAsNonRoot(sc *securityContext, pod *podSecurityContext) bool {
	if sc != nil && sc.RunAsNonRoot != nil {
		return *sc.RunAsNonRoot
	}
	if sc != nil && sc.RunAsUser != nil && *sc.RunAsUser != 0 {
		return true
	}
	if pod != nil && pod.RunAsNonRoot != nil {
		return *pod.RunAsNonRoot
	}
	if pod != nil && pod.RunAsUser != nil && *pod.RunAsUser != 0 {
		return true
	}
	return false
}

func dropsAll(sc *securityContext) bool {
	if sc == nil || sc.Capabilities == nil {
		return false
	}
	for _, d := range sc.Capabilities.Drop {
		if strings.EqualFold(strings.TrimSpace(d), "ALL") {
			return true
		}
	}
	return false
}

// FailAt reports whether the report contains any finding at or above threshold.
func (r *Report) FailAt(threshold Severity) bool {
	for _, f := range r.Findings {
		if f.Severity >= threshold {
			return true
		}
	}
	return false
}

func sortFindings(f []Finding) {
	sort.SliceStable(f, func(i, j int) bool {
		if f[i].Severity != f[j].Severity {
			return f[i].Severity > f[j].Severity // high first
		}
		if f[i].Name != f[j].Name {
			return f[i].Name < f[j].Name
		}
		if f[i].Container != f[j].Container {
			return f[i].Container < f[j].Container
		}
		return f[i].Rule < f[j].Rule
	})
}
