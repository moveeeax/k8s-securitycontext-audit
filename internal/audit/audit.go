// Package audit statically inspects Kubernetes manifests for missing or weak
// securityContext settings and host-level escapes (host namespaces, hostPath,
// hostPort, seccomp). It never talks to a cluster: it reads YAML files
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
	var (
		findings []Finding
		warnings []string
	)
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", f, err)
		}
		fs, ws, err := auditBytes(data, f)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", f, err)
		}
		findings = append(findings, fs...)
		warnings = append(warnings, ws...)
	}
	return newReport(findings, warnings), nil
}

// AuditBytes audits a single in-memory YAML stream. label tags each finding's
// File field (use "" for none). Exposed for tests and piped input.
func AuditBytes(data []byte, label string) (*Report, error) {
	fs, ws, err := auditBytes(data, label)
	if err != nil {
		return nil, err
	}
	return newReport(fs, ws), nil
}

func newReport(findings []Finding, warnings []string) *Report {
	sortFindings(findings)
	if findings == nil {
		findings = []Finding{}
	}
	r := &Report{Findings: findings, Warnings: warnings}
	r.summarize()
	return r
}

// summarize recounts active findings per severity; suppressed findings are
// counted separately.
func (r *Report) summarize() {
	summary := map[string]int{"high": 0, "medium": 0, "low": 0, "suppressed": 0}
	for _, f := range r.Findings {
		if f.Suppressed {
			summary["suppressed"]++
			continue
		}
		summary[f.SeverityName]++
	}
	r.Summary = summary
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

func auditBytes(data []byte, label string) ([]Finding, []string, error) {
	var (
		findings []Finding
		warnings []string
	)
	for _, doc := range docSep.Split(string(data), -1) {
		if strings.TrimSpace(doc) == "" {
			continue
		}
		var r resource
		if err := yaml.Unmarshal([]byte(doc), &r); err != nil {
			return nil, nil, fmt.Errorf("parse manifest: %w", err)
		}
		if r.Kind == "" {
			continue
		}
		spec, ok := r.podSpec()
		if !ok {
			continue // not a workload kind
		}
		fs := auditPodSpec(&r, spec, label)
		warnings = append(warnings, applyAnnotations(&r, fs)...)
		findings = append(findings, fs...)
	}
	return findings, warnings, nil
}

func newFinding(r *resource, c *container, isInit bool, file, rule string, sev Severity, msg string) Finding {
	f := Finding{
		Kind:         r.Kind,
		Namespace:    r.Metadata.Namespace,
		Name:         r.Metadata.Name,
		Init:         isInit,
		Rule:         rule,
		Severity:     sev,
		SeverityName: sev.String(),
		Message:      msg,
		File:         file,
	}
	if c != nil {
		f.Container = c.Name
	}
	return f
}

func auditPodSpec(r *resource, spec podSpec, file string) []Finding {
	findings := auditPodLevel(r, spec, file)
	for _, c := range spec.Containers {
		findings = append(findings, auditContainer(r, spec.SecurityContext, c, false, file)...)
	}
	for _, c := range spec.InitContainers {
		findings = append(findings, auditContainer(r, spec.SecurityContext, c, true, file)...)
	}
	return findings
}

// auditPodLevel checks settings that apply to the whole pod. Its findings
// carry an empty Container.
func auditPodLevel(r *resource, spec podSpec, file string) []Finding {
	var out []Finding
	add := func(rule string, sev Severity, msg string) {
		out = append(out, newFinding(r, nil, false, file, rule, sev, msg))
	}

	// Host namespaces (PSS baseline: hostNetwork, hostPID, hostIPC).
	if spec.HostNetwork {
		add("host-namespace", SeverityHigh, "pod shares the host network namespace (hostNetwork: true)")
	}
	if spec.HostPID {
		add("host-namespace", SeverityHigh, "pod shares the host PID namespace (hostPID: true)")
	}
	if spec.HostIPC {
		add("host-namespace", SeverityHigh, "pod shares the host IPC namespace (hostIPC: true)")
	}

	// hostPath volumes give the pod direct access to the node filesystem.
	for _, v := range spec.Volumes {
		if v.HostPath != nil {
			add("host-path", SeverityHigh,
				fmt.Sprintf("mounts hostPath %q (volume %q)", v.HostPath.Path, v.Name))
		}
	}

	// A pod-level Unconfined profile is a PSS baseline violation even when
	// every container overrides it.
	if isUnconfined(podSeccomp(spec.SecurityContext)) {
		add("seccomp-unconfined", SeverityHigh, "pod-level seccompProfile type is Unconfined")
	}
	return out
}

func auditContainer(r *resource, pod *podSecurityContext, c container, isInit bool, file string) []Finding {
	var out []Finding
	add := func(rule string, sev Severity, msg string) {
		out = append(out, newFinding(r, &c, isInit, file, rule, sev, msg))
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

	// hostPort binds the container to a port on the node.
	for _, p := range c.Ports {
		if p.HostPort != 0 {
			add("host-port", SeverityMedium,
				fmt.Sprintf("binds hostPort %d (containerPort %d)", p.HostPort, p.ContainerPort))
		}
	}

	// seccomp: the container profile wins, otherwise the pod profile applies.
	// A pod-level Unconfined is reported once by auditPodLevel.
	var csp *seccompProfile
	if sc != nil && sc.SeccompProfile != nil && sc.SeccompProfile.Type != "" {
		csp = sc.SeccompProfile
	}
	switch {
	case isUnconfined(csp):
		add("seccomp-unconfined", SeverityHigh, "seccompProfile type is Unconfined")
	case csp == nil && podSeccomp(pod) == nil:
		add("missing-seccomp", SeverityLow,
			"seccompProfile is not set at container or pod level")
	}

	return out
}

// podSeccomp returns the pod-level seccomp profile, or nil when it is unset.
func podSeccomp(pod *podSecurityContext) *seccompProfile {
	if pod == nil || pod.SeccompProfile == nil || pod.SeccompProfile.Type == "" {
		return nil
	}
	return pod.SeccompProfile
}

func isUnconfined(p *seccompProfile) bool {
	return p != nil && p.Type == "Unconfined"
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

// FailAt reports whether the report contains any unsuppressed finding at or
// above threshold.
func (r *Report) FailAt(threshold Severity) bool {
	for _, f := range r.Findings {
		if !f.Suppressed && f.Severity >= threshold {
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
