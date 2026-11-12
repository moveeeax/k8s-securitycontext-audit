package audit

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"sigs.k8s.io/yaml"
)

// Annotation keys read from the workload's metadata.annotations.
const (
	AnnotationPrefix = "securitycontext-audit.moveeeax.io/"
	// AnnotationIgnore suppresses the listed rules for the whole workload:
	// every container plus the pod-level findings.
	AnnotationIgnore = AnnotationPrefix + "ignore"
	// AnnotationIgnoreContainer + "<container>" suppresses the listed rules
	// for one container only.
	AnnotationIgnoreContainer = AnnotationIgnore + "."
	// AnnotationReason is required; without it no annotation suppression applies.
	AnnotationReason = AnnotationPrefix + "reason"
)

// applyAnnotations marks findings of one resource as suppressed according to
// its annotations and returns warnings for suppressions it refused.
func applyAnnotations(r *resource, findings []Finding) []string {
	ann := r.Metadata.Annotations
	if len(ann) == 0 {
		return nil
	}
	ref := resourceLabel(r.Kind, r.Metadata.Namespace, r.Metadata.Name)

	keys := make([]string, 0, len(ann))
	for k := range ann {
		if k == AnnotationIgnore || strings.HasPrefix(k, AnnotationIgnoreContainer) {
			keys = append(keys, k)
		}
	}
	if len(keys) == 0 {
		return nil
	}
	sort.Strings(keys)

	reason := strings.TrimSpace(ann[AnnotationReason])
	if reason == "" {
		return []string{fmt.Sprintf("%s: %s is set without %s; findings not suppressed",
			ref, keys[0], AnnotationReason)}
	}

	var warnings []string
	workload := map[string]bool{}
	perContainer := map[string]map[string]bool{}
	for _, k := range keys {
		target := workload
		if k != AnnotationIgnore {
			name := strings.TrimPrefix(k, AnnotationIgnoreContainer)
			if name == "" {
				warnings = append(warnings, fmt.Sprintf("%s: annotation %s names no container; ignored", ref, k))
				continue
			}
			if perContainer[name] == nil {
				perContainer[name] = map[string]bool{}
			}
			target = perContainer[name]
		}
		for _, rule := range splitRules(ann[k]) {
			if !knownRule(rule) {
				warnings = append(warnings, fmt.Sprintf("%s: annotation %s: unknown rule %q; ignored", ref, k, rule))
				continue
			}
			if k != AnnotationIgnore && podOnlyRules[rule] {
				warnings = append(warnings, fmt.Sprintf("%s: annotation %s: rule %q is pod-level, use %s; ignored",
					ref, k, rule, AnnotationIgnore))
				continue
			}
			target[rule] = true
		}
	}

	for i := range findings {
		f := &findings[i]
		if workload[f.Rule] || (f.Container != "" && perContainer[f.Container][f.Rule]) {
			f.Suppressed = true
			f.Suppression = &Suppression{Source: SourceAnnotation, Reason: reason}
		}
	}
	return warnings
}

func splitRules(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// IgnoreFile is the --ignore-file format:
//
//	suppressions:
//	  - kind: DaemonSet
//	    namespace: kube-system
//	    name: cilium
//	    container: cilium-agent   # optional; omit to cover the whole workload
//	    ignore: [privileged, host-namespace]
//	    reason: CNI needs host networking
//	    expires: "2027-03-31"     # optional; last day the entry applies (UTC)
type IgnoreFile struct {
	Suppressions []IgnoreEntry `json:"suppressions"`
}

// IgnoreEntry suppresses rules on one workload, or on one of its containers.
type IgnoreEntry struct {
	Kind      string   `json:"kind"`
	Namespace string   `json:"namespace,omitempty"`
	Name      string   `json:"name"`
	Container string   `json:"container,omitempty"`
	Ignore    []string `json:"ignore"`
	Reason    string   `json:"reason"`
	Expires   string   `json:"expires,omitempty"`
}

const dateLayout = "2006-01-02"

// LoadIgnoreFile reads and validates an ignore file. Unknown keys, unknown
// rules, a missing reason, or a malformed expires date are errors.
func LoadIgnoreFile(path string) (*IgnoreFile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParseIgnoreFile(data)
}

// ParseIgnoreFile parses and validates ignore-file YAML.
func ParseIgnoreFile(data []byte) (*IgnoreFile, error) {
	var f IgnoreFile
	if err := yaml.UnmarshalStrict(data, &f); err != nil {
		return nil, fmt.Errorf("parse ignore file: %w", err)
	}
	for i := range f.Suppressions {
		e := &f.Suppressions[i]
		where := fmt.Sprintf("ignore file entry %d", i+1)
		if e.Kind == "" || e.Name == "" {
			return nil, fmt.Errorf("%s: kind and name are required", where)
		}
		where += " (" + resourceLabel(e.Kind, e.Namespace, e.Name) + ")"
		if len(e.Ignore) == 0 {
			return nil, fmt.Errorf("%s: ignore must list at least one rule", where)
		}
		for _, rule := range e.Ignore {
			if !knownRule(rule) {
				return nil, fmt.Errorf("%s: unknown rule %q", where, rule)
			}
			if e.Container != "" && podOnlyRules[rule] {
				return nil, fmt.Errorf("%s: rule %q is pod-level and cannot be scoped to container %q", where, rule, e.Container)
			}
		}
		if strings.TrimSpace(e.Reason) == "" {
			return nil, fmt.Errorf("%s: reason is required", where)
		}
		if e.Expires != "" {
			if _, err := time.Parse(dateLayout, e.Expires); err != nil {
				return nil, fmt.Errorf("%s: expires %q is not a YYYY-MM-DD date", where, e.Expires)
			}
		}
	}
	return &f, nil
}

// ApplyIgnoreFile suppresses matching findings. An entry whose expires date
// is before now (UTC) is skipped with a warning, as is an entry that matches
// no finding. Namespace must match exactly: an entry without namespace only
// matches resources without one.
func (r *Report) ApplyIgnoreFile(f *IgnoreFile, now time.Time) {
	today := now.UTC().Format(dateLayout)
	for i, e := range f.Suppressions {
		where := fmt.Sprintf("ignore file entry %d (%s)", i+1, resourceLabel(e.Kind, e.Namespace, e.Name))
		if e.Expires != "" && today > e.Expires {
			r.Warnings = append(r.Warnings, fmt.Sprintf("%s: expired on %s; findings not suppressed", where, e.Expires))
			continue
		}
		rules := map[string]bool{}
		for _, rule := range e.Ignore {
			rules[rule] = true
		}
		matched := 0
		for j := range r.Findings {
			fd := &r.Findings[j]
			if fd.Suppressed || fd.Kind != e.Kind || fd.Namespace != e.Namespace || fd.Name != e.Name {
				continue
			}
			if e.Container != "" && fd.Container != e.Container {
				continue
			}
			if !rules[fd.Rule] {
				continue
			}
			fd.Suppressed = true
			fd.Suppression = &Suppression{Source: SourceIgnoreFile, Reason: e.Reason, Expires: e.Expires}
			matched++
		}
		if matched == 0 {
			r.Warnings = append(r.Warnings, fmt.Sprintf("%s: matched no findings", where))
		}
	}
	r.summarize()
}

func resourceLabel(kind, namespace, name string) string {
	if namespace != "" {
		name = namespace + "/" + name
	}
	return kind + " " + name
}
