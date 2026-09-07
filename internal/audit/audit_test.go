package audit

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func rulesFor(r *Report, container string) map[string]Severity {
	out := map[string]Severity{}
	for _, f := range r.Findings {
		if f.Container == container {
			out[f.Rule] = f.Severity
		}
	}
	return out
}

func TestNoRunAsNonRootReportedAsRoot(t *testing.T) {
	y := `
kind: Pod
metadata: {name: p}
spec:
  containers:
    - name: app
      image: x
`
	r, err := AuditBytes([]byte(y), "")
	if err != nil {
		t.Fatal(err)
	}
	rules := rulesFor(r, "app")
	if sev, ok := rules["run-as-root"]; !ok || sev != SeverityHigh {
		t.Fatalf("expected high run-as-root finding, got %v", rules)
	}
}

func TestPrivilegedFlaggedHigh(t *testing.T) {
	y := `
kind: Pod
metadata: {name: p}
spec:
  containers:
    - name: app
      securityContext: {privileged: true}
`
	r, _ := AuditBytes([]byte(y), "")
	if sev, ok := rulesFor(r, "app")["privileged"]; !ok || sev != SeverityHigh {
		t.Fatalf("expected high privileged finding, got %v", r.Findings)
	}
}

func TestAllowPrivilegeEscalationUnsetFlagged(t *testing.T) {
	y := `
kind: Pod
metadata: {name: p}
spec:
  containers:
    - name: app
      securityContext: {runAsNonRoot: true}
`
	r, _ := AuditBytes([]byte(y), "")
	if _, ok := rulesFor(r, "app")["allow-privilege-escalation"]; !ok {
		t.Fatalf("expected allow-privilege-escalation finding, got %v", r.Findings)
	}
}

func TestAllowPrivilegeEscalationFalseNotFlagged(t *testing.T) {
	y := `
kind: Pod
metadata: {name: p}
spec:
  containers:
    - name: app
      securityContext: {allowPrivilegeEscalation: false}
`
	r, _ := AuditBytes([]byte(y), "")
	if _, ok := rulesFor(r, "app")["allow-privilege-escalation"]; ok {
		t.Fatalf("did not expect allow-privilege-escalation finding, got %v", r.Findings)
	}
}

func TestHardenedContainerHasNoFindings(t *testing.T) {
	data, err := os.ReadFile("../../testdata/hardened.yaml")
	if err != nil {
		t.Fatal(err)
	}
	r, err := AuditBytes(data, "hardened.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Findings) != 0 {
		t.Fatalf("expected zero findings for hardened pod, got %d: %+v", len(r.Findings), r.Findings)
	}
}

func TestPodLevelRunAsNonRootInherited(t *testing.T) {
	y := `
kind: Pod
metadata: {name: p}
spec:
  securityContext: {runAsNonRoot: true}
  containers:
    - name: app
      securityContext:
        allowPrivilegeEscalation: false
        readOnlyRootFilesystem: true
        capabilities: {drop: [ALL]}
`
	r, _ := AuditBytes([]byte(y), "")
	if _, ok := rulesFor(r, "app")["run-as-root"]; ok {
		t.Fatalf("pod-level runAsNonRoot should be inherited, got %v", r.Findings)
	}
}

func TestDangerousCapabilityFlaggedHigh(t *testing.T) {
	y := `
kind: Pod
metadata: {name: p}
spec:
  containers:
    - name: app
      securityContext:
        runAsNonRoot: true
        allowPrivilegeEscalation: false
        readOnlyRootFilesystem: true
        capabilities:
          add: [SYS_ADMIN]
          drop: [ALL]
`
	r, _ := AuditBytes([]byte(y), "")
	if sev, ok := rulesFor(r, "app")["added-capability"]; !ok || sev != SeverityHigh {
		t.Fatalf("expected high added-capability finding, got %v", r.Findings)
	}
}

func TestBaselineCapabilityNotFlagged(t *testing.T) {
	y := `
kind: Pod
metadata: {name: p}
spec:
  containers:
    - name: app
      securityContext:
        runAsNonRoot: true
        allowPrivilegeEscalation: false
        readOnlyRootFilesystem: true
        capabilities:
          add: [NET_BIND_SERVICE]
          drop: [ALL]
`
	r, _ := AuditBytes([]byte(y), "")
	if _, ok := rulesFor(r, "app")["added-capability"]; ok {
		t.Fatalf("NET_BIND_SERVICE should be allowed, got %v", r.Findings)
	}
}

func TestMultiDocSkipsNonWorkloads(t *testing.T) {
	data, err := os.ReadFile("../../testdata/multi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	r, err := AuditBytes(data, "multi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	// ConfigMap ignored; the CronJob container is hardened -> zero findings.
	if len(r.Findings) != 0 {
		t.Fatalf("expected zero findings, got %+v", r.Findings)
	}
}

func TestFailAtThreshold(t *testing.T) {
	data, _ := os.ReadFile("../../testdata/weak.yaml")
	r, _ := AuditBytes(data, "weak.yaml")
	if !r.FailAt(SeverityHigh) {
		t.Fatal("weak manifest should fail at high")
	}
	hardened, _ := os.ReadFile("../../testdata/hardened.yaml")
	hr, _ := AuditBytes(hardened, "hardened.yaml")
	if hr.FailAt(SeverityLow) {
		t.Fatal("hardened manifest should not fail at any level")
	}
}

func TestJSONOutputValid(t *testing.T) {
	data, _ := os.ReadFile("../../testdata/weak.yaml")
	r, _ := AuditBytes(data, "weak.yaml")
	var buf bytes.Buffer
	if err := r.WriteJSON(&buf); err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("JSON output is invalid: %v", err)
	}
	if _, ok := decoded["findings"]; !ok {
		t.Fatal("JSON missing findings key")
	}
}

func TestSARIFOutputValid(t *testing.T) {
	data, _ := os.ReadFile("../../testdata/weak.yaml")
	r, _ := AuditBytes(data, "weak.yaml")
	var buf bytes.Buffer
	if err := r.WriteSARIF(&buf, "v0.1.0"); err != nil {
		t.Fatal(err)
	}
	var log struct {
		Version string `json:"version"`
		Runs    []struct {
			Results []struct {
				RuleID string `json:"ruleId"`
				Level  string `json:"level"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
		t.Fatalf("SARIF invalid JSON: %v", err)
	}
	if log.Version != "2.1.0" {
		t.Fatalf("expected SARIF 2.1.0, got %q", log.Version)
	}
	if len(log.Runs) != 1 || len(log.Runs[0].Results) == 0 {
		t.Fatal("expected SARIF results for weak manifest")
	}
	for _, res := range log.Runs[0].Results {
		if res.Level == "" || res.RuleID == "" {
			t.Fatalf("SARIF result missing level/ruleId: %+v", res)
		}
	}
}

func TestTableOutputRendersFindings(t *testing.T) {
	data, _ := os.ReadFile("../../testdata/weak.yaml")
	r, _ := AuditBytes(data, "weak.yaml")
	var buf bytes.Buffer
	if err := r.WriteTable(&buf); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "privileged") || !strings.Contains(out, "SEVERITY") {
		t.Fatalf("table output missing expected content:\n%s", out)
	}
}
