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

// hardenedContainer is a container securityContext with no findings of its
// own, so tests below only see the rule under test.
const hardenedContainer = `
      securityContext:
        runAsNonRoot: true
        allowPrivilegeEscalation: false
        readOnlyRootFilesystem: true
        capabilities: {drop: [ALL]}
        seccompProfile: {type: RuntimeDefault}
`

func podFindings(r *Report) []Finding {
	var out []Finding
	for _, f := range r.Findings {
		if f.Container == "" {
			out = append(out, f)
		}
	}
	return out
}

func TestHostNamespacesFlaggedHighPerField(t *testing.T) {
	y := `
kind: DaemonSet
metadata: {name: agent, namespace: kube-system}
spec:
  template:
    spec:
      hostNetwork: true
      hostPID: true
      hostIPC: true
      containers:
        - name: app
          securityContext:
            runAsNonRoot: true
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities: {drop: [ALL]}
            seccompProfile: {type: RuntimeDefault}
`
	r, err := AuditBytes([]byte(y), "")
	if err != nil {
		t.Fatal(err)
	}
	pod := podFindings(r)
	if len(pod) != 3 {
		t.Fatalf("expected 3 pod-level host-namespace findings, got %+v", r.Findings)
	}
	for _, want := range []string{"hostNetwork", "hostPID", "hostIPC"} {
		found := false
		for _, f := range pod {
			if f.Rule == "host-namespace" && f.Severity == SeverityHigh && strings.Contains(f.Message, want) {
				found = true
			}
		}
		if !found {
			t.Fatalf("missing host-namespace finding for %s: %+v", want, pod)
		}
	}
	if len(rulesFor(r, "app")) != 0 {
		t.Fatalf("host namespaces must not produce container findings, got %+v", r.Findings)
	}
}

func TestHostNamespacesFalseNotFlagged(t *testing.T) {
	y := `
kind: Pod
metadata: {name: p}
spec:
  hostNetwork: false
  hostPID: false
  containers:
    - name: app` + hardenedContainer
	r, _ := AuditBytes([]byte(y), "")
	if len(r.Findings) != 0 {
		t.Fatalf("expected no findings, got %+v", r.Findings)
	}
}

func TestHostPathNamesThePath(t *testing.T) {
	y := `
kind: Pod
metadata: {name: p}
spec:
  volumes:
    - name: docker
      hostPath: {path: /var/run/docker.sock}
    - name: tmp
      emptyDir: {}
  containers:
    - name: app` + hardenedContainer
	r, _ := AuditBytes([]byte(y), "")
	pod := podFindings(r)
	if len(pod) != 1 || pod[0].Rule != "host-path" || pod[0].Severity != SeverityHigh {
		t.Fatalf("expected one high host-path finding, got %+v", r.Findings)
	}
	if !strings.Contains(pod[0].Message, `"/var/run/docker.sock"`) || !strings.Contains(pod[0].Message, `"docker"`) {
		t.Fatalf("host-path message should name the path and volume: %q", pod[0].Message)
	}
}

func TestHostPortFlaggedMedium(t *testing.T) {
	y := `
kind: Pod
metadata: {name: p}
spec:
  containers:
    - name: app
      ports:
        - containerPort: 8080
        - containerPort: 9100
          hostPort: 9100` + hardenedContainer
	r, _ := AuditBytes([]byte(y), "")
	var hits []Finding
	for _, f := range r.Findings {
		if f.Rule == "host-port" {
			hits = append(hits, f)
		}
	}
	if len(hits) != 1 || hits[0].Severity != SeverityMedium || hits[0].Container != "app" {
		t.Fatalf("expected one medium host-port finding on app, got %+v", r.Findings)
	}
	if !strings.Contains(hits[0].Message, "9100") {
		t.Fatalf("host-port message should name the port: %q", hits[0].Message)
	}
}

func TestSeccompInheritance(t *testing.T) {
	cases := []struct {
		name      string
		pod       string // pod-level seccompProfile type, "" for unset
		container string // container-level seccompProfile type, "" for unset
		podRules  []string
		appRule   string // expected seccomp rule on the container, "" for none
	}{
		{"unset everywhere", "", "", nil, "missing-seccomp"},
		{"pod RuntimeDefault", "RuntimeDefault", "", nil, ""},
		{"container Localhost", "", "Localhost", nil, ""},
		{"container Unconfined", "RuntimeDefault", "Unconfined", nil, "seccomp-unconfined"},
		{"pod Unconfined inherited", "Unconfined", "", []string{"seccomp-unconfined"}, ""},
		{"pod Unconfined overridden", "Unconfined", "RuntimeDefault", []string{"seccomp-unconfined"}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			y := "kind: Pod\nmetadata: {name: p}\nspec:\n"
			if tc.pod != "" {
				y += "  securityContext:\n    seccompProfile: {type: " + tc.pod + "}\n"
			}
			y += `  containers:
    - name: app
      securityContext:
        runAsNonRoot: true
        allowPrivilegeEscalation: false
        readOnlyRootFilesystem: true
        capabilities: {drop: [ALL]}
`
			if tc.container != "" {
				y += "        seccompProfile: {type: " + tc.container + "}\n"
			}
			r, err := AuditBytes([]byte(y), "")
			if err != nil {
				t.Fatal(err)
			}
			var podRules []string
			for _, f := range podFindings(r) {
				podRules = append(podRules, f.Rule)
			}
			if strings.Join(podRules, ",") != strings.Join(tc.podRules, ",") {
				t.Fatalf("pod rules = %v, want %v", podRules, tc.podRules)
			}
			app := rulesFor(r, "app")
			if tc.appRule == "" && len(app) != 0 {
				t.Fatalf("expected no container findings, got %v", app)
			}
			if tc.appRule != "" {
				if _, ok := app[tc.appRule]; !ok || len(app) != 1 {
					t.Fatalf("expected only %s on app, got %v", tc.appRule, app)
				}
			}
		})
	}
}

func TestSeccompSeverities(t *testing.T) {
	y := `
kind: Pod
metadata: {name: p}
spec:
  containers:
    - name: open
      securityContext: {seccompProfile: {type: Unconfined}}
    - name: unset
`
	r, _ := AuditBytes([]byte(y), "")
	if sev := rulesFor(r, "open")["seccomp-unconfined"]; sev != SeverityHigh {
		t.Fatalf("seccomp-unconfined should be high, got %v", sev)
	}
	if sev := rulesFor(r, "unset")["missing-seccomp"]; sev != SeverityLow {
		t.Fatalf("missing-seccomp should be low, got %v", sev)
	}
}

func TestTablePodLevelFindingShowsPod(t *testing.T) {
	y := `
kind: Pod
metadata: {name: p}
spec:
  hostNetwork: true
  containers:
    - name: app` + hardenedContainer
	r, _ := AuditBytes([]byte(y), "")
	var buf bytes.Buffer
	if err := r.WriteTable(&buf); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "(pod)") {
		t.Fatalf("pod-level finding should render container as (pod):\n%s", buf.String())
	}
}
