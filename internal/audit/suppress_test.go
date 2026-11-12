package audit

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// cniDaemonSet has pod-level host-namespace and host-path findings plus
// privileged on agent and nothing but the defaults on helper.
const cniDaemonSet = `
kind: DaemonSet
metadata:
  name: cni
  namespace: kube-system
  annotations:
%s
spec:
  template:
    spec:
      hostNetwork: true
      volumes:
        - name: cni-bin
          hostPath: {path: /opt/cni/bin}
      securityContext:
        runAsNonRoot: true
        seccompProfile: {type: RuntimeDefault}
      containers:
        - name: agent
          securityContext:
            privileged: true
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities: {drop: [ALL]}
        - name: helper
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities: {drop: [ALL]}
            privileged: true
`

func auditCNI(t *testing.T, annotations string) *Report {
	t.Helper()
	r, err := AuditBytes([]byte(strings.Replace(cniDaemonSet, "%s", annotations, 1)), "cni.yaml")
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func find(r *Report, container, rule string) *Finding {
	for i := range r.Findings {
		if r.Findings[i].Container == container && r.Findings[i].Rule == rule {
			return &r.Findings[i]
		}
	}
	return nil
}

func TestAnnotationSuppressesWholeWorkload(t *testing.T) {
	r := auditCNI(t, `    securitycontext-audit.moveeeax.io/ignore: "privileged, host-namespace,host-path"
    securitycontext-audit.moveeeax.io/reason: CNI agent manages node networking`)
	for _, c := range []string{"agent", "helper"} {
		f := find(r, c, "privileged")
		if f == nil || !f.Suppressed || f.Suppression.Source != SourceAnnotation ||
			f.Suppression.Reason != "CNI agent manages node networking" {
			t.Fatalf("privileged on %s should be suppressed by annotation: %+v", c, f)
		}
	}
	for _, rule := range []string{"host-namespace", "host-path"} {
		if f := find(r, "", rule); f == nil || !f.Suppressed {
			t.Fatalf("pod-level %s should be suppressed: %+v", rule, f)
		}
	}
	if r.FailAt(SeverityHigh) {
		t.Fatal("all high findings are suppressed; FailAt(high) should be false")
	}
	if r.Summary["high"] != 0 || r.Summary["suppressed"] != 4 {
		t.Fatalf("summary should count suppressed separately: %v", r.Summary)
	}
	if len(r.Warnings) != 0 {
		t.Fatalf("unexpected warnings: %v", r.Warnings)
	}
}

func TestAnnotationSuppressesOneContainer(t *testing.T) {
	r := auditCNI(t, `    securitycontext-audit.moveeeax.io/ignore.agent: privileged
    securitycontext-audit.moveeeax.io/reason: CNI agent`)
	if f := find(r, "agent", "privileged"); f == nil || !f.Suppressed {
		t.Fatalf("agent privileged should be suppressed: %+v", f)
	}
	if f := find(r, "helper", "privileged"); f == nil || f.Suppressed {
		t.Fatalf("helper privileged must stay active: %+v", f)
	}
	if f := find(r, "", "host-namespace"); f == nil || f.Suppressed {
		t.Fatalf("container-scoped annotation must not suppress pod-level findings: %+v", f)
	}
	if !r.FailAt(SeverityHigh) {
		t.Fatal("active high findings remain; FailAt(high) should be true")
	}
}

func TestAnnotationWithoutReasonIsIgnored(t *testing.T) {
	r := auditCNI(t, `    securitycontext-audit.moveeeax.io/ignore: privileged`)
	for _, f := range r.Findings {
		if f.Suppressed {
			t.Fatalf("no finding may be suppressed without a reason: %+v", f)
		}
	}
	if len(r.Warnings) != 1 || !strings.Contains(r.Warnings[0], "reason") {
		t.Fatalf("expected one missing-reason warning, got %v", r.Warnings)
	}
}

func TestAnnotationUnknownRuleWarns(t *testing.T) {
	r := auditCNI(t, `    securitycontext-audit.moveeeax.io/ignore: privilegd,host-path
    securitycontext-audit.moveeeax.io/reason: typo test`)
	if f := find(r, "", "host-path"); f == nil || !f.Suppressed {
		t.Fatalf("known rule should still be suppressed: %+v", f)
	}
	if len(r.Warnings) != 1 || !strings.Contains(r.Warnings[0], `"privilegd"`) {
		t.Fatalf("expected unknown-rule warning, got %v", r.Warnings)
	}
}

const ignoreYAML = `
suppressions:
  - kind: DaemonSet
    namespace: kube-system
    name: cni
    container: agent
    ignore: [privileged]
    reason: CNI agent
  - kind: DaemonSet
    namespace: kube-system
    name: cni
    ignore: [host-namespace]
    reason: host networking
    expires: 2027-03-31
`

func TestIgnoreFileSuppressesUntilExpiry(t *testing.T) {
	f, err := ParseIgnoreFile([]byte(ignoreYAML))
	if err != nil {
		t.Fatal(err)
	}
	if f.Suppressions[1].Expires != "2027-03-31" {
		t.Fatalf("unquoted date should decode as string, got %q", f.Suppressions[1].Expires)
	}

	// The expiry date itself is still covered.
	r := auditCNI(t, "    {}")
	r.ApplyIgnoreFile(f, time.Date(2027, 3, 31, 23, 0, 0, 0, time.UTC))
	if fd := find(r, "agent", "privileged"); fd == nil || !fd.Suppressed || fd.Suppression.Source != SourceIgnoreFile {
		t.Fatalf("agent privileged should be suppressed by ignore file: %+v", fd)
	}
	if fd := find(r, "helper", "privileged"); fd == nil || fd.Suppressed {
		t.Fatalf("helper privileged must stay active: %+v", fd)
	}
	if fd := find(r, "", "host-namespace"); fd == nil || !fd.Suppressed || fd.Suppression.Expires != "2027-03-31" {
		t.Fatalf("host-namespace should be suppressed until expiry: %+v", fd)
	}
	if len(r.Warnings) != 0 {
		t.Fatalf("unexpected warnings: %v", r.Warnings)
	}

	r = auditCNI(t, "    {}")
	r.ApplyIgnoreFile(f, time.Date(2027, 4, 1, 0, 0, 0, 0, time.UTC))
	if fd := find(r, "", "host-namespace"); fd == nil || fd.Suppressed {
		t.Fatalf("expired entry must not suppress: %+v", fd)
	}
	if len(r.Warnings) != 1 || !strings.Contains(r.Warnings[0], "expired") {
		t.Fatalf("expected an expiry warning, got %v", r.Warnings)
	}
}

func TestIgnoreFileNamespaceMustMatch(t *testing.T) {
	f, err := ParseIgnoreFile([]byte(`
suppressions:
  - kind: DaemonSet
    name: cni
    ignore: [privileged]
    reason: wrong namespace
`))
	if err != nil {
		t.Fatal(err)
	}
	r := auditCNI(t, "    {}")
	r.ApplyIgnoreFile(f, time.Now())
	if r.Summary["suppressed"] != 0 {
		t.Fatalf("entry without namespace must not match kube-system: %+v", r.Findings)
	}
	if len(r.Warnings) != 1 || !strings.Contains(r.Warnings[0], "matched no findings") {
		t.Fatalf("expected unused-entry warning, got %v", r.Warnings)
	}
}

func TestIgnoreFileValidation(t *testing.T) {
	cases := map[string]string{
		"missing reason":        "suppressions:\n  - {kind: Pod, name: p, ignore: [privileged]}\n",
		"unknown rule":          "suppressions:\n  - {kind: Pod, name: p, ignore: [nope], reason: x}\n",
		"no rules":              "suppressions:\n  - {kind: Pod, name: p, reason: x}\n",
		"no name":               "suppressions:\n  - {kind: Pod, ignore: [privileged], reason: x}\n",
		"bad date":              "suppressions:\n  - {kind: Pod, name: p, ignore: [privileged], reason: x, expires: 31.03.2027}\n",
		"unknown key":           "suppressions:\n  - {kind: Pod, name: p, rules: [privileged], reason: x}\n",
		"pod rule on container": "suppressions:\n  - {kind: Pod, name: p, container: app, ignore: [host-path], reason: x}\n",
	}
	for name, y := range cases {
		if _, err := ParseIgnoreFile([]byte(y)); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

func TestSuppressedFindingsInJSONAndSARIF(t *testing.T) {
	r := auditCNI(t, `    securitycontext-audit.moveeeax.io/ignore.agent: privileged
    securitycontext-audit.moveeeax.io/reason: CNI agent`)
	f, err := ParseIgnoreFile([]byte(`
suppressions:
  - {kind: DaemonSet, namespace: kube-system, name: cni, ignore: [host-path], reason: CNI binaries}
`))
	if err != nil {
		t.Fatal(err)
	}
	r.ApplyIgnoreFile(f, time.Now())

	var jbuf bytes.Buffer
	if err := r.WriteJSON(&jbuf); err != nil {
		t.Fatal(err)
	}
	var j struct {
		Findings []struct {
			Container   string `json:"container"`
			Rule        string `json:"rule"`
			Suppressed  bool   `json:"suppressed"`
			Suppression *struct {
				Source string `json:"source"`
				Reason string `json:"reason"`
			} `json:"suppression"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(jbuf.Bytes(), &j); err != nil {
		t.Fatal(err)
	}
	suppressed := 0
	for _, fd := range j.Findings {
		if fd.Suppressed {
			suppressed++
			if fd.Suppression == nil || fd.Suppression.Reason == "" {
				t.Fatalf("suppressed JSON finding lacks reason: %+v", fd)
			}
		}
	}
	if suppressed != 2 {
		t.Fatalf("expected 2 suppressed findings in JSON, got %d", suppressed)
	}

	var sbuf bytes.Buffer
	if err := r.WriteSARIF(&sbuf, "test"); err != nil {
		t.Fatal(err)
	}
	var s struct {
		Runs []struct {
			Results []struct {
				RuleID       string `json:"ruleId"`
				Suppressions []struct {
					Kind          string `json:"kind"`
					Status        string `json:"status"`
					Justification string `json:"justification"`
				} `json:"suppressions"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(sbuf.Bytes(), &s); err != nil {
		t.Fatal(err)
	}
	kinds := map[string]string{}
	total := 0
	for _, res := range s.Runs[0].Results {
		total++
		if len(res.Suppressions) == 1 {
			sp := res.Suppressions[0]
			if sp.Status != "accepted" || sp.Justification == "" {
				t.Fatalf("bad SARIF suppression: %+v", sp)
			}
			kinds[res.RuleID] = sp.Kind
		}
	}
	if total != len(r.Findings) {
		t.Fatalf("SARIF must keep suppressed results: %d results for %d findings", total, len(r.Findings))
	}
	if kinds["privileged"] != "inSource" || kinds["host-path"] != "external" {
		t.Fatalf("SARIF suppression kinds = %v", kinds)
	}

	var tbuf bytes.Buffer
	if err := r.WriteTable(&tbuf); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(tbuf.String(), "Suppressed:") || !strings.Contains(tbuf.String(), "CNI binaries") ||
		!strings.Contains(tbuf.String(), "; 2 suppressed") {
		t.Fatalf("table should list suppressed findings with reason:\n%s", tbuf.String())
	}
}

func TestAnnotationPodRuleOnContainerWarns(t *testing.T) {
	r := auditCNI(t, `    securitycontext-audit.moveeeax.io/ignore.agent: host-namespace
    securitycontext-audit.moveeeax.io/reason: wrong scope`)
	if f := find(r, "", "host-namespace"); f == nil || f.Suppressed {
		t.Fatalf("container-scoped key must not suppress pod-level host-namespace: %+v", f)
	}
	if len(r.Warnings) != 1 || !strings.Contains(r.Warnings[0], "pod-level") {
		t.Fatalf("expected a pod-level scope warning, got %v", r.Warnings)
	}
}
