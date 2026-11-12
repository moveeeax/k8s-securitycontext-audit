package cmd

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const privilegedPod = `
kind: Pod
metadata: {name: p, namespace: ns}
spec:
  securityContext:
    runAsNonRoot: true
    seccompProfile: {type: RuntimeDefault}
  containers:
    - name: app
      securityContext:
        privileged: true
        allowPrivilegeEscalation: false
        readOnlyRootFilesystem: true
        capabilities: {drop: [ALL]}
`

func run(t *testing.T, args ...string) (stdout, stderr string, err error) {
	t.Helper()
	root := newRootCmd()
	var out, errOut bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&errOut)
	root.SetArgs(args)
	err = root.Execute()
	return out.String(), errOut.String(), err
}

func writeFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestIgnoreFileLiftsFailOn(t *testing.T) {
	dir := t.TempDir()
	manifest := writeFile(t, dir, "pod.yaml", privilegedPod)

	_, _, err := run(t, "audit", manifest, "--fail-on", "high")
	var ee exitError
	if !errors.As(err, &ee) || ee.code != 1 {
		t.Fatalf("expected exit 1 without suppression, got %v", err)
	}

	ignore := writeFile(t, dir, "ignore.yaml", `
suppressions:
  - {kind: Pod, namespace: ns, name: p, ignore: [privileged], reason: test exception}
`)
	out, _, err := run(t, "audit", manifest, "--fail-on", "high", "--ignore-file", ignore, "-o", "json")
	if err != nil {
		t.Fatalf("suppressed finding must not trip --fail-on: %v", err)
	}
	if !strings.Contains(out, `"suppressed": true`) || !strings.Contains(out, "test exception") {
		t.Fatalf("JSON should carry the suppressed finding:\n%s", out)
	}
}

func TestIgnoreFileErrorsAndWarnings(t *testing.T) {
	dir := t.TempDir()
	manifest := writeFile(t, dir, "pod.yaml", privilegedPod)

	bad := writeFile(t, dir, "bad.yaml", "suppressions:\n  - {kind: Pod, name: p, ignore: [privileged]}\n")
	if _, _, err := run(t, "audit", manifest, "--ignore-file", bad); err == nil || !strings.Contains(err.Error(), "reason") {
		t.Fatalf("expected a missing-reason error, got %v", err)
	}

	unused := writeFile(t, dir, "unused.yaml", "suppressions:\n  - {kind: Pod, name: other, ignore: [privileged], reason: x}\n")
	_, stderr, err := run(t, "audit", manifest, "--ignore-file", unused)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stderr, "warning:") || !strings.Contains(stderr, "matched no findings") {
		t.Fatalf("expected an unused-entry warning on stderr, got %q", stderr)
	}
}
